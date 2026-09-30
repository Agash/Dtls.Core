using System.Collections.Immutable;
using Dtls.Core.Records;
using Dtls.Core.Wire;

namespace Dtls.Core.Handshake;

// A hello's extensions, by type. A type may appear once (RFC 5246 §7.4.1.4).
internal sealed class Extensions
{
    private readonly Dictionary<ushort, byte[]> _byType = [];
    private readonly List<ushort> _order = [];

    public IEnumerable<ushort> Types => _order;

    public bool Contains(ushort type) => _byType.ContainsKey(type);

    public bool TryGet(ushort type, out ReadOnlySpan<byte> data)
    {
        if (_byType.TryGetValue(type, out byte[]? bytes))
        {
            data = bytes;
            return true;
        }

        data = default;
        return false;
    }

    public Extensions Add(ushort type, ReadOnlySpan<byte> data)
    {
        if (!_byType.TryAdd(type, data.ToArray()))
        {
            throw DtlsException.Decode($"extension {type} appears twice");
        }

        _order.Add(type);
        return this;
    }

    public void Encode(WireWriter writer)
    {
        if (_order.Count == 0)
        {
            return;
        }

        WireWriter.Vector all = writer.BeginVector16();
        foreach (ushort type in _order)
        {
            writer.WriteUInt16(type);
            writer.WriteVector16(_byType[type]);
        }

        all.End();
    }

    // The extensions block is optional at the end of a hello (RFC 5246 §7.4.1.2).
    public static Extensions Decode(ref WireReader reader)
    {
        Extensions extensions = new();
        if (reader.IsEmpty)
        {
            return extensions;
        }

        WireReader block = new(reader.ReadVector16());
        while (!block.IsEmpty)
        {
            ushort type = block.ReadUInt16();
            _ = extensions.Add(type, block.ReadVector16());
        }

        return extensions;
    }
}

internal sealed record ClientHello(
    byte[] Random,
    byte[] SessionId,
    byte[] Cookie,
    ImmutableArray<ushort> CipherSuites,
    Extensions Extensions
)
{
    public void Encode(WireWriter writer)
    {
        writer.WriteUInt16(ProtocolVersion.Dtls12);
        writer.WriteBytes(Random);
        writer.WriteVector8(SessionId);
        writer.WriteVector8(Cookie);
        WireWriter.Vector suites = writer.BeginVector16();
        foreach (ushort suite in CipherSuites)
        {
            writer.WriteUInt16(suite);
        }

        suites.End();

        // Only the null compression method (RFC 5246 §7.4.1.2).
        writer.WriteVector8([0]);
        Extensions.Encode(writer);
    }

    public static ClientHello Decode(ReadOnlySpan<byte> body)
    {
        WireReader reader = new(body);
        ushort version = reader.ReadUInt16();
        byte[] random = reader.ReadBytes(32).ToArray();
        byte[] sessionId = Limited(reader.ReadVector8(), 32, "session id");
        byte[] cookie = Limited(reader.ReadVector8(), 255, "cookie");
        ReadOnlySpan<byte> suiteBytes = reader.ReadVector16();
        if (suiteBytes.Length == 0 || suiteBytes.Length % 2 != 0)
        {
            throw DtlsException.Decode("the cipher suite list");
        }

        ImmutableArray<ushort>.Builder suites = ImmutableArray.CreateBuilder<ushort>(
            suiteBytes.Length / 2
        );
        WireReader suitesReader = new(suiteBytes);
        while (!suitesReader.IsEmpty)
        {
            suites.Add(suitesReader.ReadUInt16());
        }

        ReadOnlySpan<byte> compression = reader.ReadVector8();
        if (compression.IndexOf((byte)0) < 0)
        {
            throw DtlsException.IllegalParameter("the ClientHello does not offer null compression");
        }

        Extensions extensions = Extensions.Decode(ref reader);
        reader.ExpectEnd();
        return new ClientHello(random, sessionId, cookie, suites.MoveToImmutable(), extensions)
        {
            Version = version,
        };
    }

    // The highest version the client offers. DTLS versions count down: 1.2 (0xFEFD) is below 1.0
    // (0xFEFF), and a later version below 1.2.
    public ushort Version { get; init; } = ProtocolVersion.Dtls12;

    private static byte[] Limited(ReadOnlySpan<byte> value, int maximum, string what) =>
        value.Length <= maximum
            ? value.ToArray()
            : throw DtlsException.Decode($"the {what} is too long");
}

internal sealed record HelloVerifyRequest(byte[] Cookie)
{
    public void Encode(WireWriter writer)
    {
        // RFC 6347 §4.2.1: DTLS 1.0's version, so any client can read it.
        writer.WriteUInt16(ProtocolVersion.Dtls10);
        writer.WriteVector8(Cookie);
    }

    public static HelloVerifyRequest Decode(ReadOnlySpan<byte> body)
    {
        WireReader reader = new(body);
        _ = reader.ReadUInt16();
        byte[] cookie = reader.ReadVector8().ToArray();
        reader.ExpectEnd();
        return new HelloVerifyRequest(cookie);
    }
}

internal sealed record ServerHello(
    byte[] Random,
    byte[] SessionId,
    ushort CipherSuite,
    Extensions Extensions
)
{
    public ushort Version { get; init; } = ProtocolVersion.Dtls12;

    public void Encode(WireWriter writer)
    {
        writer.WriteUInt16(Version);
        writer.WriteBytes(Random);
        writer.WriteVector8(SessionId);
        writer.WriteUInt16(CipherSuite);
        writer.WriteUInt8(0);
        Extensions.Encode(writer);
    }

    public static ServerHello Decode(ReadOnlySpan<byte> body)
    {
        WireReader reader = new(body);
        ushort version = reader.ReadUInt16();
        byte[] random = reader.ReadBytes(32).ToArray();
        ReadOnlySpan<byte> sessionId = reader.ReadVector8();
        if (sessionId.Length > 32)
        {
            throw DtlsException.Decode("the session id is too long");
        }

        ushort suite = reader.ReadUInt16();
        if (reader.ReadUInt8() != 0)
        {
            throw DtlsException.IllegalParameter("the server chose a compression method");
        }

        Extensions extensions = Extensions.Decode(ref reader);
        reader.ExpectEnd();
        return new ServerHello(random, sessionId.ToArray(), suite, extensions)
        {
            Version = version,
        };
    }
}

// A certificate chain, leaf first (RFC 5246 §7.4.2).
internal sealed record CertificateMessage(ImmutableArray<byte[]> Chain)
{
    // An upper bound on a peer's chain: WebRTC peers send one self-signed certificate.
    private const int MaximumCertificates = 10;

    public void Encode(WireWriter writer)
    {
        WireWriter.Vector all = writer.BeginVector24();
        foreach (byte[] certificate in Chain)
        {
            writer.WriteVector24(certificate);
        }

        all.End();
    }

    public static CertificateMessage Decode(ReadOnlySpan<byte> body)
    {
        WireReader reader = new(body);
        WireReader list = new(reader.ReadVector24());
        reader.ExpectEnd();
        ImmutableArray<byte[]>.Builder chain = ImmutableArray.CreateBuilder<byte[]>();
        while (!list.IsEmpty)
        {
            if (chain.Count == MaximumCertificates)
            {
                throw DtlsException.BadCertificate(
                    $"the chain is longer than {MaximumCertificates} certificates"
                );
            }

            ReadOnlySpan<byte> certificate = list.ReadVector24();
            if (certificate.Length == 0)
            {
                throw DtlsException.Decode("an empty certificate");
            }

            chain.Add(certificate.ToArray());
        }

        return new CertificateMessage(chain.ToImmutable());
    }
}

// The ECDHE parameters and their signature (RFC 8422 §5.4): named curve and point, signed with the
// server's certificate key over both randoms and the parameters.
internal sealed record ServerKeyExchange(
    NamedGroup Group,
    byte[] PublicKey,
    SignatureScheme Scheme,
    byte[] Signature
)
{
    private const byte NamedCurve = 3;

    // The part of the message the signature covers, after the randoms.
    public byte[] SignedParameters()
    {
        WireWriter writer = new(4 + PublicKey.Length);
        writer.WriteUInt8(NamedCurve);
        writer.WriteUInt16((ushort)Group);
        writer.WriteVector8(PublicKey);
        return writer.ToArray();
    }

    public void Encode(WireWriter writer)
    {
        writer.WriteBytes(SignedParameters());
        writer.WriteUInt16((ushort)Scheme);
        writer.WriteVector16(Signature);
    }

    public static ServerKeyExchange Decode(ReadOnlySpan<byte> body)
    {
        WireReader reader = new(body);
        if (reader.ReadUInt8() != NamedCurve)
        {
            throw DtlsException.IllegalParameter("the key exchange does not use a named curve");
        }

        NamedGroup group = (NamedGroup)reader.ReadUInt16();
        byte[] publicKey = reader.ReadVector8().ToArray();
        SignatureScheme scheme = (SignatureScheme)reader.ReadUInt16();
        byte[] signature = reader.ReadVector16().ToArray();
        reader.ExpectEnd();
        return new ServerKeyExchange(group, publicKey, scheme, signature);
    }
}

internal sealed record CertificateRequest(
    byte[] CertificateTypes,
    ImmutableArray<SignatureScheme> SignatureSchemes
)
{
    public void Encode(WireWriter writer)
    {
        writer.WriteVector8(CertificateTypes);
        WireWriter.Vector schemes = writer.BeginVector16();
        foreach (SignatureScheme scheme in SignatureSchemes)
        {
            writer.WriteUInt16((ushort)scheme);
        }

        schemes.End();

        // No certificate authorities: any certificate, authenticated by its fingerprint.
        writer.WriteVector16([]);
    }

    public static CertificateRequest Decode(ReadOnlySpan<byte> body)
    {
        WireReader reader = new(body);
        byte[] types = reader.ReadVector8().ToArray();
        ImmutableArray<SignatureScheme> schemes = SchemeList(reader.ReadVector16());
        _ = reader.ReadVector16();
        reader.ExpectEnd();
        return new CertificateRequest(types, schemes);
    }

    public static ImmutableArray<SignatureScheme> SchemeList(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length % 2 != 0)
        {
            throw DtlsException.Decode("the signature algorithm list");
        }

        ImmutableArray<SignatureScheme>.Builder schemes =
            ImmutableArray.CreateBuilder<SignatureScheme>(bytes.Length / 2);
        WireReader reader = new(bytes);
        while (!reader.IsEmpty)
        {
            schemes.Add((SignatureScheme)reader.ReadUInt16());
        }

        return schemes.MoveToImmutable();
    }
}

// The client's ECDHE public key (RFC 8422 §5.7).
internal sealed record ClientKeyExchange(byte[] PublicKey)
{
    public void Encode(WireWriter writer) => writer.WriteVector8(PublicKey);

    public static ClientKeyExchange Decode(ReadOnlySpan<byte> body)
    {
        WireReader reader = new(body);
        byte[] publicKey = reader.ReadVector8().ToArray();
        reader.ExpectEnd();
        return publicKey.Length > 0
            ? new ClientKeyExchange(publicKey)
            : throw DtlsException.Decode("an empty public key");
    }
}

internal sealed record CertificateVerify(SignatureScheme Scheme, byte[] Signature)
{
    public void Encode(WireWriter writer)
    {
        writer.WriteUInt16((ushort)Scheme);
        writer.WriteVector16(Signature);
    }

    public static CertificateVerify Decode(ReadOnlySpan<byte> body)
    {
        WireReader reader = new(body);
        SignatureScheme scheme = (SignatureScheme)reader.ReadUInt16();
        byte[] signature = reader.ReadVector16().ToArray();
        reader.ExpectEnd();
        return new CertificateVerify(scheme, signature);
    }
}
