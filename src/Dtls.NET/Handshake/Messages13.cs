using System.Collections.Immutable;
using Dtls.NET.Wire;

namespace Dtls.NET.Handshake;

// The handshake messages DTLS 1.3 adds or reshapes (RFC 8446 §4, RFC 9147 §5 and §7). ClientHello,
// ServerHello and CertificateVerify keep their DTLS 1.2 encodings.
internal static class Messages13
{
    // A ServerHello with this random is a HelloRetryRequest (RFC 8446 §4.1.3): SHA-256("HelloRetryRequest").
    public static ReadOnlySpan<byte> HelloRetryRequestRandom =>
        [
            0xCF,
            0x21,
            0xAD,
            0x74,
            0xE5,
            0x9A,
            0x61,
            0x11,
            0xBE,
            0x1D,
            0x8C,
            0x02,
            0x1E,
            0x65,
            0xB8,
            0x91,
            0xC2,
            0xA2,
            0x11,
            0x16,
            0x7A,
            0xBB,
            0x8C,
            0x5E,
            0x07,
            0x9E,
            0x09,
            0xE2,
            0xC8,
            0xA8,
            0x33,
            0x9C,
        ];

    // The last 8 bytes of a DTLS 1.2 ServerHello's random from a server that also speaks DTLS 1.3
    // (RFC 8446 §4.1.3): "DOWNGRD" and 1. A client that offered 1.3 and sees it aborts.
    public static ReadOnlySpan<byte> DowngradeSentinel =>
        [0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01];

    // The prefix of the content CertificateVerify signs (RFC 8446 §4.4.3): 64 spaces.
    public const int SignaturePadding = 64;
    public const string ServerSignatureContext = "TLS 1.3, server CertificateVerify";
    public const string ClientSignatureContext = "TLS 1.3, client CertificateVerify";

    // supported_versions in a ClientHello: the versions, most preferred first.
    public static byte[] SupportedVersions(IEnumerable<ushort> versions)
    {
        WireWriter writer = new(8);
        WireWriter.Vector list = writer.BeginVector8();
        foreach (ushort version in versions)
        {
            writer.WriteUInt16(version);
        }

        list.End();
        return writer.ToArray();
    }

    public static bool OffersVersion(ReadOnlySpan<byte> data, ushort version)
    {
        WireReader reader = new(data);
        ReadOnlySpan<byte> list = reader.ReadVector8();
        reader.ExpectEnd();
        if (list.Length % 2 != 0)
        {
            throw DtlsException.Decode("the supported versions");
        }

        for (int i = 0; i < list.Length; i += 2)
        {
            if (((list[i] << 8) | list[i + 1]) == version)
            {
                return true;
            }
        }

        return false;
    }

    // supported_versions in a ServerHello: the one chosen.
    public static byte[] SelectedVersion(ushort version) => [(byte)(version >> 8), (byte)version];

    public static ushort ReadSelectedVersion(ReadOnlySpan<byte> data)
    {
        WireReader reader = new(data);
        ushort version = reader.ReadUInt16();
        reader.ExpectEnd();
        return version;
    }

    // key_share in a ClientHello: KeyShareEntry client_shares<0..2^16-1>.
    public static byte[] ClientKeyShares(IEnumerable<(NamedGroup Group, byte[] Key)> shares)
    {
        WireWriter writer = new(128);
        WireWriter.Vector list = writer.BeginVector16();
        foreach ((NamedGroup group, byte[] key) in shares)
        {
            writer.WriteUInt16((ushort)group);
            writer.WriteVector16(key);
        }

        list.End();
        return writer.ToArray();
    }

    public static List<(NamedGroup Group, byte[] Key)> ReadClientKeyShares(ReadOnlySpan<byte> data)
    {
        WireReader reader = new(data);
        WireReader list = new(reader.ReadVector16());
        reader.ExpectEnd();
        List<(NamedGroup, byte[])> shares = [];
        while (!list.IsEmpty)
        {
            NamedGroup group = (NamedGroup)list.ReadUInt16();
            byte[] key = list.ReadVector16().ToArray();
            if (shares.Exists(s => s.Item1 == group))
            {
                throw DtlsException.IllegalParameter(
                    "the client sent two key shares for one group"
                );
            }

            shares.Add((group, key));
        }

        return shares;
    }

    // key_share in a ServerHello: one KeyShareEntry.
    public static byte[] ServerKeyShare(NamedGroup group, ReadOnlySpan<byte> key)
    {
        WireWriter writer = new(4 + key.Length);
        writer.WriteUInt16((ushort)group);
        writer.WriteVector16(key);
        return writer.ToArray();
    }

    public static (NamedGroup Group, byte[] Key) ReadServerKeyShare(ReadOnlySpan<byte> data)
    {
        WireReader reader = new(data);
        NamedGroup group = (NamedGroup)reader.ReadUInt16();
        byte[] key = reader.ReadVector16().ToArray();
        reader.ExpectEnd();
        return (group, key);
    }

    // key_share in a HelloRetryRequest: the group the server wants a share for.
    public static byte[] SelectedGroup(NamedGroup group) =>
        [(byte)((ushort)group >> 8), (byte)group];

    public static NamedGroup ReadSelectedGroup(ReadOnlySpan<byte> data)
    {
        WireReader reader = new(data);
        NamedGroup group = (NamedGroup)reader.ReadUInt16();
        reader.ExpectEnd();
        return group;
    }

    // cookie: opaque cookie<1..2^16-1>.
    public static byte[] Cookie(ReadOnlySpan<byte> cookie)
    {
        WireWriter writer = new(2 + cookie.Length);
        writer.WriteVector16(cookie);
        return writer.ToArray();
    }

    public static byte[] ReadCookie(ReadOnlySpan<byte> data)
    {
        WireReader reader = new(data);
        byte[] cookie = reader.ReadVector16().ToArray();
        reader.ExpectEnd();
        return cookie.Length > 0 ? cookie : throw DtlsException.Decode("an empty cookie");
    }

    // The content CertificateVerify signs: 64 spaces, the context string, a zero and the transcript hash.
    public static byte[] SignedContent(bool server, ReadOnlySpan<byte> transcriptHash)
    {
        string context = server ? ServerSignatureContext : ClientSignatureContext;
        byte[] content = new byte[SignaturePadding + context.Length + 1 + transcriptHash.Length];
        content.AsSpan(0, SignaturePadding).Fill(0x20);
        _ = System.Text.Encoding.ASCII.GetBytes(context, content.AsSpan(SignaturePadding));
        transcriptHash.CopyTo(content.AsSpan(SignaturePadding + context.Length + 1));
        return content;
    }
}

// EncryptedExtensions: the server's extensions that need no key exchange (RFC 8446 §4.3.1).
internal sealed record EncryptedExtensions(Extensions Extensions)
{
    public void Encode(WireWriter writer)
    {
        if (Extensions.Types.Any())
        {
            Extensions.Encode(writer);
        }
        else
        {
            writer.WriteUInt16(0);
        }
    }

    public static EncryptedExtensions Decode(ReadOnlySpan<byte> body)
    {
        WireReader reader = new(body);
        Extensions extensions = Extensions.Decode(ref reader);
        reader.ExpectEnd();
        return new EncryptedExtensions(extensions);
    }
}

// CertificateRequest in TLS 1.3 (RFC 8446 §4.3.2): a context and extensions, signature_algorithms among
// them.
internal sealed record CertificateRequest13(byte[] Context, Extensions Extensions)
{
    public void Encode(WireWriter writer)
    {
        writer.WriteVector8(Context);
        Extensions.Encode(writer);
    }

    public static CertificateRequest13 Decode(ReadOnlySpan<byte> body)
    {
        WireReader reader = new(body);
        byte[] context = reader.ReadVector8().ToArray();
        Extensions extensions = Extensions.Decode(ref reader);
        reader.ExpectEnd();
        return new CertificateRequest13(context, extensions);
    }
}

// Certificate in TLS 1.3 (RFC 8446 §4.4.2): a request context and entries of a certificate with its
// own extensions (none are sent; those received are not used).
internal sealed record Certificate13(byte[] Context, ImmutableArray<byte[]> Chain)
{
    private const int MaximumCertificates = 10;

    public void Encode(WireWriter writer)
    {
        writer.WriteVector8(Context);
        WireWriter.Vector list = writer.BeginVector24();
        foreach (byte[] certificate in Chain)
        {
            writer.WriteVector24(certificate);
            writer.WriteUInt16(0);
        }

        list.End();
    }

    public static Certificate13 Decode(ReadOnlySpan<byte> body)
    {
        WireReader reader = new(body);
        byte[] context = reader.ReadVector8().ToArray();
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

            _ = list.ReadVector16();
            chain.Add(certificate.ToArray());
        }

        return new Certificate13(context, chain.ToImmutable());
    }
}

// The record numbers an ACK acknowledges (RFC 9147 §7): epoch and sequence number, 64 bits each.
internal static class AckMessage
{
    public const int EntrySize = 16;

    public static byte[] Encode(IReadOnlyList<(ushort Epoch, ulong Sequence)> records)
    {
        WireWriter writer = new(2 + (EntrySize * records.Count));
        WireWriter.Vector list = writer.BeginVector16();
        foreach ((ushort epoch, ulong sequence) in records.Order())
        {
            writer.WriteUInt32(0);
            writer.WriteUInt32(epoch);
            writer.WriteUInt32((uint)(sequence >> 32));
            writer.WriteUInt32((uint)sequence);
        }

        list.End();
        return writer.ToArray();
    }

    public static List<(ushort Epoch, ulong Sequence)> Decode(ReadOnlySpan<byte> payload)
    {
        WireReader reader = new(payload);
        ReadOnlySpan<byte> bytes = reader.ReadVector16();
        reader.ExpectEnd();
        if (bytes.Length % EntrySize != 0)
        {
            throw DtlsException.Decode("an ACK's record numbers");
        }

        List<(ushort, ulong)> records = [];
        WireReader list = new(bytes);
        while (!list.IsEmpty)
        {
            ulong epoch = ((ulong)list.ReadUInt32() << 32) | list.ReadUInt32();
            ulong sequence = ((ulong)list.ReadUInt32() << 32) | list.ReadUInt32();
            if (epoch <= ushort.MaxValue)
            {
                records.Add(((ushort)epoch, sequence));
            }
        }

        return records;
    }
}
