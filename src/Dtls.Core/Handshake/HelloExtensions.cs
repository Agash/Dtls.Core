using System.Net.Security;
using Dtls.Core.Wire;

namespace Dtls.Core.Handshake;

// The bodies of the hello extensions Dtls.Core sends and reads.
internal static class HelloExtensions
{
    // The uncompressed point format, the only one RFC 8422 §5.1.2 still allows.
    private const byte Uncompressed = 0;

    // RFC 8422 §5.1.1: a list of named groups.
    public static byte[] SupportedGroups(IEnumerable<NamedGroup> groups)
    {
        WireWriter writer = new(16);
        WireWriter.Vector list = writer.BeginVector16();
        foreach (NamedGroup group in groups)
        {
            writer.WriteUInt16((ushort)group);
        }

        list.End();
        return writer.ToArray();
    }

    public static List<NamedGroup> ReadSupportedGroups(ReadOnlySpan<byte> data)
    {
        WireReader reader = new(data);
        ReadOnlySpan<byte> bytes = reader.ReadVector16();
        reader.ExpectEnd();
        if (bytes.Length % 2 != 0)
        {
            throw DtlsException.Decode("the supported groups");
        }

        List<NamedGroup> groups = [];
        WireReader list = new(bytes);
        while (!list.IsEmpty)
        {
            groups.Add((NamedGroup)list.ReadUInt16());
        }

        return groups;
    }

    // RFC 8422 §5.1.2.
    public static byte[] PointFormats() => [1, Uncompressed];

    public static bool OffersUncompressedPoints(ReadOnlySpan<byte> data)
    {
        WireReader reader = new(data);
        ReadOnlySpan<byte> formats = reader.ReadVector8();
        reader.ExpectEnd();
        return formats.Contains(Uncompressed);
    }

    // RFC 5246 §7.4.1.4.1.
    public static byte[] SignatureAlgorithms(IEnumerable<SignatureScheme> schemes)
    {
        WireWriter writer = new(16);
        WireWriter.Vector list = writer.BeginVector16();
        foreach (SignatureScheme scheme in schemes)
        {
            writer.WriteUInt16((ushort)scheme);
        }

        list.End();
        return writer.ToArray();
    }

    public static List<SignatureScheme> ReadSignatureAlgorithms(ReadOnlySpan<byte> data)
    {
        WireReader reader = new(data);
        ReadOnlySpan<byte> bytes = reader.ReadVector16();
        reader.ExpectEnd();
        return [.. CertificateRequest.SchemeList(bytes)];
    }

    // RFC 5764 §4.1.1: the profiles and an MKI, which Dtls.Core leaves empty.
    public static byte[] UseSrtp(IEnumerable<SrtpProtectionProfile> profiles)
    {
        WireWriter writer = new(16);
        WireWriter.Vector list = writer.BeginVector16();
        foreach (SrtpProtectionProfile profile in profiles)
        {
            writer.WriteUInt16((ushort)profile);
        }

        list.End();
        writer.WriteVector8([]);
        return writer.ToArray();
    }

    public static List<SrtpProtectionProfile> ReadUseSrtp(ReadOnlySpan<byte> data)
    {
        WireReader reader = new(data);
        ReadOnlySpan<byte> bytes = reader.ReadVector16();
        _ = reader.ReadVector8();
        reader.ExpectEnd();
        if (bytes.Length == 0 || bytes.Length % 2 != 0)
        {
            throw DtlsException.Decode("the SRTP protection profiles");
        }

        List<SrtpProtectionProfile> profiles = [];
        WireReader list = new(bytes);
        while (!list.IsEmpty)
        {
            profiles.Add((SrtpProtectionProfile)list.ReadUInt16());
        }

        return profiles;
    }

    // RFC 7301 §3.1: a list of protocol names.
    public static byte[] ApplicationProtocols(IEnumerable<SslApplicationProtocol> protocols)
    {
        WireWriter writer = new(32);
        WireWriter.Vector list = writer.BeginVector16();
        foreach (SslApplicationProtocol protocol in protocols)
        {
            writer.WriteVector8(protocol.Protocol.Span);
        }

        list.End();
        return writer.ToArray();
    }

    public static List<SslApplicationProtocol> ReadApplicationProtocols(ReadOnlySpan<byte> data)
    {
        WireReader reader = new(data);
        WireReader list = new(reader.ReadVector16());
        reader.ExpectEnd();
        List<SslApplicationProtocol> protocols = [];
        while (!list.IsEmpty)
        {
            ReadOnlySpan<byte> name = list.ReadVector8();
            if (name.IsEmpty)
            {
                throw DtlsException.Decode("an empty application protocol name");
            }

            protocols.Add(new SslApplicationProtocol(name.ToArray()));
        }

        return protocols.Count > 0
            ? protocols
            : throw DtlsException.Decode("an empty application protocol list");
    }

    // RFC 5746 §3.2: an initial handshake's renegotiation_info carries an empty renegotiated_connection.
    public static byte[] EmptyRenegotiationInfo() => [0];

    public static bool IsEmptyRenegotiationInfo(ReadOnlySpan<byte> data) => data is [0];

    // RFC 9146 §3: the CID the sender wants in the records it receives.
    public static byte[] ConnectionId(ReadOnlySpan<byte> cid)
    {
        WireWriter writer = new(1 + cid.Length);
        writer.WriteVector8(cid);
        return writer.ToArray();
    }

    public static byte[] ReadConnectionId(ReadOnlySpan<byte> data)
    {
        WireReader reader = new(data);
        ReadOnlySpan<byte> cid = reader.ReadVector8();
        reader.ExpectEnd();
        return cid.ToArray();
    }

    // RFC 8449 §4: the most plaintext the sender takes in a protected record.
    public static byte[] RecordSizeLimit(int limit)
    {
        WireWriter writer = new(2);
        writer.WriteUInt16((ushort)limit);
        return writer.ToArray();
    }

    public static int ReadRecordSizeLimit(ReadOnlySpan<byte> data)
    {
        WireReader reader = new(data);
        int limit = reader.ReadUInt16();
        reader.ExpectEnd();
        return limit >= 64
            ? limit
            : throw DtlsException.IllegalParameter("a record size limit below 64 bytes");
    }
}
