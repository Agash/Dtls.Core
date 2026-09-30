namespace Dtls.Core.Records;

// A record's content type (RFC 5246 §6.2.1, RFC 9147 §7).
internal enum ContentType : byte
{
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,

    // DTLS 1.3 (RFC 9147 §7).
    Ack = 26,
}

// The DTLS version numbers, the one's complement of the TLS numbers they correspond to (RFC 6347
// §4.1): DTLS 1.0 is 254.255, DTLS 1.2 is 254.253 and DTLS 1.3 (RFC 9147 §5.3) is 254.252.
internal static class ProtocolVersion
{
    public const ushort Dtls10 = 0xFEFF;
    public const ushort Dtls12 = 0xFEFD;
    public const ushort Dtls13 = 0xFEFC;
}

// A record header (RFC 6347 §4.1): type, version, epoch, 48-bit sequence number and length.
internal readonly record struct RecordHeader(
    ContentType Type,
    ushort Version,
    ushort Epoch,
    ulong Sequence,
    int Length
)
{
    public const int Size = 13;

    // The largest record fragment DTLS allows (RFC 6347 §4.1: 2^14 plus expansion).
    public const int MaximumFragment = (1 << 14) + 2048;

    public ulong EpochAndSequence => ((ulong)Epoch << 48) | Sequence;
}
