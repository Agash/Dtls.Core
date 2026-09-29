using System.Buffers.Binary;

namespace Dtls.NET.Wire;

// Reads DTLS's big-endian fields and length-prefixed vectors from a received message. A field that
// runs past the end of the message is a decode_error: nothing is read out of range, and a length a
// peer declares is never trusted beyond the bytes actually present.
internal ref struct WireReader(ReadOnlySpan<byte> data)
{
    private readonly ReadOnlySpan<byte> _data = data;
    private int _position;

    public readonly int Remaining => _data.Length - _position;

    public readonly bool IsEmpty => _position == _data.Length;

    public readonly int Position => _position;

    public byte ReadUInt8() => Take(1)[0];

    public ushort ReadUInt16() => BinaryPrimitives.ReadUInt16BigEndian(Take(2));

    public int ReadUInt24()
    {
        ReadOnlySpan<byte> bytes = Take(3);
        return (bytes[0] << 16) | (bytes[1] << 8) | bytes[2];
    }

    public ulong ReadUInt48()
    {
        ReadOnlySpan<byte> bytes = Take(6);
        return ((ulong)BinaryPrimitives.ReadUInt16BigEndian(bytes) << 32)
            | BinaryPrimitives.ReadUInt32BigEndian(bytes[2..]);
    }

    public uint ReadUInt32() => BinaryPrimitives.ReadUInt32BigEndian(Take(4));

    public ReadOnlySpan<byte> ReadBytes(int count) => Take(count);

    // An opaque vector with a one-byte length (<0..2^8-1>).
    public ReadOnlySpan<byte> ReadVector8() => Take(ReadUInt8());

    // An opaque vector with a two-byte length (<0..2^16-1>).
    public ReadOnlySpan<byte> ReadVector16() => Take(ReadUInt16());

    // An opaque vector with a three-byte length (<0..2^24-1>).
    public ReadOnlySpan<byte> ReadVector24() => Take(ReadUInt24());

    public ReadOnlySpan<byte> ReadRemaining() => Take(Remaining);

    // Ends a message: trailing bytes after its last field are a decode_error.
    public readonly void ExpectEnd()
    {
        if (!IsEmpty)
        {
            throw DtlsException.Decode("a message has trailing bytes");
        }
    }

    private ReadOnlySpan<byte> Take(int count)
    {
        if (count < 0 || count > Remaining)
        {
            throw DtlsException.Decode("a field runs past the end of its message");
        }

        ReadOnlySpan<byte> taken = _data.Slice(_position, count);
        _position += count;
        return taken;
    }
}
