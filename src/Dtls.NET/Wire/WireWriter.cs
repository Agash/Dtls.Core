using System.Buffers.Binary;

namespace Dtls.NET.Wire;

// Writes DTLS's big-endian fields and length-prefixed vectors into a growable buffer. A vector's
// length is written when it is closed, so its content can be written in place.
internal sealed class WireWriter(int capacity = 256)
{
    private byte[] _buffer = new byte[Math.Max(capacity, 16)];
    private int _length;

    public int Length => _length;

    public ReadOnlySpan<byte> Written => _buffer.AsSpan(0, _length);

    public void WriteUInt8(byte value) => Grow(1)[0] = value;

    public void WriteUInt16(ushort value) => BinaryPrimitives.WriteUInt16BigEndian(Grow(2), value);

    public void WriteUInt24(int value)
    {
        if ((uint)value > 0xFFFFFF)
        {
            throw new ArgumentOutOfRangeException(
                nameof(value),
                "A 24-bit field holds at most 2^24 - 1."
            );
        }

        Span<byte> bytes = Grow(3);
        bytes[0] = (byte)(value >> 16);
        bytes[1] = (byte)(value >> 8);
        bytes[2] = (byte)value;
    }

    public void WriteUInt48(ulong value)
    {
        if (value > 0xFFFF_FFFF_FFFF)
        {
            throw new ArgumentOutOfRangeException(
                nameof(value),
                "A 48-bit field holds at most 2^48 - 1."
            );
        }

        Span<byte> bytes = Grow(6);
        BinaryPrimitives.WriteUInt16BigEndian(bytes, (ushort)(value >> 32));
        BinaryPrimitives.WriteUInt32BigEndian(bytes[2..], (uint)value);
    }

    public void WriteBytes(ReadOnlySpan<byte> value) => value.CopyTo(Grow(value.Length));

    public void WriteVector8(ReadOnlySpan<byte> value)
    {
        Vector vector = BeginVector8();
        WriteBytes(value);
        vector.End();
    }

    public void WriteVector16(ReadOnlySpan<byte> value)
    {
        Vector vector = BeginVector16();
        WriteBytes(value);
        vector.End();
    }

    public void WriteVector24(ReadOnlySpan<byte> value)
    {
        Vector vector = BeginVector24();
        WriteBytes(value);
        vector.End();
    }

    public Vector BeginVector8() => Begin(1);

    public Vector BeginVector16() => Begin(2);

    public Vector BeginVector24() => Begin(3);

    public byte[] ToArray() => Written.ToArray();

    public void Clear() => _length = 0;

    private Vector Begin(int prefix)
    {
        int at = _length;
        _ = Grow(prefix);
        return new Vector(this, at, prefix);
    }

    private Span<byte> Grow(int count)
    {
        if (_length + count > _buffer.Length)
        {
            Array.Resize(ref _buffer, Math.Max(_buffer.Length * 2, _length + count));
        }

        Span<byte> span = _buffer.AsSpan(_length, count);
        _length += count;
        return span;
    }

    // A vector being written; End writes its length into its prefix.
    public readonly struct Vector(WireWriter writer, int at, int prefix)
    {
        public void End()
        {
            int length = writer._length - at - prefix;
            int maximum = (1 << (8 * prefix)) - 1;
            if (length > maximum)
            {
                throw new InvalidOperationException(
                    $"A vector of {length} bytes does not fit a {prefix}-byte length."
                );
            }

            Span<byte> field = writer._buffer.AsSpan(at, prefix);
            for (int i = prefix - 1; i >= 0; i--)
            {
                field[i] = (byte)length;
                length >>= 8;
            }
        }
    }
}
