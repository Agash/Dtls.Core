using System.Buffers;
using System.Security.Cryptography;

namespace Dtls.NET.Handshake;

// The handshake messages so far, as the Finished, CertificateVerify and the extended master secret
// hash them: each as one fragment covering its whole body (RFC 6347 §4.2.6), whatever fragments it
// travelled in. The cipher suite, and with it the hash, is only known once the ServerHello is in, so
// the bytes are kept in a pooled buffer rather than hashed as they come; a DTLS 1.2 handshake is a few
// kilobytes.
internal sealed class Transcript : IDisposable
{
    private byte[] _buffer = ArrayPool<byte>.Shared.Rent(4096);
    private int _length;

    public ReadOnlySpan<byte> Bytes => _buffer.AsSpan(0, _length);

    public int Length => _length;

    // Goes back to an earlier length, undoing the messages added since.
    public void Truncate(int length) => _length = Math.Min(_length, length);

    public void Add(HandshakeMessage message)
    {
        Ensure(HandshakeFragment.HeaderSize + message.Body.Length);
        Span<byte> header = _buffer.AsSpan(_length, HandshakeFragment.HeaderSize);
        header[0] = (byte)message.Type;
        WriteUInt24(header[1..], message.Body.Length);
        header[4] = (byte)(message.MessageSeq >> 8);
        header[5] = (byte)message.MessageSeq;
        WriteUInt24(header[6..], 0);
        WriteUInt24(header[9..], message.Body.Length);
        message.Body.CopyTo(_buffer.AsSpan(_length + HandshakeFragment.HeaderSize));
        _length += HandshakeFragment.HeaderSize + message.Body.Length;
    }

    // DTLS 1.3 hashes messages as TLS 1.3 does, with only the type and length in front (RFC 9147 §5.2).
    public void Add13(HandshakeType type, ReadOnlySpan<byte> body)
    {
        Ensure(4 + body.Length);
        Span<byte> header = _buffer.AsSpan(_length, 4);
        header[0] = (byte)type;
        WriteUInt24(header[1..], body.Length);
        body.CopyTo(_buffer.AsSpan(_length + 4));
        _length += 4 + body.Length;
    }

    // After a HelloRetryRequest the first ClientHello is replaced by a message_hash message holding its
    // hash (RFC 8446 §4.4.1).
    public void ReplaceWithMessageHash(HashAlgorithmName algorithm)
    {
        byte[] hash = Hash(algorithm);
        Clear();
        Add13(HandshakeType.MessageHash, hash);
    }

    // Forgets everything, as when a HelloVerifyRequest makes the first ClientHello not count (RFC
    // 6347 §4.2.1).
    public void Clear() => _length = 0;

    public byte[] Hash(HashAlgorithmName algorithm) => Crypto.Prf.Hash(algorithm, Bytes);

    public void Dispose()
    {
        ArrayPool<byte>.Shared.Return(_buffer);
        _buffer = [];
        _length = 0;
    }

    private void Ensure(int more)
    {
        if (_length + more <= _buffer.Length)
        {
            return;
        }

        byte[] larger = ArrayPool<byte>.Shared.Rent(Math.Max(_buffer.Length * 2, _length + more));
        _buffer.AsSpan(0, _length).CopyTo(larger);
        ArrayPool<byte>.Shared.Return(_buffer);
        _buffer = larger;
    }

    private static void WriteUInt24(Span<byte> destination, int value)
    {
        destination[0] = (byte)(value >> 16);
        destination[1] = (byte)(value >> 8);
        destination[2] = (byte)value;
    }
}
