using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;
using Dtls.NET.Crypto;

namespace Dtls.NET.Records;

// Protects and opens the records of one DTLS 1.3 epoch in one direction (RFC 8446 §5.2, RFC 9147
// §4). The nonce is the IV xor the 64-bit record sequence number; the additional data is the record's
// unified header with the sequence number in the clear; the plaintext ends with the true content type.
// The record number on the wire is masked with a key of its own (RFC 9147 §4.2.3).
internal sealed class RecordCipher13 : IDisposable
{
    public const int TagLength = CipherSuiteInfo.TagLength;

    private readonly AesGcm? _aes;
    private readonly ChaCha20Poly1305? _chacha;
    private readonly Aes? _sequenceAes;
    private readonly byte[]? _sequenceChaChaKey;
    private readonly byte[] _iv;

    public RecordCipher13(CipherSuiteInfo suite, TrafficKeys keys)
    {
        _iv = [.. keys.Iv];
        if (suite.Aead == AeadKind.AesGcm)
        {
            _aes = new AesGcm(keys.Key, TagLength);
            _sequenceAes = Aes.Create();
            _sequenceAes.Key = keys.SequenceKey;
        }
        else
        {
            _chacha = new ChaCha20Poly1305(keys.Key);
            _sequenceChaChaKey = [.. keys.SequenceKey];
        }
    }

    // Encrypts content || type in place; the tag follows. Returns the ciphertext's length.
    public int Seal(ulong sequence, ReadOnlySpan<byte> header, Span<byte> inner, int innerLength)
    {
        Span<byte> nonce = stackalloc byte[12];
        Nonce(sequence, nonce);
        Span<byte> text = inner[..innerLength];
        Span<byte> tag = inner.Slice(innerLength, TagLength);
        if (_aes is not null)
        {
            _aes.Encrypt(nonce, text, text, tag, header);
        }
        else
        {
            _chacha!.Encrypt(nonce, text, text, tag, header);
        }

        return innerLength + TagLength;
    }

    // Decrypts a record in place; returns the inner plaintext's length, or -1 when it does not
    // authenticate.
    public int Open(ulong sequence, ReadOnlySpan<byte> header, Span<byte> ciphertext)
    {
        int length = ciphertext.Length - TagLength;
        if (length < 1)
        {
            return -1;
        }

        Span<byte> nonce = stackalloc byte[12];
        Nonce(sequence, nonce);
        Span<byte> text = ciphertext[..length];
        try
        {
            if (_aes is not null)
            {
                _aes.Decrypt(nonce, text, ciphertext[length..], text, header);
            }
            else
            {
                _chacha!.Decrypt(nonce, text, ciphertext[length..], text, header);
            }

            return length;
        }
        catch (AuthenticationTagMismatchException)
        {
            // Deliberately not logged here: the record layer drops and counts it (RFC 9147 §4.5.2).
            return -1;
        }
    }

    // The mask for the record number, from the first 16 bytes of the ciphertext: AES-ECB with the
    // sequence key, or the ChaCha20 block with the first 4 bytes as counter and the next 12 as nonce.
    public void Mask(ReadOnlySpan<byte> ciphertext, Span<byte> mask)
    {
        Span<byte> block = stackalloc byte[64];
        if (_sequenceAes is not null)
        {
            _ = _sequenceAes.EncryptEcb(ciphertext[..16], block[..16], PaddingMode.None);
        }
        else
        {
            ChaCha20Block(
                _sequenceChaChaKey!,
                BinaryPrimitives.ReadUInt32LittleEndian(ciphertext),
                ciphertext.Slice(4, 12),
                block
            );
        }

        block[..mask.Length].CopyTo(mask);
    }

    public void Dispose()
    {
        _aes?.Dispose();
        _chacha?.Dispose();
        _sequenceAes?.Dispose();
        CryptographicOperations.ZeroMemory(_iv);
        if (_sequenceChaChaKey is not null)
        {
            CryptographicOperations.ZeroMemory(_sequenceChaChaKey);
        }
    }

    // RFC 8446 §5.3: the 64-bit sequence number, big-endian and left-padded to the IV's length, xor the
    // IV.
    private void Nonce(ulong sequence, Span<byte> nonce)
    {
        _iv.CopyTo(nonce);
        ulong low = BinaryPrimitives.ReadUInt64BigEndian(nonce[4..]) ^ sequence;
        BinaryPrimitives.WriteUInt64BigEndian(nonce[4..], low);
    }

    // The ChaCha20 block function (RFC 8439 §2.3). .NET exposes ChaCha20 only inside its AEAD, and the
    // record number mask needs the raw keystream.
    internal static void ChaCha20Block(
        ReadOnlySpan<byte> key,
        uint counter,
        ReadOnlySpan<byte> nonce,
        Span<byte> output
    )
    {
        Span<uint> state = stackalloc uint[16];
        state[0] = 0x61707865;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32;
        state[3] = 0x6b206574;
        for (int i = 0; i < 8; i++)
        {
            state[4 + i] = BinaryPrimitives.ReadUInt32LittleEndian(key[(4 * i)..]);
        }

        state[12] = counter;
        for (int i = 0; i < 3; i++)
        {
            state[13 + i] = BinaryPrimitives.ReadUInt32LittleEndian(nonce[(4 * i)..]);
        }

        Span<uint> working = stackalloc uint[16];
        state.CopyTo(working);
        for (int round = 0; round < 10; round++)
        {
            QuarterRound(working, 0, 4, 8, 12);
            QuarterRound(working, 1, 5, 9, 13);
            QuarterRound(working, 2, 6, 10, 14);
            QuarterRound(working, 3, 7, 11, 15);
            QuarterRound(working, 0, 5, 10, 15);
            QuarterRound(working, 1, 6, 11, 12);
            QuarterRound(working, 2, 7, 8, 13);
            QuarterRound(working, 3, 4, 9, 14);
        }

        for (int i = 0; i < 16; i++)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(output[(4 * i)..], working[i] + state[i]);
        }

        working.Clear();
        state.Clear();
    }

    private static void QuarterRound(Span<uint> x, int a, int b, int c, int d)
    {
        x[a] += x[b];
        x[d] = BitOperations.RotateLeft(x[d] ^ x[a], 16);
        x[c] += x[d];
        x[b] = BitOperations.RotateLeft(x[b] ^ x[c], 12);
        x[a] += x[b];
        x[d] = BitOperations.RotateLeft(x[d] ^ x[a], 8);
        x[c] += x[d];
        x[b] = BitOperations.RotateLeft(x[b] ^ x[c], 7);
    }
}
