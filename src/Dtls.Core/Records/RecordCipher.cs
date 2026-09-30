using System.Buffers.Binary;
using System.Security.Cryptography;
using Dtls.Core.Crypto;

namespace Dtls.Core.Records;

// Protects and opens the records of one epoch in one direction with the cipher suite's AEAD. The
// additional data binds each record to its epoch and sequence number, content type, version and
// length (RFC 5246 §6.2.3.3 with DTLS's 64-bit epoch-and-sequence number, RFC 6347 §4.1.2.1).
internal abstract class RecordCipher : IDisposable
{
    protected const int AdditionalDataLength = 13;
    protected const int NonceLength = 12;

    // What a record carries besides its plaintext.
    public abstract int Overhead { get; }

    public static RecordCipher Create(
        CipherSuiteInfo suite,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> iv
    ) =>
        suite.Aead switch
        {
            AeadKind.AesGcm => new AesGcmCipher(key, iv),
            _ => new ChaChaCipher(key, iv),
        };

    // Writes the protected fragment for the plaintext; returns its length.
    public abstract int Seal(
        ulong epochAndSequence,
        ContentType type,
        ReadOnlySpan<byte> plaintext,
        Span<byte> fragment
    );

    // Opens a protected fragment in place. The plaintext is left at fragment[offset..offset + length];
    // returns its length, or -1 when the record does not authenticate.
    public abstract int Open(
        ulong epochAndSequence,
        ContentType type,
        Span<byte> fragment,
        out int offset
    );

    public abstract void Dispose();

    protected static void AdditionalData(
        ulong epochAndSequence,
        ContentType type,
        int plaintextLength,
        Span<byte> destination
    )
    {
        BinaryPrimitives.WriteUInt64BigEndian(destination, epochAndSequence);
        destination[8] = (byte)type;
        BinaryPrimitives.WriteUInt16BigEndian(destination[9..], ProtocolVersion.Dtls12);
        BinaryPrimitives.WriteUInt16BigEndian(destination[11..], (ushort)plaintextLength);
    }

    // RFC 5288: nonce = salt (4) || explicit nonce (8). The explicit nonce is the record's epoch and
    // sequence number, which never repeats under one key, and travels in front of the ciphertext.
    private sealed class AesGcmCipher(ReadOnlySpan<byte> key, ReadOnlySpan<byte> salt)
        : RecordCipher
    {
        private const int ExplicitNonceLength = 8;
        private readonly AesGcm _aes = new(key, CipherSuiteInfo.TagLength);
        private readonly uint _salt = BinaryPrimitives.ReadUInt32BigEndian(salt);

        public override int Overhead => ExplicitNonceLength + CipherSuiteInfo.TagLength;

        public override int Seal(
            ulong epochAndSequence,
            ContentType type,
            ReadOnlySpan<byte> plaintext,
            Span<byte> fragment
        )
        {
            Span<byte> nonce = stackalloc byte[NonceLength];
            BinaryPrimitives.WriteUInt32BigEndian(nonce, _salt);
            BinaryPrimitives.WriteUInt64BigEndian(nonce[4..], epochAndSequence);
            nonce[4..].CopyTo(fragment);
            Span<byte> additional = stackalloc byte[AdditionalDataLength];
            AdditionalData(epochAndSequence, type, plaintext.Length, additional);
            _aes.Encrypt(
                nonce,
                plaintext,
                fragment.Slice(ExplicitNonceLength, plaintext.Length),
                fragment.Slice(ExplicitNonceLength + plaintext.Length, CipherSuiteInfo.TagLength),
                additional
            );
            return plaintext.Length + Overhead;
        }

        public override int Open(
            ulong epochAndSequence,
            ContentType type,
            Span<byte> fragment,
            out int offset
        )
        {
            offset = ExplicitNonceLength;
            int length = fragment.Length - Overhead;
            if (length < 0)
            {
                return -1;
            }

            Span<byte> nonce = stackalloc byte[NonceLength];
            BinaryPrimitives.WriteUInt32BigEndian(nonce, _salt);
            fragment[..ExplicitNonceLength].CopyTo(nonce[4..]);
            Span<byte> additional = stackalloc byte[AdditionalDataLength];
            AdditionalData(epochAndSequence, type, length, additional);
            Span<byte> body = fragment.Slice(ExplicitNonceLength, length);
            try
            {
                // In place: the ciphertext and plaintext are the same span, which AES-GCM allows.
                _aes.Decrypt(
                    nonce,
                    body,
                    fragment.Slice(ExplicitNonceLength + length, CipherSuiteInfo.TagLength),
                    body,
                    additional
                );
                return length;
            }
            catch (AuthenticationTagMismatchException)
            {
                // Deliberately not logged here: a record that does not authenticate is dropped and
                // counted by the record layer (RFC 6347 §4.1.2.7). The platform clears the output.
                return -1;
            }
        }

        public override void Dispose() => _aes.Dispose();
    }

    // RFC 7905: nonce = IV xor the 64-bit epoch-and-sequence number, left-padded to 12 bytes; the
    // record carries no nonce.
    private sealed class ChaChaCipher(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv) : RecordCipher
    {
        private readonly ChaCha20Poly1305 _chacha = new(key);
        private readonly uint _ivHigh = BinaryPrimitives.ReadUInt32BigEndian(iv);
        private readonly ulong _ivLow = BinaryPrimitives.ReadUInt64BigEndian(iv[4..]);

        public override int Overhead => CipherSuiteInfo.TagLength;

        public override int Seal(
            ulong epochAndSequence,
            ContentType type,
            ReadOnlySpan<byte> plaintext,
            Span<byte> fragment
        )
        {
            Span<byte> nonce = stackalloc byte[NonceLength];
            Nonce(epochAndSequence, nonce);
            Span<byte> additional = stackalloc byte[AdditionalDataLength];
            AdditionalData(epochAndSequence, type, plaintext.Length, additional);
            _chacha.Encrypt(
                nonce,
                plaintext,
                fragment[..plaintext.Length],
                fragment.Slice(plaintext.Length, CipherSuiteInfo.TagLength),
                additional
            );
            return plaintext.Length + Overhead;
        }

        public override int Open(
            ulong epochAndSequence,
            ContentType type,
            Span<byte> fragment,
            out int offset
        )
        {
            offset = 0;
            int length = fragment.Length - Overhead;
            if (length < 0)
            {
                return -1;
            }

            Span<byte> nonce = stackalloc byte[NonceLength];
            Nonce(epochAndSequence, nonce);
            Span<byte> additional = stackalloc byte[AdditionalDataLength];
            AdditionalData(epochAndSequence, type, length, additional);
            Span<byte> body = fragment[..length];
            try
            {
                _chacha.Decrypt(
                    nonce,
                    body,
                    fragment.Slice(length, CipherSuiteInfo.TagLength),
                    body,
                    additional
                );
                return length;
            }
            catch (AuthenticationTagMismatchException)
            {
                // Deliberately not logged here: see AesGcmCipher.Open.
                return -1;
            }
        }

        public override void Dispose() => _chacha.Dispose();

        private void Nonce(ulong epochAndSequence, Span<byte> nonce)
        {
            BinaryPrimitives.WriteUInt32BigEndian(nonce, _ivHigh);
            BinaryPrimitives.WriteUInt64BigEndian(nonce[4..], _ivLow ^ epochAndSequence);
        }
    }
}
