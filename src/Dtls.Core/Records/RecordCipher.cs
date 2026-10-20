using System.Buffers.Binary;
using System.Security.Cryptography;
using Dtls.Core.Crypto;

namespace Dtls.Core.Records;

// Protects and opens the records of one epoch in one direction with the cipher suite's AEAD. The
// additional data binds each record to its epoch and sequence number, content type, version and
// length (RFC 5246 §6.2.3.3 with DTLS's 64-bit epoch-and-sequence number, RFC 6347 §4.1.2.1); a record
// carrying a connection ID binds it with RFC 9146 §5.3's additional data instead, which the record layer
// builds and passes in.
internal abstract class RecordCipher : IDisposable
{
    protected const int AdditionalDataLength = 13;
    protected const int NonceLength = 12;

    // What a record carries besides its plaintext.
    public abstract int Overhead { get; }

    // Where the plaintext starts inside the protected fragment: after an explicit nonce, if any. A
    // plaintext written there can be sealed in place.
    public abstract int PlaintextOffset { get; }

    // The records that may fail to authenticate under these keys (RFC 9147 section 4.5.3).
    public long IntegrityLimit { get; private init; }

    public static RecordCipher Create(
        CipherSuiteInfo suite,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> iv
    ) =>
        suite.Aead switch
        {
            AeadKind.ChaCha20Poly1305 => new ChaChaCipher(key, iv)
            {
                IntegrityLimit = suite.IntegrityLimit,
            },
            _ => new SaltedCipher(suite, key, iv) { IntegrityLimit = suite.IntegrityLimit },
        };

    // Writes the protected fragment for the plaintext; returns its length.
    public int Seal(
        ulong epochAndSequence,
        ContentType type,
        ReadOnlySpan<byte> plaintext,
        Span<byte> fragment
    )
    {
        Span<byte> additional = stackalloc byte[AdditionalDataLength];
        AdditionalData(epochAndSequence, type, plaintext.Length, additional);
        return Seal(epochAndSequence, additional, plaintext, fragment);
    }

    // Opens a protected fragment in place. The plaintext is left at fragment[offset..offset + length];
    // returns its length, or -1 when the record does not authenticate.
    public int Open(ulong epochAndSequence, ContentType type, Span<byte> fragment, out int offset)
    {
        Span<byte> additional = stackalloc byte[AdditionalDataLength];
        AdditionalData(epochAndSequence, type, fragment.Length - Overhead, additional);
        return Open(epochAndSequence, additional, fragment, out offset);
    }

    // Seals with the given additional data. The plaintext may be the fragment's own span at
    // PlaintextOffset, which seals in place.
    public abstract int Seal(
        ulong epochAndSequence,
        ReadOnlySpan<byte> additional,
        ReadOnlySpan<byte> plaintext,
        Span<byte> fragment
    );

    // Opens with the given additional data.
    public abstract int Open(
        ulong epochAndSequence,
        ReadOnlySpan<byte> additional,
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

    // AES-GCM (RFC 5288) and AES-CCM (RFC 6655): nonce = salt (4) || explicit nonce (8). The explicit
    // nonce is the record's epoch and sequence number, which never repeats under one key, and travels in
    // front of the ciphertext.
    private sealed class SaltedCipher : RecordCipher
    {
        private const int ExplicitNonceLength = 8;
        private readonly AesGcm? _gcm;
        private readonly AesCcm? _ccm;
        private readonly int _tagLength;
        private readonly uint _salt;

        public SaltedCipher(CipherSuiteInfo suite, ReadOnlySpan<byte> key, ReadOnlySpan<byte> salt)
        {
            _tagLength = suite.TagLength;
            _salt = BinaryPrimitives.ReadUInt32BigEndian(salt);
            if (suite.Aead == AeadKind.AesCcm)
            {
                _ccm = new AesCcm(key);
            }
            else
            {
                _gcm = new AesGcm(key, _tagLength);
            }
        }

        public override int Overhead => ExplicitNonceLength + _tagLength;

        public override int PlaintextOffset => ExplicitNonceLength;

        public override int Seal(
            ulong epochAndSequence,
            ReadOnlySpan<byte> additional,
            ReadOnlySpan<byte> plaintext,
            Span<byte> fragment
        )
        {
            Span<byte> nonce = stackalloc byte[NonceLength];
            BinaryPrimitives.WriteUInt32BigEndian(nonce, _salt);
            BinaryPrimitives.WriteUInt64BigEndian(nonce[4..], epochAndSequence);
            nonce[4..].CopyTo(fragment);
            Span<byte> ciphertext = fragment.Slice(ExplicitNonceLength, plaintext.Length);
            Span<byte> tag = fragment.Slice(ExplicitNonceLength + plaintext.Length, _tagLength);
            if (_gcm is not null)
            {
                _gcm.Encrypt(nonce, plaintext, ciphertext, tag, additional);
            }
            else
            {
                _ccm!.Encrypt(nonce, plaintext, ciphertext, tag, additional);
            }

            return plaintext.Length + Overhead;
        }

        public override int Open(
            ulong epochAndSequence,
            ReadOnlySpan<byte> additional,
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
            Span<byte> body = fragment.Slice(ExplicitNonceLength, length);
            Span<byte> tag = fragment.Slice(ExplicitNonceLength + length, _tagLength);
            try
            {
                // In place: the ciphertext and plaintext are the same span, which both AEADs allow.
                if (_gcm is not null)
                {
                    _gcm.Decrypt(nonce, body, tag, body, additional);
                }
                else
                {
                    _ccm!.Decrypt(nonce, body, tag, body, additional);
                }

                return length;
            }
            catch (AuthenticationTagMismatchException)
            {
                // Deliberately not logged here: a record that does not authenticate is dropped and
                // counted by the record layer (RFC 6347 §4.1.2.7). The platform clears the output.
                return -1;
            }
        }

        public override void Dispose()
        {
            _gcm?.Dispose();
            _ccm?.Dispose();
        }
    }

    // RFC 7905: nonce = IV xor the 64-bit epoch-and-sequence number, left-padded to 12 bytes; the
    // record carries no nonce.
    private sealed class ChaChaCipher(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv) : RecordCipher
    {
        private const int TagLength = 16;

        private readonly ChaCha20Poly1305 _chacha = new(key);
        private readonly uint _ivHigh = BinaryPrimitives.ReadUInt32BigEndian(iv);
        private readonly ulong _ivLow = BinaryPrimitives.ReadUInt64BigEndian(iv[4..]);

        public override int Overhead => TagLength;

        public override int PlaintextOffset => 0;

        public override int Seal(
            ulong epochAndSequence,
            ReadOnlySpan<byte> additional,
            ReadOnlySpan<byte> plaintext,
            Span<byte> fragment
        )
        {
            Span<byte> nonce = stackalloc byte[NonceLength];
            Nonce(epochAndSequence, nonce);
            _chacha.Encrypt(
                nonce,
                plaintext,
                fragment[..plaintext.Length],
                fragment.Slice(plaintext.Length, TagLength),
                additional
            );
            return plaintext.Length + Overhead;
        }

        public override int Open(
            ulong epochAndSequence,
            ReadOnlySpan<byte> additional,
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
            Span<byte> body = fragment[..length];
            try
            {
                _chacha.Decrypt(nonce, body, fragment.Slice(length, TagLength), body, additional);
                return length;
            }
            catch (AuthenticationTagMismatchException)
            {
                // Deliberately not logged here: see SaltedCipher.Open.
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
