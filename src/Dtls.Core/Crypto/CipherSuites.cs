using System.Collections.Immutable;
using System.Net.Security;
using System.Security.Cryptography;

namespace Dtls.Core.Crypto;

internal enum AeadKind
{
    AesGcm,
    ChaCha20Poly1305,
    AesCcm,
}

internal enum AuthenticationKind
{
    Ecdsa,
    Rsa,
}

// What a cipher suite means for the key schedule and the record layer. For DTLS 1.2 Dtls.Core implements
// the ephemeral elliptic-curve suites with an AEAD cipher: AES-GCM and ChaCha20-Poly1305, which WebRTC
// implementations use, and AES-CCM (RFC 7251), which constrained devices and CoAP (RFC 7252 section
// 9.1.3) use. For DTLS 1.3, the AEAD suites of RFC 8446, whose PrfHash is the HKDF hash.
internal readonly record struct CipherSuiteInfo(
    TlsCipherSuite Suite,
    AeadKind Aead,
    AuthenticationKind Authentication,
    int KeyLength,
    int FixedIvLength,
    HashAlgorithmName PrfHash,
    bool Tls13 = false,
    int TagLength = 16
)
{
    // RFC 8446 section 5.5: AES-GCM protects at most 2^24.5 records under one key. RFC 9147 Appendix B:
    // AES-CCM at most 2^23. ChaCha20-Poly1305's limit lies beyond the 48-bit record sequence number,
    // which ends an epoch first.
    private const ulong AesGcmRecordLimit = 23_726_566;
    private const ulong AesCcmRecordLimit = 1UL << 23;

    // RFC 9147 section 4.5.3: the records that may fail to authenticate under one key. 2^36 for AES-GCM
    // and ChaCha20-Poly1305; 2^23.5 for AES-CCM (Appendix B.2); 2^7 for AES-CCM with an 8-byte tag,
    // whose forgery bound allows no more (Appendix B.3).
    private const long DefaultIntegrityLimit = 1L << 36;
    private const long AesCcmIntegrityLimit = 11_863_283;
    private const long AesCcm8IntegrityLimit = 1L << 7;

    // The records one key may protect (RFC 9147 section 4.5.3).
    public ulong ConfidentialityLimit =>
        Aead switch
        {
            AeadKind.AesGcm => AesGcmRecordLimit,
            AeadKind.AesCcm => AesCcmRecordLimit,
            _ => ulong.MaxValue,
        };

    // The records that may fail to authenticate under one key before the connection must end.
    public long IntegrityLimit =>
        Aead != AeadKind.AesCcm ? DefaultIntegrityLimit
        : TagLength == 8 ? AesCcm8IntegrityLimit
        : AesCcmIntegrityLimit;

    // Offered or accepted when the options name none, most preferred first.
    public static ImmutableArray<TlsCipherSuite> Default { get; } =
    [
        TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        TlsCipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
        TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM,
    ];

    // The DTLS 1.3 suites (RFC 8446 §B.4), most preferred first. They name no key exchange or
    // authentication: those are negotiated separately.
    public static ImmutableArray<TlsCipherSuite> Default13 { get; } =
    [
        TlsCipherSuite.TLS_AES_128_GCM_SHA256,
        TlsCipherSuite.TLS_AES_256_GCM_SHA384,
        TlsCipherSuite.TLS_CHACHA20_POLY1305_SHA256,
        TlsCipherSuite.TLS_AES_128_CCM_SHA256,
    ];

    public static bool TryGet(TlsCipherSuite suite, out CipherSuiteInfo info)
    {
        info = suite switch
        {
            TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 => Gcm(
                suite,
                AuthenticationKind.Ecdsa,
                16,
                HashAlgorithmName.SHA256
            ),
            TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 => Gcm(
                suite,
                AuthenticationKind.Ecdsa,
                32,
                HashAlgorithmName.SHA384
            ),
            TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 => Gcm(
                suite,
                AuthenticationKind.Rsa,
                16,
                HashAlgorithmName.SHA256
            ),
            TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 => Gcm(
                suite,
                AuthenticationKind.Rsa,
                32,
                HashAlgorithmName.SHA384
            ),
            TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 => ChaCha(
                suite,
                AuthenticationKind.Ecdsa
            ),
            TlsCipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 => ChaCha(
                suite,
                AuthenticationKind.Rsa
            ),
            TlsCipherSuite.TLS_AES_128_GCM_SHA256 => new(
                suite,
                AeadKind.AesGcm,
                default,
                16,
                12,
                HashAlgorithmName.SHA256,
                Tls13: true
            ),
            TlsCipherSuite.TLS_AES_256_GCM_SHA384 => new(
                suite,
                AeadKind.AesGcm,
                default,
                32,
                12,
                HashAlgorithmName.SHA384,
                Tls13: true
            ),
            TlsCipherSuite.TLS_CHACHA20_POLY1305_SHA256 => new(
                suite,
                AeadKind.ChaCha20Poly1305,
                default,
                32,
                12,
                HashAlgorithmName.SHA256,
                Tls13: true
            ),

            // RFC 7251: AES-CCM with ECDHE-ECDSA, a 16- or 8-byte tag, and the SHA-256 PRF for both key
            // lengths.
            TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM => Ccm(suite, 16, 16),
            TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM => Ccm(suite, 32, 16),
            TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 => Ccm(suite, 16, 8),
            TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8 => Ccm(suite, 32, 8),

            // TLS_AES_128_CCM_8_SHA256 is left out: RFC 9147 section 4.5.3 forbids it in DTLS 1.3
            // without forgery safeguards beyond the protocol's.
            TlsCipherSuite.TLS_AES_128_CCM_SHA256 => new(
                suite,
                AeadKind.AesCcm,
                default,
                16,
                12,
                HashAlgorithmName.SHA256,
                Tls13: true
            ),
            _ => default,
        };
        return info.Suite != default;
    }

    // Whether this platform's cryptography runs the suite.
    public bool IsSupported =>
        Aead switch
        {
            AeadKind.ChaCha20Poly1305 => ChaCha20Poly1305.IsSupported,
            AeadKind.AesCcm => AesCcm.IsSupported,
            _ => AesGcm.IsSupported,
        };

    // AES-GCM for TLS (RFC 5288): a 4-byte implicit salt and an 8-byte explicit nonce per record.
    private static CipherSuiteInfo Gcm(
        TlsCipherSuite suite,
        AuthenticationKind authentication,
        int keyLength,
        HashAlgorithmName prfHash
    ) => new(suite, AeadKind.AesGcm, authentication, keyLength, 4, prfHash);

    // AES-CCM for TLS (RFC 6655 section 3): the same 4-byte salt and 8-byte explicit nonce as AES-GCM.
    private static CipherSuiteInfo Ccm(TlsCipherSuite suite, int keyLength, int tagLength) =>
        new(
            suite,
            AeadKind.AesCcm,
            AuthenticationKind.Ecdsa,
            keyLength,
            4,
            HashAlgorithmName.SHA256,
            TagLength: tagLength
        );

    // ChaCha20-Poly1305 for TLS (RFC 7905): a 12-byte IV mixed with the sequence number.
    private static CipherSuiteInfo ChaCha(
        TlsCipherSuite suite,
        AuthenticationKind authentication
    ) => new(suite, AeadKind.ChaCha20Poly1305, authentication, 32, 12, HashAlgorithmName.SHA256);
}
