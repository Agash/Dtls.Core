using System.Collections.Immutable;
using System.Net.Security;
using System.Security.Cryptography;

namespace Dtls.Core.Crypto;

internal enum AeadKind
{
    AesGcm,
    ChaCha20Poly1305,
}

internal enum AuthenticationKind
{
    Ecdsa,
    Rsa,
}

// What a cipher suite means for the key schedule and the record layer. For DTLS 1.2 Dtls.Core implements
// the ephemeral elliptic-curve suites with an AEAD cipher, which are what WebRTC implementations use;
// for DTLS 1.3, the AEAD suites of RFC 8446, whose PrfHash is the HKDF hash.
internal readonly record struct CipherSuiteInfo(
    TlsCipherSuite Suite,
    AeadKind Aead,
    AuthenticationKind Authentication,
    int KeyLength,
    int FixedIvLength,
    HashAlgorithmName PrfHash,
    bool Tls13 = false
)
{
    public const int TagLength = 16;

    // Offered or accepted when the options name none, most preferred first.
    public static ImmutableArray<TlsCipherSuite> Default { get; } =
    [
        TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        TlsCipherSuite.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    ];

    // The DTLS 1.3 suites (RFC 8446 §B.4), most preferred first. They name no key exchange or
    // authentication: those are negotiated separately.
    public static ImmutableArray<TlsCipherSuite> Default13 { get; } =
    [
        TlsCipherSuite.TLS_AES_128_GCM_SHA256,
        TlsCipherSuite.TLS_AES_256_GCM_SHA384,
        TlsCipherSuite.TLS_CHACHA20_POLY1305_SHA256,
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
            _ => default,
        };
        return info.Suite != default;
    }

    // Whether this platform's cryptography runs the suite.
    public bool IsSupported =>
        Aead == AeadKind.ChaCha20Poly1305 ? ChaCha20Poly1305.IsSupported : AesGcm.IsSupported;

    // AES-GCM for TLS (RFC 5288): a 4-byte implicit salt and an 8-byte explicit nonce per record.
    private static CipherSuiteInfo Gcm(
        TlsCipherSuite suite,
        AuthenticationKind authentication,
        int keyLength,
        HashAlgorithmName prfHash
    ) => new(suite, AeadKind.AesGcm, authentication, keyLength, 4, prfHash);

    // ChaCha20-Poly1305 for TLS (RFC 7905): a 12-byte IV mixed with the sequence number.
    private static CipherSuiteInfo ChaCha(
        TlsCipherSuite suite,
        AuthenticationKind authentication
    ) => new(suite, AeadKind.ChaCha20Poly1305, authentication, 32, 12, HashAlgorithmName.SHA256);
}
