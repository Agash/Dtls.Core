using System.Collections.Immutable;
using System.Net.Security;
using System.Security.Cryptography;

namespace Dtls.NET.Crypto;

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

// What a cipher suite means for the key schedule and the record layer. Dtls.NET implements the
// ephemeral elliptic-curve suites with an AEAD cipher, which are what WebRTC implementations use.
internal readonly record struct CipherSuiteInfo(
    TlsCipherSuite Suite,
    AeadKind Aead,
    AuthenticationKind Authentication,
    int KeyLength,
    int FixedIvLength,
    HashAlgorithmName PrfHash
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
