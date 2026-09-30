using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Dtls.Core.Handshake;

namespace Dtls.Core.Crypto;

// Signing with this side's certificate key and verifying with the peer's certificate, in the
// signature schemes of RFC 8446 §4.2.3 that TLS 1.2 shares. In TLS 1.2 an ECDSA scheme names the hash
// only (RFC 5246 §7.4.1.4.1): any curve signs with either.
internal static class Signatures
{
    // The schemes this side accepts from a peer, most preferred first.
    public static ImmutableArray<SignatureScheme> Accepted { get; } =
    [
        SignatureScheme.EcdsaSecp256r1Sha256,
        SignatureScheme.EcdsaSecp384r1Sha384,
        SignatureScheme.RsaPssRsaeSha256,
        SignatureScheme.RsaPssRsaeSha384,
        SignatureScheme.RsaPkcs1Sha256,
        SignatureScheme.RsaPkcs1Sha384,
    ];

    // The first of the peer's schemes that this side's certificate key can sign with.
    public static SignatureScheme Choose(
        LocalCredential certificate,
        IEnumerable<SignatureScheme> peerSchemes
    )
    {
        foreach (SignatureScheme scheme in peerSchemes)
        {
            if (CanSign(certificate, scheme))
            {
                return scheme;
            }
        }

        throw DtlsException.HandshakeFailure(
            "the peer accepts no signature scheme this certificate can sign with"
        );
    }

    // Whether this side's certificate can sign with any of the peer's schemes.
    public static bool CanSignAny(
        LocalCredential certificate,
        IEnumerable<SignatureScheme> peerSchemes
    ) => peerSchemes.Any(scheme => CanSign(certificate, scheme));

    // Whether a scheme signs with the key a cipher suite authenticates with.
    public static bool Authenticates(SignatureScheme scheme, AuthenticationKind authentication) =>
        scheme is SignatureScheme.EcdsaSecp256r1Sha256 or SignatureScheme.EcdsaSecp384r1Sha384
            ? authentication == AuthenticationKind.Ecdsa
            : authentication == AuthenticationKind.Rsa;

    public static bool CanSign(LocalCredential certificate, SignatureScheme scheme) =>
        scheme switch
        {
            SignatureScheme.EcdsaSecp256r1Sha256 or SignatureScheme.EcdsaSecp384r1Sha384 =>
                certificate.Ecdsa is not null,
            SignatureScheme.RsaPssRsaeSha256
            or SignatureScheme.RsaPssRsaeSha384
            or SignatureScheme.RsaPkcs1Sha256
            or SignatureScheme.RsaPkcs1Sha384 => certificate.Rsa is not null,
            _ => false,
        };

    public static byte[] Sign(
        LocalCredential certificate,
        SignatureScheme scheme,
        ReadOnlySpan<byte> data
    ) =>
        scheme switch
        {
            SignatureScheme.EcdsaSecp256r1Sha256 or SignatureScheme.EcdsaSecp384r1Sha384 =>
                certificate.Ecdsa!.SignData(
                    data,
                    Hash(scheme),
                    DSASignatureFormat.Rfc3279DerSequence
                ),
            _ => certificate.Rsa!.SignData(data, Hash(scheme), Padding(scheme)),
        };

    // Verifies a signature with a certificate's public key. A scheme that does not match the key, or a
    // scheme this side did not offer, fails verification rather than being tried.
    public static bool Verify(
        X509Certificate2 certificate,
        SignatureScheme scheme,
        ReadOnlySpan<byte> data,
        ReadOnlySpan<byte> signature
    )
    {
        if (!Accepted.Contains(scheme))
        {
            return false;
        }

        try
        {
            switch (scheme)
            {
                case SignatureScheme.EcdsaSecp256r1Sha256 or SignatureScheme.EcdsaSecp384r1Sha384:
                {
                    using ECDsa? ecdsa = certificate.GetECDsaPublicKey();
                    return ecdsa is not null
                        && ecdsa.VerifyData(
                            data,
                            signature,
                            Hash(scheme),
                            DSASignatureFormat.Rfc3279DerSequence
                        );
                }

                default:
                {
                    using RSA? rsa = certificate.GetRSAPublicKey();
                    return rsa is not null
                        && rsa.VerifyData(data, signature, Hash(scheme), Padding(scheme));
                }
            }
        }
        catch (Exception error)
            when (error is CryptographicException or PlatformNotSupportedException)
        {
            // Deliberately not logged here: a malformed signature is a failed verification, which the
            // handshake turns into a decrypt_error alert and logs.
            return false;
        }
    }

    // The schemes DTLS 1.3 accepts, most preferred first. In TLS 1.3 an ECDSA scheme is bound to its
    // curve and RSA signs only with PSS (RFC 8446 §4.2.3).
    public static ImmutableArray<SignatureScheme> Accepted13 { get; } =
    [
        SignatureScheme.EcdsaSecp256r1Sha256,
        SignatureScheme.EcdsaSecp384r1Sha384,
        SignatureScheme.RsaPssRsaeSha256,
        SignatureScheme.RsaPssRsaeSha384,
    ];

    public static bool CanSign13(LocalCredential certificate, SignatureScheme scheme) =>
        scheme switch
        {
            SignatureScheme.EcdsaSecp256r1Sha256 => certificate.EcdsaKeySize == 256,
            SignatureScheme.EcdsaSecp384r1Sha384 => certificate.EcdsaKeySize == 384,
            SignatureScheme.RsaPssRsaeSha256 or SignatureScheme.RsaPssRsaeSha384 => certificate.Rsa
                is not null,
            _ => false,
        };

    public static SignatureScheme Choose13(
        LocalCredential certificate,
        IEnumerable<SignatureScheme> peerSchemes
    )
    {
        foreach (SignatureScheme scheme in peerSchemes)
        {
            if (CanSign13(certificate, scheme))
            {
                return scheme;
            }
        }

        throw DtlsException.HandshakeFailure(
            "the peer accepts no DTLS 1.3 signature scheme this certificate can sign with"
        );
    }

    // Verifies a DTLS 1.3 signature: the scheme must be one DTLS 1.3 allows and, for ECDSA, match the
    // key's curve.
    public static bool Verify13(
        X509Certificate2 certificate,
        SignatureScheme scheme,
        ReadOnlySpan<byte> data,
        ReadOnlySpan<byte> signature
    )
    {
        if (!Accepted13.Contains(scheme))
        {
            return false;
        }

        if (scheme is SignatureScheme.EcdsaSecp256r1Sha256 or SignatureScheme.EcdsaSecp384r1Sha384)
        {
            using ECDsa? ecdsa = certificate.GetECDsaPublicKey();
            if (ecdsa?.KeySize != (scheme == SignatureScheme.EcdsaSecp256r1Sha256 ? 256 : 384))
            {
                return false;
            }
        }

        return Verify(certificate, scheme, data, signature);
    }

    private static HashAlgorithmName Hash(SignatureScheme scheme) =>
        scheme switch
        {
            SignatureScheme.EcdsaSecp384r1Sha384
            or SignatureScheme.RsaPssRsaeSha384
            or SignatureScheme.RsaPkcs1Sha384 => HashAlgorithmName.SHA384,
            _ => HashAlgorithmName.SHA256,
        };

    private static RSASignaturePadding Padding(SignatureScheme scheme) =>
        scheme is SignatureScheme.RsaPssRsaeSha256 or SignatureScheme.RsaPssRsaeSha384
            ? RSASignaturePadding.Pss
            : RSASignaturePadding.Pkcs1;
}
