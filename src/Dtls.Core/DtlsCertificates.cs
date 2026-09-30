using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Dtls.Core;

/// <summary>The kind of key a self-signed certificate is made with.</summary>
public enum DtlsKeyType
{
    /// <summary>ECDSA on P-256, what WebRTC implementations use.</summary>
    EcdsaP256,

    /// <summary>ECDSA on P-384.</summary>
    EcdsaP384,

    /// <summary>RSA with a 2048-bit key.</summary>
    Rsa2048,
}

/// <summary>
/// Certificates for DTLS peers that authenticate each other by fingerprint rather than by a PKI, as
/// WebRTC peers do: each makes a self-signed certificate and signals its
/// <see cref="DtlsFingerprint"/> out of band.
/// </summary>
public static class DtlsCertificates
{
    /// <summary>Makes a self-signed certificate with a new key.</summary>
    /// <param name="keyType">The key type; ECDSA on P-256 by default.</param>
    /// <param name="validity">How long it is valid from now; 30 days by default.</param>
    /// <returns>The certificate with its private key.</returns>
    public static X509Certificate2 CreateSelfSigned(
        DtlsKeyType keyType = DtlsKeyType.EcdsaP256,
        TimeSpan? validity = null
    )
    {
        TimeSpan lifetime = validity ?? TimeSpan.FromDays(30);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(
            lifetime,
            TimeSpan.Zero,
            nameof(validity)
        );

        // A random subject, as WebRTC implementations use: the name identifies nothing.
        X500DistinguishedName subject = new(
            $"CN={Convert.ToHexString(RandomNumberGenerator.GetBytes(8))}"
        );
        DateTimeOffset now = DateTimeOffset.UtcNow;
        if (keyType == DtlsKeyType.Rsa2048)
        {
            using RSA rsa = RSA.Create(2048);
            return new CertificateRequest(
                subject,
                rsa,
                HashAlgorithmName.SHA256,
                RSASignaturePadding.Pkcs1
            ).CreateSelfSigned(now.AddDays(-1), now + lifetime);
        }

        using ECDsa ecdsa = ECDsa.Create(
            keyType == DtlsKeyType.EcdsaP384
                ? ECCurve.NamedCurves.nistP384
                : ECCurve.NamedCurves.nistP256
        );
        return new CertificateRequest(
            subject,
            ecdsa,
            keyType == DtlsKeyType.EcdsaP384 ? HashAlgorithmName.SHA384 : HashAlgorithmName.SHA256
        ).CreateSelfSigned(now.AddDays(-1), now + lifetime);
    }
}
