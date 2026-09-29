using System.Collections.Immutable;
using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Dtls.NET.Crypto;

// This side's certificate chain and the private key it signs with, taken from the authentication
// options: an SslStreamCertificateContext (leaf and intermediates) or a certificate with its key.
internal sealed class LocalCredential : IDisposable
{
    private LocalCredential(ImmutableArray<byte[]> chain, ECDsa? ecdsa, RSA? rsa)
    {
        Chain = chain;
        Ecdsa = ecdsa;
        Rsa = rsa;
    }

    // The DER certificates to send, leaf first.
    public ImmutableArray<byte[]> Chain { get; }

    public ECDsa? Ecdsa { get; }

    public RSA? Rsa { get; }

    public int EcdsaKeySize => Ecdsa?.KeySize ?? 0;

    public AuthenticationKind Authentication =>
        Ecdsa is not null ? AuthenticationKind.Ecdsa : AuthenticationKind.Rsa;

    public static LocalCredential? From(
        SslStreamCertificateContext? context,
        X509Certificate? certificate
    )
    {
        if (context is not null)
        {
            return From(context.TargetCertificate, context.IntermediateCertificates);
        }

        return certificate switch
        {
            null => null,
            X509Certificate2 withKey => From(withKey, []),
            _ => throw new ArgumentException(
                "The certificate must be an X509Certificate2 with its private key.",
                nameof(certificate)
            ),
        };
    }

    public void Dispose()
    {
        Ecdsa?.Dispose();
        Rsa?.Dispose();
    }

    private static LocalCredential From(
        X509Certificate2 leaf,
        IEnumerable<X509Certificate2> intermediates
    )
    {
        ImmutableArray<byte[]> chain =
        [
            leaf.RawData,
            .. intermediates.Select(static c => c.RawData),
        ];
        ECDsa? ecdsa = leaf.GetECDsaPrivateKey();
        if (ecdsa is { KeySize: 256 or 384 })
        {
            return new LocalCredential(chain, ecdsa, null);
        }

        ecdsa?.Dispose();
        RSA? rsa = leaf.GetRSAPrivateKey();
        return rsa is not null
            ? new LocalCredential(chain, null, rsa)
            : throw new ArgumentException(
                "The certificate has no ECDSA P-256, ECDSA P-384 or RSA private key.",
                nameof(leaf)
            );
    }
}
