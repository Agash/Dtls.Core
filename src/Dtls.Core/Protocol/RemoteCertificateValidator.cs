using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Dtls.Core.Protocol;

// Validates the peer's certificate the way SslStream and QuicConnection do: build its chain under the
// options' policy for the peer's role, check the host name when there is one, and let the
// RemoteCertificateValidationCallback decide with the result; without a callback, any error fails.
// WebRTC peers, whose certificates are self-signed, pass a callback that checks the signalled
// fingerprint (DtlsFingerprint.CreateValidationCallback).
internal sealed class RemoteCertificateValidator(
    RemoteCertificateValidationCallback? callback,
    X509ChainPolicy? chainPolicy,
    X509RevocationMode revocationMode,
    string? targetHost,
    bool validatingServer
)
{
    private const string ServerAuthentication = "1.3.6.1.5.5.7.3.1";
    private const string ClientAuthentication = "1.3.6.1.5.5.7.3.2";

    // Returns the peer's certificate when it is accepted; throws otherwise.
    public X509Certificate2 Validate(object sender, IReadOnlyList<byte[]> chainDer)
    {
        X509Certificate2 certificate;
        try
        {
            certificate = X509CertificateLoader.LoadCertificate(chainDer[0]);
        }
        catch (CryptographicException error)
        {
            throw DtlsException.CorruptCertificate($"it could not be read ({error.Message})");
        }

        SslPolicyErrors errors = SslPolicyErrors.None;
        using X509Chain chain = new();
        List<X509Certificate2> extra = [];
        try
        {
            if (chainPolicy is not null)
            {
                chain.ChainPolicy = chainPolicy.Clone();
            }
            else
            {
                chain.ChainPolicy.RevocationMode = revocationMode;
                chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
            }

            if (chain.ChainPolicy.ApplicationPolicy.Count == 0)
            {
                _ = chain.ChainPolicy.ApplicationPolicy.Add(
                    new Oid(validatingServer ? ServerAuthentication : ClientAuthentication)
                );
            }

            for (int i = 1; i < chainDer.Count; i++)
            {
                X509Certificate2 intermediate = X509CertificateLoader.LoadCertificate(chainDer[i]);
                extra.Add(intermediate);
                _ = chain.ChainPolicy.ExtraStore.Add(intermediate);
            }

            if (!chain.Build(certificate))
            {
                errors |= SslPolicyErrors.RemoteCertificateChainErrors;
            }

            if (!string.IsNullOrEmpty(targetHost) && !certificate.MatchesHostname(targetHost))
            {
                errors |= SslPolicyErrors.RemoteCertificateNameMismatch;
            }

            bool accepted = callback is not null
                ? callback(sender, certificate, chain, errors)
                : errors == SslPolicyErrors.None;
            if (!accepted)
            {
                certificate.Dispose();
                throw DtlsException.BadCertificate(
                    callback is not null
                        ? "the remote certificate validation callback refused it"
                        : $"its validation failed ({errors})"
                );
            }

            return certificate;
        }
        catch (CryptographicException error)
        {
            certificate.Dispose();
            throw DtlsException.CorruptCertificate(
                $"its chain could not be read ({error.Message})"
            );
        }
        finally
        {
            foreach (X509ChainElement element in chain.ChainElements)
            {
                if (!ReferenceEquals(element.Certificate, certificate))
                {
                    element.Certificate.Dispose();
                }
            }

            foreach (X509Certificate2 intermediate in extra)
            {
                intermediate.Dispose();
            }
        }
    }
}
