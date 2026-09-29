using System.Collections.Immutable;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using Dtls.NET.Crypto;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dtls.NET.Protocol;

// Everything the protocol engine needs, resolved once from a client's or a server's options.
internal sealed class ProtocolSettings : IDisposable
{
    private ProtocolSettings(
        DtlsConnectionOptions options,
        DtlsRole role,
        ILoggerFactory? defaultLoggerFactory,
        TimeProvider? defaultTimeProvider
    )
    {
        Role = role;
        MaximumDatagramSize = options.MaximumDatagramSize;
        HandshakeTimeout = options.HandshakeTimeout;
        InitialRetransmissionTimeout = options.InitialRetransmissionTimeout;
        MaximumHandshakeMessageSize = options.MaximumHandshakeMessageSize;
        RequireExtendedMasterSecret = options.RequireExtendedMasterSecret;
        SrtpProfiles = [.. options.SrtpProtectionProfiles.Distinct()];
        TimeProvider = options.TimeProvider ?? defaultTimeProvider ?? TimeProvider.System;
        LoggerFactory = options.LoggerFactory ?? defaultLoggerFactory ?? NullLoggerFactory.Instance;
    }

    public DtlsRole Role { get; }

    public LocalCredential? Credential { get; private init; }

    public ImmutableArray<CipherSuiteInfo> CipherSuites { get; private init; }

    public RemoteCertificateValidator Validator { get; private init; } = null!;

    public bool ClientCertificateRequired { get; private init; }

    public bool CookieExchange { get; private init; }

    public ImmutableArray<SslApplicationProtocol> ApplicationProtocols { get; private init; } = [];

    public int MaximumDatagramSize { get; }

    public TimeSpan HandshakeTimeout { get; }

    public TimeSpan InitialRetransmissionTimeout { get; }

    public int MaximumHandshakeMessageSize { get; }

    public bool RequireExtendedMasterSecret { get; }

    public ImmutableArray<SrtpProtectionProfile> SrtpProfiles { get; }

    public TimeProvider TimeProvider { get; }

    public ILoggerFactory LoggerFactory { get; }

    // The defaults are the application's services, for what the options leave unset.
    public static ProtocolSettings ForClient(
        DtlsClientConnectionOptions options,
        ILoggerFactory? defaultLoggerFactory = null,
        TimeProvider? defaultTimeProvider = null
    )
    {
        options.Validate();
        SslClientAuthenticationOptions ssl = options.ClientAuthenticationOptions;
        LocalCredential? credential = LocalCredential.From(
            ssl.ClientCertificateContext,
            FirstWithKey(ssl.ClientCertificates)
        );

        return new ProtocolSettings(
            options,
            DtlsRole.Client,
            defaultLoggerFactory,
            defaultTimeProvider
        )
        {
            Credential = credential,
            CipherSuites = Usable(Requested(options), credential, client: true),
            Validator = new RemoteCertificateValidator(
                ssl.RemoteCertificateValidationCallback,
                ssl.CertificateChainPolicy,
                ssl.CertificateRevocationCheckMode,
                ssl.TargetHost,
                validatingServer: true
            ),
            ApplicationProtocols = [.. ssl.ApplicationProtocols ?? []],
        };
    }

    public static ProtocolSettings ForServer(
        DtlsServerConnectionOptions options,
        ILoggerFactory? defaultLoggerFactory = null,
        TimeProvider? defaultTimeProvider = null
    )
    {
        options.Validate();
        SslServerAuthenticationOptions ssl = options.ServerAuthenticationOptions;
        LocalCredential credential = LocalCredential.From(
            ssl.ServerCertificateContext,
            ssl.ServerCertificate
        )!;

        return new ProtocolSettings(
            options,
            DtlsRole.Server,
            defaultLoggerFactory,
            defaultTimeProvider
        )
        {
            Credential = credential,
            CipherSuites = Usable(Requested(options), credential, client: false),
            Validator = new RemoteCertificateValidator(
                ssl.RemoteCertificateValidationCallback,
                ssl.CertificateChainPolicy,
                ssl.CertificateRevocationCheckMode,
                targetHost: null,
                validatingServer: false
            ),
            ClientCertificateRequired = ssl.ClientCertificateRequired,
            CookieExchange = options.CookieExchange,
            ApplicationProtocols = [.. ssl.ApplicationProtocols ?? []],
        };
    }

    public void Dispose() => Credential?.Dispose();

    private static ImmutableArray<TlsCipherSuite> Requested(DtlsConnectionOptions options) =>
        options.CipherSuites is { } suites ? [.. suites] : CipherSuiteInfo.Default;

    // The suites this side can use: implemented, run by the platform, and (for a server, which signs
    // the key exchange) matching the certificate's key. A client offers both authentications: the
    // server's certificate decides.
    private static ImmutableArray<CipherSuiteInfo> Usable(
        ImmutableArray<TlsCipherSuite> requested,
        LocalCredential? credential,
        bool client
    )
    {
        ImmutableArray<CipherSuiteInfo>.Builder usable =
            ImmutableArray.CreateBuilder<CipherSuiteInfo>();
        foreach (TlsCipherSuite suite in requested.Distinct())
        {
            if (
                CipherSuiteInfo.TryGet(suite, out CipherSuiteInfo info)
                && info.IsSupported
                && (client || info.Authentication == credential!.Authentication)
            )
            {
                usable.Add(info);
            }
        }

        return usable.Count > 0
            ? usable.ToImmutable()
            : throw new ArgumentException(
                "None of the cipher suites can be used with this certificate on this platform.",
                nameof(requested)
            );
    }

    private static X509Certificate2? FirstWithKey(X509CertificateCollection? certificates) =>
        certificates?.OfType<X509Certificate2>().FirstOrDefault(static c => c.HasPrivateKey);
}
