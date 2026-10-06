using System.Collections.Immutable;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using Dtls.Core.Crypto;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

namespace Dtls.Core.Protocol;

// Everything the protocol engine needs, resolved once from a client's or a server's options.
internal sealed class ProtocolSettings : IDisposable
{
    private readonly DtlsProtocols _enabled;

    private ProtocolSettings(
        DtlsConnectionOptions options,
        DtlsRole role,
        ILoggerFactory? defaultLoggerFactory,
        TimeProvider? defaultTimeProvider
    )
    {
        Role = role;
        _enabled = options.EnabledProtocols;
        MaximumDatagramSize = options.MaximumDatagramSize;
        ConnectionIdLength = options.ConnectionIdLength;
        RecordSizeLimit = options.RecordSizeLimit;
        HandshakeTimeout = options.HandshakeTimeout;
        InitialRetransmissionTimeout = options.InitialRetransmissionTimeout;
        MaximumHandshakeMessageSize = options.MaximumHandshakeMessageSize;
        ReceiveQueueCapacity = options.ReceiveQueueCapacity;
        ReceiveQueueFullMode = options.ReceiveQueueFullMode;
        RequireExtendedMasterSecret = options.RequireExtendedMasterSecret;
        SrtpProfiles = [.. options.SrtpProtectionProfiles.Distinct()];
        TimeProvider = options.TimeProvider ?? defaultTimeProvider ?? TimeProvider.System;
        LoggerFactory = options.LoggerFactory ?? defaultLoggerFactory ?? NullLoggerFactory.Instance;
    }

    public DtlsRole Role { get; }

    public LocalCredential? Credential { get; private init; }

    // The DTLS 1.2 suites.
    public ImmutableArray<CipherSuiteInfo> CipherSuites { get; private init; }

    // The DTLS 1.3 suites.
    public ImmutableArray<CipherSuiteInfo> CipherSuites13 { get; private init; }

    // The versions enabled that have suites to use.
    public DtlsProtocols Protocols =>
        (CipherSuites.IsEmpty ? DtlsProtocols.None : _enabled & DtlsProtocols.Dtls12)
        | (CipherSuites13.IsEmpty ? DtlsProtocols.None : _enabled & DtlsProtocols.Dtls13);

    public bool Allows12 => (Protocols & DtlsProtocols.Dtls12) != 0;

    public bool Allows13 => (Protocols & DtlsProtocols.Dtls13) != 0;

    public RemoteCertificateValidator Validator { get; private init; } = null!;

    public bool ClientCertificateRequired { get; private init; }

    public bool CookieExchange { get; private init; }

    public ImmutableArray<SslApplicationProtocol> ApplicationProtocols { get; private init; } = [];

    public int MaximumDatagramSize { get; }

    public int? ConnectionIdLength { get; }

    public int RecordSizeLimit { get; }

    public TimeSpan HandshakeTimeout { get; }

    public TimeSpan InitialRetransmissionTimeout { get; }

    public int MaximumHandshakeMessageSize { get; }

    public int ReceiveQueueCapacity { get; }

    public System.Threading.Channels.BoundedChannelFullMode ReceiveQueueFullMode { get; }

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
            CipherSuites = Usable(Requested(options), credential, client: true, tls13: false),
            CipherSuites13 = Usable(Requested(options), credential, client: true, tls13: true),
            Validator = new RemoteCertificateValidator(
                ssl.RemoteCertificateValidationCallback,
                ssl.CertificateChainPolicy,
                ssl.CertificateRevocationCheckMode,
                ssl.TargetHost,
                validatingServer: true
            ),
            ApplicationProtocols = [.. ssl.ApplicationProtocols ?? []],
        }.Checked();
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
            CipherSuites = Usable(Requested(options), credential, client: false, tls13: false),
            CipherSuites13 = Usable(Requested(options), credential, client: false, tls13: true),
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
        }.Checked();
    }

    public void Dispose() => Credential?.Dispose();

    private static ImmutableArray<TlsCipherSuite> Requested(DtlsConnectionOptions options) =>
        options.CipherSuites is { } suites
            ? [.. suites]
            : [.. CipherSuiteInfo.Default13, .. CipherSuiteInfo.Default];

    // The suites of one version this side can use: implemented, run by the platform, and (for a DTLS 1.2
    // server, which signs the key exchange) matching the certificate's key. A client offers both
    // authentications: the server's certificate decides. DTLS 1.3 suites name no authentication.
    private static ImmutableArray<CipherSuiteInfo> Usable(
        ImmutableArray<TlsCipherSuite> requested,
        LocalCredential? credential,
        bool client,
        bool tls13
    )
    {
        ImmutableArray<CipherSuiteInfo>.Builder usable =
            ImmutableArray.CreateBuilder<CipherSuiteInfo>();
        foreach (TlsCipherSuite suite in requested.Distinct())
        {
            if (
                CipherSuiteInfo.TryGet(suite, out CipherSuiteInfo info)
                && info.IsSupported
                && info.Tls13 == tls13
                && (client || tls13 || info.Authentication == credential!.Authentication)
            )
            {
                usable.Add(info);
            }
        }

        return usable.ToImmutable();
    }

    // Fails when no enabled version has a suite to use.
    private ProtocolSettings Checked() =>
        Protocols != DtlsProtocols.None
            ? this
            : throw new ArgumentException(
                "None of the cipher suites can be used with this certificate and these DTLS versions on this platform.",
                "options"
            );

    private static X509Certificate2? FirstWithKey(X509CertificateCollection? certificates) =>
        certificates?.OfType<X509Certificate2>().FirstOrDefault(static c => c.HasPrivateKey);
}
