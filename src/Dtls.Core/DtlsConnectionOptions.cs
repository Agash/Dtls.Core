using System.Net.Security;
using System.Threading.Channels;
using Microsoft.Extensions.Logging;

namespace Dtls.Core;

/// <summary>
/// What a DTLS connection needs besides its authentication options: the path's datagram size, the
/// handshake's timing, and DTLS-SRTP.
/// </summary>
public abstract class DtlsConnectionOptions
{
    private protected DtlsConnectionOptions() { }

    /// <summary>
    /// The largest datagram sent: the path MTU less the IP and UDP headers. 1200 bytes by default, the
    /// size WebRTC assumes every path carries.
    /// </summary>
    public int MaximumDatagramSize { get; set; } = 1200;

    /// <summary>
    /// The length of the connection ID this side asks the peer to put in every protected record it
    /// sends (RFC 9146; RFC 9147 section 9), so the association survives a change of the peer's
    /// address, such as a NAT rebinding. 0 offers the extension without asking for one, which still lets
    /// a peer that wants one get it (RFC 9147 recommends offering it); null does not offer it.
    /// </summary>
    public int? ConnectionIdLength { get; set; } = 0;

    /// <summary>
    /// The most plaintext this side takes in a protected record (RFC 8449), advertised to the peer:
    /// 64 to 16384 bytes, the protocol maximum by default. A constrained receiver sets less.
    /// </summary>
    public int RecordSizeLimit { get; set; } = 1 << 14;

    /// <summary>How long the handshake may take before it fails; 30 seconds by default.</summary>
    public TimeSpan HandshakeTimeout { get; set; } = TimeSpan.FromSeconds(30);

    /// <summary>
    /// How long a flight waits for its answer before it is sent again; each retransmission doubles it,
    /// up to a minute (RFC 6347 §4.2.4.1). One second by default.
    /// </summary>
    public TimeSpan InitialRetransmissionTimeout { get; set; } = TimeSpan.FromSeconds(1);

    /// <summary>
    /// The SRTP protection profiles for DTLS-SRTP (RFC 5764), most preferred first. When not empty the
    /// handshake must agree on one of them, and <see cref="DtlsConnection.SrtpKeyingMaterial"/> holds the
    /// keys it exports; when empty, DTLS-SRTP is not offered.
    /// </summary>
    public IList<SrtpProtectionProfile> SrtpProtectionProfiles { get; set; } = [];

    /// <summary>
    /// The DTLS versions the handshake may agree on; DTLS 1.2 and 1.3 by default. The highest both sides
    /// allow is used, and a server that allows 1.3 marks a 1.2 handshake so a client that allows 1.3
    /// detects an attacker forcing it down (RFC 8446 §4.1.3).
    /// </summary>
    public DtlsProtocols EnabledProtocols { get; set; } =
        DtlsProtocols.Dtls12 | DtlsProtocols.Dtls13;

    /// <summary>
    /// The cipher suites offered or accepted, most preferred first; null for the defaults (for DTLS 1.2
    /// the ECDHE suites with AES-GCM and, where the platform has it, ChaCha20-Poly1305; for DTLS 1.3
    /// AES-GCM and ChaCha20-Poly1305). Suites Dtls.Core does not implement, the platform cannot run, or
    /// the certificate cannot sign for are left out.
    /// </summary>
    public IList<TlsCipherSuite>? CipherSuites { get; set; }

    /// <summary>
    /// Whether the extended master secret (RFC 7627) is required, which binds the keys to the whole
    /// handshake. Every current DTLS implementation offers it. True by default.
    /// </summary>
    public bool RequireExtendedMasterSecret { get; set; } = true;

    /// <summary>
    /// How many received application data records wait for <see cref="DtlsConnection.ReceiveAsync"/>; 256
    /// by default. The connection reads the transport whether or not the application does, so a full
    /// queue drops records as a full socket buffer drops datagrams, and counts them in
    /// <see cref="DtlsConnectionStatistics.ApplicationRecordsDropped"/>.
    /// </summary>
    public int ReceiveQueueCapacity { get; set; } = 256;

    /// <summary>
    /// Which record a full receive queue drops: <see cref="BoundedChannelFullMode.DropWrite"/> (the one
    /// arriving, the default) or <see cref="BoundedChannelFullMode.DropOldest"/> (the oldest waiting, which
    /// suits live media) or <see cref="BoundedChannelFullMode.DropNewest"/>. <see cref="BoundedChannelFullMode.Wait"/> is not allowed: the connection never
    /// stops reading.
    /// </summary>
    public BoundedChannelFullMode ReceiveQueueFullMode { get; set; } =
        BoundedChannelFullMode.DropWrite;

    /// <summary>The largest handshake message accepted from the peer; 64 KiB by default.</summary>
    public int MaximumHandshakeMessageSize { get; set; } = 64 * 1024;

    /// <summary>The clock for retransmission and timeouts; the system clock when null.</summary>
    public TimeProvider? TimeProvider { get; set; }

    /// <summary>Where the connection logs its handshake and failures; nowhere when null.</summary>
    public ILoggerFactory? LoggerFactory { get; set; }

    private protected void ValidateCommon()
    {
        // An IPv4 path carries at least 576-byte datagrams; below 256 not even a ClientHello fits.
        if (MaximumDatagramSize is < 256 or > 65507)
        {
            throw new ArgumentOutOfRangeException(
                nameof(MaximumDatagramSize),
                MaximumDatagramSize,
                "A datagram size must be between 256 and 65507 bytes."
            );
        }

        if (ConnectionIdLength is < 0 or > 255)
        {
            throw new ArgumentOutOfRangeException(
                nameof(ConnectionIdLength),
                ConnectionIdLength,
                "A connection ID is 0 to 255 bytes."
            );
        }

        if (RecordSizeLimit is < 64 or > 1 << 14)
        {
            throw new ArgumentOutOfRangeException(
                nameof(RecordSizeLimit),
                RecordSizeLimit,
                "A record size limit is 64 to 16384 bytes."
            );
        }

        if (HandshakeTimeout <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(
                nameof(HandshakeTimeout),
                HandshakeTimeout,
                "The handshake timeout must be positive."
            );
        }

        if (InitialRetransmissionTimeout <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(
                nameof(InitialRetransmissionTimeout),
                InitialRetransmissionTimeout,
                "The retransmission timeout must be positive."
            );
        }

        if (MaximumHandshakeMessageSize < 1024)
        {
            throw new ArgumentOutOfRangeException(
                nameof(MaximumHandshakeMessageSize),
                MaximumHandshakeMessageSize,
                "Handshake messages of at least 1024 bytes must be accepted."
            );
        }

        ArgumentNullException.ThrowIfNull(SrtpProtectionProfiles, nameof(SrtpProtectionProfiles));
        ArgumentOutOfRangeException.ThrowIfLessThan(
            ReceiveQueueCapacity,
            1,
            nameof(ReceiveQueueCapacity)
        );
        if (
            ReceiveQueueFullMode
            is not (
                BoundedChannelFullMode.DropWrite
                or BoundedChannelFullMode.DropOldest
                or BoundedChannelFullMode.DropNewest
            )
        )
        {
            throw new ArgumentOutOfRangeException(
                nameof(ReceiveQueueFullMode),
                ReceiveQueueFullMode,
                "A DTLS connection never stops reading: a full receive queue must drop."
            );
        }
        if (
            (EnabledProtocols & (DtlsProtocols.Dtls12 | DtlsProtocols.Dtls13)) == DtlsProtocols.None
        )
        {
            throw new ArgumentOutOfRangeException(
                nameof(EnabledProtocols),
                EnabledProtocols,
                "At least one of DTLS 1.2 and DTLS 1.3 must be enabled."
            );
        }
    }
}

/// <summary>Options for a DTLS client connection (<see cref="DtlsConnection.ConnectAsync"/>).</summary>
public sealed class DtlsClientConnectionOptions : DtlsConnectionOptions
{
    /// <summary>
    /// The client's authentication, as for <see cref="SslStream"/>: its certificate
    /// (<see cref="SslClientAuthenticationOptions.ClientCertificates"/> or
    /// <see cref="SslClientAuthenticationOptions.ClientCertificateContext"/>), how the server's
    /// certificate is validated (<see cref="SslClientAuthenticationOptions.RemoteCertificateValidationCallback"/>,
    /// <see cref="SslClientAuthenticationOptions.CertificateChainPolicy"/>) and its name
    /// (<see cref="SslClientAuthenticationOptions.TargetHost"/>).
    /// </summary>
    public SslClientAuthenticationOptions ClientAuthenticationOptions { get; set; } = null!;

    internal void Validate()
    {
        ValidateCommon();
        ArgumentNullException.ThrowIfNull(
            ClientAuthenticationOptions,
            nameof(ClientAuthenticationOptions)
        );
    }
}

/// <summary>Options for a DTLS server connection (<see cref="DtlsConnection.AcceptAsync"/>).</summary>
public sealed class DtlsServerConnectionOptions : DtlsConnectionOptions
{
    /// <summary>
    /// The server's authentication, as for <see cref="SslStream"/>: its certificate
    /// (<see cref="SslServerAuthenticationOptions.ServerCertificate"/> or
    /// <see cref="SslServerAuthenticationOptions.ServerCertificateContext"/>), whether the client must
    /// present one (<see cref="SslServerAuthenticationOptions.ClientCertificateRequired"/>, which
    /// WebRTC needs) and how it is validated.
    /// </summary>
    public SslServerAuthenticationOptions ServerAuthenticationOptions { get; set; } = null!;

    /// <summary>
    /// Whether the client must prove its address with a cookie before the server does any expensive
    /// work (RFC 6347 §4.2.1), which keeps the server from being used to amplify traffic at a forged
    /// address. Costs one round trip; a path already verified (by ICE, in WebRTC) may turn it off. True
    /// by default.
    /// </summary>
    public bool CookieExchange { get; set; } = true;

    internal void Validate()
    {
        ValidateCommon();
        ArgumentNullException.ThrowIfNull(
            ServerAuthenticationOptions,
            nameof(ServerAuthenticationOptions)
        );
        if (
            ServerAuthenticationOptions.ServerCertificate is null
            && ServerAuthenticationOptions.ServerCertificateContext is null
        )
        {
            throw new ArgumentException(
                "A DTLS server needs a certificate: set ServerCertificate or ServerCertificateContext.",
                nameof(ServerAuthenticationOptions)
            );
        }
    }
}
