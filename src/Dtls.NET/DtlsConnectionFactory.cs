using System.Security.Authentication;
using Dtls.NET.Protocol;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Dtls.NET;

/// <summary>
/// Makes DTLS connections with the application's services and configured options: the connections
/// log through its <see cref="ILoggerFactory"/> and run on its <see cref="TimeProvider"/> unless their
/// options name others, and options can be configured once by name, as <c>IHttpClientFactory</c> does
/// for HTTP clients.
/// </summary>
/// <remarks>
/// Registered with <see cref="Microsoft.Extensions.DependencyInjection.DtlsServiceCollectionExtensions.AddDtls"/>. Named options are configured
/// with <c>services.Configure&lt;DtlsClientConnectionOptions&gt;("name", options =&gt; ...)</c>; an
/// options instance is shared by every connection made with its name, so it is configured, not changed
/// per connection.
/// </remarks>
/// <param name="clientOptions">The configured client options.</param>
/// <param name="serverOptions">The configured server options.</param>
/// <param name="loggerFactory">Where connections log when their options name no logger factory.</param>
/// <param name="timeProvider">The clock connections run on when their options name none.</param>
public sealed class DtlsConnectionFactory(
    IOptionsMonitor<DtlsClientConnectionOptions> clientOptions,
    IOptionsMonitor<DtlsServerConnectionOptions> serverOptions,
    ILoggerFactory? loggerFactory = null,
    TimeProvider? timeProvider = null
)
{
    /// <summary>Connects to a DTLS server with the client options configured under a name.</summary>
    /// <param name="transport">The datagram path to the server; it stays the caller's to dispose.</param>
    /// <param name="name">The options' name; <see cref="Options.DefaultName"/> for the unnamed options.</param>
    /// <param name="cancellationToken">Cancels the handshake.</param>
    /// <returns>The connection, once the handshake has completed.</returns>
    /// <exception cref="AuthenticationException">The handshake failed.</exception>
    /// <exception cref="TimeoutException">The handshake did not complete in time.</exception>
    public ValueTask<DtlsConnection> ConnectAsync(
        IDatagramTransport transport,
        string name,
        CancellationToken cancellationToken = default
    )
    {
        ArgumentNullException.ThrowIfNull(name);
        return ConnectAsync(transport, clientOptions.Get(name), cancellationToken);
    }

    /// <summary>Connects to a DTLS server.</summary>
    /// <param name="transport">The datagram path to the server; it stays the caller's to dispose.</param>
    /// <param name="options">The client's options.</param>
    /// <param name="cancellationToken">Cancels the handshake.</param>
    /// <returns>The connection, once the handshake has completed.</returns>
    /// <exception cref="AuthenticationException">The handshake failed.</exception>
    /// <exception cref="TimeoutException">The handshake did not complete in time.</exception>
    public ValueTask<DtlsConnection> ConnectAsync(
        IDatagramTransport transport,
        DtlsClientConnectionOptions options,
        CancellationToken cancellationToken = default
    )
    {
        ArgumentNullException.ThrowIfNull(transport);
        ArgumentNullException.ThrowIfNull(options);
        return DtlsConnection.StartAsync(
            transport,
            ProtocolSettings.ForClient(options, loggerFactory, timeProvider),
            cancellationToken
        );
    }

    /// <summary>Accepts a DTLS client with the server options configured under a name.</summary>
    /// <param name="transport">The datagram path to the client; it stays the caller's to dispose.</param>
    /// <param name="name">The options' name; <see cref="Options.DefaultName"/> for the unnamed options.</param>
    /// <param name="cancellationToken">Cancels the handshake.</param>
    /// <returns>The connection, once the handshake has completed.</returns>
    /// <exception cref="AuthenticationException">The handshake failed.</exception>
    /// <exception cref="TimeoutException">The handshake did not complete in time.</exception>
    public ValueTask<DtlsConnection> AcceptAsync(
        IDatagramTransport transport,
        string name,
        CancellationToken cancellationToken = default
    )
    {
        ArgumentNullException.ThrowIfNull(name);
        return AcceptAsync(transport, serverOptions.Get(name), cancellationToken);
    }

    /// <summary>Accepts a DTLS client.</summary>
    /// <param name="transport">The datagram path to the client; it stays the caller's to dispose.</param>
    /// <param name="options">The server's options.</param>
    /// <param name="cancellationToken">Cancels the handshake.</param>
    /// <returns>The connection, once the handshake has completed.</returns>
    /// <exception cref="AuthenticationException">The handshake failed.</exception>
    /// <exception cref="TimeoutException">The handshake did not complete in time.</exception>
    public ValueTask<DtlsConnection> AcceptAsync(
        IDatagramTransport transport,
        DtlsServerConnectionOptions options,
        CancellationToken cancellationToken = default
    )
    {
        ArgumentNullException.ThrowIfNull(transport);
        ArgumentNullException.ThrowIfNull(options);
        return DtlsConnection.StartAsync(
            transport,
            ProtocolSettings.ForServer(options, loggerFactory, timeProvider),
            cancellationToken
        );
    }
}
