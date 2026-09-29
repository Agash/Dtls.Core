using System.Buffers;
using System.Net.Security;
using System.Runtime.ExceptionServices;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Channels;
using Dtls.NET.Protocol;
using Dtls.NET.Records;
using Microsoft.Extensions.Logging;

namespace Dtls.NET;

/// <summary>
/// A DTLS 1.2 connection (RFC 6347) over a datagram transport: an authenticated, encrypted datagram
/// channel to one peer, and with DTLS-SRTP the keys for its media.
/// </summary>
/// <remarks>
/// <para>
/// A connection is made with <see cref="ConnectAsync"/> or <see cref="AcceptAsync"/>, which return once
/// the handshake has completed and the peer is authenticated. From then on it reads the transport in
/// the background: it answers the peer's retransmissions and alerts whether or not the application
/// reads, and queues the application data that arrives for <see cref="ReceiveAsync"/>.
/// </para>
/// <para>
/// DTLS keeps datagram boundaries: each <see cref="SendAsync"/> arrives as one
/// <see cref="ReceiveAsync"/>, whole, or not at all, in any order. <see cref="SendAsync"/> and
/// <see cref="ReceiveAsync"/> may run at the same time; each may run once at a time.
/// </para>
/// </remarks>
public sealed class DtlsConnection : IAsyncDisposable
{
    private const int ReceiveBufferSize = 65535;
    private const int ReceiveQueueCapacity = 256;

    // Labels RFC 5705 §4 keeps from exporters: TLS's own uses of the PRF.
    private static readonly string[] s_reservedLabels =
    [
        "client finished",
        "server finished",
        "master secret",
        "key expansion",
        "extended master secret",
    ];

    private readonly Lock _lock = new();
    private readonly ProtocolSettings _settings;
    private readonly DtlsProtocol _protocol;
    private readonly IDatagramTransport _transport;
    private readonly ITimer _timer;
    private readonly CancellationTokenSource _stop = new();
    private readonly TaskCompletionSource _handshake = new(
        TaskCreationOptions.RunContinuationsAsynchronously
    );
    private readonly Channel<ReceivedRecord> _received;
    private readonly List<Range> _applicationData = [];
    private Task _receiveLoop = Task.CompletedTask;
    private bool _disposed;

    private DtlsConnection(IDatagramTransport transport, ProtocolSettings settings)
    {
        _transport = transport;
        _settings = settings;
        _protocol = new DtlsProtocol(
            settings,
            this,
            settings.LoggerFactory.CreateLogger<DtlsConnection>()
        );
        _received = Channel.CreateBounded<ReceivedRecord>(
            new BoundedChannelOptions(ReceiveQueueCapacity)
            {
                FullMode = BoundedChannelFullMode.DropWrite,
            },
            static record => record.Return()
        );
        _timer = settings.TimeProvider.CreateTimer(
            static state => ((DtlsConnection)state!).OnTimer(),
            this,
            Timeout.InfiniteTimeSpan,
            Timeout.InfiniteTimeSpan
        );
    }

    /// <summary>The peer's certificate, which the handshake validated.</summary>
    public X509Certificate2? RemoteCertificate => _protocol.RemoteCertificate;

    /// <summary>The cipher suite the handshake chose.</summary>
    public TlsCipherSuite NegotiatedCipherSuite => _protocol.NegotiatedCipherSuite;

    /// <summary>The application protocol ALPN chose; default when none was negotiated.</summary>
    public SslApplicationProtocol NegotiatedApplicationProtocol =>
        _protocol.NegotiatedApplicationProtocol;

    /// <summary>
    /// The SRTP master keys and salts (RFC 5764 §4.2) when the options asked for DTLS-SRTP; null
    /// otherwise.
    /// </summary>
    public SrtpKeyingMaterial? SrtpKeyingMaterial => _protocol.SrtpKeyingMaterial;

    /// <summary>The most application data one <see cref="SendAsync"/> carries: the datagram limit less the record's overhead.</summary>
    public int MaximumApplicationDataSize
    {
        get
        {
            lock (_lock)
            {
                return _protocol.MaximumApplicationDataSize;
            }
        }
    }

    /// <summary>Connects to a DTLS server: runs the handshake as the client.</summary>
    /// <param name="transport">The datagram path to the server; it stays the caller's to dispose.</param>
    /// <param name="options">The client's options.</param>
    /// <param name="cancellationToken">Cancels the handshake.</param>
    /// <returns>The connection, once the handshake has completed.</returns>
    /// <exception cref="AuthenticationException">
    /// The handshake failed; the inner <see cref="DtlsException"/> says how.
    /// </exception>
    /// <exception cref="TimeoutException">The handshake did not complete within <see cref="DtlsConnectionOptions.HandshakeTimeout"/>.</exception>
    /// <exception cref="ArgumentException">The options are incomplete or out of range.</exception>
    public static ValueTask<DtlsConnection> ConnectAsync(
        IDatagramTransport transport,
        DtlsClientConnectionOptions options,
        CancellationToken cancellationToken = default
    )
    {
        ArgumentNullException.ThrowIfNull(transport);
        ArgumentNullException.ThrowIfNull(options);
        return StartAsync(transport, ProtocolSettings.ForClient(options), cancellationToken);
    }

    /// <summary>Accepts a DTLS client: runs the handshake as the server.</summary>
    /// <param name="transport">The datagram path to the client; it stays the caller's to dispose.</param>
    /// <param name="options">The server's options.</param>
    /// <param name="cancellationToken">Cancels the handshake.</param>
    /// <returns>The connection, once the handshake has completed.</returns>
    /// <exception cref="AuthenticationException">
    /// The handshake failed; the inner <see cref="DtlsException"/> says how.
    /// </exception>
    /// <exception cref="TimeoutException">The handshake did not complete within <see cref="DtlsConnectionOptions.HandshakeTimeout"/>.</exception>
    /// <exception cref="ArgumentException">The options are incomplete or out of range.</exception>
    public static ValueTask<DtlsConnection> AcceptAsync(
        IDatagramTransport transport,
        DtlsServerConnectionOptions options,
        CancellationToken cancellationToken = default
    )
    {
        ArgumentNullException.ThrowIfNull(transport);
        ArgumentNullException.ThrowIfNull(options);
        return StartAsync(transport, ProtocolSettings.ForServer(options), cancellationToken);
    }

    /// <summary>Sends application data as one datagram.</summary>
    /// <param name="data">The data, at most <see cref="MaximumApplicationDataSize"/> bytes.</param>
    /// <param name="cancellationToken">Cancels the send.</param>
    /// <returns>A task that completes when the datagram has been handed to the transport.</returns>
    /// <exception cref="ArgumentException">The data does not fit one datagram.</exception>
    /// <exception cref="DtlsException">The connection has closed or failed.</exception>
    /// <exception cref="ObjectDisposedException">The connection is disposed.</exception>
    public async ValueTask SendAsync(
        ReadOnlyMemory<byte> data,
        CancellationToken cancellationToken = default
    )
    {
        lock (_lock)
        {
            ThrowIfUnusable();
            _protocol.Send(data.Span);
        }

        await FlushAsync(cancellationToken).ConfigureAwait(false);
        lock (_lock)
        {
            ThrowIfUnusable();
        }
    }

    /// <summary>Receives the next application data the peer sent.</summary>
    /// <param name="buffer">Where to put it; large enough for the peer's largest datagram.</param>
    /// <param name="cancellationToken">Cancels the wait.</param>
    /// <returns>The data's length; 0 once the peer has closed the connection and everything it sent before has been read.</returns>
    /// <exception cref="ArgumentException">
    /// The next data does not fit the buffer; it stays queued for a call with a larger one.
    /// </exception>
    /// <exception cref="DtlsException">The connection failed.</exception>
    public async ValueTask<int> ReceiveAsync(
        Memory<byte> buffer,
        CancellationToken cancellationToken = default
    )
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        ChannelReader<ReceivedRecord> reader = _received.Reader;
        while (true)
        {
            if (reader.TryPeek(out ReceivedRecord next))
            {
                if (next.Length > buffer.Length)
                {
                    throw new ArgumentException(
                        $"The next datagram holds {next.Length} bytes, more than the {buffer.Length}-byte buffer.",
                        nameof(buffer)
                    );
                }

                if (reader.TryRead(out ReceivedRecord record))
                {
                    record.Buffer.AsSpan(0, record.Length).CopyTo(buffer.Span);
                    record.Return();
                    return record.Length;
                }
            }

            if (!await reader.WaitToReadAsync(cancellationToken).ConfigureAwait(false))
            {
                return 0;
            }
        }
    }

    /// <summary>
    /// Exports keying material bound to this connection (RFC 5705), as DTLS-SRTP does for its keys.
    /// </summary>
    /// <param name="label">The exporter label, registered with IANA for its use.</param>
    /// <param name="destination">Where to write the keying material; its length is how much.</param>
    /// <exception cref="ArgumentException">The label is empty or one TLS keeps for itself.</exception>
    public void ExportKeyingMaterial(string label, Span<byte> destination) =>
        Export(label, [], useContext: false, destination);

    /// <summary>
    /// Exports keying material bound to this connection and a context value (RFC 5705). An empty
    /// context differs from none.
    /// </summary>
    /// <param name="label">The exporter label, registered with IANA for its use.</param>
    /// <param name="context">The context value, at most 65,535 bytes.</param>
    /// <param name="destination">Where to write the keying material; its length is how much.</param>
    /// <exception cref="ArgumentException">The label is empty or one TLS keeps for itself, or the context is too long.</exception>
    public void ExportKeyingMaterial(
        string label,
        ReadOnlySpan<byte> context,
        Span<byte> destination
    )
    {
        ArgumentOutOfRangeException.ThrowIfGreaterThan(
            context.Length,
            ushort.MaxValue,
            nameof(context)
        );
        Export(label, context, useContext: true, destination);
    }

    /// <summary>Closes the connection, telling the peer with a close_notify alert.</summary>
    /// <param name="cancellationToken">Cancels sending the alert.</param>
    /// <returns>A task that completes when the alert has been sent.</returns>
    public async ValueTask CloseAsync(CancellationToken cancellationToken = default)
    {
        lock (_lock)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            _protocol.Close();
            Observe();
        }

        await FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>Closes the connection if it is open, then releases it.</summary>
    /// <returns>A task that completes when the connection is released.</returns>
    public async ValueTask DisposeAsync()
    {
        lock (_lock)
        {
            if (_disposed)
            {
                return;
            }

            _protocol.Close();
            Observe();
        }

        await FlushAsync(CancellationToken.None).ConfigureAwait(false);
        await _stop.CancelAsync().ConfigureAwait(false);
        await _receiveLoop.ConfigureAwait(false);
        await _timer.DisposeAsync().ConfigureAwait(false);
        lock (_lock)
        {
            _disposed = true;
            _ = _received.Writer.TryComplete(new ObjectDisposedException(nameof(DtlsConnection)));
            while (_received.Reader.TryRead(out ReceivedRecord record))
            {
                record.Return();
            }

            _protocol.Dispose();
        }

        _stop.Dispose();
        _settings.Dispose();
    }

    private static async ValueTask<DtlsConnection> StartAsync(
        IDatagramTransport transport,
        ProtocolSettings settings,
        CancellationToken cancellationToken
    )
    {
        DtlsConnection connection = new(transport, settings);
        try
        {
            lock (connection._lock)
            {
                connection._protocol.Start();
                connection.Observe();
            }

            connection._receiveLoop = connection.ReceiveLoopAsync();
            await connection.FlushAsync(cancellationToken).ConfigureAwait(false);
            await connection._handshake.Task.WaitAsync(cancellationToken).ConfigureAwait(false);
            return connection;
        }
        catch
        {
            await connection.DisposeAsync().ConfigureAwait(false);
            throw;
        }
    }

    // Reads the transport for the connection's lifetime: the handshake, the peer's retransmissions and
    // alerts, and application data for ReceiveAsync.
    private async Task ReceiveLoopAsync()
    {
        byte[] buffer = ArrayPool<byte>.Shared.Rent(ReceiveBufferSize);
        CancellationToken stop = _stop.Token;
        try
        {
            while (true)
            {
                int length = await _transport.ReceiveAsync(buffer, stop).ConfigureAwait(false);
                bool open;
                lock (_lock)
                {
                    _applicationData.Clear();
                    _protocol.Receive(buffer.AsSpan(0, length), _applicationData);
                    foreach (Range range in _applicationData)
                    {
                        ReceivedRecord record = ReceivedRecord.Copy(buffer.AsSpan(range));
                        if (!_received.Writer.TryWrite(record))
                        {
                            record.Return();
                        }
                    }

                    Observe();
                    open = _protocol.State is ProtocolState.Handshaking or ProtocolState.Connected;
                }

                await FlushAsync(stop).ConfigureAwait(false);
                if (!open)
                {
                    return;
                }
            }
        }
        catch (OperationCanceledException) when (stop.IsCancellationRequested)
        {
            // Deliberately not logged: the connection is being disposed.
        }
        catch (Exception error) when (error is not OutOfMemoryException)
        {
            // The transport failed, or an application callback the handshake ran threw: either ends the
            // connection, which records and logs the error and hands it to the application.
            lock (_lock)
            {
                _protocol.Abort(error);
                Observe();
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private void OnTimer()
    {
        lock (_lock)
        {
            if (_disposed)
            {
                return;
            }

            _protocol.OnTimer();
            Observe();
        }

        _ = FlushInBackgroundAsync();
    }

    private async Task FlushInBackgroundAsync()
    {
        try
        {
            await FlushAsync(_stop.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // Deliberately not logged: the connection is being disposed.
        }
    }

    // Sends what the protocol has queued. A transport failure ends the connection rather than being
    // thrown here; the caller finds it in the connection's state.
    private async ValueTask FlushAsync(CancellationToken cancellationToken)
    {
        while (true)
        {
            OutgoingDatagram datagram;
            lock (_lock)
            {
                if (_disposed || !_protocol.TryDequeue(out datagram))
                {
                    return;
                }
            }

            try
            {
                await _transport
                    .SendAsync(datagram.Memory, cancellationToken)
                    .ConfigureAwait(false);
            }
            catch (Exception error)
                when (error is not (OperationCanceledException or OutOfMemoryException))
            {
                lock (_lock)
                {
                    _protocol.Abort(error);
                    Observe();
                }

                return;
            }
            finally
            {
                datagram.Return();
            }
        }
    }

    // Brings the handshake task, the receive queue and the timer up to date with the protocol. Runs
    // under the lock.
    private void Observe()
    {
        switch (_protocol.State)
        {
            case ProtocolState.Connected:
                _ = _handshake.TrySetResult();
                break;
            case ProtocolState.Failed:
                Exception error = _protocol.Error!;
                _ = _handshake.TrySetException(HandshakeError(error));
                _ = _received.Writer.TryComplete(error);
                break;
            case ProtocolState.Closed:
                _ = _handshake.TrySetException(
                    HandshakeError(
                        new DtlsException(
                            DtlsAlert.CloseNotify,
                            _protocol.ClosedByPeer,
                            "The connection was closed during the handshake."
                        )
                    )
                );
                _ = _received.Writer.TryComplete();
                break;
        }

        long deadline = _protocol.Deadline;
        if (deadline == long.MaxValue || _disposed)
        {
            _ = _timer.Change(Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
            return;
        }

        TimeProvider time = _settings.TimeProvider;
        long now = time.GetTimestamp();
        TimeSpan due = deadline > now ? time.GetElapsedTime(now, deadline) : TimeSpan.Zero;
        _ = _timer.Change(due, Timeout.InfiniteTimeSpan);
    }

    // What ConnectAsync and AcceptAsync throw for a failed handshake, as SslStream does: a protocol
    // failure is an AuthenticationException with the DTLS detail inside.
    private static Exception HandshakeError(Exception error) =>
        error is DtlsException dtls
            ? new AuthenticationException($"The DTLS handshake failed: {dtls.Message}", dtls)
            : error;

    private void ThrowIfUnusable()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        switch (_protocol.State)
        {
            case ProtocolState.Failed:
                ExceptionDispatchInfo.Throw(_protocol.Error!);
                break;
            case ProtocolState.Closed:
                throw new DtlsException(
                    DtlsAlert.CloseNotify,
                    _protocol.ClosedByPeer,
                    "The DTLS connection is closed."
                );
        }
    }

    private void Export(
        string label,
        ReadOnlySpan<byte> context,
        bool useContext,
        Span<byte> destination
    )
    {
        ArgumentException.ThrowIfNullOrEmpty(label);
        if (s_reservedLabels.Contains(label, StringComparer.Ordinal))
        {
            throw new ArgumentException(
                $"\"{label}\" is a label TLS keeps for itself.",
                nameof(label)
            );
        }

        lock (_lock)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            _protocol.ExportKeyingMaterial(label, context, useContext, destination);
        }
    }

    // Application data received, in a buffer rented from the shared pool.
    private readonly record struct ReceivedRecord(byte[] Buffer, int Length)
    {
        public static ReceivedRecord Copy(ReadOnlySpan<byte> data)
        {
            byte[] buffer = ArrayPool<byte>.Shared.Rent(data.Length);
            data.CopyTo(buffer);
            return new ReceivedRecord(buffer, data.Length);
        }

        public void Return() => ArrayPool<byte>.Shared.Return(Buffer);
    }
}
