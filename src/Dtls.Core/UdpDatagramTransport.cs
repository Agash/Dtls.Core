using System.Net;
using System.Net.Sockets;

namespace Dtls.Core;

/// <summary>
/// A UDP socket as a <see cref="IDatagramTransport"/>: connected to one peer address, or bound and following
/// the peer to new addresses (<see cref="IMobileDatagramTransport"/>), which connection IDs make safe.
/// </summary>
public sealed class UdpDatagramTransport : IMobileDatagramTransport, IDisposable
{
    private readonly bool _ownsSocket;

    // Unconnected: where the last datagram came from, and where datagrams go. Both are SocketAddress so
    // receiving and sending allocate nothing; the peer is replaced whole, never written in place, since
    // sends read it concurrently.
    private readonly SocketAddress? _lastSender;
    private SocketAddress? _peer;

    /// <summary>Uses a UDP socket already connected to the peer.</summary>
    /// <param name="socket">The socket.</param>
    /// <param name="ownsSocket">Whether disposing the transport disposes the socket.</param>
    /// <exception cref="ArgumentException">The socket is not a connected datagram socket.</exception>
    public UdpDatagramTransport(Socket socket, bool ownsSocket = true)
    {
        ArgumentNullException.ThrowIfNull(socket);
        if (socket.SocketType != SocketType.Dgram || !socket.Connected)
        {
            throw new ArgumentException(
                "The socket must be a connected datagram socket.",
                nameof(socket)
            );
        }

        Socket = socket;
        _ownsSocket = ownsSocket;
    }

    /// <summary>
    /// Wraps a bound, unconnected datagram socket that sends to <paramref name="remoteEndPoint"/> until the
    /// connection follows its peer elsewhere (<see cref="FollowLastSender"/>). It receives from any address;
    /// DTLS discards what does not authenticate.
    /// </summary>
    /// <param name="socket">A bound, unconnected datagram socket.</param>
    /// <param name="remoteEndPoint">The peer's first address.</param>
    /// <param name="ownsSocket">Whether disposing the transport disposes the socket.</param>
    /// <returns>The transport.</returns>
    public static UdpDatagramTransport FromBoundSocket(
        Socket socket,
        IPEndPoint remoteEndPoint,
        bool ownsSocket = true
    )
    {
        ArgumentNullException.ThrowIfNull(socket);
        ArgumentNullException.ThrowIfNull(remoteEndPoint);
        if (socket.SocketType != SocketType.Dgram || socket.Connected || !socket.IsBound)
        {
            throw new ArgumentException(
                "The socket must be a bound, unconnected datagram socket.",
                nameof(socket)
            );
        }

        return new UdpDatagramTransport(socket, remoteEndPoint, ownsSocket);
    }

    private UdpDatagramTransport(Socket socket, IPEndPoint remoteEndPoint, bool ownsSocket)
    {
        Socket = socket;
        _ownsSocket = ownsSocket;
        _peer = remoteEndPoint.Serialize();
        _lastSender = new SocketAddress(socket.AddressFamily);
    }

    /// <summary>The socket.</summary>
    public Socket Socket { get; }

    /// <summary>Where datagrams go: the connected peer, or the address the peer was last followed to.</summary>
    public IPEndPoint RemoteEndPoint =>
        Volatile.Read(ref _peer) is { } peer
            ? (IPEndPoint)new IPEndPoint(IPAddress.Any, 0).Create(peer)
            : (IPEndPoint)Socket.RemoteEndPoint!;

    /// <summary>
    /// Binds a socket for <paramref name="remoteEndPoint"/> without connecting it, so the connection can
    /// follow the peer to a new address once connection IDs are agreed.
    /// </summary>
    /// <param name="remoteEndPoint">The peer's first address.</param>
    /// <param name="localEndPoint">The local address; any, on an ephemeral port, by default.</param>
    /// <returns>The transport, which owns the socket.</returns>
    public static UdpDatagramTransport Bind(
        IPEndPoint remoteEndPoint,
        IPEndPoint? localEndPoint = null
    )
    {
        ArgumentNullException.ThrowIfNull(remoteEndPoint);
        Socket socket = new(remoteEndPoint.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        try
        {
            socket.Bind(localEndPoint ?? AnyFor(remoteEndPoint));
            return FromBoundSocket(socket, remoteEndPoint);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    /// <summary>Opens a UDP socket connected to a peer.</summary>
    /// <param name="remoteEndPoint">The peer.</param>
    /// <param name="localEndPoint">Where to bind; any port on any address when null.</param>
    /// <returns>The transport, which owns the socket.</returns>
    public static UdpDatagramTransport Connect(
        IPEndPoint remoteEndPoint,
        IPEndPoint? localEndPoint = null
    )
    {
        ArgumentNullException.ThrowIfNull(remoteEndPoint);
        Socket socket = new(remoteEndPoint.AddressFamily, SocketType.Dgram, ProtocolType.Udp);
        try
        {
            socket.Bind(localEndPoint ?? AnyFor(remoteEndPoint));
            socket.Connect(remoteEndPoint);
            return new UdpDatagramTransport(socket);
        }
        catch
        {
            socket.Dispose();
            throw;
        }
    }

    /// <inheritdoc/>
    /// <remarks>
    /// A send the peer's host refused (an ICMP port unreachable reported on an earlier datagram) is
    /// treated as lost: DTLS retransmits, and a peer that is not listening yet may be soon.
    /// </remarks>
    public async ValueTask SendAsync(
        ReadOnlyMemory<byte> datagram,
        CancellationToken cancellationToken
    )
    {
        try
        {
            _ = Volatile.Read(ref _peer) is { } peer
                ? await Socket
                    .SendToAsync(datagram, SocketFlags.None, peer, cancellationToken)
                    .ConfigureAwait(false)
                : await Socket
                    .SendAsync(datagram, SocketFlags.None, cancellationToken)
                    .ConfigureAwait(false);
        }
        catch (SocketException error) when (IsRefusal(error))
        {
            // Deliberately ignored: a refused datagram is a lost datagram, which DTLS recovers from.
        }
    }

    /// <inheritdoc/>
    /// <remarks>Refusals by the peer's host are skipped, as for <see cref="SendAsync"/>.</remarks>
    public async ValueTask<int> ReceiveAsync(
        Memory<byte> buffer,
        CancellationToken cancellationToken
    )
    {
        while (true)
        {
            try
            {
                return _lastSender is { } sender
                    ? await Socket
                        .ReceiveFromAsync(buffer, SocketFlags.None, sender, cancellationToken)
                        .ConfigureAwait(false)
                    : await Socket
                        .ReceiveAsync(buffer, SocketFlags.None, cancellationToken)
                        .ConfigureAwait(false);
            }
            catch (SocketException error) when (IsRefusal(error))
            {
                // Deliberately ignored: see SendAsync.
            }
        }
    }

    /// <inheritdoc/>
    /// <remarks>A connected socket has one peer address, so it never changes.</remarks>
    public bool FollowLastSender()
    {
        if (_lastSender is not { } sender || sender.Equals(Volatile.Read(ref _peer)))
        {
            return false;
        }

        SocketAddress next = new(sender.Family, sender.Size);
        sender.Buffer.Span[..sender.Size].CopyTo(next.Buffer.Span);
        Volatile.Write(ref _peer, next);
        return true;
    }

    /// <inheritdoc/>
    public void Dispose()
    {
        if (_ownsSocket)
        {
            Socket.Dispose();
        }
    }

    private static IPEndPoint AnyFor(IPEndPoint remote) =>
        new(
            remote.AddressFamily == AddressFamily.InterNetworkV6
                ? IPAddress.IPv6Any
                : IPAddress.Any,
            0
        );

    private static bool IsRefusal(SocketException error) =>
        error.SocketErrorCode is SocketError.ConnectionReset or SocketError.ConnectionRefused;
}
