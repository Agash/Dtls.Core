using System.Net;
using System.Net.Sockets;

namespace Dtls.NET;

/// <summary>A connected UDP socket as a <see cref="IDatagramTransport"/>.</summary>
public sealed class UdpDatagramTransport : IDatagramTransport, IDisposable
{
    private readonly bool _ownsSocket;

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

    /// <summary>The socket.</summary>
    public Socket Socket { get; }

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
            socket.Bind(
                localEndPoint
                    ?? new IPEndPoint(
                        remoteEndPoint.AddressFamily == AddressFamily.InterNetworkV6
                            ? IPAddress.IPv6Any
                            : IPAddress.Any,
                        0
                    )
            );
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
            _ = await Socket
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
                return await Socket
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
    public void Dispose()
    {
        if (_ownsSocket)
        {
            Socket.Dispose();
        }
    }

    private static bool IsRefusal(SocketException error) =>
        error.SocketErrorCode is SocketError.ConnectionReset or SocketError.ConnectionRefused;
}
