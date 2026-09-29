namespace Dtls.NET;

/// <summary>
/// The datagram path a <see cref="DtlsConnection"/> runs over: to and from one peer, unreliable and
/// unordered, keeping datagram boundaries. A connected UDP socket
/// (<see cref="UdpDatagramTransport"/>) is one; an ICE transport, which demultiplexes DTLS from SRTP
/// and STUN on one socket, is another.
/// </summary>
/// <remarks>
/// A connection calls <see cref="ReceiveAsync"/> from one loop at a time, and <see cref="SendAsync"/>
/// from its loop, its retransmission timer and the application, possibly at once; an implementation
/// must allow concurrent sends, as a UDP socket does. The connection does not dispose the transport.
/// </remarks>
public interface IDatagramTransport
{
    /// <summary>Sends one datagram to the peer.</summary>
    /// <param name="datagram">The datagram; valid only until the returned task completes.</param>
    /// <param name="cancellationToken">Cancels the send.</param>
    /// <returns>A task that completes when the datagram has been handed to the path.</returns>
    ValueTask SendAsync(ReadOnlyMemory<byte> datagram, CancellationToken cancellationToken);

    /// <summary>Receives the next datagram from the peer.</summary>
    /// <param name="buffer">Where to put it: 65,535 bytes, so no datagram is truncated.</param>
    /// <param name="cancellationToken">Cancels the receive.</param>
    /// <returns>The datagram's length.</returns>
    ValueTask<int> ReceiveAsync(Memory<byte> buffer, CancellationToken cancellationToken);
}
