using System.Net;

namespace Dtls.Core;

/// <summary>
/// A <see cref="IDatagramTransport"/> whose peer can change address mid-connection, such as a phone moving
/// from Wi-Fi to cellular or a NAT rebinding its mapping. With connection IDs agreed (RFC 9146, RFC 9147
/// section 9), a <see cref="DtlsConnection"/> recognises the peer's records from any address, and follows
/// the peer to a new one under the rules of RFC 9146 section 6: only for a record that authenticated, carried
/// a connection ID, and is newer than every record before it, so a replayed or forged datagram cannot redirect
/// the connection, and only once <see cref="DtlsConnectionOptions.PeerAddressValidation"/> has shown the new
/// address receives.
/// </summary>
/// <remarks>
/// The connection reads <see cref="LastSender"/>, sends with <see cref="SendToAsync"/> and calls
/// <see cref="FollowLastSender"/> from its receive loop, right after the
/// <see cref="IDatagramTransport.ReceiveAsync"/> that returned the record, and before the next one.
/// </remarks>
public interface IMobileDatagramTransport : IDatagramTransport
{
    /// <summary>
    /// Where the datagram most recently returned by <see cref="IDatagramTransport.ReceiveAsync"/> came
    /// from; null before the first.
    /// </summary>
    EndPoint? LastSender { get; }

    /// <summary>Whether <see cref="LastSender"/> is somewhere else than where datagrams go.</summary>
    bool LastSenderMoved { get; }

    /// <summary>Sends from now on to <see cref="LastSender"/>.</summary>
    /// <returns>Whether that is a different address than before.</returns>
    bool FollowLastSender();

    /// <summary>
    /// Sends one datagram to <paramref name="destination"/>, leaving where the others go as it is, as
    /// the return routability check does to probe or answer an address.
    /// </summary>
    /// <param name="datagram">The datagram.</param>
    /// <param name="destination">Where it goes.</param>
    /// <param name="cancellationToken">Cancels the send.</param>
    /// <returns>A task that completes when the datagram is handed to the network.</returns>
    ValueTask SendToAsync(
        ReadOnlyMemory<byte> datagram,
        EndPoint destination,
        CancellationToken cancellationToken
    );
}
