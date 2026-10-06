namespace Dtls.Core;

/// <summary>
/// A <see cref="IDatagramTransport"/> whose peer can change address mid-connection, such as a phone moving
/// from Wi-Fi to cellular or a NAT rebinding its mapping. With connection IDs agreed (RFC 9146, RFC 9147
/// section 9), a <see cref="DtlsConnection"/> recognises the peer's records from any address, and follows
/// the peer to a new one under the rules of RFC 9146 section 6: only for a record that authenticated, carried
/// a connection ID, and is newer than every record before it, so a replayed or forged datagram cannot redirect
/// the connection.
/// </summary>
/// <remarks>
/// The connection calls <see cref="FollowLastSender"/> from its receive loop, right after the
/// <see cref="IDatagramTransport.ReceiveAsync"/> that returned the record, and before the next one.
/// </remarks>
public interface IMobileDatagramTransport : IDatagramTransport
{
    /// <summary>
    /// Sends from now on to where the datagram most recently returned by
    /// <see cref="IDatagramTransport.ReceiveAsync"/> came from.
    /// </summary>
    /// <returns>Whether that is a different address than before.</returns>
    bool FollowLastSender();
}
