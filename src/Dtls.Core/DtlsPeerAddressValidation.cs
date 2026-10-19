namespace Dtls.Core;

/// <summary>
/// How a connection with connection IDs makes sure a peer's new address receives before it sends there
/// (RFC 9146 section 6), when the peer's records start arriving from somewhere else, as after a NAT
/// rebinding or a move from Wi-Fi to cellular. Only an <see cref="IMobileDatagramTransport"/> moves.
/// </summary>
public enum DtlsPeerAddressValidation
{
    /// <summary>
    /// The return routability check (draft-ietf-tls-dtls-rrc): the new address is sent a challenge, and
    /// the connection moves there once the answer comes back from it. Offered with connection IDs; a
    /// peer that does not take part is not followed.
    /// </summary>
    ReturnRoutabilityCheck,

    /// <summary>
    /// The application validates addresses itself (ICE consent, CoAP Echo), so the connection moves to
    /// a new address at once.
    /// </summary>
    Application,
}
