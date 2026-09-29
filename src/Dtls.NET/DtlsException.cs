namespace Dtls.NET;

/// <summary>
/// A DTLS connection failed: this side found a fault and sent <see cref="Alert"/> to the peer, or the
/// peer sent it (<see cref="IsRemote"/>). A peer that could not be authenticated is reported as an
/// <see cref="System.Security.Authentication.AuthenticationException"/> with this as its inner exception.
/// </summary>
public sealed class DtlsException : IOException
{
    /// <summary>Creates an exception for an internal error.</summary>
    public DtlsException()
        : this(DtlsAlert.InternalError, isRemote: false, "The DTLS connection failed.") { }

    /// <summary>Creates an exception for an internal error.</summary>
    /// <param name="message">What happened.</param>
    public DtlsException(string message)
        : this(DtlsAlert.InternalError, isRemote: false, message) { }

    /// <summary>Creates an exception for an internal error.</summary>
    /// <param name="message">What happened.</param>
    /// <param name="innerException">What caused it.</param>
    public DtlsException(string message, Exception innerException)
        : base(message, innerException) => Alert = DtlsAlert.InternalError;

    /// <summary>Creates an exception for an alert.</summary>
    /// <param name="alert">The alert.</param>
    /// <param name="isRemote">Whether the peer sent it.</param>
    /// <param name="message">What happened.</param>
    public DtlsException(DtlsAlert alert, bool isRemote, string message)
        : base(message)
    {
        Alert = alert;
        IsRemote = isRemote;
    }

    /// <summary>The alert the connection failed with.</summary>
    public DtlsAlert Alert { get; }

    /// <summary>Whether the peer sent the alert, rather than this side.</summary>
    public bool IsRemote { get; }

    // The message was malformed rather than refused on its merits.
    internal bool IsMalformed { get; private init; }

    internal static DtlsException Decode(string what) =>
        new(DtlsAlert.DecodeError, isRemote: false, $"A message could not be decoded: {what}.");

    internal static DtlsException Unexpected(string what) =>
        new(DtlsAlert.UnexpectedMessage, isRemote: false, $"An unexpected message: {what}.");

    internal static DtlsException IllegalParameter(string what) =>
        new(DtlsAlert.IllegalParameter, isRemote: false, $"An illegal parameter: {what}.");

    internal static DtlsException HandshakeFailure(string what) =>
        new(DtlsAlert.HandshakeFailure, isRemote: false, $"The handshake failed: {what}.");

    internal static DtlsException DecryptError(string what) =>
        new(DtlsAlert.DecryptError, isRemote: false, $"Verification failed: {what}.");

    // A certificate that does not even parse: bad_certificate on the wire (RFC 5246 §7.2.2), but
    // a fault any corrupted or forged copy of the message causes.
    internal static DtlsException CorruptCertificate(string what) =>
        new(
            DtlsAlert.BadCertificate,
            isRemote: false,
            $"The peer's certificate was refused: {what}."
        )
        {
            IsMalformed = true,
        };

    internal static DtlsException BadCertificate(string what) =>
        new(
            DtlsAlert.BadCertificate,
            isRemote: false,
            $"The peer's certificate was refused: {what}."
        );

    internal static DtlsException FromPeer(DtlsAlert alert) =>
        new(alert, isRemote: true, $"The peer sent the {alert} alert.");
}
