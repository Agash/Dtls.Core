namespace Dtls.NET;

/// <summary>A TLS alert: why a connection was closed or refused (RFC 5246 §7.2, RFC 8446 §6).</summary>
public enum DtlsAlert : byte
{
    /// <summary>The sender is closing the connection in an orderly way.</summary>
    CloseNotify = 0,

    /// <summary>A message arrived that is not appropriate at this point.</summary>
    UnexpectedMessage = 10,

    /// <summary>A record failed authentication.</summary>
    BadRecordMac = 20,

    /// <summary>A record was too long.</summary>
    RecordOverflow = 22,

    /// <summary>No set of parameters both sides accept.</summary>
    HandshakeFailure = 40,

    /// <summary>A certificate was corrupt or failed its checks.</summary>
    BadCertificate = 42,

    /// <summary>A certificate of an unsupported type.</summary>
    UnsupportedCertificate = 43,

    /// <summary>A certificate was revoked.</summary>
    CertificateRevoked = 44,

    /// <summary>A certificate has expired or is not yet valid.</summary>
    CertificateExpired = 45,

    /// <summary>A certificate was refused for another reason.</summary>
    CertificateUnknown = 46,

    /// <summary>A field was out of range or inconsistent with the others.</summary>
    IllegalParameter = 47,

    /// <summary>A certificate chain did not lead to an accepted issuer.</summary>
    UnknownCa = 48,

    /// <summary>The peer is not allowed to proceed.</summary>
    AccessDenied = 49,

    /// <summary>A message could not be decoded.</summary>
    DecodeError = 50,

    /// <summary>A cryptographic operation failed, including a Finished that did not verify.</summary>
    DecryptError = 51,

    /// <summary>The peer's protocol version is not supported.</summary>
    ProtocolVersion = 70,

    /// <summary>The peer's parameters are weaker than required.</summary>
    InsufficientSecurity = 71,

    /// <summary>An error unrelated to the peer or the protocol.</summary>
    InternalError = 80,

    /// <summary>The handshake was cancelled.</summary>
    UserCanceled = 90,

    /// <summary>The sender does not renegotiate (a warning).</summary>
    NoRenegotiation = 100,

    /// <summary>An extension the peer should not have sent.</summary>
    UnsupportedExtension = 110,

    /// <summary>No application protocol both sides accept.</summary>
    NoApplicationProtocol = 120,
}
