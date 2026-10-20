using System.Net.Security;
using Dtls.Core.Handshake;
using Microsoft.Extensions.Logging;

namespace Dtls.Core.Protocol;

internal sealed partial class DtlsProtocol
{
    [LoggerMessage(1, LogLevel.Debug, "DTLS handshake starting as the {Role}")]
    private partial void LogStarting(DtlsRole role);

    [LoggerMessage(
        2,
        LogLevel.Information,
        "DTLS connected with {CipherSuite}, SRTP profile {SrtpProfile}, peer {Subject}"
    )]
    private partial void LogConnected(
        TlsCipherSuite cipherSuite,
        SrtpProtectionProfile? srtpProfile,
        string? subject
    );

    [LoggerMessage(
        3,
        LogLevel.Debug,
        "No answer to the last flight; sending it again and waiting {Timeout}"
    )]
    private partial void LogRetransmitting(TimeSpan timeout);

    [LoggerMessage(4, LogLevel.Debug, "The peer sent its last flight again; answering it again")]
    private partial void LogAnsweringRetransmission();

    [LoggerMessage(5, LogLevel.Information, "DTLS connection closed (by the peer: {ByPeer})")]
    private partial void LogClosed(bool byPeer);

    [LoggerMessage(
        6,
        LogLevel.Warning,
        "DTLS connection failed with the {Alert} alert (sent by the peer: {Remote})"
    )]
    private partial void LogFailed(Exception error, DtlsAlert alert, bool remote);

    [LoggerMessage(7, LogLevel.Warning, "DTLS handshake did not complete within {Timeout}")]
    private partial void LogHandshakeTimedOut(TimeSpan timeout);

    [LoggerMessage(8, LogLevel.Information, "Refused a renegotiation the peer started with {Type}")]
    private partial void LogRenegotiationRefused(HandshakeType type);

    [LoggerMessage(9, LogLevel.Information, "The peer sent the {Alert} warning alert")]
    private partial void LogWarningAlert(DtlsAlert alert);

    [LoggerMessage(10, LogLevel.Debug, "Reading epoch {Epoch}")]
    private partial void LogReadEpoch(ushort epoch);

    [LoggerMessage(11, LogLevel.Debug, "Asked the client to prove its address with a cookie first")]
    private partial void LogCookieSent();

    [LoggerMessage(
        12,
        LogLevel.Debug,
        "The server asked for a {Length}-byte cookie; sending the ClientHello again"
    )]
    private partial void LogCookieReceived(int length);

    [LoggerMessage(13, LogLevel.Debug, "Dropped a ClientHello that could not be read: {Reason}")]
    private partial void LogClientHelloDropped(string reason);

    [LoggerMessage(
        15,
        LogLevel.Debug,
        "The server sent a HelloRetryRequest; sending the ClientHello again"
    )]
    private partial void LogRetryRequested();

    [LoggerMessage(
        14,
        LogLevel.Warning,
        "The server accepts no signature this side's certificate makes; answering its request without one"
    )]
    private partial void LogClientCertificateUnusable();

    [LoggerMessage(
        16,
        LogLevel.Debug,
        "Dropped an unauthenticated {Type} that could not be read: {Reason}"
    )]
    private partial void LogMessageDropped(HandshakeType type, string reason);

    [LoggerMessage(
        17,
        LogLevel.Debug,
        "Refused a ClientHello whose cookie this server did not make"
    )]
    private partial void LogCookieRefused();

    [LoggerMessage(
        18,
        LogLevel.Information,
        "The peer moved to {Address}; following it by its connection ID"
    )]
    internal partial void LogPeerMoved(string address);

    [LoggerMessage(
        19,
        LogLevel.Information,
        "The peer shut down its sending; this side may still send"
    )]
    private partial void LogPeerShutDown();

    [LoggerMessage(
        20,
        LogLevel.Debug,
        "Records came from a new address; sending it a path_challenge"
    )]
    private partial void LogPathChallenged();

    [LoggerMessage(21, LogLevel.Debug, "The new address answered the path_challenge")]
    private partial void LogPathValidated();

    [LoggerMessage(
        22,
        LogLevel.Information,
        "The new address did not answer the path_challenge within {Timeout}; the peer stays where it was"
    )]
    private partial void LogPathNotValidated(TimeSpan timeout);

    [LoggerMessage(
        23,
        LogLevel.Information,
        "Records came from a new address, but the peer takes no return routability check; it is not followed (RFC 9146 section 6)"
    )]
    internal partial void LogPeerNotFollowed();

    [LoggerMessage(
        24,
        LogLevel.Information,
        "The write keys protected {Written} of the {Limit} records their AEAD allows; moving to new keys (RFC 9147 section 4.5.3)"
    )]
    private partial void LogRecordLimitNear(ulong written, ulong limit);

    [LoggerMessage(
        25,
        LogLevel.Warning,
        "{Failed} records failed to authenticate under the peer's keys, of {Limit} allowed; asking it for new keys (RFC 9147 section 4.5.3)"
    )]
    private partial void LogIntegrityLimitNear(long failed, long limit);

    [LoggerMessage(
        26,
        LogLevel.Debug,
        "A handshake fragment arrived out of order; acknowledging what arrived (RFC 9147 section 7.1)"
    )]
    private partial void LogOutOfOrderAcknowledged();

    [LoggerMessage(
        27,
        LogLevel.Debug,
        "The peer's flight is still partial a quarter timeout on; acknowledging what arrived (RFC 9147 section 7.1)"
    )]
    private partial void LogPartialFlightAcknowledged();

    [LoggerMessage(
        28,
        LogLevel.Warning,
        "The write keys are at their AEAD's limit after {Written} records and the KeyUpdate is not yet acknowledged; the record is held back (RFC 9147 section 4.5.3)"
    )]
    private partial void LogRecordHeldBack(ulong written);
}
