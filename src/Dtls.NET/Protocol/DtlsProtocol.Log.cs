using System.Net.Security;
using Dtls.NET.Handshake;
using Microsoft.Extensions.Logging;

namespace Dtls.NET.Protocol;

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

    [LoggerMessage(
        11,
        LogLevel.Debug,
        "Sent a HelloVerifyRequest: the client proves its address with a cookie first"
    )]
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
        14,
        LogLevel.Warning,
        "The server accepts no signature this side's certificate makes; answering its request without one"
    )]
    private partial void LogClientCertificateUnusable();
}
