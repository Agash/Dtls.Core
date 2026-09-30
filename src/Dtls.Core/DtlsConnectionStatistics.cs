namespace Dtls.Core;

/// <summary>What a connection has sent, received and refused so far.</summary>
/// <param name="DatagramsSent">Datagrams handed to the transport.</param>
/// <param name="DatagramsReceived">Datagrams read from the transport.</param>
/// <param name="RecordsDropped">
/// Records dropped on the way in: malformed, from an unknown epoch, replayed, or failing authentication.
/// </param>
/// <param name="AuthenticationFailures">Protected records that failed to authenticate.</param>
/// <param name="Retransmissions">Handshake flights sent again, on a timer or because the peer repeated its own.</param>
/// <param name="ApplicationRecordsSent">Application data records sent.</param>
/// <param name="ApplicationRecordsReceived">Application data records received and queued.</param>
/// <param name="ApplicationRecordsDropped">
/// Application data records dropped because the receive queue was full
/// (<see cref="DtlsConnectionOptions.ReceiveQueueCapacity"/>).
/// </param>
/// <param name="HandshakeDuration">How long the handshake took; null before it completes.</param>
public readonly record struct DtlsConnectionStatistics(
    long DatagramsSent,
    long DatagramsReceived,
    long RecordsDropped,
    long AuthenticationFailures,
    long Retransmissions,
    long ApplicationRecordsSent,
    long ApplicationRecordsReceived,
    long ApplicationRecordsDropped,
    TimeSpan? HandshakeDuration
);
