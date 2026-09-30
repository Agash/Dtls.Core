using System.Net.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Dtls.Core.Crypto;
using Dtls.Core.Handshake;
using Dtls.Core.Records;
using Dtls.Core.Wire;
using Microsoft.Extensions.Logging;

namespace Dtls.Core.Protocol;

internal enum DtlsRole
{
    Client,
    Server,
}

internal enum ProtocolState
{
    Handshaking,
    Connected,
    Closed,
    Failed,
}

// One DTLS connection, 1.2 (RFC 6347) or 1.3 (RFC 9147), with no I/O of its own: it is handed the
// datagrams that arrive from the peer and the time, and queues the datagrams to send. The handshake,
// record protection, fragmentation, retransmission and replay protection happen here; DtlsConnection
// drives it over a datagram transport. Not thread-safe: the driver serialises every call.
//
// The version is settled by the hellos: a client offers the versions it allows in one ClientHello and
// the server's answer (a HelloVerifyRequest or DTLS 1.2 ServerHello, or a DTLS 1.3 ServerHello or
// HelloRetryRequest) decides which half of this class runs the rest.
internal sealed partial class DtlsProtocol(ProtocolSettings settings, object owner, ILogger logger)
    : IDisposable
{
    private const byte WarningLevel = 1;
    private const byte FatalLevel = 2;
    private static readonly TimeSpan s_maximumRetransmissionTimeout = TimeSpan.FromSeconds(60);

    private readonly ProtocolSettings _settings = settings;
    private readonly object _owner = owner;
    private readonly ILogger _logger = logger;
    private readonly RecordLayer _records = new(settings.MaximumDatagramSize);
    private readonly HandshakeReassembler _reassembler = new(settings.MaximumHandshakeMessageSize);
    private readonly Transcript _transcript = new();
    private readonly WireWriter _scratch = new(512);
    private readonly byte[] _localRandom = RandomNumberGenerator.GetBytes(32);
    private readonly TimeProvider _time = settings.TimeProvider;

    private byte[]? _peerRandom;
    private CipherSuiteInfo _suite;
    private KeyShare? _keyShare;
    private byte[]? _masterSecret;
    private ushort _sendSequence;
    private X509Certificate2? _remoteCertificate;
    private SrtpProtectionProfile? _srtpProfile;
    private RecordCipher? _pendingRead;
    private Step _step = settings.Role == DtlsRole.Client ? Step.ServerHello : Step.ClientHello;

    // The last flight sent, kept to send again (RFC 6347 §4.2.4).
    private Flight? _flight;
    private bool _flightTimed;
    private TimeSpan _timeout = settings.InitialRetransmissionTimeout;
    private long _retransmitAt = long.MaxValue;
    private long _handshakeDeadline = long.MaxValue;
    private int _refusedRenegotiation = -1;
    private bool _closeNotifySent;

    // The last unauthenticated message refused, reported if the handshake then runs out of time.
    private DtlsException? _refused;

    private long _datagramsSent;
    private long _datagramsReceived;
    private long _retransmissions;
    private long _applicationSent;
    private long _applicationReceived;
    private long _dropsReported;
    private long _handshakeStarted;
    private TimeSpan? _handshakeDuration;

    // Where the handshake is: the message expected next.
    private enum Step
    {
        ClientHello,
        ServerHello,
        ServerCertificate,
        ServerKeyExchange,
        CertificateRequestOrDone,
        ServerHelloDone,
        ClientCertificate,
        ClientKeyExchange,
        CertificateVerify,
        Finished,
        Done,

        // DTLS 1.3.
        EncryptedExtensions,
        CertificateRequestOrCertificate,
        ServerCertificateVerify,
    }

    // The version the hellos settled on; None until then.
    public DtlsProtocols NegotiatedProtocol => _version;

    public DtlsRole Role => _settings.Role;

    public ProtocolState State { get; private set; }

    // Why the connection failed: a DtlsException, a TimeoutException for a handshake that ran out of
    // time, or what the driver aborted it with.
    public Exception? Error { get; private set; }

    // Whether the peer closed the connection with close_notify.
    public bool ClosedByPeer { get; private set; }

    public TlsCipherSuite NegotiatedCipherSuite => _suite.Suite;

    public SslApplicationProtocol NegotiatedApplicationProtocol { get; private set; }

    public X509Certificate2? RemoteCertificate => _remoteCertificate;

    public SrtpKeyingMaterial? SrtpKeyingMaterial { get; private set; }

    public int MaximumApplicationDataSize =>
        State == ProtocolState.Connected
            ? _records.MaximumDatagram - _records.Overhead(_records.WriteEpoch)
            : 0;

    // Records dropped on the way in: malformed, unauthenticated, replayed or from an unknown epoch.
    public long DroppedRecords => _records.Dropped;

    // When OnTimer should next run, as a TimeProvider timestamp; long.MaxValue when nothing waits.
    public long Deadline =>
        Math.Min(_flightTimed ? _retransmitAt : long.MaxValue, _handshakeDeadline);

    // Starts the handshake: a client sends its ClientHello; a server waits for one.
    public void Start()
    {
        long now = _time.GetTimestamp();
        _handshakeDeadline = now + Ticks(_settings.HandshakeTimeout);
        _handshakeStarted = now;
        LogStarting(Role);
        Guard(() =>
        {
            if (Role == DtlsRole.Client)
            {
                SendClientHello(cookie: []);
            }
        });
    }

    // Opens a datagram from the peer in place and runs the protocol on its records. The application
    // data it carries is left in the datagram; its ranges are added to applicationData.
    public void Receive(Span<byte> datagram, List<Range> applicationData)
    {
        if (State is ProtocolState.Closed or ProtocolState.Failed)
        {
            return;
        }

        try
        {
            _datagramsReceived++;
            RecordDispatcher dispatcher = new(this, applicationData);
            _records.Read(datagram, ref dispatcher);
            ReportDrops();
            if (_records.IntegrityLimitReached)
            {
                Fail(
                    new DtlsException(
                        DtlsAlert.InternalError,
                        isRemote: false,
                        "Too many records failed to authenticate under one key (RFC 9147 §4.5.3)."
                    ),
                    sendAlert: false
                );
                return;
            }

            if (_reassembler.TakePreviousFlightRetransmitted())
            {
                // The peer sent its last flight again whole: it has not seen this side's answer.
                LogAnsweringRetransmission();
                CountRetransmission();
                Transmit(_flight);
            }
        }
        catch (DtlsException error)
        {
            Fail(error, sendAlert: !error.IsRemote);
        }
    }

    // Sends the last flight again when its answer is overdue, and fails the handshake when it has run
    // out of time.
    public void OnTimer()
    {
        if (State is ProtocolState.Closed or ProtocolState.Failed)
        {
            return;
        }

        long now = _time.GetTimestamp();
        if (State == ProtocolState.Handshaking && now >= _handshakeDeadline)
        {
            LogHandshakeTimedOut(_settings.HandshakeTimeout);
            if (_refused is { } refused)
            {
                // What the handshake last refused explains the timeout better than the timeout does.
                Fail(refused, sendAlert: true);
                return;
            }

            Fail(
                new TimeoutException(
                    $"The DTLS handshake did not complete within {_settings.HandshakeTimeout}."
                )
            );
            return;
        }

        if (_flightTimed && now >= _retransmitAt)
        {
            // RFC 6347 §4.2.4.1: double the timer on each retransmission, up to 60 seconds.
            _timeout = TimeSpan.FromTicks(
                Math.Min(_timeout.Ticks * 2, s_maximumRetransmissionTimeout.Ticks)
            );
            LogRetransmitting(_timeout);
            CountRetransmission();
            Guard(() => Transmit(_flight));
            _retransmitAt = now + Ticks(_timeout);
        }
    }

    // Sends application data as one record in one datagram. DTLS keeps datagram boundaries: what is
    // sent here arrives whole or not at all.
    public void Send(ReadOnlySpan<byte> data)
    {
        if (State != ProtocolState.Connected)
        {
            throw Error is not null
                ? new InvalidOperationException("The DTLS connection failed.", Error)
                : new InvalidOperationException(
                    $"Application data is sent once connected; the connection is {State}."
                );
        }

        if (data.Length > MaximumApplicationDataSize)
        {
            throw new ArgumentException(
                $"{data.Length} bytes do not fit one record; at most {MaximumApplicationDataSize} are sent in one datagram.",
                nameof(data)
            );
        }

        _ = _records.Write(ContentType.ApplicationData, _records.WriteEpoch, data);
        _records.Flush();
        _applicationSent++;
    }

    public bool TryDequeue(out OutgoingDatagram datagram)
    {
        if (!_records.TryDequeue(out datagram))
        {
            return false;
        }

        _datagramsSent++;
        return true;
    }

    public DtlsConnectionStatistics Statistics =>
        new(
            _datagramsSent,
            _datagramsReceived,
            _records.Dropped,
            _records.AuthenticationFailures,
            _retransmissions,
            _applicationSent,
            _applicationReceived,
            ApplicationRecordsDropped: 0,
            _handshakeDuration
        );

    // The path MTU changed, as when ICE moves to another candidate pair.
    public int MaximumDatagramSize => _records.MaximumDatagram;

    public void SetMaximumDatagramSize(int size) => _records.SetMaximumDatagram(size);

    // Closes the connection, telling the peer with close_notify.
    public void Close()
    {
        if (State is ProtocolState.Closed or ProtocolState.Failed)
        {
            return;
        }

        SendCloseNotify();
        State = ProtocolState.Closed;
        StopTimers();
        LogClosed(byPeer: false);
    }

    // Fails the connection with an error from outside the protocol: the transport failed, or an
    // application callback threw.
    public void Abort(Exception error) =>
        Fail(
            error,
            alert: error is DtlsException dtls ? dtls.Alert : DtlsAlert.InternalError,
            sendAlert: error is not IOException
        );

    // RFC 5705 keying material exporter.
    public void ExportKeyingMaterial(
        string label,
        ReadOnlySpan<byte> context,
        bool useContext,
        Span<byte> destination
    )
    {
        if (State != ProtocolState.Connected)
        {
            throw new InvalidOperationException("Keying material is exported once connected.");
        }

        if (_version == DtlsProtocols.Dtls13)
        {
            KeySchedule13.Export(
                _suite.PrfHash,
                KeySchedule13.DtlsPrefix,
                _exporterSecret,
                label,
                context,
                destination
            );
            return;
        }

        (byte[] client, byte[] server) = Randoms;
        KeySchedule.Export(
            _suite,
            _masterSecret,
            label,
            client,
            server,
            context,
            useContext,
            destination
        );
    }

    public void Dispose()
    {
        _records.Dispose();
        _transcript.Dispose();
        _keyShare?.Dispose();
        Dispose13();
        _pendingRead?.Dispose();
        _remoteCertificate?.Dispose();
        if (_masterSecret is not null)
        {
            CryptographicOperations.ZeroMemory(_masterSecret);
        }
    }

    private (byte[] Client, byte[] Server) Randoms =>
        Role == DtlsRole.Client ? (_localRandom, _peerRandom!) : (_peerRandom!, _localRandom);

    private void OnRecord(
        ContentType type,
        ushort epoch,
        ulong sequence,
        ReadOnlySpan<byte> payload,
        int offset,
        List<Range> applicationData
    )
    {
        if (State is ProtocolState.Closed or ProtocolState.Failed)
        {
            return;
        }

        // Once connected, only DTLS 1.2's current epoch or DTLS 1.3's traffic epochs are authenticated;
        // what arrives in epoch 0 is read only to recognise the peer retransmitting its last flight.
        bool tls13 = _version == DtlsProtocols.Dtls13;
        bool current = epoch == _records.ReadEpoch;
        bool authenticated = tls13 ? epoch >= HandshakeEpoch : current;
        switch (type)
        {
            case ContentType.Handshake:
                ReceiveHandshake(epoch, sequence, payload);
                break;
            case ContentType.ChangeCipherSpec when current && !tls13:
                ReceiveChangeCipherSpec(payload);
                break;
            case ContentType.Alert when authenticated || State == ProtocolState.Handshaking:
                ReceiveAlert(payload);
                break;
            case ContentType.Ack when tls13:
                ReceiveAck(payload);
                break;
            case ContentType.ApplicationData
                when (tls13 ? epoch >= ApplicationEpoch : current && epoch > 0)
                    && State == ProtocolState.Connected
                    && !payload.IsEmpty:
                applicationData.Add(new Range(offset, offset + payload.Length));
                _applicationReceived++;
                break;
            default:
                // Application data before the handshake completes cannot yet be authenticated as the
                // peer's, and records of a stale epoch are dropped (RFC 6347 §4.1).
                break;
        }
    }

    private void ReceiveHandshake(ushort epoch, ulong recordSequence, ReadOnlySpan<byte> record)
    {
        if (Role == DtlsRole.Server && _step == Step.ClientHello && _settings.CookieExchange)
        {
            ReceiveClientHelloStatelessly(epoch, recordSequence, record);
            return;
        }

        bool encrypted = epoch > 0;
        bool used = false;
        while (HandshakeFragment.TryReadNext(ref record, out HandshakeFragment fragment))
        {
            if (_version == DtlsProtocols.Dtls13)
            {
                // Only the hellos travel unencrypted in DTLS 1.3 (RFC 9147 §6.1).
                bool hello =
                    fragment.Type is HandshakeType.ClientHello or HandshakeType.ServerHello;
                if (hello == encrypted)
                {
                    break;
                }

                // After the handshake, epoch 2 carries only retransmissions of the handshake: a new
                // post-handshake message must come under the application keys (RFC 9147 §6.1).
                if (
                    State == ProtocolState.Connected
                    && epoch < ApplicationEpoch
                    && fragment.MessageSeq >= _reassembler.Next
                )
                {
                    break;
                }
            }
            else
            {
                // The initial DTLS 1.2 handshake sends its Finished messages, and nothing else,
                // encrypted.
                bool finished = fragment.Type == HandshakeType.Finished;
                if (finished != encrypted)
                {
                    if (encrypted && State == ProtocolState.Connected)
                    {
                        RefuseRenegotiation(fragment);
                    }

                    break;
                }
            }

            used |= _reassembler.Add(fragment, authenticated: encrypted);
        }

        while (_reassembler.TryDequeue(out HandshakeMessage message))
        {
            if (_version == DtlsProtocols.Dtls13 && State == ProtocolState.Connected)
            {
                ReceivePostHandshake(message);
                continue;
            }

            if (State != ProtocolState.Handshaking)
            {
                continue;
            }

            if (encrypted)
            {
                Dispatch(message);
            }
            else
            {
                DispatchUnauthenticated(message);
            }
        }

        if (used && encrypted && _version == DtlsProtocols.Dtls13)
        {
            HandshakeRecordReceived(epoch, recordSequence);
        }
    }

    private void Dispatch(HandshakeMessage message)
    {
        if (_version == DtlsProtocols.Dtls13)
        {
            Receive13(message);
        }
        else if (Role == DtlsRole.Client)
        {
            ClientReceive(message);
        }
        else
        {
            ServerReceive(message);
        }
    }

    // A message from unauthenticated records that does not even decode is dropped rather than ending
    // the handshake: anyone can send one. The handshake goes back to where it was, and the peer's
    // retransmission of the genuine message is read again (RFC 6347 §4.1.2.7 applied to messages).
    private void DispatchUnauthenticated(HandshakeMessage message)
    {
        Step step = _step;
        DtlsProtocols version = _version;
        (ushort Read, ushort Write) epochs = (_records.ReadEpoch, _records.WriteEpoch);
        int transcript = _transcript.Length;
        int transcript13 = _transcript13?.Length ?? 0;
        try
        {
            Dispatch(message);
        }
        catch (DtlsException error)
            when (Forgeable(error) && epochs == (_records.ReadEpoch, _records.WriteEpoch))
        {
            _step = step;
            _version = version;
            _transcript.Truncate(transcript);
            _transcript13?.Truncate(transcript13);
            _reassembler.Restart(message.MessageSeq);
            _refused = error;
            LogMessageDropped(message.Type, error.Message);
        }
    }

    // Faults a forged or corrupted copy of a message can cause. The outcomes of a well-formed
    // negotiation (no shared version, suite, group or application protocol, or a certificate refused)
    // still end the handshake at once, as the peer needs to hear.
    private static bool Forgeable(DtlsException error) =>
        error.IsMalformed
        || error.Alert
            is DtlsAlert.DecodeError
                or DtlsAlert.UnexpectedMessage
                or DtlsAlert.IllegalParameter
                or DtlsAlert.DecryptError
                or DtlsAlert.UnsupportedExtension
                or DtlsAlert.MissingExtension;

    // A new handshake on a connected connection is a renegotiation, which Dtls.Core does not do; the
    // peer is told once per message with a no_renegotiation warning (RFC 5746 §4.2).
    private void RefuseRenegotiation(in HandshakeFragment fragment)
    {
        if (
            fragment.Type is not (HandshakeType.ClientHello or HandshakeType.HelloRequest)
            || fragment.MessageSeq < _reassembler.Next
            || fragment.MessageSeq == _refusedRenegotiation
        )
        {
            return;
        }

        _refusedRenegotiation = fragment.MessageSeq;
        LogRenegotiationRefused(fragment.Type);
        SendAlert(DtlsAlert.NoRenegotiation, fatal: false);
    }

    private void ReceiveChangeCipherSpec(ReadOnlySpan<byte> payload)
    {
        // Only where the peer's flight is complete up to its ChangeCipherSpec; one that arrives
        // earlier, out of order, is dropped and comes again with the retransmitted flight.
        if (payload is not [1] || _pendingRead is null || _step != Step.Finished)
        {
            return;
        }

        _records.InstallRead(_pendingRead);
        _pendingRead = null;
        LogReadEpoch(_records.ReadEpoch);
    }

    private void ReceiveAlert(ReadOnlySpan<byte> payload)
    {
        if (payload.Length != 2)
        {
            return;
        }

        DtlsAlert alert = (DtlsAlert)payload[1];
        if (alert == DtlsAlert.CloseNotify)
        {
            // RFC 5246 §7.2.1: answer with a close_notify of this side's own.
            SendCloseNotify();
            ClosedByPeer = true;
            State = ProtocolState.Closed;
            StopTimers();
            LogClosed(byPeer: true);
            return;
        }

        if (payload[0] == FatalLevel)
        {
            Fail(DtlsException.FromPeer(alert), sendAlert: false);
            return;
        }

        LogWarningAlert(alert);
    }

    // Sends a flight and keeps it to send again; a timed flight is sent again when its answer does
    // not come, the last flight of the handshake only when the peer asks by retransmitting.
    private void SendFlight(Flight flight, bool timed)
    {
        _reassembler.FlightAnswered();
        _handshakeRecords.Clear();
        _flight = flight;
        _flightTimed = timed;
        _timeout = _settings.InitialRetransmissionTimeout;
        Transmit(flight);
        _retransmitAt = timed ? _time.GetTimestamp() + Ticks(_timeout) : long.MaxValue;
    }

    private void Transmit(Flight? flight) => flight?.Transmit(_records, _scratch);

    private HandshakeMessage NewMessage(HandshakeType type, Action<WireWriter> encode)
    {
        _scratch.Clear();
        encode(_scratch);
        // message_seq is 16 bits and must not repeat within the association (RFC 9147 §5.2).
        if (_sendSequence == ushort.MaxValue)
        {
            throw new DtlsException(
                DtlsAlert.InternalError,
                isRemote: false,
                "The handshake message sequence number is exhausted."
            );
        }

        return new HandshakeMessage(type, _sendSequence++, _scratch.ToArray());
    }

    private void Connected()
    {
        State = ProtocolState.Connected;
        RecordHandshake("connected");
        _step = Step.Done;
        _handshakeDeadline = long.MaxValue;
        if (Role == DtlsRole.Client && _version != DtlsProtocols.Dtls13)
        {
            // The server's Finished answers the client's last DTLS 1.2 flight; nothing is resent from
            // here. The client's last DTLS 1.3 flight is sent until the server acknowledges it.
            _flightTimed = false;
        }

        if (_srtpProfile is { } profile)
        {
            (int key, int salt) = SrtpKeyingMaterial.Lengths(profile);
            Span<byte> material = stackalloc byte[(2 * key) + (2 * salt)];
            ExportKeyingMaterial(SrtpKeyingMaterial.ExporterLabel, [], useContext: false, material);
            SrtpKeyingMaterial = SrtpKeyingMaterial.Split(profile, material);
            CryptographicOperations.ZeroMemory(material);
        }

        ForgetHandshakeSecrets();
        _keyShare?.Dispose();
        _keyShare = null;
        LogConnected(_suite.Suite, _srtpProfile, _remoteCertificate?.Subject);
    }

    private void SendCloseNotify()
    {
        if (!_closeNotifySent)
        {
            _closeNotifySent = true;
            SendAlert(DtlsAlert.CloseNotify, fatal: false);
        }
    }

    private void SendAlert(DtlsAlert alert, bool fatal)
    {
        ReadOnlySpan<byte> payload = [fatal ? FatalLevel : WarningLevel, (byte)alert];
        _ = _records.Write(ContentType.Alert, _records.WriteEpoch, payload);
        _records.Flush();
    }

    private void Fail(DtlsException error, bool sendAlert) => Fail(error, error.Alert, sendAlert);

    private void Fail(TimeoutException error) =>
        Fail(error, DtlsAlert.HandshakeFailure, sendAlert: false);

    private void Fail(Exception error, DtlsAlert alert, bool sendAlert)
    {
        if (State is ProtocolState.Failed or ProtocolState.Closed)
        {
            return;
        }

        if (sendAlert)
        {
            SendAlert(alert, fatal: true);
        }

        if (State == ProtocolState.Handshaking)
        {
            RecordHandshake(error is TimeoutException ? "timeout" : "failed");
        }

        Error = error;
        State = ProtocolState.Failed;
        StopTimers();
        LogFailed(error, alert, error is DtlsException { IsRemote: true });
    }

    // Runs protocol work; a protocol fault fails the connection with its alert.
    private void Guard(Action work)
    {
        try
        {
            work();
        }
        catch (DtlsException error)
        {
            Fail(error, sendAlert: !error.IsRemote);
        }
    }

    private void CountRetransmission()
    {
        _retransmissions++;
        DtlsMetrics.Retransmissions.Add(1);
    }

    private void ReportDrops()
    {
        long dropped = _records.Dropped - _dropsReported;
        if (dropped > 0)
        {
            _dropsReported = _records.Dropped;
            DtlsMetrics.RecordsDropped.Add(dropped);
        }
    }

    private void RecordHandshake(string outcome)
    {
        TimeSpan duration = _time.GetElapsedTime(_handshakeStarted);
        if (outcome == "connected")
        {
            _handshakeDuration = duration;
        }

        DtlsMetrics.HandshakeDuration.Record(
            duration.TotalSeconds,
            new KeyValuePair<string, object?>(
                "dtls.protocol.version",
                _version == DtlsProtocols.Dtls13 ? "1.3"
                    : _version == DtlsProtocols.Dtls12 ? "1.2"
                    : null
            ),
            new KeyValuePair<string, object?>(
                "dtls.role",
                Role == DtlsRole.Client ? "client" : "server"
            ),
            new KeyValuePair<string, object?>("dtls.handshake.outcome", outcome)
        );
    }

    private void StopTimers()
    {
        _flightTimed = false;
        _retransmitAt = long.MaxValue;
        _handshakeDeadline = long.MaxValue;
    }

    private long Ticks(TimeSpan span) => (long)(span.TotalSeconds * _time.TimestampFrequency);

    // Checks the peer's certificate chain and keeps the certificate.
    private void AcceptRemoteCertificate(CertificateMessage certificate)
    {
        X509Certificate2 accepted = _settings.Validator.Validate(_owner, certificate.Chain);
        _remoteCertificate?.Dispose();
        _remoteCertificate = accepted;
    }

    // Hands the records of a datagram to the protocol without a closure.
    private readonly ref struct RecordDispatcher(DtlsProtocol protocol, List<Range> applicationData)
        : IRecordHandler
    {
        public void OnRecord(
            ContentType type,
            ushort epoch,
            ulong sequence,
            ReadOnlySpan<byte> payload,
            int offset
        ) => protocol.OnRecord(type, epoch, sequence, payload, offset, applicationData);
    }
}
