using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Dtls.NET.Crypto;
using Dtls.NET.Handshake;
using Dtls.NET.Records;

namespace Dtls.NET.Protocol;

// What both sides of a DTLS 1.3 connection share (RFC 9147): the key schedule and its epochs, ACKs,
// and the messages that can arrive after the handshake.
internal sealed partial class DtlsProtocol
{
    // RFC 9147 §6.1: handshake traffic is epoch 2, application traffic epoch 3 and one more for each
    // KeyUpdate. Epoch 1 is early data, which Dtls.NET does not send or accept.
    private const ushort HandshakeEpoch = 2;
    private const ushort ApplicationEpoch = 3;

    private DtlsProtocols _version;
    private Transcript? _transcript13;
    private KeySchedule13? _schedule;
    private KeyShare? _keyShare13;
    private byte[]? _clientHandshakeSecret;
    private byte[]? _serverHandshakeSecret;
    private byte[]? _readTrafficSecret;
    private byte[]? _writeTrafficSecret;
    private byte[]? _exporterSecret;

    // The handshake records received in the peer's current flight, to acknowledge (RFC 9147 §7).
    private readonly List<(ushort Epoch, ulong Sequence)> _handshakeRecords = [];

    // A KeyUpdate this side sent and the peer has not acknowledged yet; the new write keys wait for it
    // (RFC 9147 §8).
    private Flight? _keyUpdate;

    private const string Prefix = KeySchedule13.DtlsPrefix;

    // For tests: updates this side's sending keys, asking the peer to update theirs too.
    internal void RequestKeyUpdate() => SendKeyUpdate(requestUpdate: true);

    private void Receive13(HandshakeMessage message)
    {
        if (Role == DtlsRole.Client)
        {
            ClientReceive13(message);
        }
        else
        {
            ServerReceive13(message);
        }
    }

    // A handshake record was processed: remember it for the ACK, and acknowledge right away what has
    // no other answer: the client's last flight (the server's Finished already answered, so the server
    // is connected by then) and post-handshake messages.
    private void HandshakeRecordReceived(ushort epoch, ulong sequence)
    {
        if (!_handshakeRecords.Contains((epoch, sequence)))
        {
            _handshakeRecords.Add((epoch, sequence));
        }

        if (
            State == ProtocolState.Connected
            && (Role == DtlsRole.Server || epoch >= ApplicationEpoch)
        )
        {
            SendAck();
        }
    }

    private void SendAck()
    {
        if (_handshakeRecords.Count == 0)
        {
            return;
        }

        // As many record numbers as fit one record, the most recent first.
        int room =
            (_records.MaximumDatagram - _records.Overhead(_records.WriteEpoch) - 2)
            / AckMessage.EntrySize;
        List<(ushort Epoch, ulong Sequence)> acknowledged =
            _handshakeRecords.Count <= room ? _handshakeRecords : _handshakeRecords[^room..];
        _ = _records.Write(ContentType.Ack, _records.WriteEpoch, AckMessage.Encode(acknowledged));
        _records.Flush();
        if (State == ProtocolState.Connected && Role == DtlsRole.Client)
        {
            _handshakeRecords.Clear();
        }
    }

    // The peer acknowledged records: the messages in them are not sent again, and a flight whose
    // messages are all acknowledged is done.
    private void ReceiveAck(ReadOnlySpan<byte> payload)
    {
        List<(ushort Epoch, ulong Sequence)> records;
        try
        {
            records = AckMessage.Decode(payload);
        }
        catch (DtlsException)
        {
            // Deliberately not fatal: a malformed ACK is ignored; the flight is sent again on its timer.
            return;
        }

        if (_keyUpdate is { } update)
        {
            update.Acknowledge(records);
            if (update.IsAcknowledged)
            {
                _keyUpdate = null;
                if (ReferenceEquals(_flight, update))
                {
                    _flightTimed = false;
                }

                InstallNextWriteKeys();
            }
        }

        if (_flight is { } flight && !ReferenceEquals(flight, _keyUpdate) && _flightTimed)
        {
            flight.Acknowledge(records);
            if (flight.IsAcknowledged)
            {
                _flightTimed = false;
            }
        }
    }

    // After the handshake: KeyUpdate (RFC 9147 §8) and the server's NewSessionTicket, which Dtls.NET
    // does not resume from and only acknowledges. Anything else is a protocol violation.
    private void ReceivePostHandshake(HandshakeMessage message)
    {
        switch (message.Type)
        {
            case HandshakeType.KeyUpdate:
                if (message.Body is not [0 or 1])
                {
                    throw DtlsException.Decode("a KeyUpdate");
                }

                InstallNextReadKeys();
                if (message.Body[0] == 1 && _keyUpdate is null)
                {
                    SendKeyUpdate(requestUpdate: false);
                }

                return;
            case HandshakeType.NewSessionTicket when Role == DtlsRole.Client:
                return;
            default:
                throw DtlsException.Unexpected($"{message.Type} after the handshake");
        }
    }

    private void SendKeyUpdate(bool requestUpdate)
    {
        if (
            State != ProtocolState.Connected
            || _version != DtlsProtocols.Dtls13
            || _keyUpdate is not null
        )
        {
            return;
        }

        HandshakeMessage update = NewMessage(
            HandshakeType.KeyUpdate,
            w => w.WriteUInt8(requestUpdate ? (byte)1 : (byte)0)
        );
        Flight flight = new();
        flight.AddMessage(_records.WriteEpoch, update);
        _keyUpdate = flight;
        _flight = flight;
        _flightTimed = true;
        _timeout = _settings.InitialRetransmissionTimeout;
        Transmit(flight);
        _retransmitAt = _time.GetTimestamp() + Ticks(_timeout);
    }

    private void InstallNextReadKeys()
    {
        byte[] next = KeySchedule13.NextTrafficSecret(_suite.PrfHash, Prefix, _readTrafficSecret);
        CryptographicOperations.ZeroMemory(_readTrafficSecret);
        _readTrafficSecret = next;
        ushort epoch = checked((ushort)(_records.ReadEpoch + 1));
        _records.InstallRead(epoch, Cipher(next));
        LogReadEpoch(epoch);
    }

    private void InstallNextWriteKeys()
    {
        byte[] next = KeySchedule13.NextTrafficSecret(_suite.PrfHash, Prefix, _writeTrafficSecret);
        CryptographicOperations.ZeroMemory(_writeTrafficSecret);
        _writeTrafficSecret = next;
        _records.InstallWrite(checked((ushort)(_records.WriteEpoch + 1)), Cipher(next));
    }

    private RecordCipher13 Cipher(ReadOnlySpan<byte> trafficSecret)
    {
        using TrafficKeys keys = KeySchedule13.Keys(_suite, Prefix, trafficSecret);
        return new RecordCipher13(_suite, keys);
    }

    // The handshake secrets once the ECDHE secret is known, from the transcript through the
    // ServerHello; epoch 2 opens in both directions.
    private void DeriveHandshakeSecrets(ReadOnlySpan<byte> sharedSecret)
    {
        _schedule = new KeySchedule13(_suite.PrfHash);
        _schedule.Advance(sharedSecret);
        byte[] transcript = _transcript13!.Hash(_suite.PrfHash);
        _clientHandshakeSecret = _schedule.DeriveSecret("c hs traffic", transcript);
        _serverHandshakeSecret = _schedule.DeriveSecret("s hs traffic", transcript);
        bool client = Role == DtlsRole.Client;
        _records.InstallRead(
            HandshakeEpoch,
            Cipher(client ? _serverHandshakeSecret : _clientHandshakeSecret)
        );
        _records.InstallWrite(
            HandshakeEpoch,
            Cipher(client ? _clientHandshakeSecret : _serverHandshakeSecret)
        );
    }

    // The application secrets from the transcript through the server's Finished (RFC 8446 §7.1). The
    // read keys of epoch 3 open now; the write keys wait until this side may send application data.
    private void DeriveApplicationSecrets()
    {
        _schedule!.Advance([]);
        byte[] transcript = _transcript13!.Hash(_suite.PrfHash);
        byte[] client = _schedule.DeriveSecret("c ap traffic", transcript);
        byte[] server = _schedule.DeriveSecret("s ap traffic", transcript);
        _exporterSecret = _schedule.DeriveSecret("exp master", transcript);
        bool isClient = Role == DtlsRole.Client;
        _readTrafficSecret = isClient ? server : client;
        _writeTrafficSecret = isClient ? client : server;
        _records.InstallRead(ApplicationEpoch, Cipher(_readTrafficSecret));
    }

    private void InstallApplicationWriteKeys() =>
        _records.InstallWrite(ApplicationEpoch, Cipher(_writeTrafficSecret));

    // A Finished over the transcript so far, with the sender's handshake secret.
    private byte[] VerifyData13(bool fromClient) =>
        KeySchedule13.VerifyData(
            _suite.PrfHash,
            Prefix,
            fromClient ? _clientHandshakeSecret : _serverHandshakeSecret,
            _transcript13!.Hash(_suite.PrfHash)
        );

    private void ReceiveFinished13(HandshakeMessage message, bool fromClient)
    {
        byte[] expected = VerifyData13(fromClient);
        if (!CryptographicOperations.FixedTimeEquals(expected, message.Body))
        {
            throw DtlsException.DecryptError("the peer's Finished does not match the handshake");
        }

        _transcript13!.Add13(message.Type, message.Body);
    }

    private HandshakeMessage FinishedMessage13(bool fromClient)
    {
        byte[] verifyData = VerifyData13(fromClient);
        HandshakeMessage finished = NewMessage(
            HandshakeType.Finished,
            w => w.WriteBytes(verifyData)
        );
        _transcript13!.Add13(finished.Type, finished.Body);
        return finished;
    }

    // CertificateVerify over the transcript through the Certificate.
    private HandshakeMessage CertificateVerifyMessage13(
        LocalCredential credential,
        SignatureScheme scheme
    )
    {
        byte[] content = Messages13.SignedContent(
            Role == DtlsRole.Server,
            _transcript13!.Hash(_suite.PrfHash)
        );
        byte[] signature = Signatures.Sign(credential, scheme, content);
        HandshakeMessage verify = NewMessage(
            HandshakeType.CertificateVerify,
            new CertificateVerify(scheme, signature).Encode
        );
        _transcript13.Add13(verify.Type, verify.Body);
        return verify;
    }

    private void ReceiveCertificateVerify13(HandshakeMessage message, bool fromServer)
    {
        CertificateVerify verify = CertificateVerify.Decode(message.Body);
        byte[] content = Messages13.SignedContent(fromServer, _transcript13!.Hash(_suite.PrfHash));
        if (!Signatures.Verify13(_remoteCertificate!, verify.Scheme, content, verify.Signature))
        {
            throw DtlsException.DecryptError(
                $"the {(fromServer ? "server" : "client")}'s CertificateVerify"
            );
        }

        _transcript13.Add13(message.Type, message.Body);
    }

    private void AcceptRemoteCertificate(Certificate13 certificate)
    {
        X509Certificate2 accepted = _settings.Validator.Validate(_owner, certificate.Chain);
        _remoteCertificate?.Dispose();
        _remoteCertificate = accepted;
    }

    // use_srtp and ALPN as the server's EncryptedExtensions carry them (the DTLS 1.2 checks apply).
    private Extensions NegotiatedExtensions()
    {
        Extensions extensions = new();
        if (_srtpProfile is { } profile)
        {
            _ = extensions.Add(ExtensionType.UseSrtp, HelloExtensions.UseSrtp([profile]));
        }

        if (NegotiatedApplicationProtocol != default)
        {
            _ = extensions.Add(
                ExtensionType.ApplicationLayerProtocolNegotiation,
                HelloExtensions.ApplicationProtocols([NegotiatedApplicationProtocol])
            );
        }

        return extensions;
    }

    private void Dispose13()
    {
        _transcript13?.Dispose();
        _schedule?.Dispose();
        _keyShare13?.Dispose();
        foreach (
            byte[]? secret in (byte[]?[])
                [
                    _clientHandshakeSecret,
                    _serverHandshakeSecret,
                    _readTrafficSecret,
                    _writeTrafficSecret,
                    _exporterSecret,
                ]
        )
        {
            if (secret is not null)
            {
                CryptographicOperations.ZeroMemory(secret);
            }
        }
    }
}
