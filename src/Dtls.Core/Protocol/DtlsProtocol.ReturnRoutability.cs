using System.Security.Cryptography;
using Dtls.Core.Handshake;
using Dtls.Core.Records;

namespace Dtls.Core.Protocol;

// The return routability check (draft-ietf-tls-dtls-rrc-20). With connection IDs the peer's records are
// recognised from any address, and RFC 9146 section 6 lets this side send to a new one only once
// something shows that address receives. RRC is that something: a path_challenge to the new address,
// answered by a path_response that echoes its cookie. This side runs the basic check of section 5.1;
// it never moves voluntarily, so it answers every challenge with path_response.
internal sealed partial class DtlsProtocol
{
    private const byte PathChallenge = 0;
    private const byte PathResponse = 1;
    private const int PathCookieLength = 8;

    // Section 5.5: T is one second when nothing tells the RTT of the path in use.
    private static readonly TimeSpan s_pathValidationTimeout = TimeSpan.FromSeconds(1);

    private bool _rrcOffered;
    private byte[]? _pathCookie;
    private long _pathDeadline = long.MaxValue;
    private bool _pathValidated;

    // Whether both sides offered rrc, with connection IDs agreed (section 3).
    public bool ReturnRoutabilityCheckAgreed { get; private set; }

    // Starts validating the address the last datagram came from; nothing while a check is under way,
    // as section 5 does not handle a rebinding during one. The challenge goes out with the datagrams
    // for the sender (TryDequeueToSender).
    public bool ChallengePath()
    {
        if (
            !ReturnRoutabilityCheckAgreed
            || State != ProtocolState.Connected
            || _pathCookie is not null
        )
        {
            return false;
        }

        _pathCookie = RandomNumberGenerator.GetBytes(PathCookieLength);
        _pathDeadline = _time.GetTimestamp() + Ticks(s_pathValidationTimeout);
        Guard(() => SendReturnRoutability(PathChallenge, _pathCookie));
        LogPathChallenged();
        return true;
    }

    // Whether the last datagram answered the challenge: the peer may be followed to where it came from.
    public bool TakePathValidated()
    {
        bool validated = _pathValidated;
        _pathValidated = false;
        return validated;
    }

    // The datagrams that go back to where the last received one came from.
    public bool TryDequeueToSender(out OutgoingDatagram datagram)
    {
        if (!_records.TryDequeueToSender(out datagram))
        {
            return false;
        }

        _datagramsSent++;
        return true;
    }

    private void ReceiveReturnRoutability(ReadOnlySpan<byte> payload)
    {
        // Section 4: path_challenge, path_response and path_drop carry an 8-byte cookie; a message type
        // this side does not know is ignored.
        if (payload.Length != 1 + PathCookieLength)
        {
            return;
        }

        ReadOnlySpan<byte> cookie = payload[1..];
        switch (payload[0])
        {
            case PathChallenge:
                // Section 5.4: answered at once, exactly once, to the address the challenge came from.
                SendReturnRoutability(PathResponse, cookie);
                break;
            case PathResponse
                when _pathCookie is { } sent
                    && CryptographicOperations.FixedTimeEquals(sent, cookie):
                _pathCookie = null;
                _pathDeadline = long.MaxValue;
                _pathValidated = true;
                LogPathValidated();
                break;
            default:
                // A response to no challenge of this side's, a path_drop (the basic check never
                // challenges the old path) or an unknown type: discarded silently (section 5.4).
                break;
        }
    }

    private void SendReturnRoutability(byte type, ReadOnlySpan<byte> cookie)
    {
        // Section 4: protected with the current keys, in a datagram of its own for the sender.
        _records.Flush();
        _ = _records.Write(
            ContentType.ReturnRoutabilityCheck,
            _records.WriteEpoch,
            [type, .. cookie]
        );
        _records.FlushToSender();
    }

    // Section 5.1 step 5: an unanswered challenge leaves the peer where it was.
    private void ExpirePathValidation(long now)
    {
        if (_pathCookie is not null && now >= _pathDeadline)
        {
            _pathCookie = null;
            _pathDeadline = long.MaxValue;
            LogPathNotValidated(s_pathValidationTimeout);
        }
    }

    // Client: rrc goes with connection_id when this side validates new addresses by RRC (section 3).
    private void OfferReturnRoutability(Extensions extensions)
    {
        if (OffersReturnRoutability)
        {
            _ = extensions.Add(ExtensionType.ReturnRoutabilityCheck, []);
        }
    }

    private bool OffersReturnRoutability =>
        _localConnectionId is not null
        && _settings.PeerAddressValidation == DtlsPeerAddressValidation.ReturnRoutabilityCheck;

    // Client: the server's answer agrees on RRC; it takes connection IDs agreed as well.
    private void AcceptReturnRoutability(Extensions extensions)
    {
        if (
            extensions.TryGet(ExtensionType.ReturnRoutabilityCheck, out ReadOnlySpan<byte> data)
            && !data.IsEmpty
        )
        {
            throw DtlsException.Decode("the rrc extension, which is empty");
        }

        ReturnRoutabilityCheckAgreed =
            OffersReturnRoutability
            && _cidAgreed
            && extensions.Contains(ExtensionType.ReturnRoutabilityCheck);
    }

    // Server: what the client offered.
    private void SelectReturnRoutability(Extensions extensions)
    {
        if (
            extensions.TryGet(ExtensionType.ReturnRoutabilityCheck, out ReadOnlySpan<byte> data)
            && !data.IsEmpty
        )
        {
            throw DtlsException.Decode("the rrc extension, which is empty");
        }

        _rrcOffered = extensions.Contains(ExtensionType.ReturnRoutabilityCheck);
    }

    // Server: rrc in the ServerHello only for a client that offered it with connection IDs agreed
    // (section 3), when this side validates new addresses by RRC.
    private void AnswerReturnRoutability(Extensions extensions)
    {
        if (
            _rrcOffered
            && _cidAgreed
            && _settings.PeerAddressValidation == DtlsPeerAddressValidation.ReturnRoutabilityCheck
        )
        {
            _ = extensions.Add(ExtensionType.ReturnRoutabilityCheck, []);
            ReturnRoutabilityCheckAgreed = true;
        }
    }
}
