using System.Security.Cryptography;
using Dtls.Core.Handshake;
using Dtls.Core.Wire;

namespace Dtls.Core.Protocol;

// DTLS 1.3 connection ID management after the handshake (RFC 9147 §9): NewConnectionId gives the peer CIDs
// to put in the records it sends, to use at once or keep as spares; RequestConnectionId asks the peer for
// spares. An endpoint SHOULD use a new CID on a new path, so it keeps the peer's spares to switch to.
//
// Each message is a post-handshake flight the peer acknowledges (RFC 9147 §7), retransmitted until it
// is. Only one such flight is out at a time: one NewConnectionId outstanding at most, and a KeyUpdate or
// a CID message that comes up meanwhile waits its turn.
internal sealed partial class DtlsProtocol
{
    private const byte CidImmediate = 0;
    private const byte CidSpare = 1;

    // The peer's spare CIDs kept; extras are discarded, which RFC 9147 §9 allows.
    private const int MaximumSpareCids = 8;

    // The CIDs this side gives out over a connection; requests beyond it are answered with fewer, down
    // to none, as RFC 9147 §9 allows.
    private const int MaximumCidsIssued = 64;

    // The requests this side answers before treating more as excessive and closing the connection.
    private const int MaximumCidRequests = 128;

    private readonly Queue<byte[]> _spareRemoteCids = new();
    private readonly Queue<Action> _postHandshakeWaiting = new();
    private Flight? _cidFlight;
    private bool _cidRequestOutstanding;
    private int _cidsIssued;
    private int _cidRequests;

    // The peer's CIDs this side can switch to.
    public int SpareConnectionIds => _spareRemoteCids.Count;

    // Gives the peer more CIDs for its records: spares, or one to use at once and the rest spares.
    public void IssueConnectionIds(int count, bool immediate)
    {
        RequireCidManagement();
        if (LocalConnectionId.Length == 0)
        {
            throw new InvalidOperationException(
                "This side receives no connection ID, so it has none to give (RFC 9147 §9)."
            );
        }

        ArgumentOutOfRangeException.ThrowIfLessThan(count, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(count, MaximumSpareCids);
        RunPostHandshake(() => SendNewConnectionId(count, immediate));
    }

    // Asks the peer for spare CIDs; one request at a time.
    public void RequestConnectionIds(int count)
    {
        RequireCidManagement();
        if (RemoteConnectionId.Length == 0)
        {
            throw new InvalidOperationException(
                "This side sends no connection ID, so it may not ask for more (RFC 9147 §9)."
            );
        }

        ArgumentOutOfRangeException.ThrowIfLessThan(count, 1);
        ArgumentOutOfRangeException.ThrowIfGreaterThan(count, byte.MaxValue);
        if (_cidRequestOutstanding)
        {
            throw new InvalidOperationException(
                "A request for connection IDs is still unanswered (RFC 9147 §9)."
            );
        }

        _cidRequestOutstanding = true;
        RunPostHandshake(() =>
            SendPostHandshake(
                NewMessage(HandshakeType.RequestConnectionId, w => w.WriteUInt8((byte)count))
            )
        );
    }

    // Switches the CID this side's records carry to the peer's next spare, as on a new path.
    public bool TryUseNextConnectionId()
    {
        if (!_spareRemoteCids.TryDequeue(out byte[]? next))
        {
            return false;
        }

        RemoteConnectionId = next;
        _records.UseSendConnectionId(next);
        return true;
    }

    private void RequireCidManagement()
    {
        if (State != ProtocolState.Connected || _version != DtlsProtocols.Dtls13 || !_cidAgreed)
        {
            throw new InvalidOperationException(
                "Connection IDs are managed only on a connected DTLS 1.3 association that agreed on them."
            );
        }
    }

    private void SendNewConnectionId(int count, bool immediate)
    {
        List<byte[]> cids = [];
        for (int i = 0; i < count; i++)
        {
            byte[] cid = RandomNumberGenerator.GetBytes(LocalConnectionId.Length);
            _records.AcceptConnectionId(cid);
            cids.Add(cid);
        }

        _cidsIssued += count;
        SendPostHandshake(
            NewMessage(
                HandshakeType.NewConnectionId,
                w =>
                {
                    WireWriter.Vector list = w.BeginVector16();
                    foreach (byte[] cid in cids)
                    {
                        w.WriteVector8(cid);
                    }

                    list.End();
                    w.WriteUInt8(immediate ? CidImmediate : CidSpare);
                }
            )
        );
    }

    private void ReceiveNewConnectionId(byte[] body)
    {
        // Only a side that receives a non-empty CID may give more of them out.
        if (!_cidAgreed || RemoteConnectionId.Length == 0)
        {
            throw DtlsException.Unexpected("NewConnectionId without a connection ID agreed");
        }

        WireReader reader = new(body);
        WireReader list = new(reader.ReadVector16());
        byte usage = reader.ReadUInt8();
        reader.ExpectEnd();
        List<byte[]> cids = [];
        while (!list.IsEmpty)
        {
            cids.Add(list.ReadVector8().ToArray());
        }

        if (usage is not (CidImmediate or CidSpare) || (usage == CidImmediate && cids.Count == 0))
        {
            throw DtlsException.IllegalParameter("a NewConnectionId");
        }

        _cidRequestOutstanding = false;
        int first = 0;
        if (usage == CidImmediate)
        {
            RemoteConnectionId = cids[0];
            _records.UseSendConnectionId(cids[0]);
            first = 1;
        }

        for (int i = first; i < cids.Count && _spareRemoteCids.Count < MaximumSpareCids; i++)
        {
            _spareRemoteCids.Enqueue(cids[i]);
        }
    }

    private void ReceiveRequestConnectionId(byte[] body)
    {
        // Only a side that sends a non-empty CID may ask for more.
        if (!_cidAgreed || LocalConnectionId.Length == 0)
        {
            throw DtlsException.Unexpected("RequestConnectionId without a connection ID agreed");
        }

        if (body is not [var count])
        {
            throw DtlsException.Decode("a RequestConnectionId");
        }

        if (++_cidRequests > MaximumCidRequests)
        {
            throw new DtlsException(
                DtlsAlert.TooManyCidsRequested,
                isRemote: false,
                $"The peer asked for connection IDs {_cidRequests} times."
            );
        }

        // Always answered, with fewer or none when the request is excessive, which fulfils it and lets
        // the peer ask again.
        RunPostHandshake(() =>
            SendNewConnectionId(
                Math.Min(Math.Min((int)count, MaximumSpareCids), MaximumCidsIssued - _cidsIssued),
                immediate: false
            )
        );
    }

    // Whether a flight is out and unacknowledged: a KeyUpdate, a CID message, or the client's last
    // handshake flight, which nothing may replace before the server acknowledges it.
    private bool PostHandshakeBusy =>
        _keyUpdate is not null || _cidFlight is not null || _flightTimed;

    // A post-handshake flight goes now when none is out, else after the one that is.
    private void RunPostHandshake(Action send)
    {
        if (!PostHandshakeBusy)
        {
            send();
        }
        else
        {
            _postHandshakeWaiting.Enqueue(send);
        }
    }

    private void SendPostHandshake(HandshakeMessage message)
    {
        Flight flight = new();
        flight.AddMessage(_records.WriteEpoch, message);
        _cidFlight = flight;
        _flight = flight;
        _flightTimed = true;
        _timeout = _settings.InitialRetransmissionTimeout;
        Transmit(flight);
        _retransmitAt = _time.GetTimestamp() + Ticks(_timeout);
    }

    // The peer acknowledged records: a CID flight they complete is done.
    private void AcknowledgeConnectionIdFlight(List<(ushort Epoch, ulong Sequence)> records)
    {
        if (_cidFlight is { } flight)
        {
            flight.Acknowledge(records);
            if (flight.IsAcknowledged)
            {
                _cidFlight = null;
                if (ReferenceEquals(_flight, flight))
                {
                    _flightTimed = false;
                }
            }
        }
    }

    // Once nothing is out, the next waiting post-handshake flight goes.
    private void SendWaitingPostHandshake()
    {
        while (!PostHandshakeBusy && _postHandshakeWaiting.TryDequeue(out Action? next))
        {
            next();
        }
    }
}
