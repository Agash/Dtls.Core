using System.Buffers.Binary;
using Dtls.Core.Records;
using Dtls.Core.Wire;

namespace Dtls.Core.Handshake;

// A handshake message fragment as a record carries it (RFC 6347 §4.2.2): type, total length,
// message_seq, and which bytes of the body this fragment holds. The body is a view of the record.
internal readonly ref struct HandshakeFragment(
    HandshakeType type,
    int length,
    ushort messageSeq,
    int offset,
    ReadOnlySpan<byte> body
)
{
    public const int HeaderSize = 12;

    public HandshakeType Type { get; } = type;

    public int Length { get; } = length;

    public ushort MessageSeq { get; } = messageSeq;

    public int Offset { get; } = offset;

    public ReadOnlySpan<byte> Body { get; } = body;

    // Whether this fragment is the whole message.
    public bool IsWhole => Offset == 0 && Body.Length == Length;

    // Reads the next fragment of a handshake record. A fragment that is truncated or runs past its
    // message ends the record: it is ignored with the rest of it, not treated as fatal, because
    // unencrypted handshake records are not authenticated and a forged one must not end the handshake.
    public static bool TryReadNext(ref ReadOnlySpan<byte> record, out HandshakeFragment fragment)
    {
        fragment = default;
        if (record.Length < HeaderSize)
        {
            return false;
        }

        int length = ReadUInt24(record[1..]);
        ushort sequence = BinaryPrimitives.ReadUInt16BigEndian(record[4..]);
        int offset = ReadUInt24(record[6..]);
        int count = ReadUInt24(record[9..]);
        if (count > record.Length - HeaderSize || offset + count > length)
        {
            return false;
        }

        fragment = new HandshakeFragment(
            (HandshakeType)record[0],
            length,
            sequence,
            offset,
            record.Slice(HeaderSize, count)
        );
        record = record[(HeaderSize + count)..];
        return true;
    }

    public static void WriteHeader(
        WireWriter writer,
        HandshakeType type,
        int length,
        ushort sequence,
        int offset,
        int count
    )
    {
        writer.WriteUInt8((byte)type);
        writer.WriteUInt24(length);
        writer.WriteUInt16(sequence);
        writer.WriteUInt24(offset);
        writer.WriteUInt24(count);
    }

    private static int ReadUInt24(ReadOnlySpan<byte> bytes) =>
        (bytes[0] << 16) | (bytes[1] << 8) | bytes[2];
}

// A complete handshake message, reassembled.
internal readonly record struct HandshakeMessage(
    HandshakeType Type,
    ushort MessageSeq,
    byte[] Body
);

// Puts received fragments back together and hands out whole messages in message_seq order (RFC 6347
// §4.2.3). Fragments may arrive in any order, overlap or repeat. Messages beyond a small window ahead
// are ignored rather than buffered, and none may exceed the size limit, so a peer cannot make this
// hold unbounded memory.
//
// It also recognises the peer retransmitting: when this side has answered a flight and the whole of
// that flight arrives again, the peer lost the answer and it is sent again. Only a complete
// retransmission counts, never a stray fragment, so a forged or duplicated datagram cannot make this
// side resend (the rule BouncyCastle's DTLS implementation uses).
internal sealed class HandshakeReassembler(int maximumMessage)
{
    private const int Window = 8;

    private readonly Dictionary<ushort, Assembly> _partial = [];
    private readonly Queue<HandshakeMessage> _complete = [];
    private readonly List<(ushort Sequence, HandshakeType Type, int Length)> _delivered = [];
    private readonly Dictionary<ushort, Assembly> _previousFlight = [];
    private bool _previousFlightSeen;

    public ushort Next { get; private set; }

    // Starts reading at a message_seq, as a server does from the ClientHello that carried its cookie.
    public void Restart(ushort next)
    {
        _partial.Clear();
        _complete.Clear();
        _delivered.Clear();
        _previousFlight.Clear();
        Next = next;
    }

    // Adds a fragment; false when it is not one the handshake can use (ahead of the window, or not
    // matching what earlier fragments of its message said).
    // A fragment from an authenticated record that breaks the rules is a protocol error; one from an
    // unauthenticated record is ignored, so a forged datagram cannot end the handshake.
    public bool Add(in HandshakeFragment fragment, bool authenticated)
    {
        if (fragment.MessageSeq < Next)
        {
            if (
                _previousFlight.TryGetValue(fragment.MessageSeq, out Assembly? previous)
                && previous.Matches(fragment)
            )
            {
                _ = previous.Fill(fragment.Offset, fragment.Body, keep: false);
                _previousFlightSeen = true;
            }

            return true;
        }

        if (fragment.MessageSeq >= Next + Window)
        {
            return false;
        }

        if (fragment.Length > maximumMessage)
        {
            if (!authenticated)
            {
                return false;
            }

            throw new DtlsException(
                DtlsAlert.HandshakeFailure,
                isRemote: false,
                $"A {fragment.Length}-byte handshake message exceeds the {maximumMessage}-byte limit."
            );
        }

        if (!_partial.TryGetValue(fragment.MessageSeq, out Assembly? partial))
        {
            partial = new Assembly(fragment.Type, fragment.Length, keep: true);
            _partial.Add(fragment.MessageSeq, partial);
        }
        else if (!partial.Matches(fragment))
        {
            if (authenticated || partial.IsComplete)
            {
                return false;
            }

            // Two unauthenticated fragments disagree on the message: either may be forged. The newer
            // one replaces the incomplete older one, so a forgery cannot hold the slot for good; the
            // genuine message wins once the peer retransmits it.
            partial = new Assembly(fragment.Type, fragment.Length, keep: true);
            _partial[fragment.MessageSeq] = partial;
        }

        if (!partial.Fill(fragment.Offset, fragment.Body, keep: true))
        {
            // RFC 9147 §5.5: a retransmission may split a message differently but must not change it.
            if (authenticated)
            {
                throw DtlsException.IllegalParameter(
                    "a handshake fragment contradicts an earlier one"
                );
            }

            // Unauthenticated, either may be the forgery: the newer starts the message over, as for a
            // mismatched type or length.
            partial = new Assembly(fragment.Type, fragment.Length, keep: true);
            _partial[fragment.MessageSeq] = partial;
            _ = partial.Fill(fragment.Offset, fragment.Body, keep: true);
        }

        while (_partial.TryGetValue(Next, out Assembly? next) && next.IsComplete)
        {
            _ = _partial.Remove(Next);
            _complete.Enqueue(new HandshakeMessage(next.Type, Next, next.Body!));
            _delivered.Add((Next, next.Type, next.Length));
            Next++;
        }

        return true;
    }

    public bool TryDequeue(out HandshakeMessage message) => _complete.TryDequeue(out message);

    // This side answered the flight delivered so far: from now on, a complete retransmission of that
    // flight means the answer was lost.
    public void FlightAnswered()
    {
        _previousFlight.Clear();
        foreach ((ushort sequence, HandshakeType type, int length) in _delivered)
        {
            _previousFlight[sequence] = new Assembly(type, length, keep: false);
        }

        _delivered.Clear();
        _previousFlightSeen = false;
    }

    // Whether the peer has sent the whole answered flight again since the last call; the coverage
    // starts over, so the next complete retransmission is recognised too.
    public bool TakePreviousFlightRetransmitted()
    {
        if (!_previousFlightSeen)
        {
            return false;
        }

        _previousFlightSeen = false;
        foreach (Assembly assembly in _previousFlight.Values)
        {
            if (!assembly.IsComplete)
            {
                return false;
            }
        }

        foreach (Assembly assembly in _previousFlight.Values)
        {
            assembly.Reset();
        }

        return _previousFlight.Count > 0;
    }

    // Which bytes of a message have arrived, and (for a message still to be delivered) the bytes.
    private sealed class Assembly(HandshakeType type, int length, bool keep)
    {
        private readonly bool[] _have = new bool[length];
        private int _missing = length;

        public HandshakeType Type { get; } = type;

        public int Length { get; } = length;

        public byte[]? Body { get; } = keep ? new byte[length] : null;

        public bool IsComplete => _missing == 0;

        public bool Matches(in HandshakeFragment fragment) =>
            fragment.Type == Type && fragment.Length == Length;

        // Adds bytes; false, adding nothing, when they differ from bytes already received there.
        public bool Fill(int offset, ReadOnlySpan<byte> bytes, bool keep)
        {
            Span<bool> have = _have.AsSpan(offset, bytes.Length);
            if (keep)
            {
                Span<byte> body = Body.AsSpan(offset, bytes.Length);
                for (int i = 0; i < have.Length; i++)
                {
                    if (have[i] && body[i] != bytes[i])
                    {
                        return false;
                    }
                }

                bytes.CopyTo(body);
            }

            for (int i = 0; i < have.Length; i++)
            {
                if (!have[i])
                {
                    have[i] = true;
                    _missing--;
                }
            }

            return true;
        }

        public void Reset()
        {
            Array.Clear(_have);
            _missing = Length;
        }
    }
}

// One flight of this side's handshake (RFC 6347 §4.2.4, RFC 9147 §5.8): its messages (and in DTLS 1.2
// its ChangeCipherSpec), kept so the flight can be sent again when the peer's answer does not come.
// Every transmission is fragmented to fit the path's MTU in its epoch and uses new record sequence
// numbers. In DTLS 1.3 the peer acknowledges records (RFC 9147 §7): a message whose records of its
// latest transmission have all been acknowledged is not sent again.
internal sealed class Flight
{
    private readonly List<Entry> _entries = [];
    private readonly HashSet<(ushort Epoch, ulong Sequence)> _acknowledged = [];

    public bool IsEmpty => _entries.Count == 0;

    // Whether every message of the flight has been acknowledged.
    public bool IsAcknowledged => _entries.TrueForAll(static e => e.Acknowledged);

    public void AddMessage(ushort epoch, HandshakeMessage message) =>
        _entries.Add(new Entry(epoch, message));

    public void AddChangeCipherSpec(ushort epoch) => _entries.Add(new Entry(epoch, null));

    public void Acknowledge(IEnumerable<(ushort Epoch, ulong Sequence)> records)
    {
        _acknowledged.UnionWith(records);
        foreach (Entry entry in _entries)
        {
            entry.Acknowledged |=
                entry.Records.Count > 0 && entry.Records.TrueForAll(_acknowledged.Contains);
        }
    }

    public void Transmit(RecordLayer records, WireWriter scratch)
    {
        foreach (Entry entry in _entries)
        {
            if (entry.Acknowledged)
            {
                continue;
            }

            entry.Records.Clear();
            if (entry.Message is not { } message)
            {
                entry.Records.Add(
                    (entry.Epoch, records.Write(ContentType.ChangeCipherSpec, entry.Epoch, [1]))
                );
                continue;
            }

            int room =
                records.MaximumDatagram
                - records.Overhead(entry.Epoch)
                - HandshakeFragment.HeaderSize;
            if (room <= 0)
            {
                throw new InvalidOperationException(
                    "The datagram limit leaves no room for a handshake fragment."
                );
            }

            int offset = 0;
            do
            {
                int count = Math.Min(room, message.Body.Length - offset);
                scratch.Clear();
                HandshakeFragment.WriteHeader(
                    scratch,
                    message.Type,
                    message.Body.Length,
                    message.MessageSeq,
                    offset,
                    count
                );
                scratch.WriteBytes(message.Body.AsSpan(offset, count));
                entry.Records.Add(
                    (
                        entry.Epoch,
                        records.Write(ContentType.Handshake, entry.Epoch, scratch.Written)
                    )
                );
                offset += count;
            } while (offset < message.Body.Length);
        }

        records.Flush();
    }

    private sealed class Entry(ushort epoch, HandshakeMessage? message)
    {
        public ushort Epoch { get; } = epoch;

        public HandshakeMessage? Message { get; } = message;

        // The records of the latest transmission.
        public List<(ushort Epoch, ulong Sequence)> Records { get; } = [];

        public bool Acknowledged { get; set; }
    }
}
