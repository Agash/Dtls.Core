using System.Buffers.Binary;
using Dtls.NET.Records;
using Dtls.NET.Wire;

namespace Dtls.NET.Handshake;

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
    public bool Add(in HandshakeFragment fragment)
    {
        if (fragment.MessageSeq < Next)
        {
            if (
                _previousFlight.TryGetValue(fragment.MessageSeq, out Assembly? previous)
                && previous.Matches(fragment)
            )
            {
                previous.Fill(fragment.Offset, fragment.Body, keep: false);
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
            return false;
        }

        partial.Fill(fragment.Offset, fragment.Body, keep: true);
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

        public void Fill(int offset, ReadOnlySpan<byte> bytes, bool keep)
        {
            if (keep)
            {
                bytes.CopyTo(Body.AsSpan(offset));
            }

            Span<bool> have = _have.AsSpan(offset, bytes.Length);
            for (int i = 0; i < have.Length; i++)
            {
                if (!have[i])
                {
                    have[i] = true;
                    _missing--;
                }
            }
        }

        public void Reset()
        {
            Array.Clear(_have);
            _missing = Length;
        }
    }
}

// One flight of this side's handshake (RFC 6347 §4.2.4): its messages and ChangeCipherSpec, kept so
// the whole flight can be sent again when the peer's answer does not come. Every transmission is
// fragmented to fit the path's MTU in its epoch, and uses new record sequence numbers.
internal sealed class Flight
{
    private readonly List<Entry> _entries = [];

    public bool IsEmpty => _entries.Count == 0;

    public void AddMessage(ushort epoch, HandshakeMessage message) =>
        _entries.Add(new Entry(epoch, message));

    public void AddChangeCipherSpec(ushort epoch) => _entries.Add(new Entry(epoch, null));

    public void Transmit(RecordLayer records, WireWriter scratch)
    {
        foreach (Entry entry in _entries)
        {
            if (entry.Message is not { } message)
            {
                records.Write(ContentType.ChangeCipherSpec, entry.Epoch, [1]);
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
                records.Write(ContentType.Handshake, entry.Epoch, scratch.Written);
                offset += count;
            } while (offset < message.Body.Length);
        }

        records.Flush();
    }

    private readonly record struct Entry(ushort Epoch, HandshakeMessage? Message);
}
