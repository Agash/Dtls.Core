using System.Buffers;
using System.Buffers.Binary;

namespace Dtls.NET.Records;

// Receives the records of a datagram as they are opened. A record is opened in place: its payload is
// the slice of the datagram at offset, and stays there as long as the datagram's buffer does.
internal interface IRecordHandler
{
    void OnRecord(
        ContentType type,
        ushort epoch,
        ulong sequence,
        ReadOnlySpan<byte> payload,
        int offset
    );
}

// A datagram built by the record layer, in a buffer rented from the shared pool; Return gives it back.
internal readonly record struct OutgoingDatagram(byte[] Buffer, int Length)
{
    public ReadOnlyMemory<byte> Memory => Buffer.AsMemory(0, Length);

    public void Return() => ArrayPool<byte>.Shared.Return(Buffer);
}

// DTLS's record layer (RFC 6347 §4.1): records in and out, protected with each epoch's keys, packed
// into datagrams of at most the path's MTU, checked against replays on the way in. Nothing on the data
// path allocates: records are opened in place in the received datagram and handed on as spans, and
// datagrams are built in pooled buffers.
//
// Epochs are kept per direction. A write epoch stays usable after the next one is installed because a
// retransmitted flight can span the change (the client's last flight is epoch 0 up to its
// ChangeCipherSpec and epoch 1 after it). The previous read epoch stays readable so a peer's
// retransmission of its last unencrypted flight is still recognised after the switch.
internal sealed class RecordLayer(int maximumDatagram) : IDisposable
{
    // The sequence number is 48 bits; a connection that would wrap it must end (RFC 6347 §4.1).
    private const ulong SequenceLimit = (1UL << 48) - 1;

    private readonly List<WriteState> _write = [new(0, null)];
    private readonly Queue<OutgoingDatagram> _datagrams = [];
    private ReadState _current = new(0, null);
    private ReadState? _previous;
    private byte[]? _building;
    private int _buildingLength;

    public int MaximumDatagram { get; } = maximumDatagram;

    public ushort WriteEpoch => _write[^1].Epoch;

    public ushort ReadEpoch => _current.Epoch;

    // Records dropped because they failed to parse, authenticate, or were replays.
    public long Dropped { get; private set; }

    // The protection overhead of a record in an epoch, header included.
    public int Overhead(ushort epoch) =>
        RecordHeader.Size + (FindWrite(epoch).Cipher?.Overhead ?? 0);

    public void InstallWrite(RecordCipher cipher) =>
        _write.Add(new WriteState(checked((ushort)(WriteEpoch + 1)), cipher));

    public void InstallRead(RecordCipher cipher)
    {
        _previous?.Cipher?.Dispose();
        _previous = _current;
        _current = new ReadState(checked((ushort)(ReadEpoch + 1)), cipher);
    }

    // Makes the epoch's next record use at least this sequence number: a server answering a ClientHello
    // with a HelloVerifyRequest reuses the ClientHello's record sequence number (RFC 6347 §4.2.1).
    public void AdvanceSequence(ushort epoch, ulong sequence)
    {
        WriteState state = FindWrite(epoch);
        state.NextSequence = Math.Max(state.NextSequence, sequence);
    }

    // Protects a record in an epoch into the datagram being built, sending that datagram first when
    // the record does not fit behind what it already holds.
    public void Write(ContentType type, ushort epoch, ReadOnlySpan<byte> payload)
    {
        WriteState state = FindWrite(epoch);
        int size = RecordHeader.Size + payload.Length + (state.Cipher?.Overhead ?? 0);
        if (size > MaximumDatagram)
        {
            throw new InvalidOperationException(
                $"A {size}-byte record does not fit the {MaximumDatagram}-byte datagram limit."
            );
        }

        if (_buildingLength + size > MaximumDatagram)
        {
            Flush();
        }

        if (state.NextSequence > SequenceLimit)
        {
            throw new DtlsException(
                DtlsAlert.InternalError,
                isRemote: false,
                "The epoch's 48-bit sequence number is exhausted."
            );
        }

        _building ??= ArrayPool<byte>.Shared.Rent(MaximumDatagram);
        ulong sequence = state.NextSequence++;
        Span<byte> record = _building.AsSpan(_buildingLength, size);
        int length;
        if (state.Cipher is null)
        {
            payload.CopyTo(record[RecordHeader.Size..]);
            length = payload.Length;
        }
        else
        {
            length = state.Cipher.Seal(
                ((ulong)epoch << 48) | sequence,
                type,
                payload,
                record[RecordHeader.Size..]
            );
        }

        record[0] = (byte)type;
        BinaryPrimitives.WriteUInt16BigEndian(record[1..], ProtocolVersion.Dtls12);
        BinaryPrimitives.WriteUInt16BigEndian(record[3..], epoch);
        BinaryPrimitives.WriteUInt16BigEndian(record[5..], (ushort)(sequence >> 32));
        BinaryPrimitives.WriteUInt32BigEndian(record[7..], (uint)sequence);
        BinaryPrimitives.WriteUInt16BigEndian(record[11..], (ushort)length);
        _buildingLength += RecordHeader.Size + length;
    }

    // Ends the datagram being built.
    public void Flush()
    {
        if (_buildingLength > 0)
        {
            _datagrams.Enqueue(new OutgoingDatagram(_building!, _buildingLength));
            _building = null;
            _buildingLength = 0;
        }
    }

    // The next datagram to send; the caller returns its buffer to the pool once sent.
    public bool TryDequeue(out OutgoingDatagram datagram)
    {
        Flush();
        return _datagrams.TryDequeue(out datagram);
    }

    // Opens the records of a received datagram in place and hands each to the handler. What does not
    // parse, authenticate, belong to a readable epoch or is a replay is dropped silently (RFC 6347
    // §4.1.2.7) and counted: an attacker who can inject datagrams must not be able to end the
    // connection that way.
    public void Read<THandler>(Span<byte> datagram, ref THandler handler)
        where THandler : IRecordHandler, allows ref struct
    {
        int consumed = 0;
        while (datagram.Length > 0)
        {
            if (datagram.Length < RecordHeader.Size)
            {
                Dropped++;
                return;
            }

            ContentType type = (ContentType)datagram[0];
            ushort version = BinaryPrimitives.ReadUInt16BigEndian(datagram[1..]);
            ushort epoch = BinaryPrimitives.ReadUInt16BigEndian(datagram[3..]);
            ulong sequence =
                ((ulong)BinaryPrimitives.ReadUInt16BigEndian(datagram[5..]) << 32)
                | BinaryPrimitives.ReadUInt32BigEndian(datagram[7..]);
            int length = BinaryPrimitives.ReadUInt16BigEndian(datagram[11..]);
            if (
                length > datagram.Length - RecordHeader.Size
                || length > RecordHeader.MaximumFragment
            )
            {
                // A length that runs past the datagram leaves no way to find the next record.
                Dropped++;
                return;
            }

            Span<byte> fragment = datagram.Slice(RecordHeader.Size, length);
            int fragmentAt = consumed + RecordHeader.Size;
            datagram = datagram[(RecordHeader.Size + length)..];
            consumed = fragmentAt + length;
            int opened = Open(type, version, epoch, sequence, fragment, out int offset);
            if (opened < 0)
            {
                Dropped++;
                continue;
            }

            handler.OnRecord(
                type,
                epoch,
                sequence,
                fragment.Slice(offset, opened),
                fragmentAt + offset
            );
        }
    }

    public void Dispose()
    {
        foreach (WriteState state in _write)
        {
            state.Cipher?.Dispose();
        }

        _current.Cipher?.Dispose();
        _previous?.Cipher?.Dispose();
        if (_building is not null)
        {
            ArrayPool<byte>.Shared.Return(_building);
            _building = null;
        }

        while (_datagrams.TryDequeue(out OutgoingDatagram datagram))
        {
            datagram.Return();
        }
    }

    // Opens a record in place; returns the payload's length, or -1 to drop it.
    private int Open(
        ContentType type,
        ushort version,
        ushort epoch,
        ulong sequence,
        Span<byte> fragment,
        out int offset
    )
    {
        offset = 0;
        if (
            !Enum.IsDefined(type)
            || version is not (ProtocolVersion.Dtls12 or ProtocolVersion.Dtls10)
        )
        {
            return -1;
        }

        ReadState? state =
            epoch == _current.Epoch ? _current
            : epoch == _previous?.Epoch ? _previous
            : null;
        if (state is null || !state.Window.IsFresh(sequence))
        {
            return -1;
        }

        int length = state.Cipher is null
            ? fragment.Length
            : state.Cipher.Open(((ulong)epoch << 48) | sequence, type, fragment, out offset);
        if (length < 0)
        {
            return -1;
        }

        state.Window.MarkSeen(sequence);
        return length;
    }

    private WriteState FindWrite(ushort epoch) =>
        _write.Find(w => w.Epoch == epoch)
        ?? throw new InvalidOperationException($"Epoch {epoch} has no write keys.");

    private sealed class WriteState(ushort epoch, RecordCipher? cipher)
    {
        public ushort Epoch { get; } = epoch;

        public RecordCipher? Cipher { get; } = cipher;

        public ulong NextSequence { get; set; }
    }

    private sealed class ReadState(ushort epoch, RecordCipher? cipher)
    {
        public ushort Epoch { get; } = epoch;

        public RecordCipher? Cipher { get; } = cipher;

        public ReplayWindow Window;
    }
}
