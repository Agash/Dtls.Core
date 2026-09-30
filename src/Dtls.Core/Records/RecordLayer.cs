using System.Buffers;
using System.Buffers.Binary;

namespace Dtls.Core.Records;

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

// DTLS's record layer: records in and out, protected with each epoch's keys, packed into datagrams of
// at most the path's MTU, checked against replays on the way in. Nothing on the data path allocates:
// records are opened in place in the received datagram and handed on as spans, and datagrams are built
// in pooled buffers.
//
// Unprotected records, and every DTLS 1.2 record, have the 13-byte header of RFC 6347 §4.1. A DTLS 1.3
// epoch's records have the unified header of RFC 9147 §4: the low two bits of the epoch, the low 16
// bits of the sequence number masked with the epoch's sequence key, and the length; the content type
// travels inside the encryption.
//
// Epochs are kept per direction. A write epoch stays usable after the next one is installed because a
// retransmitted flight can span the change (the client's last DTLS 1.2 flight is epoch 0 up to its
// ChangeCipherSpec and epoch 1 after it). Earlier read epochs stay readable so a peer's retransmission
// of a flight from before the switch is still recognised.
internal sealed class RecordLayer(int maximumDatagram) : IDisposable
{
    // The sequence number is 48 bits; a connection that would wrap it must end (RFC 6347 §4.1).
    private const ulong SequenceLimit = (1UL << 48) - 1;

    // A unified header: fixed bits 001, 16-bit sequence number and length present, epoch bits.
    private const byte UnifiedHeaderBits = 0x2C;
    private const int UnifiedHeaderSize = 5;
    private const int SequenceMaskSource = 16;

    private readonly List<WriteState> _write = [new(0, null, null)];
    private readonly List<ReadState> _read = [new(0, null, null)];
    private readonly Queue<OutgoingDatagram> _datagrams = [];
    private byte[]? _building;
    private int _buildingLength;

    public int MaximumDatagram { get; private set; } = maximumDatagram;

    // A new path MTU: what is being built goes out at the old size, what follows at the new.
    public void SetMaximumDatagram(int size)
    {
        Flush();
        MaximumDatagram = size;
    }

    public ushort WriteEpoch => _write[^1].Epoch;

    public ushort ReadEpoch => _read[^1].Epoch;

    // Records dropped because they failed to parse, authenticate, or were replays.
    public long Dropped { get; private set; }

    // DTLS 1.3 records that failed to authenticate under the keys of one epoch, most of any epoch. RFC
    // 9147 §4.5.3 bounds this per key: past 2^36 forgeries an attacker's chance against AES-GCM and
    // ChaCha20-Poly1305 is no longer negligible, and the connection must end.
    public const long IntegrityLimit = 1L << 36;

    public bool IntegrityLimitReached { get; private set; }

    // Protected records that failed to authenticate, in any epoch.
    public long AuthenticationFailures { get; private set; }

    // Epochs never wrap (RFC 6347 §4.1, RFC 9147 §4.2.1). Dtls.Core counts them in 16 bits, the
    // width DTLS 1.2 records carry, which allows 65,532 DTLS 1.3 key updates: a new association
    // is needed after that.
    public static ushort NextEpoch(ushort epoch) =>
        epoch < ushort.MaxValue
            ? (ushort)(epoch + 1)
            : throw new DtlsException(
                DtlsAlert.InternalError,
                isRemote: false,
                "The epoch is exhausted: the association must be replaced."
            );

    // The protection overhead of a record in an epoch, header included.
    public int Overhead(ushort epoch)
    {
        WriteState state = FindWrite(epoch);
        return state.Cipher13 is not null
            ? UnifiedHeaderSize + 1 + RecordCipher13.TagLength
            : RecordHeader.Size + (state.Cipher?.Overhead ?? 0);
    }

    // DTLS 1.2: the next epoch's keys.
    public void InstallWrite(RecordCipher cipher) =>
        _write.Add(new WriteState(NextEpoch(WriteEpoch), cipher, null));

    public void InstallRead(RecordCipher cipher)
    {
        _read.Add(new ReadState(NextEpoch(ReadEpoch), cipher, null));
        if (_read.Count > 2)
        {
            _read[0].Dispose();
            _read.RemoveAt(0);
        }
    }

    // DTLS 1.3: an epoch's keys (epochs 2 and 3 for the handshake and application traffic, one more for
    // each KeyUpdate). Epochs from two updates back are retired: nothing is sent in them any more.
    public void InstallWrite(ushort epoch, RecordCipher13 cipher)
    {
        _write.Add(new WriteState(epoch, null, cipher));
        Retire(_write, epoch);
    }

    public void InstallRead(ushort epoch, RecordCipher13 cipher)
    {
        _read.Add(new ReadState(epoch, null, cipher));
        Retire(_read, epoch);
    }

    // Makes the epoch's next record use at least this sequence number: a server answering a ClientHello
    // with a HelloVerifyRequest reuses the ClientHello's record sequence number (RFC 6347 §4.2.1).
    public void AdvanceSequence(ushort epoch, ulong sequence)
    {
        WriteState state = FindWrite(epoch);
        state.NextSequence = Math.Max(state.NextSequence, sequence);
    }

    // Protects a record in an epoch into the datagram being built, sending that datagram first when
    // the record does not fit behind what it already holds. Returns the record's sequence number.
    public ulong Write(ContentType type, ushort epoch, ReadOnlySpan<byte> payload)
    {
        WriteState state = FindWrite(epoch);
        int size = Overhead(epoch) + payload.Length;
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
        _buildingLength += state.Cipher13 is not null
            ? Write13(state.Cipher13, type, epoch, sequence, payload, record)
            : Write12(state.Cipher, type, epoch, sequence, payload, record);
        return sequence;
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
    // §4.1.2.7, RFC 9147 §4.5.2) and counted: an attacker who can inject datagrams must not be able to
    // end the connection that way.
    public void Read<THandler>(Span<byte> datagram, ref THandler handler)
        where THandler : IRecordHandler, allows ref struct
    {
        int consumed = 0;
        while (consumed < datagram.Length)
        {
            Span<byte> rest = datagram[consumed..];
            int next =
                (rest[0] & 0xE0) == 0x20
                    ? Read13(datagram, consumed, ref handler)
                    : Read12(datagram, consumed, ref handler);
            if (next < 0)
            {
                // Nothing after a record that cannot be delimited can be found.
                Dropped++;
                return;
            }

            consumed = next;
        }
    }

    public void Dispose()
    {
        foreach (WriteState state in _write)
        {
            state.Dispose();
        }

        foreach (ReadState state in _read)
        {
            state.Dispose();
        }

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

    private static int Write12(
        RecordCipher? cipher,
        ContentType type,
        ushort epoch,
        ulong sequence,
        ReadOnlySpan<byte> payload,
        Span<byte> record
    )
    {
        int length;
        if (cipher is null)
        {
            payload.CopyTo(record[RecordHeader.Size..]);
            length = payload.Length;
        }
        else
        {
            length = cipher.Seal(
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
        return RecordHeader.Size + length;
    }

    // DTLSInnerPlaintext (content || type), sealed behind a unified header whose sequence number is
    // then masked. The additional data is the header with the sequence number in the clear.
    private static int Write13(
        RecordCipher13 cipher,
        ContentType type,
        ushort epoch,
        ulong sequence,
        ReadOnlySpan<byte> payload,
        Span<byte> record
    )
    {
        Span<byte> header = record[..UnifiedHeaderSize];
        header[0] = (byte)(UnifiedHeaderBits | (epoch & 0x03));
        BinaryPrimitives.WriteUInt16BigEndian(header[1..], (ushort)sequence);
        BinaryPrimitives.WriteUInt16BigEndian(
            header[3..],
            (ushort)(payload.Length + 1 + RecordCipher13.TagLength)
        );
        Span<byte> body = record[UnifiedHeaderSize..];
        payload.CopyTo(body);
        body[payload.Length] = (byte)type;
        int length = cipher.Seal(sequence, header, body, payload.Length + 1);
        Span<byte> mask = stackalloc byte[2];
        cipher.Mask(body[..SequenceMaskSource], mask);
        header[1] ^= mask[0];
        header[2] ^= mask[1];
        return UnifiedHeaderSize + length;
    }

    // A record with the 13-byte header; returns where the next record starts, or -1.
    private int Read12<THandler>(Span<byte> datagram, int at, ref THandler handler)
        where THandler : IRecordHandler, allows ref struct
    {
        Span<byte> rest = datagram[at..];
        if (rest.Length < RecordHeader.Size)
        {
            return -1;
        }

        ContentType type = (ContentType)rest[0];
        ushort version = BinaryPrimitives.ReadUInt16BigEndian(rest[1..]);
        ushort epoch = BinaryPrimitives.ReadUInt16BigEndian(rest[3..]);
        ulong sequence =
            ((ulong)BinaryPrimitives.ReadUInt16BigEndian(rest[5..]) << 32)
            | BinaryPrimitives.ReadUInt32BigEndian(rest[7..]);
        int length = BinaryPrimitives.ReadUInt16BigEndian(rest[11..]);
        if (length > rest.Length - RecordHeader.Size || length > RecordHeader.MaximumFragment)
        {
            return -1;
        }

        int fragmentAt = at + RecordHeader.Size;
        Span<byte> fragment = datagram.Slice(fragmentAt, length);
        int opened = Open12(type, version, epoch, sequence, fragment, out int offset);
        if (opened < 0)
        {
            Dropped++;
        }
        else
        {
            handler.OnRecord(
                type,
                epoch,
                sequence,
                fragment.Slice(offset, opened),
                fragmentAt + offset
            );
        }

        return fragmentAt + length;
    }

    // Opens a record in place; returns the payload's length, or -1 to drop it.
    private int Open12(
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

        ReadState? state = FindRead(epoch);
        if (state is null || state.Cipher13 is not null)
        {
            return -1;
        }

        // Replay protection needs authentication: an unprotected record proves nothing about its
        // sequence number, and letting one move the window would let a single forged datagram with a
        // high number make every genuine record after it look old. Duplicate unprotected handshake
        // records are recognised by their message_seq instead.
        if (state.Cipher is null)
        {
            return fragment.Length;
        }

        if (!state.Window.IsFresh(sequence))
        {
            return -1;
        }

        int length = state.Cipher.Open(((ulong)epoch << 48) | sequence, type, fragment, out offset);
        if (length < 0)
        {
            AuthenticationFailures++;
            return -1;
        }

        state.Window.MarkSeen(sequence);
        return length;
    }

    // A record with a unified header (RFC 9147 §4); returns where the next record starts, or -1.
    private int Read13<THandler>(Span<byte> datagram, int at, ref THandler handler)
        where THandler : IRecordHandler, allows ref struct
    {
        Span<byte> rest = datagram[at..];
        byte flags = rest[0];
        if ((flags & 0x10) != 0)
        {
            // A connection ID, which was not negotiated: the record cannot be delimited.
            return -1;
        }

        int sequenceLength = (flags & 0x08) != 0 ? 2 : 1;
        bool hasLength = (flags & 0x04) != 0;
        int headerLength = 1 + sequenceLength + (hasLength ? 2 : 0);
        if (rest.Length < headerLength)
        {
            return -1;
        }

        int length = hasLength
            ? BinaryPrimitives.ReadUInt16BigEndian(rest[(1 + sequenceLength)..])
            : rest.Length - headerLength;
        if (length > rest.Length - headerLength)
        {
            return -1;
        }

        int fragmentAt = at + headerLength;
        Span<byte> header = rest[..headerLength];
        Span<byte> ciphertext = datagram.Slice(fragmentAt, length);
        ReadState? state = FindRead13(flags & 0x03);
        if (state is null || ciphertext.Length < SequenceMaskSource)
        {
            Dropped++;
            return fragmentAt + length;
        }

        Span<byte> mask = stackalloc byte[2];
        state.Cipher13!.Mask(ciphertext[..SequenceMaskSource], mask);
        header[1] ^= mask[0];
        ulong partial = header[1];
        if (sequenceLength == 2)
        {
            header[2] ^= mask[1];
            partial = BinaryPrimitives.ReadUInt16BigEndian(header[1..]);
        }

        ulong sequence = Reconstruct(state.Window.NextExpected, partial, 8 * sequenceLength);
        bool fresh = state.Window.IsFresh(sequence);
        int inner = fresh ? state.Cipher13.Open(sequence, header, ciphertext) : -1;
        int typeAt = inner - 1;
        while (typeAt >= 0 && ciphertext[typeAt] == 0)
        {
            typeAt--;
        }

        if (fresh && inner < 0)
        {
            AuthenticationFailures++;
            if (++state.AuthenticationFailures >= IntegrityLimit)
            {
                IntegrityLimitReached = true;
            }
        }

        if (typeAt < 0)
        {
            // It did not authenticate, or its padding holds no content type.
            Dropped++;
            return fragmentAt + length;
        }

        state.Window.MarkSeen(sequence);
        handler.OnRecord(
            (ContentType)ciphertext[typeAt],
            state.Epoch,
            sequence,
            ciphertext[..typeAt],
            fragmentAt
        );
        return fragmentAt + length;
    }

    // The full sequence number closest to the one expected whose low bits are those received (RFC 9147
    // §4.2.2).
    internal static ulong Reconstruct(ulong expected, ulong low, int bits)
    {
        ulong range = 1UL << bits;
        ulong candidate = (expected & ~(range - 1)) | low;
        if (candidate > expected + (range / 2) && candidate >= range)
        {
            candidate -= range;
        }
        else if (candidate + (range / 2) < expected)
        {
            candidate += range;
        }

        return candidate;
    }

    private static void Retire<TState>(List<TState> states, ushort epoch)
        where TState : EpochState
    {
        for (int i = states.Count - 1; i >= 0; i--)
        {
            if (states[i].Epoch > 3 && states[i].Epoch + 2 <= epoch)
            {
                states[i].Dispose();
                states.RemoveAt(i);
            }
        }
    }

    private WriteState FindWrite(ushort epoch)
    {
        for (int i = _write.Count - 1; i >= 0; i--)
        {
            if (_write[i].Epoch == epoch)
            {
                return _write[i];
            }
        }

        throw new InvalidOperationException($"Epoch {epoch} has no write keys.");
    }

    private ReadState? FindRead(ushort epoch)
    {
        for (int i = _read.Count - 1; i >= 0; i--)
        {
            if (_read[i].Epoch == epoch)
            {
                return _read[i];
            }
        }

        return null;
    }

    // The most recent DTLS 1.3 epoch with these low bits.
    private ReadState? FindRead13(int bits)
    {
        for (int i = _read.Count - 1; i >= 0; i--)
        {
            if (_read[i].Cipher13 is not null && (_read[i].Epoch & 0x03) == bits)
            {
                return _read[i];
            }
        }

        return null;
    }

    private abstract class EpochState(ushort epoch, RecordCipher? cipher, RecordCipher13? cipher13)
        : IDisposable
    {
        public ushort Epoch { get; } = epoch;

        public RecordCipher? Cipher { get; } = cipher;

        public RecordCipher13? Cipher13 { get; } = cipher13;

        public void Dispose()
        {
            Cipher?.Dispose();
            Cipher13?.Dispose();
        }
    }

    private sealed class WriteState(ushort epoch, RecordCipher? cipher, RecordCipher13? cipher13)
        : EpochState(epoch, cipher, cipher13)
    {
        public ulong NextSequence { get; set; }
    }

    private sealed class ReadState(ushort epoch, RecordCipher? cipher, RecordCipher13? cipher13)
        : EpochState(epoch, cipher, cipher13)
    {
        public ReplayWindow Window;

        public long AuthenticationFailures { get; set; }
    }
}
