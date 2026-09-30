using System.Net.Security;
using System.Security.Cryptography;
using Dtls.Core.Crypto;
using Dtls.Core.Records;

namespace Dtls.Core.Tests;

[TestClass]
public sealed class RecordLayerTests
{
    [TestMethod]
    [DataRow(TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)]
    [DataRow(TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384)]
    [DataRow(TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256)]
    public void Read_ProtectedRecords_OpenOnceInPlace(TlsCipherSuite suite)
    {
        Assert.IsTrue(CipherSuiteInfo.TryGet(suite, out CipherSuiteInfo info));
        if (!info.IsSupported)
        {
            Assert.Inconclusive($"{suite} is not supported on this platform.");
        }

        (RecordLayer sender, RecordLayer receiver) = Pair(info);
        using (sender)
        using (receiver)
        {
            byte[] first = RandomNumberGenerator.GetBytes(300);
            byte[] second = RandomNumberGenerator.GetBytes(20);
            sender.Write(ContentType.ApplicationData, 1, first);
            sender.Write(ContentType.ApplicationData, 1, second);
            byte[] wire = Take(sender);
            byte[] replay = [.. wire];

            Collector collector = new(wire);
            receiver.Read(wire, ref collector);
            Collector again = new(replay);
            receiver.Read(replay, ref again);

            Assert.HasCount(2, collector.Payloads);
            CollectionAssert.AreEqual(first, collector.Payloads[0]);
            CollectionAssert.AreEqual(second, collector.Payloads[1]);
            Assert.IsEmpty(again.Payloads);
            Assert.AreEqual(2, receiver.Dropped);
        }
    }

    [TestMethod]
    public void Read_TamperedRecord_IsDropped()
    {
        Assert.IsTrue(
            CipherSuiteInfo.TryGet(
                TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                out CipherSuiteInfo info
            )
        );
        (RecordLayer sender, RecordLayer receiver) = Pair(info);
        using (sender)
        using (receiver)
        {
            sender.Write(ContentType.ApplicationData, 1, [1, 2, 3]);
            byte[] wire = Take(sender);
            wire[^1] ^= 1;

            Collector collector = new(wire);
            receiver.Read(wire, ref collector);

            Assert.IsEmpty(collector.Payloads);
            Assert.AreEqual(1, receiver.Dropped);
        }
    }

    [TestMethod]
    public void Write_RecordsBeyondTheLimit_StartANewDatagram()
    {
        using RecordLayer records = new(100);
        records.Write(ContentType.Handshake, 0, new byte[60]);
        records.Write(ContentType.Handshake, 0, new byte[60]);

        byte[] first = Take(records);
        byte[] second = Take(records);

        Assert.HasCount(73, first);
        Assert.HasCount(73, second);
        Assert.IsFalse(records.TryDequeue(out _));
    }

    [TestMethod]
    public void Write_PastThe48BitSequenceNumber_FailsInsteadOfWrapping()
    {
        using RecordLayer records = new(1200);
        records.AdvanceSequence(0, (1UL << 48) - 1);
        Assert.AreEqual((1UL << 48) - 1, records.Write(ContentType.Handshake, 0, [1]));

        DtlsException error = Assert.ThrowsExactly<DtlsException>(() =>
            records.Write(ContentType.Handshake, 0, [1])
        );
        Assert.AreEqual(DtlsAlert.InternalError, error.Alert);
    }

    [TestMethod]
    public void NextEpoch_AtTheLast_FailsInsteadOfWrapping() =>
        Assert.ThrowsExactly<DtlsException>(() => RecordLayer.NextEpoch(ushort.MaxValue));

    [TestMethod]
    public void Read_TamperedRecord_LeavesTheReplayWindowAlone()
    {
        Assert.IsTrue(
            CipherSuiteInfo.TryGet(
                TlsCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                out CipherSuiteInfo info
            )
        );
        (RecordLayer sender, RecordLayer receiver) = Pair(info);
        using (sender)
        using (receiver)
        {
            _ = sender.Write(ContentType.ApplicationData, 1, [1, 2, 3]);
            byte[] genuine = Take(sender);
            byte[] tampered = [.. genuine];
            tampered[^1] ^= 1;

            Collector first = new(tampered);
            receiver.Read(tampered, ref first);
            Collector second = new(genuine);
            receiver.Read(genuine, ref second);

            // The forgery with the same sequence number did not mark it seen.
            Assert.IsEmpty(first.Payloads);
            Assert.HasCount(1, second.Payloads);
        }
    }

    private static byte[] Take(RecordLayer records)
    {
        Assert.IsTrue(records.TryDequeue(out OutgoingDatagram datagram));
        byte[] wire = datagram.Memory.ToArray();
        datagram.Return();
        return wire;
    }

    private static (RecordLayer Sender, RecordLayer Receiver) Pair(CipherSuiteInfo info)
    {
        byte[] master = RandomNumberGenerator.GetBytes(48);
        byte[] client = RandomNumberGenerator.GetBytes(32);
        byte[] server = RandomNumberGenerator.GetBytes(32);
        (RecordCipher write, RecordCipher unusedWrite) = KeySchedule.RecordCiphers(
            info,
            master,
            client,
            server
        );
        (RecordCipher read, RecordCipher unusedRead) = KeySchedule.RecordCiphers(
            info,
            master,
            client,
            server
        );
        unusedWrite.Dispose();
        unusedRead.Dispose();
        RecordLayer sender = new(1200);
        RecordLayer receiver = new(1200);
        sender.InstallWrite(write);
        receiver.InstallRead(read);
        return (sender, receiver);
    }

    private readonly struct Collector(byte[] datagram) : IRecordHandler
    {
        public List<byte[]> Payloads { get; } = [];

        public void OnRecord(
            ContentType type,
            ushort epoch,
            ulong sequence,
            ReadOnlySpan<byte> payload,
            int offset
        )
        {
            CollectionAssert.AreEqual(
                payload.ToArray(),
                datagram.AsSpan(offset, payload.Length).ToArray()
            );
            Payloads.Add(payload.ToArray());
        }
    }
}
