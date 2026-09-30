using System.Net.Security;
using System.Security.Cryptography;
using Dtls.Core.Crypto;
using Dtls.Core.Records;

namespace Dtls.Core.Tests;

[TestClass]
public sealed class KeySchedule13Tests
{
    // RFC 8448 §3, the simple 1-RTT handshake, with TLS's "tls13 " prefix: DTLS differs only in it.
    private const string TlsPrefix = "tls13 ";

    [TestMethod]
    public void Advance_Rfc8448SimpleHandshake_DerivesItsSecretsAndKeys()
    {
        using KeySchedule13 schedule = new(HashAlgorithmName.SHA256, TlsPrefix);
        Assert.AreEqual(
            "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a",
            Hex(schedule.Secret)
        );

        schedule.Advance(
            Convert.FromHexString(
                "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d"
            )
        );
        Assert.AreEqual(
            "1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac",
            Hex(schedule.Secret)
        );

        byte[] transcript = Convert.FromHexString(
            "860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8"
        );
        byte[] clientTraffic = schedule.DeriveSecret("c hs traffic", transcript);
        byte[] serverTraffic = schedule.DeriveSecret("s hs traffic", transcript);
        Assert.AreEqual(
            "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21",
            Hex(clientTraffic)
        );
        Assert.AreEqual(
            "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38",
            Hex(serverTraffic)
        );

        Assert.IsTrue(
            CipherSuiteInfo.TryGet(TlsCipherSuite.TLS_AES_128_GCM_SHA256, out CipherSuiteInfo suite)
        );
        using TrafficKeys keys = KeySchedule13.Keys(suite, TlsPrefix, serverTraffic);
        Assert.AreEqual("3fce516009c21727d0f2e4e86ee403bc", Hex(keys.Key));
        Assert.AreEqual("5d313eb2671276ee13000b30", Hex(keys.Iv));

        schedule.Advance([]);
        Assert.AreEqual(
            "18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919",
            Hex(schedule.Secret)
        );
    }

    [TestMethod]
    public void ChaCha20Block_MatchesThePlatformsKeystream()
    {
        byte[] key = RandomNumberGenerator.GetBytes(32);
        byte[] nonce = RandomNumberGenerator.GetBytes(12);
        byte[] keystream = new byte[64];
        using (ChaCha20Poly1305 aead = new(key))
        {
            // The AEAD encrypts from block counter 1: zeros encrypt to the keystream.
            aead.Encrypt(nonce, new byte[64], keystream, new byte[16]);
        }

        byte[] block = new byte[64];
        RecordCipher13.ChaCha20Block(key, 1, nonce, block);

        CollectionAssert.AreEqual(keystream, block);
    }

    [TestMethod]
    [DataRow(TlsCipherSuite.TLS_AES_128_GCM_SHA256)]
    [DataRow(TlsCipherSuite.TLS_AES_256_GCM_SHA384)]
    [DataRow(TlsCipherSuite.TLS_CHACHA20_POLY1305_SHA256)]
    public void Read_Dtls13Records_OpenWithReconstructedSequenceNumbers(TlsCipherSuite name)
    {
        Assert.IsTrue(CipherSuiteInfo.TryGet(name, out CipherSuiteInfo suite));
        if (!suite.IsSupported)
        {
            Assert.Inconclusive($"{name} is not supported on this platform.");
        }

        byte[] secret = RandomNumberGenerator.GetBytes(Prf.HashSize(suite.PrfHash));
        using RecordLayer sender = new(1200);
        using RecordLayer receiver = new(1200);
        sender.InstallWrite(
            3,
            new RecordCipher13(suite, KeySchedule13.Keys(suite, KeySchedule13.DtlsPrefix, secret))
        );
        receiver.InstallRead(
            3,
            new RecordCipher13(suite, KeySchedule13.Keys(suite, KeySchedule13.DtlsPrefix, secret))
        );

        byte[] payload = RandomNumberGenerator.GetBytes(100);
        Assert.AreEqual(0UL, sender.Write(ContentType.ApplicationData, 3, payload));
        _ = sender.Write(ContentType.Ack, 3, [0, 0]);
        Assert.IsTrue(sender.TryDequeue(out OutgoingDatagram datagram));
        byte[] wire = datagram.Memory.ToArray();
        datagram.Return();
        Assert.AreEqual(0x2F, wire[0]);

        Collector collector = new();
        receiver.Read(wire, ref collector);

        Assert.HasCount(2, collector.Records);
        Assert.AreEqual(
            (ContentType.ApplicationData, (ushort)3, 0UL),
            (collector.Records[0].Type, collector.Records[0].Epoch, collector.Records[0].Sequence)
        );
        CollectionAssert.AreEqual(payload, collector.Records[0].Payload);
        Assert.AreEqual(ContentType.Ack, collector.Records[1].Type);
    }

    [TestMethod]
    [DataRow(0UL, 5UL, 16, 5UL)]
    [DataRow(65_530UL, 3UL, 16, 65_539UL)]
    [DataRow(70_000UL, 4_460UL, 16, 69_996UL)]
    [DataRow(300UL, 250UL, 8, 250UL)]
    [DataRow(300UL, 20UL, 8, 276UL)]
    public void Reconstruct_LowBits_PicksTheClosestSequenceNumber(
        ulong expected,
        ulong low,
        int bits,
        ulong sequence
    ) => Assert.AreEqual(sequence, RecordLayer.Reconstruct(expected, low, bits));

    private static string Hex(ReadOnlySpan<byte> bytes) => Convert.ToHexStringLower(bytes);

    private readonly struct Collector() : IRecordHandler
    {
        public List<(
            ContentType Type,
            ushort Epoch,
            ulong Sequence,
            byte[] Payload
        )> Records { get; } = [];

        public void OnRecord(
            ContentType type,
            ushort epoch,
            ulong sequence,
            ReadOnlySpan<byte> payload,
            int offset
        ) => Records.Add((type, epoch, sequence, payload.ToArray()));
    }
}
