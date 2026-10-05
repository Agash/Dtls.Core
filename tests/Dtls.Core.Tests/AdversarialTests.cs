using System.Security.Cryptography.X509Certificates;

namespace Dtls.Core.Tests;

// What a hostile or broken path can do to a connection: lose, reorder, repeat, corrupt and forge
// datagrams. Every case must end either in a working connection or a defined failure, never in a
// crash or a silently broken state.
[TestClass]
public sealed class AdversarialTests
{
    private static readonly TimeSpan s_timeout = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan s_retransmission = TimeSpan.FromMilliseconds(100);

    public TestContext TestContext { get; set; } = null!;

    private readonly TestLog _log = new();

    [TestInitialize]
    public void ClearTrace() => Direction.Trace.Clear();

    [TestCleanup]
    public void PrintLog()
    {
        if (TestContext.CurrentTestOutcome != UnitTestOutcome.Passed)
        {
            TestContext.WriteLine(_log.ToString());
            TestContext.WriteLine(string.Join(Environment.NewLine, Direction.Trace));
        }
    }

    [TestMethod]
    [DataRow(true)]
    [DataRow(false)]
    public async Task KeyUpdate_EitherSide_MovesBothDirectionsToNewEpochs(bool fromClient)
    {
        Path path = new();
        (DtlsConnection client, DtlsConnection server) = await ConnectAsync(
            path,
            DtlsProtocols.Dtls13
        );
        await using (client)
        await using (server)
        {
            await (fromClient ? client : server).RequestKeyUpdateAsync();
            await TalkAsync(client, server, rounds: 3);

            // update_requested: the other side updates too, so every direction is on epoch 4.
            await EventuallyAsync(() => client.Epochs == (4, 4) && server.Epochs == (4, 4));
        }
    }

    [TestMethod]
    public async Task KeyUpdate_Repeated_KeepsTheConnectionWorking()
    {
        Path path = new();
        (DtlsConnection client, DtlsConnection server) = await ConnectAsync(
            path,
            DtlsProtocols.Dtls13
        );
        await using (client)
        await using (server)
        {
            // Each request asks the peer to update too, so both sides move one epoch per round; the
            // peer's answering update lands after the request, so each round waits for both.
            int start = (int)client.Epochs.Write;
            for (int i = 0; i < 5; i++)
            {
                await (i % 2 == 0 ? client : server).RequestKeyUpdateAsync();
                await TalkAsync(client, server, rounds: 1);
                int expected = start + i + 1;
                await EventuallyAsync(() =>
                    client.Epochs.Write == expected
                    && server.Epochs.Write == expected
                    && client.Epochs.Write == server.Epochs.Read
                    && server.Epochs.Write == client.Epochs.Read
                );
            }

            Assert.AreEqual(start + 5, (int)client.Epochs.Write);
            await TalkAsync(client, server, rounds: 1);
        }
    }

    [TestMethod]
    public async Task KeyUpdate_Crossed_BothSidesSettle()
    {
        Path path = new();
        (DtlsConnection client, DtlsConnection server) = await ConnectAsync(
            path,
            DtlsProtocols.Dtls13
        );
        await using (client)
        await using (server)
        {
            await Task.WhenAll(
                client.RequestKeyUpdateAsync().AsTask(),
                server.RequestKeyUpdateAsync().AsTask()
            );
            await TalkAsync(client, server, rounds: 3);
            await EventuallyAsync(() =>
                client.Epochs.Write == server.Epochs.Read
                && server.Epochs.Write == client.Epochs.Read
            );
        }
    }

    [TestMethod]
    [DataRow(true)]
    [DataRow(false)]
    public async Task KeyUpdate_LostUpdateOrAck_IsRetransmittedUntilAcknowledged(bool loseUpdate)
    {
        Path path = new();
        (DtlsConnection client, DtlsConnection server) = await ConnectAsync(
            path,
            DtlsProtocols.Dtls13
        );
        await using (client)
        await using (server)
        {
            // The next datagram in that direction is the KeyUpdate, or the server's ACK of it.
            (loseUpdate ? path.ToServer : path.ToClient).DropNext(1);
            await client.RequestKeyUpdateAsync();

            await EventuallyAsync(() => client.Epochs.Write == 4 && server.Epochs.Read == 4);
            await TalkAsync(client, server, rounds: 2);
        }
    }

    [TestMethod]
    public async Task KeyUpdate_OldEpochDataAfterTheUpdate_IsStillRead()
    {
        Path path = new();
        (DtlsConnection client, DtlsConnection server) = await ConnectAsync(
            path,
            DtlsProtocols.Dtls13
        );
        await using (client)
        await using (server)
        {
            // Hold a datagram of epoch 3, update the keys, then deliver it late.
            path.ToServer.HoldNext();
            await client.SendAsync("early"u8.ToArray(), TestContext.CancellationToken);
            await client.RequestKeyUpdateAsync();
            await EventuallyAsync(() => client.Epochs.Write == 4);
            path.ToServer.Release();

            byte[] buffer = new byte[64];
            int length = await server
                .ReceiveAsync(buffer, TestContext.CancellationToken)
                .AsTask()
                .WaitAsync(s_timeout, TestContext.CancellationToken);
            CollectionAssert.AreEqual("early"u8.ToArray(), buffer[..length]);
        }
    }

    [TestMethod]
    public async Task PostHandshakeMessage_InTheHandshakeEpoch_IsIgnored()
    {
        Path path = new();
        (DtlsConnection client, DtlsConnection server) = await ConnectAsync(
            path,
            DtlsProtocols.Dtls13
        );
        await using (client)
        await using (server)
        {
            // A KeyUpdate under the handshake keys (epoch 2) must not reach post-handshake processing.
            await client.SendHandshakeForTestAsync(epoch: 2, type: 24, body: [1]);
            await TalkAsync(client, server, rounds: 2);

            Assert.AreEqual((ushort)3, server.Epochs.Read);
            Assert.IsFalse(server.IsFailed);
        }
    }

    [TestMethod]
    [DataRow(DtlsProtocols.Dtls13, 1)]
    [DataRow(DtlsProtocols.Dtls13, 2)]
    [DataRow(DtlsProtocols.Dtls12, 3)]
    [DataRow(DtlsProtocols.Dtls12, 4)]
    public async Task Handshake_WithForgedCopiesOfEveryDatagram_StillCompletes(
        DtlsProtocols version,
        int seed
    )
    {
        // Every real datagram arrives, followed by mutated copies: flipped bits, truncations,
        // extensions and random bytes, as an attacker off the path or a duplicating network produces
        // them. None may end the handshake.
        Random random = new(seed);
        Path path = new(forge: datagram => Mutations(random, datagram, 3));
        (DtlsConnection client, DtlsConnection server) = await ConnectAsync(path, version);
        await using (client)
        await using (server)
        {
            await TalkAsync(client, server, rounds: 2);
        }
    }

    [TestMethod]
    [DataRow(DtlsProtocols.Dtls13, 7)]
    [DataRow(DtlsProtocols.Dtls13, 8)]
    [DataRow(DtlsProtocols.Dtls12, 9)]
    [DataRow(DtlsProtocols.Dtls12, 10)]
    public async Task Handshake_WithForgeriesArrivingFirst_SucceedsOrFailsCleanly(
        DtlsProtocols version,
        int seed
    )
    {
        // A forgery that arrives before the genuine message cannot be told from it: the unencrypted
        // handshake is authenticated only by the Finished messages. Such a handshake may fail, but
        // only as a handshake failure or a timeout, never with anything else.
        Random random = new(seed);
        Path path = new(forge: datagram => Mutations(random, datagram, 2), forgeFirst: true);
        try
        {
            (DtlsConnection client, DtlsConnection server) = await ConnectAsync(
                path,
                version,
                TimeSpan.FromSeconds(3)
            );
            await client.DisposeAsync();
            await server.DisposeAsync();
        }
        catch (Exception error)
            when (error
                    is System.Security.Authentication.AuthenticationException
                        or TimeoutException
            )
        {
            // Deliberately swallowed: the defined outcomes of a forged handshake.
        }
    }

    [TestMethod]
    [DataRow(DtlsProtocols.Dtls13, 5)]
    [DataRow(DtlsProtocols.Dtls12, 6)]
    public async Task Connected_ThousandsOfForgedDatagrams_ChangeNothing(
        DtlsProtocols version,
        int seed
    )
    {
        Random random = new(seed);
        List<byte[]> seen = [];
        Path path = new(observe: seen.Add);
        (DtlsConnection client, DtlsConnection server) = await ConnectAsync(path, version);
        await using (client)
        await using (server)
        {
            (ushort, ushort) clientEpochs = client.Epochs;
            (ushort, ushort) serverEpochs = server.Epochs;
            byte[][] samples;
            lock (seen)
            {
                samples = [.. seen];
            }

            for (int i = 0; i < 2000; i++)
            {
                byte[] forged =
                    random.Next(4) == 0
                        ? RandomBytes(random, random.Next(1, 300))
                        : Mutations(random, samples[random.Next(samples.Length)], 1)[0];
                (i % 2 == 0 ? path.ToServer : path.ToClient).Inject(forged);
            }

            await TalkAsync(client, server, rounds: 3);
            Assert.IsFalse(client.IsFailed);
            Assert.IsFalse(server.IsFailed);
            Assert.AreEqual(clientEpochs, client.Epochs);
            Assert.AreEqual(serverEpochs, server.Epochs);
        }
    }

    [TestMethod]
    [DataRow(DtlsProtocols.Dtls12)]
    [DataRow(DtlsProtocols.Dtls13)]
    public async Task Handshake_ForgedPlaintextRecordWithAHighSequenceNumber_DoesNotBlockIt(
        DtlsProtocols version
    )
    {
        // A blind attacker's single datagram: were unprotected records replay-checked, its sequence
        // number would make every genuine record after it look old.
        Path path = new();
        path.ToServer.Inject([22, 0xFE, 0xFD, 0, 0, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0, 1, 0]);
        path.ToClient.Inject([22, 0xFE, 0xFD, 0, 0, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0, 1, 0]);

        (DtlsConnection client, DtlsConnection server) = await ConnectAsync(
            path,
            version,
            TimeSpan.FromSeconds(10)
        );
        await using (client)
        await using (server)
        {
            await TalkAsync(client, server, rounds: 1);
        }
    }

    [TestMethod]
    public async Task ChangeCipherSpec_InDtls13_IsIgnored()
    {
        Path path = new();
        (DtlsConnection client, DtlsConnection server) = await ConnectAsync(
            path,
            DtlsProtocols.Dtls13
        );
        await using (client)
        await using (server)
        {
            // A plaintext DTLS 1.2-style ChangeCipherSpec record in epoch 0.
            path.ToServer.Inject([20, 0xFE, 0xFD, 0, 0, 0, 0, 0, 0, 0, 9, 0, 1, 1]);
            await TalkAsync(client, server, rounds: 1);
            Assert.AreEqual((ushort)3, server.Epochs.Read);
        }
    }

    private async Task<(DtlsConnection Client, DtlsConnection Server)> ConnectAsync(
        Path path,
        DtlsProtocols version,
        TimeSpan? handshakeTimeout = null
    )
    {
        using X509Certificate2 clientCertificate = DtlsCertificates.CreateSelfSigned();
        using X509Certificate2 serverCertificate = DtlsCertificates.CreateSelfSigned();
        DtlsClientConnectionOptions clientOptions = HandshakeTests.Client(
            clientCertificate,
            serverCertificate
        );
        DtlsServerConnectionOptions serverOptions = HandshakeTests.Server(
            serverCertificate,
            clientCertificate,
            cookieExchange: true
        );
        clientOptions.LoggerFactory = _log;
        serverOptions.LoggerFactory = _log;
        clientOptions.EnabledProtocols = version;
        serverOptions.EnabledProtocols = version;
        clientOptions.InitialRetransmissionTimeout = s_retransmission;
        serverOptions.InitialRetransmissionTimeout = s_retransmission;
        clientOptions.HandshakeTimeout = handshakeTimeout ?? clientOptions.HandshakeTimeout;
        serverOptions.HandshakeTimeout = handshakeTimeout ?? serverOptions.HandshakeTimeout;
        Task<DtlsConnection> server = DtlsConnection
            .AcceptAsync(path.Pair.Server, serverOptions, TestContext.CancellationToken)
            .AsTask();
        Task<DtlsConnection> client = DtlsConnection
            .ConnectAsync(path.Pair.Client, clientOptions, TestContext.CancellationToken)
            .AsTask();
        await Task.WhenAll(server, client).WaitAsync(s_timeout, TestContext.CancellationToken);
        Assert.AreEqual(version, (await client).NegotiatedProtocol);
        return (await client, await server);
    }

    private async Task TalkAsync(DtlsConnection client, DtlsConnection server, int rounds)
    {
        byte[] buffer = new byte[4096];
        for (int i = 0; i < rounds; i++)
        {
            foreach (
                (DtlsConnection from, DtlsConnection to) in (ReadOnlySpan<(
                    DtlsConnection,
                    DtlsConnection
                )>)
                    [(client, server), (server, client)]
            )
            {
                byte[] message = RandomBytes(Random.Shared, 200);
                await from.SendAsync(message, TestContext.CancellationToken);
                int length = await to.ReceiveAsync(buffer, TestContext.CancellationToken)
                    .AsTask()
                    .WaitAsync(s_timeout, TestContext.CancellationToken);
                CollectionAssert.AreEqual(message, buffer[..length]);
            }
        }
    }

    private async Task EventuallyAsync(Func<bool> condition)
    {
        long deadline = Environment.TickCount64 + (long)s_timeout.TotalMilliseconds;
        while (!condition())
        {
            Assert.IsLessThan(
                deadline,
                Environment.TickCount64,
                "The condition did not hold in time."
            );
            await Task.Delay(10, TestContext.CancellationToken);
        }
    }

    private static byte[][] Mutations(Random random, byte[] datagram, int count)
    {
        byte[][] mutations = new byte[count][];
        for (int i = 0; i < count; i++)
        {
            byte[] copy = [.. datagram];
            switch (random.Next(4))
            {
                case 0 when copy.Length > 0:
                    copy[random.Next(copy.Length)] ^= (byte)(1 << random.Next(8));
                    break;
                case 1 when copy.Length > 1:
                    copy = copy[..random.Next(1, copy.Length)];
                    break;
                case 2:
                    copy = [.. copy, .. RandomBytes(random, random.Next(1, 40))];
                    break;
                default:
                    for (int j = 0; j < 4 && copy.Length > 0; j++)
                    {
                        copy[random.Next(copy.Length)] = (byte)random.Next(256);
                    }

                    break;
            }

            mutations[i] = copy;
        }

        return mutations;
    }

    private static byte[] RandomBytes(Random random, int length)
    {
        byte[] bytes = new byte[length];
        random.NextBytes(bytes);
        return bytes;
    }

    // An in-memory path whose directions can drop, hold, forge and inject datagrams.
    private sealed class Path
    {
        public Path(
            Func<byte[], byte[][]>? forge = null,
            Action<byte[]>? observe = null,
            bool forgeFirst = false
        )
        {
            ToServer = new Direction(forge, observe, forgeFirst);
            ToClient = new Direction(forge, observe, forgeFirst);
            ToServer.Name = "C->S";
            ToClient.Name = "S->C";
            Pair = new DatagramPair(toServer: ToServer.Filter, toClient: ToClient.Filter);
            ToServer.Deliver = Pair.Client.Inject;
            ToClient.Deliver = Pair.Server.Inject;
        }

        public DatagramPair Pair { get; }

        public Direction ToServer { get; }

        public Direction ToClient { get; }
    }

    private sealed class Direction(
        Func<byte[], byte[][]>? forge,
        Action<byte[]>? observe,
        bool forgeFirst
    )
    {
        private static readonly Lock s_forging = new();
        private readonly Lock _lock = new();
        private int _drop;
        private bool _hold;
        private byte[]? _held;

        public Action<byte[]> Deliver { get; set; } = static _ => { };

        public void DropNext(int count)
        {
            lock (_lock)
            {
                _drop = count;
            }
        }

        public void HoldNext()
        {
            lock (_lock)
            {
                _hold = true;
            }
        }

        public void Release()
        {
            byte[]? held;
            lock (_lock)
            {
                held = _held;
                _held = null;
            }

            if (held is not null)
            {
                Deliver(held);
            }
        }

        public void Inject(byte[] datagram) => Deliver(datagram);

        public bool Filter(int index, byte[] datagram)
        {
            if (observe is not null)
            {
                lock (_lock)
                {
                    observe(datagram);
                }
            }

            lock (_lock)
            {
                if (_drop > 0)
                {
                    _drop--;
                    return false;
                }

                if (_hold)
                {
                    _hold = false;
                    _held = datagram;
                    return false;
                }
            }

            byte[][] forgeries = [];
            if (forge is not null)
            {
                // The forger's Random is not thread-safe, and both sides send at once.
                lock (s_forging)
                {
                    forgeries = forge(datagram);
                }
            }

            if (forgeries.Length == 0 || forgeFirst)
            {
                foreach (byte[] forged in forgeries)
                {
                    Deliver(forged);
                }

                return true;
            }

            Trace.Enqueue($"{Name} genuine {Describe(datagram)}");
            Deliver(datagram);
            foreach (byte[] forged in forgeries)
            {
                Trace.Enqueue($"{Name}  forged {Describe(forged)}");
                Deliver(forged);
            }

            return false;
        }

        public static System.Collections.Concurrent.ConcurrentQueue<string> Trace { get; } = new();

        public string Name { get; set; } = "";

        private static string Describe(byte[] d)
        {
            System.Text.StringBuilder s = new($"len={d.Length}");
            int at = 0;
            while (at + 13 <= d.Length && (d[at] & 0xE0) != 0x20)
            {
                int length = (d[at + 11] << 8) | d[at + 12];
                _ = s.Append(
                    $" [t={d[at]} e={(d[at + 3] << 8) | d[at + 4]} s={d[at + 10]} n={length}"
                );
                if (d[at] == 22 && at + 25 <= d.Length)
                {
                    _ = s.Append(
                        $" hs={d[at + 13]} len={(d[at + 14] << 16) | (d[at + 15] << 8) | d[at + 16]} seq={(d[at + 17] << 8) | d[at + 18]} off={(d[at + 19] << 16) | (d[at + 20] << 8) | d[at + 21]} cnt={(d[at + 22] << 16) | (d[at + 23] << 8) | d[at + 24]}"
                    );
                }

                _ = s.Append(']');
                at += 13 + length;
            }

            if (at < d.Length)
            {
                _ = s.Append($" [rest {d.Length - at} first={d[at]:X2}]");
            }

            return s.ToString();
        }
    }
}
