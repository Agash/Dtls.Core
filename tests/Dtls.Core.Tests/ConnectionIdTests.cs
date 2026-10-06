using System.Collections.Concurrent;
using System.Security.Cryptography.X509Certificates;

namespace Dtls.Core.Tests;

// Connection IDs (RFC 9146, RFC 9147 section 9) and record size limits (RFC 8449).
[TestClass]
public sealed class ConnectionIdTests
{
    private static readonly TimeSpan s_timeout = TimeSpan.FromSeconds(30);

    public TestContext TestContext { get; set; } = null!;

    // Both ask for one: each side's protected records carry the CID the other asked for, which shows on
    // the wire as tls12_cid records (DTLS 1.2) or the unified header's C bit (DTLS 1.3).
    [TestMethod]
    [DataRow(DtlsProtocols.Dtls12)]
    [DataRow(DtlsProtocols.Dtls13)]
    public async Task BothAskForConnectionIds_RecordsCarryThem(DtlsProtocols version)
    {
        ConcurrentQueue<byte[]> toServer = new();
        DatagramPair path = new(toServer: (_, d) => Record(toServer, d));
        (DtlsConnection client, DtlsConnection server) = await ConnectAsync(
            path,
            version,
            static c => c.ConnectionIdLength = 8,
            static s => s.ConnectionIdLength = 8
        );
        await using (client)
        await using (server)
        {
            Assert.AreEqual(8, client.LocalConnectionId.Length);
            Assert.AreEqual(8, server.LocalConnectionId.Length);
            CollectionAssert.AreEqual(
                client.LocalConnectionId.ToArray(),
                server.RemoteConnectionId.ToArray()
            );
            CollectionAssert.AreEqual(
                server.LocalConnectionId.ToArray(),
                client.RemoteConnectionId.ToArray()
            );
            toServer.Clear();
            await CarriesAsync(client, server);
            await CarriesAsync(server, client);

            byte[] cid = server.LocalConnectionId.ToArray();
            byte[] datagram = toServer.Last();
            if (version == DtlsProtocols.Dtls12)
            {
                Assert.AreEqual(25, datagram[0], "tls12_cid");
                CollectionAssert.AreEqual(cid, datagram.AsSpan(11, 8).ToArray());
            }
            else
            {
                Assert.AreEqual(0x10, datagram[0] & 0x10, "the C bit");
                CollectionAssert.AreEqual(cid, datagram.AsSpan(1, 8).ToArray());
            }
        }
    }

    [TestMethod]
    [DataRow(DtlsProtocols.Dtls12)]
    [DataRow(DtlsProtocols.Dtls13)]
    public async Task ClientDoesNotOffer_NoConnectionIds(DtlsProtocols version)
    {
        (DtlsConnection client, DtlsConnection server) = await ConnectAsync(
            new DatagramPair(),
            version,
            static c => c.ConnectionIdLength = null,
            static s => s.ConnectionIdLength = 8
        );
        await using (client)
        await using (server)
        {
            Assert.AreEqual(0, client.RemoteConnectionId.Length);
            Assert.AreEqual(0, server.RemoteConnectionId.Length);
            await CarriesAsync(client, server);
            await CarriesAsync(server, client);
        }
    }

    // RFC 9146 section 3: an empty CID asks for none but still sends the peer's.
    [TestMethod]
    [DataRow(DtlsProtocols.Dtls12)]
    [DataRow(DtlsProtocols.Dtls13)]
    public async Task OneSideAsksForNone_OnlyTheOtherDirectionCarriesOne(DtlsProtocols version)
    {
        (DtlsConnection client, DtlsConnection server) = await ConnectAsync(
            new DatagramPair(),
            version,
            static c => c.ConnectionIdLength = 0,
            static s => s.ConnectionIdLength = 4
        );
        await using (client)
        await using (server)
        {
            Assert.AreEqual(4, client.RemoteConnectionId.Length, "the client sends the server's");
            Assert.AreEqual(0, server.RemoteConnectionId.Length, "the server sends none");
            await CarriesAsync(client, server);
            await CarriesAsync(server, client);
        }
    }

    // A record whose CID is not the receiver's is dropped.
    [TestMethod]
    [DataRow(DtlsProtocols.Dtls12, 11)]
    [DataRow(DtlsProtocols.Dtls13, 1)]
    public async Task WrongConnectionId_IsDropped(DtlsProtocols version, int cidAt)
    {
        ConcurrentQueue<byte[]> toServer = new();
        DatagramPair path = new(toServer: (_, d) => Record(toServer, d));
        (DtlsConnection client, DtlsConnection server) = await ConnectAsync(
            path,
            version,
            static c => c.ConnectionIdLength = 8,
            static s => s.ConnectionIdLength = 8
        );
        await using (client)
        await using (server)
        {
            toServer.Clear();
            await CarriesAsync(client, server);
            byte[] forged = toServer.Last();
            forged[cidAt] ^= 0xFF;
            long before = server.Statistics.RecordsDropped;
            path.Client.Inject(forged);
            await CarriesAsync(client, server);

            Assert.IsGreaterThan(before, server.Statistics.RecordsDropped);
        }
    }

    // RFC 8449: the server's limit reaches the client, which keeps its protected records within it.
    [TestMethod]
    [DataRow(DtlsProtocols.Dtls12, 256)]
    [DataRow(DtlsProtocols.Dtls13, 255)]
    public async Task RecordSizeLimit_BoundsWhatThePeerSends(DtlsProtocols version, int maximum)
    {
        (DtlsConnection client, DtlsConnection server) = await ConnectAsync(
            new DatagramPair(),
            version,
            static _ => { },
            static s => s.RecordSizeLimit = 256
        );
        await using (client)
        await using (server)
        {
            Assert.AreEqual(256, client.PeerRecordSizeLimit);
            Assert.AreEqual(maximum, client.MaximumApplicationDataSize);
            await CarriesAsync(client, server);
            await CarriesAsync(server, client);
        }
    }

    // RFC 9147 section 9: NewConnectionId gives spares, used in order when this side moves to one.
    [TestMethod]
    public async Task IssuedSpares_ThePeerSwitchesToThemInOrder()
    {
        ConcurrentQueue<byte[]> toServer = new();
        DatagramPair path = new(toServer: (_, d) => Record(toServer, d));
        (DtlsConnection client, DtlsConnection server) = await Connect13Async(path);
        await using (client)
        await using (server)
        {
            byte[] first = client.RemoteConnectionId.ToArray();
            await server.IssueConnectionIdsAsync(
                3,
                cancellationToken: TestContext.CancellationToken
            );
            await CarriesAsync(server, client);
            Assert.AreEqual(3, client.SpareConnectionIds);

            Assert.IsTrue(client.TryUseNextConnectionId());
            byte[] next = client.RemoteConnectionId.ToArray();
            CollectionAssert.AreNotEqual(first, next);
            toServer.Clear();
            await CarriesAsync(client, server);
            CollectionAssert.AreEqual(next, toServer.Last().AsSpan(1, 8).ToArray());
            Assert.AreEqual(2, client.SpareConnectionIds);
        }
    }

    [TestMethod]
    public async Task IssuedImmediately_ThePeerUsesItAtOnce()
    {
        ConcurrentQueue<byte[]> toServer = new();
        DatagramPair path = new(toServer: (_, d) => Record(toServer, d));
        (DtlsConnection client, DtlsConnection server) = await Connect13Async(path);
        await using (client)
        await using (server)
        {
            byte[] first = client.RemoteConnectionId.ToArray();
            await server.IssueConnectionIdsAsync(
                2,
                useImmediately: true,
                TestContext.CancellationToken
            );
            await CarriesAsync(server, client);

            CollectionAssert.AreNotEqual(first, client.RemoteConnectionId.ToArray());
            Assert.AreEqual(1, client.SpareConnectionIds);
            toServer.Clear();
            await CarriesAsync(client, server);
            CollectionAssert.AreEqual(
                client.RemoteConnectionId.ToArray(),
                toServer.Last().AsSpan(1, 8).ToArray()
            );
        }
    }

    // RequestConnectionId is answered with spares; a second request waits for the first's answer.
    [TestMethod]
    public async Task RequestedConnectionIds_ArriveAsSpares()
    {
        // The request is held back at first, so it is still unanswered when the second one is tried.
        bool hold = false;
        DatagramPair path = new(toServer: (_, _) => !Volatile.Read(ref hold));
        (DtlsConnection client, DtlsConnection server) = await Connect13Async(path);
        await using (client)
        await using (server)
        {
            Volatile.Write(ref hold, true);
            await client.RequestConnectionIdsAsync(4, TestContext.CancellationToken);
            _ = await Assert.ThrowsExactlyAsync<InvalidOperationException>(async () =>
                await client.RequestConnectionIdsAsync(1, TestContext.CancellationToken)
            );
            Volatile.Write(ref hold, false);
            await CarriesAsync(client, server);
            await CarriesAsync(server, client);
            // The held request goes again on the retransmission timer.
            long deadline = Environment.TickCount64 + 10_000;
            while (client.SpareConnectionIds == 0 && Environment.TickCount64 < deadline)
            {
                await CarriesAsync(server, client);
            }

            Assert.AreEqual(4, client.SpareConnectionIds);
            await client.RequestConnectionIdsAsync(1, TestContext.CancellationToken);
        }
    }

    // A KeyUpdate that comes up while a NewConnectionId is unacknowledged follows it; both complete.
    [TestMethod]
    public async Task KeyUpdateDuringNewConnectionId_BothComplete()
    {
        (DtlsConnection client, DtlsConnection server) = await Connect13Async(new DatagramPair());
        await using (client)
        await using (server)
        {
            ushort epoch = server.Epochs.Write;
            await server.IssueConnectionIdsAsync(
                2,
                cancellationToken: TestContext.CancellationToken
            );
            await server.RequestKeyUpdateAsync();
            for (int i = 0; i < 4; i++)
            {
                await CarriesAsync(server, client);
                await CarriesAsync(client, server);
            }

            Assert.AreEqual(2, client.SpareConnectionIds);
            Assert.AreEqual(epoch + 1, server.Epochs.Write);
        }
    }

    // RFC 9147 section 9: the messages need DTLS 1.3 with CIDs agreed, and a non-empty CID on the side
    // that gives them or the side that asks.
    [TestMethod]
    public async Task ConnectionIdManagement_WithoutTheRightCid_IsRefused()
    {
        (DtlsConnection client, DtlsConnection server) = await ConnectAsync(
            new DatagramPair(),
            DtlsProtocols.Dtls13,
            static c => c.ConnectionIdLength = 0,
            static s => s.ConnectionIdLength = 8
        );
        await using (client)
        await using (server)
        {
            _ = await Assert.ThrowsExactlyAsync<InvalidOperationException>(async () =>
                await client.IssueConnectionIdsAsync(
                    1,
                    cancellationToken: TestContext.CancellationToken
                )
            );
            _ = await Assert.ThrowsExactlyAsync<InvalidOperationException>(async () =>
                await server.RequestConnectionIdsAsync(1, TestContext.CancellationToken)
            );
        }

        (client, server) = await ConnectAsync(
            new DatagramPair(),
            DtlsProtocols.Dtls12,
            static c => c.ConnectionIdLength = 8,
            static s => s.ConnectionIdLength = 8
        );
        await using (client)
        await using (server)
        {
            _ = await Assert.ThrowsExactlyAsync<InvalidOperationException>(async () =>
                await server.IssueConnectionIdsAsync(
                    1,
                    cancellationToken: TestContext.CancellationToken
                )
            );
        }
    }

    private Task<(DtlsConnection Client, DtlsConnection Server)> Connect13Async(
        DatagramPair path
    ) =>
        ConnectAsync(
            path,
            DtlsProtocols.Dtls13,
            static c => c.ConnectionIdLength = 8,
            static s => s.ConnectionIdLength = 8
        );

    private static bool Record(ConcurrentQueue<byte[]> seen, byte[] datagram)
    {
        seen.Enqueue(datagram);
        return true;
    }

    private async Task CarriesAsync(DtlsConnection from, DtlsConnection to)
    {
        byte[] message = new byte[from.MaximumApplicationDataSize];
        Random.Shared.NextBytes(message);
        await from.SendAsync(message, TestContext.CancellationToken);
        byte[] buffer = new byte[4096];
        int length = await to.ReceiveAsync(buffer, TestContext.CancellationToken)
            .AsTask()
            .WaitAsync(s_timeout, TestContext.CancellationToken);
        CollectionAssert.AreEqual(message, buffer.AsSpan(0, length).ToArray());
    }

    private async Task<(DtlsConnection Client, DtlsConnection Server)> ConnectAsync(
        DatagramPair path,
        DtlsProtocols version,
        Action<DtlsClientConnectionOptions> client,
        Action<DtlsServerConnectionOptions> server
    )
    {
        using X509Certificate2 clientCertificate = DtlsCertificates.CreateSelfSigned(
            DtlsKeyType.EcdsaP256
        );
        using X509Certificate2 serverCertificate = DtlsCertificates.CreateSelfSigned(
            DtlsKeyType.EcdsaP256
        );
        DtlsClientConnectionOptions clientOptions = HandshakeTests.Client(
            clientCertificate,
            serverCertificate
        );
        DtlsServerConnectionOptions serverOptions = HandshakeTests.Server(
            serverCertificate,
            clientCertificate,
            cookieExchange: true
        );
        clientOptions.EnabledProtocols = version;
        serverOptions.EnabledProtocols = version;
        client(clientOptions);
        server(serverOptions);
        Task<DtlsConnection> accepting = DtlsConnection
            .AcceptAsync(path.Server, serverOptions, TestContext.CancellationToken)
            .AsTask();
        Task<DtlsConnection> connecting = DtlsConnection
            .ConnectAsync(path.Client, clientOptions, TestContext.CancellationToken)
            .AsTask();
        await Task.WhenAll(accepting, connecting)
            .WaitAsync(s_timeout, TestContext.CancellationToken);
        return (await connecting, await accepting);
    }
}
