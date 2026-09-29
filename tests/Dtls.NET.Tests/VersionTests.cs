using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace Dtls.NET.Tests;

// Version negotiation between DTLS 1.2 and 1.3, and DTLS 1.3 handshakes in memory.
[TestClass]
public sealed class VersionTests
{
    private static readonly TimeSpan s_timeout = TimeSpan.FromSeconds(30);

    public TestContext TestContext { get; set; } = null!;

    private readonly TestLog _log = new();

    [TestCleanup]
    public void PrintLog()
    {
        if (TestContext.CurrentTestOutcome != UnitTestOutcome.Passed)
        {
            TestContext.WriteLine(_log.ToString());
        }
    }

    [TestMethod]
    [DataRow(
        DtlsProtocols.Dtls12 | DtlsProtocols.Dtls13,
        DtlsProtocols.Dtls12 | DtlsProtocols.Dtls13,
        DtlsProtocols.Dtls13
    )]
    [DataRow(
        DtlsProtocols.Dtls13,
        DtlsProtocols.Dtls12 | DtlsProtocols.Dtls13,
        DtlsProtocols.Dtls13
    )]
    [DataRow(
        DtlsProtocols.Dtls12 | DtlsProtocols.Dtls13,
        DtlsProtocols.Dtls13,
        DtlsProtocols.Dtls13
    )]
    [DataRow(
        DtlsProtocols.Dtls12,
        DtlsProtocols.Dtls12 | DtlsProtocols.Dtls13,
        DtlsProtocols.Dtls12
    )]
    [DataRow(
        DtlsProtocols.Dtls12 | DtlsProtocols.Dtls13,
        DtlsProtocols.Dtls12,
        DtlsProtocols.Dtls12
    )]
    public async Task Handshake_EnabledVersions_AgreeOnTheHighestShared(
        DtlsProtocols client,
        DtlsProtocols server,
        DtlsProtocols expected
    )
    {
        (DtlsConnection clientConnection, DtlsConnection serverConnection) = await ConnectAsync(
            new DatagramPair(),
            client,
            server,
            DtlsKeyType.EcdsaP256,
            cookieExchange: true
        );
        await using (clientConnection)
        await using (serverConnection)
        {
            Assert.AreEqual(expected, clientConnection.NegotiatedProtocol);
            Assert.AreEqual(expected, serverConnection.NegotiatedProtocol);
            await AssertAgreeAsync(clientConnection, serverConnection);
        }
    }

    [TestMethod]
    [DataRow(DtlsKeyType.EcdsaP256, true)]
    [DataRow(DtlsKeyType.EcdsaP384, false)]
    [DataRow(DtlsKeyType.Rsa2048, true)]
    public async Task Handshake_Dtls13_AuthenticatesBothSides(
        DtlsKeyType keyType,
        bool cookieExchange
    )
    {
        (DtlsConnection client, DtlsConnection server) = await ConnectAsync(
            new DatagramPair(),
            DtlsProtocols.Dtls13,
            DtlsProtocols.Dtls13,
            keyType,
            cookieExchange
        );
        await using (client)
        await using (server)
        {
            Assert.AreEqual(DtlsProtocols.Dtls13, client.NegotiatedProtocol);
            Assert.IsNotNull(client.RemoteCertificate);
            Assert.IsNotNull(server.RemoteCertificate);
            await AssertAgreeAsync(client, server);
        }
    }

    [TestMethod]
    public async Task Handshake_Dtls13OverALossyPath_Completes()
    {
        DatagramPair path = new(
            toServer: static (i, _) => i != 0 && i % 3 != 1,
            toClient: static (i, _) => i != 0 && i % 3 != 2
        );
        (DtlsConnection client, DtlsConnection server) = await ConnectAsync(
            path,
            DtlsProtocols.Dtls13,
            DtlsProtocols.Dtls13,
            DtlsKeyType.EcdsaP256,
            cookieExchange: true,
            retransmission: TimeSpan.FromMilliseconds(100)
        );
        await using (client)
        await using (server)
        {
            // Keys only: the path goes on losing datagrams, and application data is not retransmitted.
            Assert.AreEqual(DtlsProtocols.Dtls13, client.NegotiatedProtocol);
            CollectionAssert.AreEqual(
                client.SrtpKeyingMaterial!.ClientMasterKey.ToArray(),
                server.SrtpKeyingMaterial!.ClientMasterKey.ToArray()
            );
        }
    }

    [TestMethod]
    public async Task Handshake_Dtls13SmallDatagrams_FragmentsTheFlights()
    {
        (DtlsConnection client, DtlsConnection server) = await ConnectAsync(
            new DatagramPair(),
            DtlsProtocols.Dtls13,
            DtlsProtocols.Dtls13,
            DtlsKeyType.Rsa2048,
            cookieExchange: true,
            maximumDatagram: 256
        );
        await using (client)
        await using (server)
        {
            await AssertAgreeAsync(client, server);
        }
    }

    [TestMethod]
    public async Task KeyUpdate_Dtls13_BothSidesKeepTalking()
    {
        (DtlsConnection client, DtlsConnection server) = await ConnectAsync(
            new DatagramPair(),
            DtlsProtocols.Dtls13,
            DtlsProtocols.Dtls13,
            DtlsKeyType.EcdsaP256,
            cookieExchange: false
        );
        await using (client)
        await using (server)
        {
            await client.RequestKeyUpdateAsync();
            for (int i = 0; i < 3; i++)
            {
                await AssertCarriesAsync(client, server);
                await AssertCarriesAsync(server, client);
            }
        }
    }

    [TestMethod]
    public async Task Handshake_NoSharedVersion_Fails()
    {
        Task<(DtlsConnection, DtlsConnection)> connecting = ConnectAsync(
            new DatagramPair(),
            DtlsProtocols.Dtls13,
            DtlsProtocols.Dtls12,
            DtlsKeyType.EcdsaP256,
            cookieExchange: false
        );

        _ = await Assert.ThrowsExactlyAsync<AuthenticationException>(() => connecting);
    }

    private async Task<(DtlsConnection Client, DtlsConnection Server)> ConnectAsync(
        DatagramPair path,
        DtlsProtocols clientVersions,
        DtlsProtocols serverVersions,
        DtlsKeyType keyType,
        bool cookieExchange,
        TimeSpan? retransmission = null,
        int maximumDatagram = 1200
    )
    {
        using X509Certificate2 clientCertificate = DtlsCertificates.CreateSelfSigned(keyType);
        using X509Certificate2 serverCertificate = DtlsCertificates.CreateSelfSigned(keyType);
        DtlsClientConnectionOptions clientOptions = HandshakeTests.Client(
            clientCertificate,
            serverCertificate
        );
        DtlsServerConnectionOptions serverOptions = HandshakeTests.Server(
            serverCertificate,
            clientCertificate,
            cookieExchange
        );
        clientOptions.LoggerFactory = _log;
        serverOptions.LoggerFactory = _log;
        clientOptions.EnabledProtocols = clientVersions;
        serverOptions.EnabledProtocols = serverVersions;
        clientOptions.MaximumDatagramSize = maximumDatagram;
        serverOptions.MaximumDatagramSize = maximumDatagram;
        if (retransmission is { } timeout)
        {
            clientOptions.InitialRetransmissionTimeout = timeout;
            serverOptions.InitialRetransmissionTimeout = timeout;
        }

        Task<DtlsConnection> server = DtlsConnection
            .AcceptAsync(path.Server, serverOptions, TestContext.CancellationToken)
            .AsTask();
        Task<DtlsConnection> client = DtlsConnection
            .ConnectAsync(path.Client, clientOptions, TestContext.CancellationToken)
            .AsTask();
        try
        {
            await Task.WhenAll(server, client).WaitAsync(s_timeout, TestContext.CancellationToken);
        }
        catch
        {
            await DisposeAsync(server);
            await DisposeAsync(client);
            throw;
        }

        return (await client, await server);
    }

    private static async Task DisposeAsync(Task<DtlsConnection> connecting)
    {
        if (connecting.IsCompletedSuccessfully)
        {
            await connecting.Result.DisposeAsync();
        }
    }

    private async Task AssertAgreeAsync(DtlsConnection client, DtlsConnection server)
    {
        Assert.AreEqual(client.NegotiatedCipherSuite, server.NegotiatedCipherSuite);
        CollectionAssert.AreEqual(
            client.SrtpKeyingMaterial!.ClientMasterKey.ToArray(),
            server.SrtpKeyingMaterial!.ClientMasterKey.ToArray()
        );
        CollectionAssert.AreEqual(
            client.SrtpKeyingMaterial.ServerMasterSalt.ToArray(),
            server.SrtpKeyingMaterial.ServerMasterSalt.ToArray()
        );
        byte[] a = new byte[32];
        byte[] b = new byte[32];
        client.ExportKeyingMaterial("EXPORTER-test", [7], a);
        server.ExportKeyingMaterial("EXPORTER-test", [7], b);
        CollectionAssert.AreEqual(a, b);
        await AssertCarriesAsync(client, server);
        await AssertCarriesAsync(server, client);
    }

    private async Task AssertCarriesAsync(DtlsConnection from, DtlsConnection to)
    {
        byte[] message = new byte[from.MaximumApplicationDataSize];
        Random.Shared.NextBytes(message);
        await from.SendAsync(message, TestContext.CancellationToken);
        byte[] buffer = new byte[4096];
        int length = await to.ReceiveAsync(buffer, TestContext.CancellationToken)
            .AsTask()
            .WaitAsync(s_timeout, TestContext.CancellationToken);
        CollectionAssert.AreEqual(message, buffer[..length]);
    }
}
