using System.Net.Security;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace Dtls.NET.Tests;

[TestClass]
public sealed class HandshakeTests
{
    private static readonly TimeSpan s_testTimeout = TimeSpan.FromSeconds(30);

    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    [DataRow(DtlsKeyType.EcdsaP256, true)]
    [DataRow(DtlsKeyType.EcdsaP256, false)]
    [DataRow(DtlsKeyType.EcdsaP384, true)]
    [DataRow(DtlsKeyType.Rsa2048, true)]
    public async Task Handshake_WebRtcPeers_AgreeOnKeysAndCarryData(
        DtlsKeyType keyType,
        bool cookieExchange
    )
    {
        using X509Certificate2 clientCertificate = DtlsCertificates.CreateSelfSigned(keyType);
        using X509Certificate2 serverCertificate = DtlsCertificates.CreateSelfSigned(keyType);
        DatagramPair path = new();

        (DtlsConnection client, DtlsConnection server) = await ConnectAsync(
            path,
            Client(clientCertificate, serverCertificate),
            Server(serverCertificate, clientCertificate, cookieExchange)
        );
        await using (client)
        await using (server)
        {
            Assert.AreEqual(client.NegotiatedCipherSuite, server.NegotiatedCipherSuite);
            Assert.AreEqual(
                SrtpProtectionProfile.AeadAes128Gcm,
                client.SrtpKeyingMaterial!.Profile
            );
            AssertSameKeys(client.SrtpKeyingMaterial, server.SrtpKeyingMaterial!);
            Assert.AreEqual(serverCertificate.Thumbprint, client.RemoteCertificate!.Thumbprint);
            Assert.AreEqual(clientCertificate.Thumbprint, server.RemoteCertificate!.Thumbprint);

            byte[] clientExport = new byte[40];
            byte[] serverExport = new byte[40];
            client.ExportKeyingMaterial("EXPORTER-test", [1, 2, 3], clientExport);
            server.ExportKeyingMaterial("EXPORTER-test", [1, 2, 3], serverExport);
            CollectionAssert.AreEqual(clientExport, serverExport);

            await AssertCarriesAsync(client, server);
            await AssertCarriesAsync(server, client);
        }
    }

    [TestMethod]
    public async Task Handshake_OverALossyPath_Completes()
    {
        using X509Certificate2 clientCertificate = DtlsCertificates.CreateSelfSigned();
        using X509Certificate2 serverCertificate = DtlsCertificates.CreateSelfSigned();

        // Lose the first transmission of every flight in both directions, and every third datagram
        // after that, so each side has to retransmit and to answer retransmissions.
        DatagramPair path = new(
            toServer: static (i, _) => i != 0 && i % 3 != 1,
            toClient: static (i, _) => i != 0 && i % 3 != 2
        );
        DtlsClientConnectionOptions clientOptions = Client(clientCertificate, serverCertificate);
        DtlsServerConnectionOptions serverOptions = Server(
            serverCertificate,
            clientCertificate,
            cookieExchange: true
        );
        clientOptions.InitialRetransmissionTimeout = TimeSpan.FromMilliseconds(100);
        serverOptions.InitialRetransmissionTimeout = TimeSpan.FromMilliseconds(100);

        (DtlsConnection client, DtlsConnection server) = await ConnectAsync(
            path,
            clientOptions,
            serverOptions
        );
        await using (client)
        await using (server)
        {
            AssertSameKeys(client.SrtpKeyingMaterial!, server.SrtpKeyingMaterial!);
        }
    }

    [TestMethod]
    public async Task Handshake_SmallDatagrams_FragmentsTheFlights()
    {
        using X509Certificate2 clientCertificate = DtlsCertificates.CreateSelfSigned(
            DtlsKeyType.Rsa2048
        );
        using X509Certificate2 serverCertificate = DtlsCertificates.CreateSelfSigned(
            DtlsKeyType.Rsa2048
        );
        int largest = 0;
        DatagramPair path = new(toServer: (_, d) => Track(d), toClient: (_, d) => Track(d));
        DtlsClientConnectionOptions clientOptions = Client(clientCertificate, serverCertificate);
        DtlsServerConnectionOptions serverOptions = Server(
            serverCertificate,
            clientCertificate,
            cookieExchange: true
        );
        clientOptions.MaximumDatagramSize = 256;
        serverOptions.MaximumDatagramSize = 256;

        (DtlsConnection client, DtlsConnection server) = await ConnectAsync(
            path,
            clientOptions,
            serverOptions
        );
        await using (client)
        await using (server)
        {
            Assert.IsLessThanOrEqualTo(256, largest);
            await AssertCarriesAsync(client, server);
        }

        bool Track(byte[] datagram)
        {
            _ = Interlocked.Exchange(
                ref largest,
                Math.Max(Volatile.Read(ref largest), datagram.Length)
            );
            return true;
        }
    }

    [TestMethod]
    public async Task Handshake_WrongFingerprint_FailsBothSides()
    {
        using X509Certificate2 clientCertificate = DtlsCertificates.CreateSelfSigned();
        using X509Certificate2 serverCertificate = DtlsCertificates.CreateSelfSigned();
        using X509Certificate2 impostor = DtlsCertificates.CreateSelfSigned();
        DatagramPair path = new();

        Task<DtlsConnection> server = DtlsConnection
            .AcceptAsync(
                path.Server,
                Server(serverCertificate, clientCertificate, cookieExchange: true),
                TestContext.CancellationToken
            )
            .AsTask();
        Task<DtlsConnection> client = DtlsConnection
            .ConnectAsync(
                path.Client,
                Client(clientCertificate, impostor),
                TestContext.CancellationToken
            )
            .AsTask();

        AuthenticationException clientError =
            await Assert.ThrowsExactlyAsync<AuthenticationException>(() =>
                client.WaitAsync(s_testTimeout, TestContext.CancellationToken)
            );
        AuthenticationException serverError =
            await Assert.ThrowsExactlyAsync<AuthenticationException>(() =>
                server.WaitAsync(s_testTimeout, TestContext.CancellationToken)
            );

        DtlsException clientDtls = Assert.IsInstanceOfType<DtlsException>(
            clientError.InnerException
        );
        Assert.AreEqual(DtlsAlert.BadCertificate, clientDtls.Alert);
        Assert.IsFalse(clientDtls.IsRemote);
        DtlsException serverDtls = Assert.IsInstanceOfType<DtlsException>(
            serverError.InnerException
        );
        Assert.AreEqual(DtlsAlert.BadCertificate, serverDtls.Alert);
        Assert.IsTrue(serverDtls.IsRemote);
    }

    [TestMethod]
    public async Task Handshake_NoCommonSrtpProfile_Fails()
    {
        using X509Certificate2 clientCertificate = DtlsCertificates.CreateSelfSigned();
        using X509Certificate2 serverCertificate = DtlsCertificates.CreateSelfSigned();
        DatagramPair path = new();
        DtlsClientConnectionOptions clientOptions = Client(clientCertificate, serverCertificate);
        clientOptions.SrtpProtectionProfiles = [SrtpProtectionProfile.Aes128CmHmacSha132];

        Task<DtlsConnection> server = DtlsConnection
            .AcceptAsync(
                path.Server,
                Server(serverCertificate, clientCertificate, cookieExchange: false),
                TestContext.CancellationToken
            )
            .AsTask();
        Task<DtlsConnection> client = DtlsConnection
            .ConnectAsync(path.Client, clientOptions, TestContext.CancellationToken)
            .AsTask();

        AuthenticationException serverError =
            await Assert.ThrowsExactlyAsync<AuthenticationException>(() =>
                server.WaitAsync(s_testTimeout, TestContext.CancellationToken)
            );
        AuthenticationException clientError =
            await Assert.ThrowsExactlyAsync<AuthenticationException>(() =>
                client.WaitAsync(s_testTimeout, TestContext.CancellationToken)
            );

        Assert.AreEqual(
            DtlsAlert.HandshakeFailure,
            ((DtlsException)serverError.InnerException!).Alert
        );
        Assert.IsTrue(((DtlsException)clientError.InnerException!).IsRemote);
    }

    [TestMethod]
    public async Task Handshake_NoPeer_TimesOut()
    {
        using X509Certificate2 clientCertificate = DtlsCertificates.CreateSelfSigned();
        using X509Certificate2 serverCertificate = DtlsCertificates.CreateSelfSigned();
        DatagramPair path = new();
        DtlsClientConnectionOptions options = Client(clientCertificate, serverCertificate);
        options.HandshakeTimeout = TimeSpan.FromMilliseconds(500);
        options.InitialRetransmissionTimeout = TimeSpan.FromMilliseconds(100);

        await Assert.ThrowsExactlyAsync<TimeoutException>(() =>
            DtlsConnection
                .ConnectAsync(path.Client, options, TestContext.CancellationToken)
                .AsTask()
                .WaitAsync(s_testTimeout, TestContext.CancellationToken)
        );
        Assert.IsGreaterThan(1, path.Client.Sent);
    }

    [TestMethod]
    public async Task Handshake_Cancelled_Throws()
    {
        using X509Certificate2 clientCertificate = DtlsCertificates.CreateSelfSigned();
        using X509Certificate2 serverCertificate = DtlsCertificates.CreateSelfSigned();
        DatagramPair path = new();
        using CancellationTokenSource cancel = new(TimeSpan.FromMilliseconds(200));

        await Assert.ThrowsAsync<OperationCanceledException>(() =>
            DtlsConnection
                .ConnectAsync(
                    path.Client,
                    Client(clientCertificate, serverCertificate),
                    cancel.Token
                )
                .AsTask()
        );
    }

    [TestMethod]
    public async Task CloseAsync_ByThePeer_EndsReceiving()
    {
        using X509Certificate2 clientCertificate = DtlsCertificates.CreateSelfSigned();
        using X509Certificate2 serverCertificate = DtlsCertificates.CreateSelfSigned();
        DatagramPair path = new();

        (DtlsConnection client, DtlsConnection server) = await ConnectAsync(
            path,
            Client(clientCertificate, serverCertificate),
            Server(serverCertificate, clientCertificate, cookieExchange: true)
        );
        await using (client)
        await using (server)
        {
            await client.SendAsync(new byte[] { 7 }, TestContext.CancellationToken);
            await client.CloseAsync(TestContext.CancellationToken);

            byte[] buffer = new byte[2048];
            Assert.AreEqual(
                1,
                await server
                    .ReceiveAsync(buffer, TestContext.CancellationToken)
                    .AsTask()
                    .WaitAsync(s_testTimeout, TestContext.CancellationToken)
            );
            Assert.AreEqual(
                0,
                await server
                    .ReceiveAsync(buffer, TestContext.CancellationToken)
                    .AsTask()
                    .WaitAsync(s_testTimeout, TestContext.CancellationToken)
            );
            DtlsException error = await Assert.ThrowsExactlyAsync<DtlsException>(() =>
                server.SendAsync(new byte[] { 1 }, TestContext.CancellationToken).AsTask()
            );
            Assert.IsTrue(error.IsRemote);
        }
    }

    [TestMethod]
    public async Task ExportKeyingMaterial_ReservedLabel_Throws()
    {
        using X509Certificate2 clientCertificate = DtlsCertificates.CreateSelfSigned();
        using X509Certificate2 serverCertificate = DtlsCertificates.CreateSelfSigned();
        (DtlsConnection client, DtlsConnection server) = await ConnectAsync(
            new DatagramPair(),
            Client(clientCertificate, serverCertificate),
            Server(serverCertificate, clientCertificate, cookieExchange: false)
        );
        await using (client)
        await using (server)
        {
            Assert.ThrowsExactly<ArgumentException>(() =>
                client.ExportKeyingMaterial("master secret", new byte[16])
            );
        }
    }

    private async Task<(DtlsConnection Client, DtlsConnection Server)> ConnectAsync(
        DatagramPair path,
        DtlsClientConnectionOptions clientOptions,
        DtlsServerConnectionOptions serverOptions
    )
    {
        Task<DtlsConnection> server = DtlsConnection
            .AcceptAsync(path.Server, serverOptions, TestContext.CancellationToken)
            .AsTask();
        Task<DtlsConnection> client = DtlsConnection
            .ConnectAsync(path.Client, clientOptions, TestContext.CancellationToken)
            .AsTask();
        await Task.WhenAll(server, client).WaitAsync(s_testTimeout, TestContext.CancellationToken);
        return (await client, await server);
    }

    private async Task AssertCarriesAsync(DtlsConnection from, DtlsConnection to)
    {
        byte[] message = new byte[from.MaximumApplicationDataSize];
        Random.Shared.NextBytes(message);
        await from.SendAsync(message, TestContext.CancellationToken);
        byte[] buffer = new byte[4096];
        int length = await to.ReceiveAsync(buffer, TestContext.CancellationToken)
            .AsTask()
            .WaitAsync(s_testTimeout, TestContext.CancellationToken);
        CollectionAssert.AreEqual(message, buffer[..length]);
    }

    private static void AssertSameKeys(SrtpKeyingMaterial a, SrtpKeyingMaterial b)
    {
        Assert.AreEqual(a.Profile, b.Profile);
        CollectionAssert.AreEqual(a.ClientMasterKey.ToArray(), b.ClientMasterKey.ToArray());
        CollectionAssert.AreEqual(a.ClientMasterSalt.ToArray(), b.ClientMasterSalt.ToArray());
        CollectionAssert.AreEqual(a.ServerMasterKey.ToArray(), b.ServerMasterKey.ToArray());
        CollectionAssert.AreEqual(a.ServerMasterSalt.ToArray(), b.ServerMasterSalt.ToArray());
        CollectionAssert.AreNotEqual(a.ClientMasterKey.ToArray(), a.ServerMasterKey.ToArray());
    }

    internal static DtlsClientConnectionOptions Client(
        X509Certificate2 own,
        X509Certificate2 expectedPeer
    ) =>
        new()
        {
            ClientAuthenticationOptions = new SslClientAuthenticationOptions
            {
                ClientCertificates = [own],
                RemoteCertificateValidationCallback = DtlsFingerprint
                    .Compute(expectedPeer)
                    .CreateValidationCallback(),
            },
            SrtpProtectionProfiles =
            [
                SrtpProtectionProfile.AeadAes128Gcm,
                SrtpProtectionProfile.Aes128CmHmacSha180,
            ],
        };

    internal static DtlsServerConnectionOptions Server(
        X509Certificate2 own,
        X509Certificate2 expectedPeer,
        bool cookieExchange
    ) =>
        new()
        {
            ServerAuthenticationOptions = new SslServerAuthenticationOptions
            {
                ServerCertificate = own,
                ClientCertificateRequired = true,
                RemoteCertificateValidationCallback = DtlsFingerprint
                    .Compute(expectedPeer)
                    .CreateValidationCallback(),
            },
            SrtpProtectionProfiles =
            [
                SrtpProtectionProfile.AeadAes128Gcm,
                SrtpProtectionProfile.Aes128CmHmacSha180,
            ],
            CookieExchange = cookieExchange,
        };
}
