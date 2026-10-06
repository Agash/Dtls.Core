using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;

namespace Dtls.Core.Tests;

// RFC 9146 section 6 over real loopback sockets: the client sits behind a NAT that rebinds to a new port and
// forgets the old one, so the server's answers reach the client only if the server follows it.
[TestClass]
public sealed class PeerAddressUpdateTests
{
    private static readonly TimeSpan s_timeout = TimeSpan.FromSeconds(30);

    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    [DataRow(DtlsProtocols.Dtls12)]
    [DataRow(DtlsProtocols.Dtls13)]
    public async Task NatRebinding_ServerFollowsTheClient(DtlsProtocols version)
    {
        using Socket serverSocket = Bound();
        await using Nat nat = new((IPEndPoint)serverSocket.LocalEndPoint!);
        using UdpDatagramTransport serverTransport = UdpDatagramTransport.FromBoundSocket(
            serverSocket,
            nat.Outside,
            ownsSocket: false
        );
        using UdpDatagramTransport clientTransport = UdpDatagramTransport.Connect(nat.Inside);
        (DtlsConnection client, DtlsConnection server) = await ConnectAsync(
            clientTransport,
            serverTransport,
            version,
            cid: 8
        );
        await using (client)
        await using (server)
        {
            await CarriesAsync(client, server);
            await CarriesAsync(server, client);

            nat.Rebind();
            await CarriesAsync(client, server);
            Assert.AreEqual(nat.Outside, serverTransport.RemoteEndPoint);
            await CarriesAsync(server, client);

            // An old record replayed from elsewhere authenticates but is not newer: the server stays put.
            using Socket attacker = Bound();
            _ = await attacker.SendToAsync(
                nat.Captured!,
                (IPEndPoint)serverSocket.LocalEndPoint!,
                TestContext.CancellationToken
            );
            await CarriesAsync(client, server);
            Assert.AreEqual(nat.Outside, serverTransport.RemoteEndPoint);
            await CarriesAsync(server, client);
        }
    }

    // Without connection IDs nothing identifies the peer apart from its address, so nothing is followed.
    [TestMethod]
    public async Task WithoutConnectionIds_ServerStaysOnTheFirstAddress()
    {
        using Socket serverSocket = Bound();
        await using Nat nat = new((IPEndPoint)serverSocket.LocalEndPoint!);
        using UdpDatagramTransport serverTransport = UdpDatagramTransport.FromBoundSocket(
            serverSocket,
            nat.Outside,
            ownsSocket: false
        );
        using UdpDatagramTransport clientTransport = UdpDatagramTransport.Connect(nat.Inside);
        (DtlsConnection client, DtlsConnection server) = await ConnectAsync(
            clientTransport,
            serverTransport,
            DtlsProtocols.Dtls13,
            cid: null
        );
        await using (client)
        await using (server)
        {
            IPEndPoint first = nat.Outside;
            nat.Rebind();
            await CarriesAsync(client, server);
            Assert.AreEqual(first, serverTransport.RemoteEndPoint);
        }
    }

    private static Socket Bound()
    {
        Socket socket = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        return socket;
    }

    private async Task CarriesAsync(DtlsConnection from, DtlsConnection to)
    {
        byte[] message = new byte[64];
        Random.Shared.NextBytes(message);
        await from.SendAsync(message, TestContext.CancellationToken);
        byte[] buffer = new byte[4096];
        int length = await to.ReceiveAsync(buffer, TestContext.CancellationToken)
            .AsTask()
            .WaitAsync(s_timeout, TestContext.CancellationToken);
        CollectionAssert.AreEqual(message, buffer.AsSpan(0, length).ToArray());
    }

    private async Task<(DtlsConnection Client, DtlsConnection Server)> ConnectAsync(
        IDatagramTransport clientTransport,
        IDatagramTransport serverTransport,
        DtlsProtocols version,
        int? cid
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
        clientOptions.ConnectionIdLength = cid;
        serverOptions.ConnectionIdLength = cid;
        Task<DtlsConnection> accepting = DtlsConnection
            .AcceptAsync(serverTransport, serverOptions, TestContext.CancellationToken)
            .AsTask();
        Task<DtlsConnection> connecting = DtlsConnection
            .ConnectAsync(clientTransport, clientOptions, TestContext.CancellationToken)
            .AsTask();
        await Task.WhenAll(accepting, connecting)
            .WaitAsync(s_timeout, TestContext.CancellationToken);
        return (await connecting, await accepting);
    }

    // A one-client NAT: datagrams from the inside leave from the current outside port; answers to that
    // port come back in. Rebind moves to a new outside port and closes the old one, as a NAT whose mapping
    // expired does. It keeps a copy of the last datagram it forwarded out, to replay.
    private sealed class Nat : IAsyncDisposable
    {
        private readonly IPEndPoint _server;
        private readonly Socket _inside = Bound();
        private readonly CancellationTokenSource _stop = new();
        private readonly List<Task> _loops = [];
        private Socket _outside = Bound();
        private IPEndPoint? _client;

        public Nat(IPEndPoint server)
        {
            _server = server;
            _loops.Add(ForwardOutAsync());
            _loops.Add(ForwardInAsync(_outside));
        }

        public IPEndPoint Inside => (IPEndPoint)_inside.LocalEndPoint!;

        public IPEndPoint Outside => (IPEndPoint)Volatile.Read(ref _outside).LocalEndPoint!;

        public byte[]? Captured { get; private set; }

        public void Rebind()
        {
            Socket next = Bound();
            Socket old = Interlocked.Exchange(ref _outside, next);
            old.Dispose();
            _loops.Add(ForwardInAsync(next));
        }

        public async ValueTask DisposeAsync()
        {
            await _stop.CancelAsync();
            _inside.Dispose();
            Volatile.Read(ref _outside).Dispose();
            try
            {
                await Task.WhenAll(_loops);
            }
            catch (Exception error)
                when (error
                        is OperationCanceledException
                            or SocketException
                            or ObjectDisposedException
                )
            {
                // Deliberately not logged: the sockets were closed under the loops.
            }

            _stop.Dispose();
        }

        private async Task ForwardOutAsync()
        {
            byte[] buffer = new byte[65535];
            while (!_stop.IsCancellationRequested)
            {
                SocketReceiveFromResult received = await _inside.ReceiveFromAsync(
                    buffer,
                    new IPEndPoint(IPAddress.Any, 0),
                    _stop.Token
                );
                _client = (IPEndPoint)received.RemoteEndPoint;
                Captured = buffer[..received.ReceivedBytes];
                _ = await Volatile.Read(ref _outside).SendToAsync(Captured, _server, _stop.Token);
            }
        }

        private async Task ForwardInAsync(Socket outside)
        {
            byte[] buffer = new byte[65535];
            try
            {
                while (!_stop.IsCancellationRequested)
                {
                    int length = await outside.ReceiveAsync(buffer, _stop.Token);
                    if (_client is { } client)
                    {
                        _ = await _inside.SendToAsync(
                            buffer.AsMemory(0, length),
                            client,
                            _stop.Token
                        );
                    }
                }
            }
            catch (Exception error) when (error is SocketException or ObjectDisposedException)
            {
                // Deliberately not logged: a rebind closed this port; answers to it are lost, as intended.
            }
        }
    }
}
