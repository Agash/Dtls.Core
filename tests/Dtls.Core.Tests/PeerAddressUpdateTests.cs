using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;

namespace Dtls.Core.Tests;

// RFC 9146 section 6 over real loopback sockets: the client sits behind a NAT that rebinds to a new port and
// forgets the old one, so the server's answers reach the client only if the server follows it. The server
// follows once a return routability check (draft-ietf-tls-dtls-rrc-20) shows the new address answers, or
// at once when the application validates addresses itself.
[TestClass]
public sealed class PeerAddressUpdateTests
{
    private static readonly TimeSpan s_timeout = TimeSpan.FromSeconds(30);

    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    [DataRow(DtlsProtocols.Dtls12, DtlsPeerAddressValidation.ReturnRoutabilityCheck)]
    [DataRow(DtlsProtocols.Dtls13, DtlsPeerAddressValidation.ReturnRoutabilityCheck)]
    [DataRow(DtlsProtocols.Dtls12, DtlsPeerAddressValidation.Application)]
    [DataRow(DtlsProtocols.Dtls13, DtlsPeerAddressValidation.Application)]
    public async Task NatRebinding_ServerFollowsTheClient(
        DtlsProtocols version,
        DtlsPeerAddressValidation validation
    )
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
            cid: 8,
            validation
        );
        await using (client)
        await using (server)
        {
            await CarriesAsync(client, server);
            await CarriesAsync(server, client);

            nat.Rebind();
            await CarriesAsync(client, server);
            await FollowedAsync(serverTransport, nat.Outside);
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

    // Section 8.1.2 of the RRC draft: an attacker on the path diverts a genuine, newer record and sends
    // it from an address of its own. The record authenticates and is newer, so the server challenges
    // that address; the attacker cannot answer, and after T the server is where it was.
    [TestMethod]
    [DataRow(DtlsProtocols.Dtls12)]
    [DataRow(DtlsProtocols.Dtls13)]
    public async Task DivertedRecord_FromAnAddressThatDoesNotAnswer_IsNotFollowed(
        DtlsProtocols version
    )
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
            cid: 8,
            DtlsPeerAddressValidation.ReturnRoutabilityCheck
        );
        await using (client)
        await using (server)
        {
            await CarriesAsync(client, server);
            IPEndPoint home = nat.Outside;

            Task<byte[]> diverted = nat.DivertNextAsync();
            await client.SendAsync(new byte[] { 1, 2, 3 }, TestContext.CancellationToken);
            using Socket attacker = Bound();
            _ = await attacker.SendToAsync(
                await diverted.WaitAsync(s_timeout, TestContext.CancellationToken),
                (IPEndPoint)serverSocket.LocalEndPoint!,
                TestContext.CancellationToken
            );

            // The record is delivered, and the server challenges the attacker's address.
            byte[] buffer = new byte[64];
            Assert.AreEqual(
                3,
                await server
                    .ReceiveAsync(buffer, TestContext.CancellationToken)
                    .AsTask()
                    .WaitAsync(s_timeout, TestContext.CancellationToken)
            );
            SocketReceiveFromResult challenge = await attacker
                .ReceiveFromAsync(
                    buffer,
                    new IPEndPoint(IPAddress.Any, 0),
                    TestContext.CancellationToken
                )
                .AsTask()
                .WaitAsync(s_timeout, TestContext.CancellationToken);
            Assert.IsGreaterThan(0, challenge.ReceivedBytes);
            Assert.AreEqual(home, serverTransport.RemoteEndPoint, "not followed before an answer");

            // Unanswered past T (one second), the binding stays; traffic goes on as before.
            await Task.Delay(TimeSpan.FromSeconds(1.5), TestContext.CancellationToken);
            await CarriesAsync(client, server);
            await CarriesAsync(server, client);
            Assert.AreEqual(home, serverTransport.RemoteEndPoint);
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
            cid: null,
            DtlsPeerAddressValidation.ReturnRoutabilityCheck
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

    // The move takes the check's round trip after the record that showed the new address.
    private async Task FollowedAsync(UdpDatagramTransport transport, IPEndPoint expected)
    {
        using CancellationTokenSource limit = CancellationTokenSource.CreateLinkedTokenSource(
            TestContext.CancellationToken
        );
        limit.CancelAfter(s_timeout);
        while (!expected.Equals(transport.RemoteEndPoint))
        {
            // Deliberate: polls the transport's peer, which changes from the connection's receive loop.
            await Task.Delay(10, limit.Token);
        }
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
        int? cid,
        DtlsPeerAddressValidation validation
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
        clientOptions.PeerAddressValidation = validation;
        serverOptions.PeerAddressValidation = validation;
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

        private TaskCompletionSource<byte[]>? _divert;

        // The next datagram from the inside goes to the caller instead of out to the server.
        public Task<byte[]> DivertNextAsync()
        {
            var divert = new TaskCompletionSource<byte[]>(
                TaskCreationOptions.RunContinuationsAsynchronously
            );
            Volatile.Write(ref _divert, divert);
            return divert.Task;
        }

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
                if (Interlocked.Exchange(ref _divert, null) is { } divert)
                {
                    _ = divert.TrySetResult(Captured);
                    continue;
                }

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
