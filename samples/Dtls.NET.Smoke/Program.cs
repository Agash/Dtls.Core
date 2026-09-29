using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Dtls.NET;

// A DTLS-SRTP handshake between two connections over loopback UDP, published as Native AOT: the
// program fails unless both sides agree on the keys and data crosses in both directions.
using X509Certificate2 clientCertificate = DtlsCertificates.CreateSelfSigned();
using X509Certificate2 serverCertificate = DtlsCertificates.CreateSelfSigned();
(Socket clientSocket, Socket serverSocket) = ConnectedPair();
using UdpDatagramTransport clientTransport = new(clientSocket);
using UdpDatagramTransport serverTransport = new(serverSocket);
using CancellationTokenSource timeout = new(TimeSpan.FromSeconds(30));

Task<DtlsConnection> accepting = DtlsConnection
    .AcceptAsync(
        serverTransport,
        new DtlsServerConnectionOptions
        {
            ServerAuthenticationOptions = new SslServerAuthenticationOptions
            {
                ServerCertificate = serverCertificate,
                ClientCertificateRequired = true,
                RemoteCertificateValidationCallback = DtlsFingerprint
                    .Compute(clientCertificate)
                    .CreateValidationCallback(),
            },
            SrtpProtectionProfiles = [SrtpProtectionProfile.AeadAes128Gcm],
        },
        timeout.Token
    )
    .AsTask();
await using DtlsConnection client = await DtlsConnection.ConnectAsync(
    clientTransport,
    new DtlsClientConnectionOptions
    {
        ClientAuthenticationOptions = new SslClientAuthenticationOptions
        {
            ClientCertificates = [clientCertificate],
            RemoteCertificateValidationCallback = DtlsFingerprint
                .Compute(serverCertificate)
                .CreateValidationCallback(),
        },
        SrtpProtectionProfiles = [SrtpProtectionProfile.AeadAes128Gcm],
    },
    timeout.Token
);
await using DtlsConnection server = await accepting;

if (
    !client.SrtpKeyingMaterial!.ClientMasterKey.Span.SequenceEqual(
        server.SrtpKeyingMaterial!.ClientMasterKey.Span
    )
)
{
    Console.Error.WriteLine("The two sides exported different SRTP keys.");
    return 1;
}

byte[] buffer = new byte[2048];
await client.SendAsync(Encoding.UTF8.GetBytes("ping"), timeout.Token);
int length = await server.ReceiveAsync(buffer, timeout.Token);
await server.SendAsync(buffer.AsMemory(0, length), timeout.Token);
length = await client.ReceiveAsync(buffer, timeout.Token);
if (Encoding.UTF8.GetString(buffer, 0, length) != "ping")
{
    Console.Error.WriteLine("The data did not come back.");
    return 1;
}

Console.WriteLine(
    $"DTLS-SRTP over loopback: {client.NegotiatedCipherSuite}, {client.SrtpKeyingMaterial.Profile}"
);
return 0;

static (Socket, Socket) ConnectedPair()
{
    Socket a = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
    Socket b = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
    a.Bind(new IPEndPoint(IPAddress.Loopback, 0));
    b.Bind(new IPEndPoint(IPAddress.Loopback, 0));
    a.Connect(b.LocalEndPoint!);
    b.Connect(a.LocalEndPoint!);
    return (a, b);
}
