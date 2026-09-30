using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;

namespace Dtls.Core.Tests;

// Handshakes with wolfSSL's example client and server, which speak DTLS 1.3 (few implementations do)
// as well as 1.2. DTLS_WOLFSSL_EXAMPLES names wolfSSL's examples directory, built with --enable-dtls13
// --enable-srtp; without it the tests are inconclusive. Each side authenticates the other: wolfSSL
// trusts the peer's self-signed certificate as its CA.
[TestClass]
[TestCategory("Interop")]
public sealed partial class WolfSslInteropTests
{
    private const int KeyingMaterialLength = 60;
    private static readonly TimeSpan s_timeout = TimeSpan.FromSeconds(30);

    private const DtlsProtocols Both = DtlsProtocols.Dtls12 | DtlsProtocols.Dtls13;

    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    // wolfSSL's -v: 4 is DTLS 1.3 only, 3 is DTLS 1.2 only, d accepts either and prefers 1.3.
    [DataRow("4", Both, DtlsProtocols.Dtls13, DtlsKeyType.EcdsaP256)]
    [DataRow("4", Both, DtlsProtocols.Dtls13, DtlsKeyType.Rsa2048)]
    [DataRow("3", Both, DtlsProtocols.Dtls12, DtlsKeyType.EcdsaP256)]
    [DataRow("3", DtlsProtocols.Dtls12, DtlsProtocols.Dtls12, DtlsKeyType.Rsa2048)]
    [DataRow("d", Both, DtlsProtocols.Dtls13, DtlsKeyType.EcdsaP256)]
    [DataRow("d", DtlsProtocols.Dtls12, DtlsProtocols.Dtls12, DtlsKeyType.EcdsaP256)]
    public async Task Connect_ToWolfSslServer_AgreesOnKeys(
        string version,
        DtlsProtocols enabled,
        DtlsProtocols expected,
        DtlsKeyType keyType
    )
    {
        using X509Certificate2 own = DtlsCertificates.CreateSelfSigned(keyType);
        using X509Certificate2 peer = DtlsCertificates.CreateSelfSigned(keyType);
        using OpenSslInteropTests.TempPem ownPem = new(own);
        using OpenSslInteropTests.TempPem peerPem = new(peer);
        int port = OpenSslInteropTests.FreePort();
        using PeerProcess server = Start(
            "server",
            $"-u -v {version} -p {port} -c {peerPem.Certificate} -k {peerPem.Key} -A {ownPem.Certificate} --srtp SRTP_AES128_CM_SHA1_80"
        );
        try
        {
            using UdpDatagramTransport transport = UdpDatagramTransport.Connect(
                new IPEndPoint(IPAddress.Loopback, port)
            );
            DtlsClientConnectionOptions options = HandshakeTests.Client(own, peer);
            options.SrtpProtectionProfiles = [SrtpProtectionProfile.Aes128CmHmacSha180];
            options.EnabledProtocols = enabled;
            await using DtlsConnection connection = await DtlsConnection
                .ConnectAsync(transport, options, TestContext.CancellationToken)
                .AsTask()
                .WaitAsync(s_timeout, TestContext.CancellationToken);

            Assert.AreEqual(expected, connection.NegotiatedProtocol);
            Assert.AreEqual(
                await server.WaitForAsync(KeyingMaterial(), TestContext.CancellationToken),
                Export(connection)
            );
            await connection.SendAsync(
                Encoding.ASCII.GetBytes("hello wolfssl!"),
                TestContext.CancellationToken
            );
            byte[] buffer = new byte[2048];
            int length = await connection
                .ReceiveAsync(buffer, TestContext.CancellationToken)
                .AsTask()
                .WaitAsync(s_timeout, TestContext.CancellationToken);
            StringAssert.StartsWith(
                Encoding.ASCII.GetString(buffer, 0, length),
                "I hear you fa shizzle!"
            );
        }
        catch (Exception error)
            when (error is not AssertFailedException and not AssertInconclusiveException)
        {
            Assert.Fail($"{error}\nwolfSSL:\n{server.Output}");
        }
    }

    [TestMethod]
    [DataRow("4", Both, DtlsProtocols.Dtls13, true)]
    [DataRow("4", Both, DtlsProtocols.Dtls13, false)]
    [DataRow("3", Both, DtlsProtocols.Dtls12, true)]
    [DataRow("3", DtlsProtocols.Dtls12, DtlsProtocols.Dtls12, false)]
    [DataRow("d", Both, DtlsProtocols.Dtls13, true)]
    [DataRow("d", DtlsProtocols.Dtls12, DtlsProtocols.Dtls12, true)]
    public async Task Accept_FromWolfSslClient_AgreesOnKeys(
        string version,
        DtlsProtocols enabled,
        DtlsProtocols expected,
        bool cookieExchange
    )
    {
        using X509Certificate2 own = DtlsCertificates.CreateSelfSigned();
        using X509Certificate2 peer = DtlsCertificates.CreateSelfSigned();
        using OpenSslInteropTests.TempPem ownPem = new(own);
        using OpenSslInteropTests.TempPem peerPem = new(peer);
        using ListeningTransport transport = new();
        using PeerProcess client = Start(
            "client",
            $"-u -v {version} -h 127.0.0.1 -p {transport.Port} -c {peerPem.Certificate} -k {peerPem.Key} -A {ownPem.Certificate} --srtp SRTP_AES128_CM_SHA1_80"
        );
        try
        {
            DtlsServerConnectionOptions options = HandshakeTests.Server(own, peer, cookieExchange);
            options.SrtpProtectionProfiles = [SrtpProtectionProfile.Aes128CmHmacSha180];
            options.EnabledProtocols = enabled;
            await using DtlsConnection connection = await DtlsConnection
                .AcceptAsync(transport, options, TestContext.CancellationToken)
                .AsTask()
                .WaitAsync(s_timeout, TestContext.CancellationToken);

            Assert.AreEqual(expected, connection.NegotiatedProtocol);
            Assert.AreEqual(
                await client.WaitForAsync(KeyingMaterial(), TestContext.CancellationToken),
                Export(connection)
            );
            byte[] buffer = new byte[2048];
            int length = await connection
                .ReceiveAsync(buffer, TestContext.CancellationToken)
                .AsTask()
                .WaitAsync(s_timeout, TestContext.CancellationToken);
            StringAssert.StartsWith(Encoding.ASCII.GetString(buffer, 0, length), "hello wolfssl!");
            await connection.SendAsync(
                Encoding.ASCII.GetBytes("I hear you fa shizzle!"),
                TestContext.CancellationToken
            );
            _ = await client.WaitForAsync("I hear you fa shizzle!", TestContext.CancellationToken);
        }
        catch (Exception error)
            when (error is not AssertFailedException and not AssertInconclusiveException)
        {
            Assert.Fail($"{error}\nwolfSSL:\n{client.Output}");
        }
    }

    private static PeerProcess Start(string program, string arguments)
    {
        string? examples = Environment.GetEnvironmentVariable("DTLS_WOLFSSL_EXAMPLES");
        if (examples is null)
        {
            Assert.Inconclusive("DTLS_WOLFSSL_EXAMPLES names no wolfSSL examples directory.");
        }

        // The examples run from wolfSSL's source root, where they look for their files.
        // Line-buffered stdout: the examples print what the test waits for, and a pipe would hold it.
        string path = Path.Combine(examples, program, program);
        return PeerProcess.Start(
            "stdbuf",
            $"-oL {path} {arguments}",
            Path.GetDirectoryName(Path.GetFullPath(examples))
        );
    }

    // DTLS-SRTP's keying material, as wolfSSL exports it: no context.
    private static string Export(DtlsConnection connection)
    {
        byte[] ours = new byte[KeyingMaterialLength];
        connection.ExportKeyingMaterial("EXTRACTOR-dtls_srtp", ours);
        return Convert.ToHexString(ours);
    }

    [GeneratedRegex(@"Exported key material: ([0-9A-F]+)")]
    private static partial Regex KeyingMaterial();
}
