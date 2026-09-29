using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text.RegularExpressions;

namespace Dtls.NET.Tests;

// Handshakes with Apple's Network.framework in both directions, through tests/NetworkFrameworkPeer:
// the handshake completes, both sides agree on the cipher suite and the exported keying material,
// each has the other's certificate, and data crosses. Network.framework has no DTLS-SRTP, so
// use_srtp is not offered here; the exporter it would feed is compared directly.
[TestClass]
[TestCategory("Interop")]
public sealed partial class NetworkFrameworkInteropTests
{
    private const string Password = "dtls";
    private const int KeyingMaterialLength = 60;
    private static readonly TimeSpan s_timeout = TimeSpan.FromSeconds(120);

    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    [DataRow(DtlsKeyType.EcdsaP256)]
    [DataRow(DtlsKeyType.Rsa2048)]
    public async Task Connect_ToNetworkFrameworkServer_AgreesOnKeys(DtlsKeyType keyType)
    {
        using X509Certificate2 own = DtlsCertificates.CreateSelfSigned(keyType);
        using X509Certificate2 peer = DtlsCertificates.CreateSelfSigned(keyType);
        using TempIdentity identity = new(peer);
        using PeerProcess server = StartPeer($"server {identity.Path} {Password}");
        int port = int.Parse(
            await server.WaitForAsync(Ready(), TestContext.CancellationToken),
            System.Globalization.CultureInfo.InvariantCulture
        );

        using UdpDatagramTransport transport = UdpDatagramTransport.Connect(
            new IPEndPoint(IPAddress.Loopback, port)
        );
        DtlsClientConnectionOptions options = HandshakeTests.Client(own, peer);
        options.SrtpProtectionProfiles = [];
        await using DtlsConnection connection = await DtlsConnection
            .ConnectAsync(transport, options, TestContext.CancellationToken)
            .AsTask()
            .WaitAsync(s_timeout, TestContext.CancellationToken);

        await AssertAgreesAsync(connection, server, own);
    }

    [TestMethod]
    [DataRow(DtlsKeyType.EcdsaP256, true)]
    [DataRow(DtlsKeyType.Rsa2048, false)]
    public async Task Accept_FromNetworkFrameworkClient_AgreesOnKeys(
        DtlsKeyType keyType,
        bool cookieExchange
    )
    {
        using X509Certificate2 own = DtlsCertificates.CreateSelfSigned(keyType);
        using X509Certificate2 peer = DtlsCertificates.CreateSelfSigned(keyType);
        using TempIdentity identity = new(peer);
        using ListeningTransport transport = new();
        using PeerProcess client = StartPeer($"client {transport.Port} {identity.Path} {Password}");

        DtlsServerConnectionOptions options = HandshakeTests.Server(own, peer, cookieExchange);
        options.SrtpProtectionProfiles = [];
        await using DtlsConnection connection = await DtlsConnection
            .AcceptAsync(transport, options, TestContext.CancellationToken)
            .AsTask()
            .WaitAsync(s_timeout, TestContext.CancellationToken);

        await AssertAgreesAsync(connection, client, own);
    }

    private async Task AssertAgreesAsync(
        DtlsConnection connection,
        PeerProcess peer,
        X509Certificate2 own
    )
    {
        string cipher = await peer.WaitForAsync(Cipher(), TestContext.CancellationToken);
        Assert.AreEqual(
            (int)connection.NegotiatedCipherSuite,
            int.Parse(cipher, System.Globalization.CultureInfo.InvariantCulture)
        );
        // sec_protocol_metadata_create_secret exports with an empty context, not with none (RFC 5705 tells
        // them apart; OpenSSL and Schannel export without one and agree with Dtls.NET there).
        byte[] ours = new byte[KeyingMaterialLength];
        connection.ExportKeyingMaterial("EXTRACTOR-dtls_srtp", [], ours);
        Assert.AreEqual(
            Convert.ToHexString(ours),
            await peer.WaitForAsync(Key(), TestContext.CancellationToken)
        );
        Assert.AreEqual(
            Convert.ToHexString(own.RawData),
            await peer.WaitForAsync(Peer(), TestContext.CancellationToken)
        );

        await connection.SendAsync(
            "to-network-framework"u8.ToArray(),
            TestContext.CancellationToken
        );
        _ = await peer.WaitForAsync("RECV to-network-framework", TestContext.CancellationToken);
        byte[] buffer = new byte[2048];
        int length = await connection
            .ReceiveAsync(buffer, TestContext.CancellationToken)
            .AsTask()
            .WaitAsync(s_timeout, TestContext.CancellationToken);
        CollectionAssert.AreEqual("from-network-framework"u8.ToArray(), buffer[..length]);
    }

    private static PeerProcess StartPeer(string arguments)
    {
        if (!OperatingSystem.IsMacOS())
        {
            Assert.Inconclusive("Network.framework is Apple's.");
        }

        return PeerProcess.Start("swift", $"{Script()} {arguments}");
    }

    // tests/NetworkFrameworkPeer/peer.swift, found from the test assembly's directory.
    private static string Script()
    {
        for (
            DirectoryInfo? directory = new(AppContext.BaseDirectory);
            directory is not null;
            directory = directory.Parent
        )
        {
            string candidate = Path.Combine(
                directory.FullName,
                "tests",
                "NetworkFrameworkPeer",
                "peer.swift"
            );
            if (File.Exists(candidate))
            {
                return candidate;
            }
        }

        Assert.Fail("tests/NetworkFrameworkPeer/peer.swift was not found.");
        return "";
    }

    [GeneratedRegex(@"READY (\d+)")]
    private static partial Regex Ready();

    [GeneratedRegex(@"CIPHER (\d+)")]
    private static partial Regex Cipher();

    [GeneratedRegex(@"KEY ([0-9A-F]+)")]
    private static partial Regex Key();

    [GeneratedRegex(@"PEER ([0-9A-F]+)")]
    private static partial Regex Peer();

    // A certificate and its key as a PKCS #12 file, which Security.framework imports.
    private sealed class TempIdentity : IDisposable
    {
        public TempIdentity(X509Certificate2 certificate)
        {
            Path = System.IO.Path.GetTempFileName();
            File.WriteAllBytes(
                Path,
                certificate.ExportPkcs12(Pkcs12ExportPbeParameters.Pkcs12TripleDesSha1, Password)
            );
        }

        public string Path { get; }

        public void Dispose() => File.Delete(Path);
    }
}
