using System.Runtime.Versioning;
using System.Security.Cryptography.X509Certificates;

namespace Dtls.Core.Tests;

// Handshakes with Windows' Schannel in both directions: the handshake completes, both sides agree on
// the SRTP profile and the keying material, each has the other's certificate, and data crosses.
[TestClass]
[TestCategory("Interop")]
public sealed class SchannelInteropTests
{
    private static readonly TimeSpan s_timeout = TimeSpan.FromSeconds(30);
    private static readonly ushort[] s_profiles =
    [
        (ushort)SrtpProtectionProfile.AeadAes128Gcm,
        (ushort)SrtpProtectionProfile.Aes128CmHmacSha180,
    ];

    private readonly List<string> _trace = [];
    private readonly TestLog _log = new();

    public TestContext TestContext { get; set; } = null!;

    [TestCleanup]
    public void PrintTrace()
    {
        if (TestContext.CurrentTestOutcome != UnitTestOutcome.Passed)
        {
            TestContext.WriteLine("Schannel: " + string.Join(" | ", _trace));
            TestContext.WriteLine("Dtls.Core:\n" + _log);
        }
    }

    [TestMethod]
    [DataRow(DtlsKeyType.EcdsaP256, true)]
    [DataRow(DtlsKeyType.EcdsaP384, false)]
    [DataRow(DtlsKeyType.Rsa2048, true)]
    [SupportedOSPlatform("windows")]
    public async Task Connect_ToSchannelServer_AgreesOnKeys(
        DtlsKeyType keyType,
        bool smallDatagrams
    )
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Inconclusive("Schannel is Windows'.");
            return;
        }

        using X509Certificate2 own = DtlsCertificates.CreateSelfSigned(keyType);
        using X509Certificate2 peer = Persisted(DtlsCertificates.CreateSelfSigned(keyType));
        DatagramPair path = new();
        DtlsClientConnectionOptions options = HandshakeTests.Client(own, peer);
        options.MaximumDatagramSize = smallDatagrams ? 300 : 1200;
        options.LoggerFactory = _log;

        Task<SchannelPeer> accepting = Task.Run(
            () =>
                SchannelPeer.AcceptAsync(
                    path.Server,
                    peer,
                    s_profiles,
                    _trace,
                    TestContext.CancellationToken
                ),
            TestContext.CancellationToken
        );
        await using DtlsConnection connection = await DtlsConnection
            .ConnectAsync(path.Client, options, TestContext.CancellationToken)
            .AsTask()
            .WaitAsync(s_timeout, TestContext.CancellationToken);
        using SchannelPeer schannel = await accepting.WaitAsync(
            s_timeout,
            TestContext.CancellationToken
        );

        await AssertAgreesAsync(connection, schannel, own);
    }

    [TestMethod]
    [DataRow(DtlsKeyType.EcdsaP256, true)]
    [DataRow(DtlsKeyType.EcdsaP256, false)]
    [DataRow(DtlsKeyType.Rsa2048, true)]
    [SupportedOSPlatform("windows")]
    public async Task Accept_FromSchannelClient_AgreesOnKeys(
        DtlsKeyType keyType,
        bool cookieExchange
    )
    {
        if (!OperatingSystem.IsWindows())
        {
            Assert.Inconclusive("Schannel is Windows'.");
            return;
        }

        using X509Certificate2 own = DtlsCertificates.CreateSelfSigned(keyType);
        using X509Certificate2 peer = Persisted(DtlsCertificates.CreateSelfSigned(keyType));
        DatagramPair path = new();

        Task<DtlsConnection> accepting = DtlsConnection
            .AcceptAsync(
                path.Server,
                WithLog(HandshakeTests.Server(own, peer, cookieExchange)),
                TestContext.CancellationToken
            )
            .AsTask();
        using SchannelPeer schannel = await Task.Run(
                () =>
                    SchannelPeer.ConnectAsync(
                        path.Client,
                        peer,
                        s_profiles,
                        _trace,
                        TestContext.CancellationToken
                    ),
                TestContext.CancellationToken
            )
            .WaitAsync(s_timeout, TestContext.CancellationToken);
        await using DtlsConnection connection = await accepting.WaitAsync(
            s_timeout,
            TestContext.CancellationToken
        );

        await AssertAgreesAsync(connection, schannel, own);
    }

    private DtlsServerConnectionOptions WithLog(DtlsServerConnectionOptions options)
    {
        options.LoggerFactory = _log;
        return options;
    }

    [SupportedOSPlatform("windows")]
    private async Task AssertAgreesAsync(
        DtlsConnection connection,
        SchannelPeer schannel,
        X509Certificate2 own
    )
    {
        Assert.AreEqual((int)connection.NegotiatedCipherSuite, schannel.CipherSuite);
        Assert.AreEqual((ushort)connection.SrtpKeyingMaterial!.Profile, schannel.SrtpProfile);
        byte[] ours = new byte[SchannelPeer.KeyingMaterialLength];
        connection.ExportKeyingMaterial(SchannelPeer.ExporterLabel, ours);
        CollectionAssert.AreEqual(ours, schannel.KeyingMaterial);
        CollectionAssert.AreEqual(own.RawData, schannel.RemoteCertificate);

        byte[] toSchannel = [.. "to-schannel"u8];
        await connection.SendAsync(toSchannel, TestContext.CancellationToken);
        CollectionAssert.AreEqual(
            toSchannel,
            await schannel
                .ReceiveAsync(TestContext.CancellationToken)
                .WaitAsync(s_timeout, TestContext.CancellationToken)
        );

        byte[] fromSchannel = [.. "from-schannel"u8];
        await schannel.SendAsync(fromSchannel, TestContext.CancellationToken);
        byte[] buffer = new byte[2048];
        int length = await connection
            .ReceiveAsync(buffer, TestContext.CancellationToken)
            .AsTask()
            .WaitAsync(s_timeout, TestContext.CancellationToken);
        CollectionAssert.AreEqual(fromSchannel, buffer[..length]);
    }

    // Schannel signs in LSA, which cannot use an ephemeral key: the certificate is re-imported with a
    // key container that lives until the certificate is disposed.
    private static X509Certificate2 Persisted(X509Certificate2 certificate)
    {
        using (certificate)
        {
            return X509CertificateLoader.LoadPkcs12(
                certificate.Export(X509ContentType.Pkcs12),
                null
            );
        }
    }
}
