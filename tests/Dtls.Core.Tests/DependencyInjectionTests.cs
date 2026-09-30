using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Dtls.Core.Tests;

[TestClass]
public sealed class DependencyInjectionTests
{
    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    public async Task AddDtls_NamedOptions_ConnectWithTheApplicationsLogger()
    {
        using X509Certificate2 clientCertificate = DtlsCertificates.CreateSelfSigned();
        using X509Certificate2 serverCertificate = DtlsCertificates.CreateSelfSigned();
        TestLog log = new();
        ServiceCollection services = new();
        _ = services
            .AddSingleton<ILoggerFactory>(log)
            .AddDtlsClient(
                "webrtc",
                options =>
                    Copy(HandshakeTests.Client(clientCertificate, serverCertificate), options)
            )
            .AddDtlsServer(
                "webrtc",
                options =>
                    Copy(
                        HandshakeTests.Server(
                            serverCertificate,
                            clientCertificate,
                            cookieExchange: true
                        ),
                        options
                    )
            );
        await using ServiceProvider provider = services.BuildServiceProvider();
        DtlsConnectionFactory factory = provider.GetRequiredService<DtlsConnectionFactory>();
        DatagramPair path = new();

        Task<DtlsConnection> accepting = factory
            .AcceptAsync(path.Server, "webrtc", TestContext.CancellationToken)
            .AsTask();
        await using DtlsConnection client = await factory.ConnectAsync(
            path.Client,
            "webrtc",
            TestContext.CancellationToken
        );
        await using DtlsConnection server = await accepting;

        Assert.AreEqual(client.SrtpKeyingMaterial!.Profile, server.SrtpKeyingMaterial!.Profile);
        Assert.Contains("DTLS connected", log.ToString());
    }

    [TestMethod]
    public void AddDtls_Twice_RegistersOneFactory()
    {
        ServiceCollection services = new();
        _ = services.AddDtls().AddDtls();

        Assert.HasCount(
            1,
            services.Where(static d => d.ServiceType == typeof(DtlsConnectionFactory))
        );
    }

    private static void Copy(DtlsClientConnectionOptions from, DtlsClientConnectionOptions to)
    {
        to.ClientAuthenticationOptions = from.ClientAuthenticationOptions;
        to.SrtpProtectionProfiles = from.SrtpProtectionProfiles;
    }

    private static void Copy(DtlsServerConnectionOptions from, DtlsServerConnectionOptions to)
    {
        to.ServerAuthenticationOptions = from.ServerAuthenticationOptions;
        to.SrtpProtectionProfiles = from.SrtpProtectionProfiles;
        to.CookieExchange = from.CookieExchange;
    }
}
