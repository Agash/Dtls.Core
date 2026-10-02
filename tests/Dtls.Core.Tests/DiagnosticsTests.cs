using System.Diagnostics.Metrics;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Channels;

namespace Dtls.Core.Tests;

[TestClass]
public sealed class DiagnosticsTests
{
    private static readonly TimeSpan s_timeout = TimeSpan.FromSeconds(30);

    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    public async Task Statistics_AfterAnExchange_CountWhatHappened()
    {
        (DtlsConnection client, DtlsConnection server) = await ConnectAsync(
            new DtlsClientConnectionOptions(),
            new DtlsServerConnectionOptions()
        );
        await using (client)
        await using (server)
        {
            await client.SendAsync(new byte[10], TestContext.CancellationToken);
            _ = await server
                .ReceiveAsync(new byte[64], TestContext.CancellationToken)
                .AsTask()
                .WaitAsync(s_timeout, TestContext.CancellationToken);

            DtlsConnectionStatistics sent = client.Statistics;
            DtlsConnectionStatistics received = server.Statistics;
            Assert.IsNotNull(sent.HandshakeDuration);
            Assert.IsGreaterThan(0, sent.DatagramsSent);
            Assert.AreEqual(1, sent.ApplicationRecordsSent);
            Assert.AreEqual(1, received.ApplicationRecordsReceived);
            Assert.AreEqual(0, received.AuthenticationFailures);
        }
    }

    [TestMethod]
    public async Task Metrics_Handshake_RecordsItsDurationAndOutcome()
    {
        List<(double Seconds, string? Outcome)> recorded = [];
        using MeterListener listener = new();
        listener.InstrumentPublished = (instrument, l) =>
        {
            if (
                instrument.Meter.Name == "Dtls.Core"
                && instrument.Name == "dtls.handshake.duration"
            )
            {
                l.EnableMeasurementEvents(instrument);
            }
        };
        listener.SetMeasurementEventCallback<double>(
            (_, value, tags, _) =>
            {
                string? outcome = null;
                foreach (KeyValuePair<string, object?> tag in tags)
                {
                    if (tag.Key == "dtls.handshake.outcome")
                    {
                        outcome = tag.Value as string;
                    }
                }

                lock (recorded)
                {
                    recorded.Add((value, outcome));
                }
            }
        );
        listener.Start();

        (DtlsConnection client, DtlsConnection server) = await ConnectAsync(
            new DtlsClientConnectionOptions(),
            new DtlsServerConnectionOptions()
        );
        await client.DisposeAsync();
        await server.DisposeAsync();

        lock (recorded)
        {
            Assert.IsGreaterThanOrEqualTo(2, recorded.Count(r => r.Outcome == "connected"));
        }
    }

    [TestMethod]
    public async Task ReceiveQueue_Full_DropsAndCounts()
    {
        DtlsServerConnectionOptions serverOptions = new()
        {
            ReceiveQueueCapacity = 2,
            ReceiveQueueFullMode = BoundedChannelFullMode.DropOldest,
        };
        (DtlsConnection client, DtlsConnection server) = await ConnectAsync(
            new DtlsClientConnectionOptions(),
            serverOptions
        );
        await using (client)
        await using (server)
        {
            for (byte i = 0; i < 10; i++)
            {
                await client.SendAsync(new byte[] { i }, TestContext.CancellationToken);
            }

            long deadline = Environment.TickCount64 + 10_000;
            while (
                server.Statistics.ApplicationRecordsReceived < 10
                && Environment.TickCount64 < deadline
            )
            {
                await Task.Delay(10, TestContext.CancellationToken);
            }

            byte[] buffer = new byte[16];
            Assert.AreEqual(8, server.Statistics.ApplicationRecordsDropped);

            // DropOldest keeps the newest two.
            _ = await server.ReceiveAsync(buffer, TestContext.CancellationToken);
            Assert.AreEqual(8, buffer[0]);
        }
    }

    [TestMethod]
    public void ReceiveQueueFullMode_Wait_IsRefused() =>
        Assert.ThrowsExactly<ArgumentOutOfRangeException>(() =>
            _ = DtlsConnection.ConnectAsync(
                new DatagramPair().Client,
                new DtlsClientConnectionOptions
                {
                    ClientAuthenticationOptions = new(),
                    ReceiveQueueFullMode = BoundedChannelFullMode.Wait,
                },
                TestContext.CancellationToken
            )
        );

    [TestMethod]
    public async Task MaximumDatagramSize_Lowered_ShrinksWhatOneSendCarries()
    {
        (DtlsConnection client, DtlsConnection server) = await ConnectAsync(
            new DtlsClientConnectionOptions(),
            new DtlsServerConnectionOptions()
        );
        await using (client)
        await using (server)
        {
            int before = client.MaximumApplicationDataSize;
            client.MaximumDatagramSize = 400;

            Assert.AreEqual(before - 800, client.MaximumApplicationDataSize);
            _ = await Assert.ThrowsExactlyAsync<ArgumentException>(() =>
                client.SendAsync(new byte[before], TestContext.CancellationToken).AsTask()
            );
            await client.SendAsync(
                new byte[client.MaximumApplicationDataSize],
                TestContext.CancellationToken
            );
            Assert.AreEqual(
                client.MaximumApplicationDataSize,
                await server
                    .ReceiveAsync(new byte[2048], TestContext.CancellationToken)
                    .AsTask()
                    .WaitAsync(s_timeout, TestContext.CancellationToken)
            );
        }
    }

    private async Task<(DtlsConnection Client, DtlsConnection Server)> ConnectAsync(
        DtlsClientConnectionOptions client,
        DtlsServerConnectionOptions server
    )
    {
        using X509Certificate2 clientCertificate = DtlsCertificates.CreateSelfSigned();
        using X509Certificate2 serverCertificate = DtlsCertificates.CreateSelfSigned();
        DtlsClientConnectionOptions clientTemplate = HandshakeTests.Client(
            clientCertificate,
            serverCertificate
        );
        DtlsServerConnectionOptions serverTemplate = HandshakeTests.Server(
            serverCertificate,
            clientCertificate,
            cookieExchange: true
        );
        client.ClientAuthenticationOptions = clientTemplate.ClientAuthenticationOptions;
        client.SrtpProtectionProfiles = clientTemplate.SrtpProtectionProfiles;
        server.ServerAuthenticationOptions = serverTemplate.ServerAuthenticationOptions;
        server.SrtpProtectionProfiles = serverTemplate.SrtpProtectionProfiles;
        DatagramPair path = new();
        Task<DtlsConnection> accepting = DtlsConnection
            .AcceptAsync(path.Server, server, TestContext.CancellationToken)
            .AsTask();
        Task<DtlsConnection> connecting = DtlsConnection
            .ConnectAsync(path.Client, client, TestContext.CancellationToken)
            .AsTask();
        await Task.WhenAll(accepting, connecting)
            .WaitAsync(s_timeout, TestContext.CancellationToken);
        return (await connecting, await accepting);
    }
}
