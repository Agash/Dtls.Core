using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using Dtls.Core.Handshake;
using Dtls.Core.Records;

namespace Dtls.Core.Tests;

/// <summary>
/// Feeds what a peer or the network sends, mutated, to every parser that reads it: the handshake
/// message decoders, the record layer, and whole handshakes with datagrams corrupted in flight. Seeds
/// are a real handshake's own messages, so mutations reach deep into each format. The seed is fixed so a
/// failure reproduces; DTLS_FUZZ_ITERATIONS raises the count for a soak.
/// </summary>
[TestClass]
public sealed class ParserFuzzTests
{
    private static readonly int Iterations = int.TryParse(
        Environment.GetEnvironmentVariable("DTLS_FUZZ_ITERATIONS"),
        out int iterations
    )
        ? iterations
        : 5_000;

    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(30);

    public TestContext TestContext { get; set; } = null!;

    // A malformed message is refused with a DtlsException, never anything else.
    [TestMethod]
    public async Task HandshakeDecoders_MutatedMessages_FailOnlyWithDtlsException()
    {
        Dictionary<HandshakeType, List<byte[]>> messages = Messages(
            await CaptureAsync(DtlsProtocols.Dtls12)
        );
        (HandshakeType Type, Action<byte[]> Decode)[] decoders =
        [
            (HandshakeType.ClientHello, static b => _ = ClientHello.Decode(b)),
            (HandshakeType.HelloVerifyRequest, static b => _ = HelloVerifyRequest.Decode(b)),
            (HandshakeType.ServerHello, static b => _ = ServerHello.Decode(b)),
            (HandshakeType.Certificate, static b => _ = CertificateMessage.Decode(b)),
            (HandshakeType.ServerKeyExchange, static b => _ = ServerKeyExchange.Decode(b)),
            (
                HandshakeType.CertificateRequest,
                static b => _ = Handshake.CertificateRequest.Decode(b)
            ),
            (HandshakeType.ClientKeyExchange, static b => _ = ClientKeyExchange.Decode(b)),
            (HandshakeType.CertificateVerify, static b => _ = CertificateVerify.Decode(b)),
        ];

        foreach ((HandshakeType type, Action<byte[]> decode) in decoders)
        {
            Assert.IsTrue(
                messages.TryGetValue(type, out List<byte[]>? seeds),
                $"no {type} captured"
            );
            decode(seeds[0]); // the seed itself decodes
            Fuzz(
                type.ToString(),
                seeds,
                input =>
                {
                    try
                    {
                        decode(input);
                    }
                    catch (DtlsException)
                    {
                        // Refused as malformed: what a decoder is for.
                    }
                }
            );
        }
    }

    // The record layer drops what it cannot read; nothing a datagram holds makes it throw.
    [TestMethod]
    [DataRow(DtlsProtocols.Dtls12)]
    [DataRow(DtlsProtocols.Dtls13)]
    public async Task RecordLayer_MutatedDatagrams_AreDroppedNotThrown(DtlsProtocols version)
    {
        List<byte[]> datagrams = await CaptureAsync(version);
        Fuzz(
            $"records {version}",
            datagrams,
            static input =>
            {
                using RecordLayer records = new(1500);
                Discard handler = default;
                records.Read(input, ref handler);
            }
        );
    }

    // A handshake whose datagrams are corrupted in flight completes or fails with a DtlsException
    // (or its timeout), on both sides, and never hangs. Each handshake is bounded on its own, so a
    // soak's run time grows with its round count.
    [TestMethod]
    [DataRow(DtlsProtocols.Dtls12)]
    [DataRow(DtlsProtocols.Dtls13)]
    public async Task Handshake_CorruptedDatagrams_CompletesOrFailsCleanly(DtlsProtocols version)
    {
        int rounds = Math.Max(10, Iterations / 250);
        for (int round = 0; round < rounds; round++)
        {
            Random random = new(round);
            object gate = new();
            byte[] Corrupt(byte[] datagram)
            {
                lock (gate)
                {
                    return random.Next(4) == 0 ? Mutate(random, datagram, [datagram]) : datagram;
                }
            }

            // A corrupted datagram replaces the original: the original is dropped and the mutation
            // sent past the filter, so it may be longer or shorter.
            DatagramPair? path = null;
            bool Pass(DatagramPair.End from, byte[] datagram)
            {
                byte[] sent = Corrupt(datagram);
                if (ReferenceEquals(sent, datagram))
                {
                    return true;
                }

                from.Inject(sent);
                return false;
            }

            path = new(
                toServer: (_, d) => Pass(path!.Client, d),
                toClient: (_, d) => Pass(path!.Server, d)
            );
            await HandshakeAsync(path, version, TimeSpan.FromSeconds(3));
        }
    }

    // Both ends of a handshake over a path; any outcome but success or a clean DTLS failure fails.
    private async Task HandshakeAsync(DatagramPair path, DtlsProtocols version, TimeSpan timeout)
    {
        using X509Certificate2 clientCertificate = DtlsCertificates.CreateSelfSigned();
        using X509Certificate2 serverCertificate = DtlsCertificates.CreateSelfSigned();
        DtlsClientConnectionOptions client = HandshakeTests.Client(
            clientCertificate,
            serverCertificate
        );
        DtlsServerConnectionOptions server = HandshakeTests.Server(
            serverCertificate,
            clientCertificate,
            cookieExchange: true
        );
        client.EnabledProtocols = server.EnabledProtocols = version;
        client.HandshakeTimeout = server.HandshakeTimeout = timeout;
        client.InitialRetransmissionTimeout = server.InitialRetransmissionTimeout =
            TimeSpan.FromMilliseconds(50);
        using CancellationTokenSource stop = CancellationTokenSource.CreateLinkedTokenSource(
            TestContext.CancellationToken
        );
        stop.CancelAfter(timeout * 3);
        Task<DtlsConnection> accepting = DtlsConnection
            .AcceptAsync(path.Server, server, stop.Token)
            .AsTask();
        Task<DtlsConnection> connecting = DtlsConnection
            .ConnectAsync(path.Client, client, stop.Token)
            .AsTask();
        foreach (Task<DtlsConnection> side in (Task<DtlsConnection>[])[accepting, connecting])
        {
            try
            {
                await using DtlsConnection connection = await side.WaitAsync(Timeout);
            }
            catch (Exception exception)
                when (exception
                        is DtlsException
                            or AuthenticationException
                            or TimeoutException
                            or OperationCanceledException
                )
            {
                // A corrupted handshake may fail; failing cleanly is the property.
            }
        }

        stop.Cancel();
    }

    // The datagrams of one handshake, both directions.
    private async Task<List<byte[]>> CaptureAsync(DtlsProtocols version)
    {
        ConcurrentQueue<byte[]> seen = new();
        DatagramPair path = new(
            toServer: (_, d) => Keep(seen, d),
            toClient: (_, d) => Keep(seen, d)
        );
        await HandshakeAsync(path, version, TimeSpan.FromSeconds(10));
        Assert.IsNotEmpty(seen);
        return [.. seen];
    }

    private static bool Keep(ConcurrentQueue<byte[]> seen, byte[] datagram)
    {
        seen.Enqueue([.. datagram]);
        return true;
    }

    // The whole handshake messages in the unencrypted DTLS 1.2 records (epoch 0), by type.
    private static Dictionary<HandshakeType, List<byte[]>> Messages(List<byte[]> datagrams)
    {
        Dictionary<HandshakeType, List<byte[]>> messages = [];
        foreach (byte[] datagram in datagrams)
        {
            ReadOnlySpan<byte> rest = datagram;
            while (rest.Length >= 13)
            {
                byte type = rest[0];
                ushort epoch = BinaryPrimitives.ReadUInt16BigEndian(rest[3..]);
                int length = BinaryPrimitives.ReadUInt16BigEndian(rest[11..]);
                if (rest.Length < 13 + length)
                {
                    break;
                }

                ReadOnlySpan<byte> record = rest.Slice(13, length);
                rest = rest[(13 + length)..];
                if (type != 22 || epoch != 0)
                {
                    continue;
                }

                while (HandshakeFragment.TryReadNext(ref record, out HandshakeFragment fragment))
                {
                    if (fragment.IsWhole)
                    {
                        if (!messages.TryGetValue(fragment.Type, out List<byte[]>? list))
                        {
                            messages[fragment.Type] = list = [];
                        }

                        list.Add(fragment.Body.ToArray());
                    }
                }
            }
        }

        return messages;
    }

    private static void Fuzz(string what, List<byte[]> seeds, Action<byte[]> parse)
    {
        Random random = new(20261002);
        for (int i = 0; i < Iterations; i++)
        {
            byte[] seed = seeds[random.Next(seeds.Count)];
            byte[] input = Mutate(random, seed, seeds);
            try
            {
                parse(input);
            }
            catch (Exception exception)
            {
                Assert.Fail(
                    $"{what} threw {exception.GetType().Name} on iteration {i}: {Convert.ToHexString(input)}\n{exception}"
                );
            }
        }
    }

    // Bit flips, truncations, extensions, splices of another seed, and random bytes.
    private static byte[] Mutate(Random random, byte[] seed, List<byte[]> seeds)
    {
        byte[] data = [.. seed];
        switch (random.Next(6))
        {
            case 0 when data.Length > 0:
                for (int n = random.Next(1, 9); n > 0; n--)
                {
                    data[random.Next(data.Length)] ^= (byte)(1 << random.Next(8));
                }

                return data;
            case 1:
                return data[..random.Next(data.Length + 1)];
            case 2:
                byte[] longer = new byte[data.Length + random.Next(1, 64)];
                data.CopyTo(longer, 0);
                random.NextBytes(longer.AsSpan(data.Length));
                return longer;
            case 3:
                byte[] other = seeds[random.Next(seeds.Count)];
                int cut = random.Next(data.Length + 1);
                return [.. data.AsSpan(0, cut), .. other.AsSpan(random.Next(other.Length + 1))];
            case 4 when data.Length > 0:
                // A length or count field set to an extreme: the first bytes of most fields.
                int at = random.Next(data.Length);
                data[at] = random.Next(2) == 0 ? (byte)0xFF : (byte)0x00;
                return data;
            default:
                byte[] noise = new byte[random.Next(0, 256)];
                random.NextBytes(noise);
                return noise;
        }
    }

    private struct Discard : IRecordHandler
    {
        public readonly void OnRecord(
            ContentType type,
            ushort epoch,
            ulong sequence,
            ReadOnlySpan<byte> payload,
            int offset
        ) { }
    }
}
