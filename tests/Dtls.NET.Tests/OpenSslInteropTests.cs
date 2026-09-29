using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;

namespace Dtls.NET.Tests;

// Handshakes with OpenSSL's s_server and s_client, each side checking the other: the handshake
// completes, the DTLS-SRTP keys both export are the same, and application data arrives.
[TestClass]
[TestCategory("Interop")]
public sealed partial class OpenSslInteropTests
{
    private const int KeyingMaterialLength = 56;
    private static readonly TimeSpan s_timeout = TimeSpan.FromSeconds(30);

    public TestContext TestContext { get; set; } = null!;

    [TestMethod]
    [DataRow(DtlsKeyType.EcdsaP256, "ECDHE-ECDSA-AES128-GCM-SHA256", true)]
    [DataRow(DtlsKeyType.EcdsaP256, "ECDHE-ECDSA-AES256-GCM-SHA384", false)]
    [DataRow(DtlsKeyType.EcdsaP256, "ECDHE-ECDSA-CHACHA20-POLY1305", false)]
    [DataRow(DtlsKeyType.Rsa2048, "ECDHE-RSA-AES128-GCM-SHA256", false)]
    public async Task Connect_ToOpenSslServer_AgreesOnKeys(
        DtlsKeyType keyType,
        string cipher,
        bool smallDatagrams
    )
    {
        if (OperatingSystem.IsWindows())
        {
            // The Windows builds of s_server wait on stdin when it is a pipe and never read the DTLS socket;
            // s_client works, so our server is checked there, and our client on Linux and macOS.
            Assert.Inconclusive("s_server does not serve DTLS with piped stdin on Windows.");
        }

        using X509Certificate2 own = DtlsCertificates.CreateSelfSigned(keyType);
        using X509Certificate2 peer = DtlsCertificates.CreateSelfSigned(keyType);
        using TempPem pem = new(peer);
        int port = FreePort();
        using OpenSsl server = OpenSsl.Start(
            $"s_server -dtls1_2 -accept 127.0.0.1:{port} -cert {pem.Certificate} -key {pem.Key} -cipher {cipher} "
                + $"-use_srtp SRTP_AEAD_AES_128_GCM:SRTP_AES128_CM_SHA1_80 -keymatexport EXTRACTOR-dtls_srtp -keymatexportlen {KeyingMaterialLength} "
                + $"-Verify 1 -mtu {(smallDatagrams ? 300 : 1400)}"
        );
        await server.WaitForAsync("ACCEPT", TestContext.CancellationToken);
        try
        {
            await ConnectAsync(own, peer, port, smallDatagrams, server);
        }
        catch (Exception error) when (error is not AssertFailedException)
        {
            Assert.Fail($"{error}\nopenssl:\n{server.Output}");
        }
    }

    private async Task ConnectAsync(
        X509Certificate2 own,
        X509Certificate2 peer,
        int port,
        bool smallDatagrams,
        OpenSsl server
    )
    {
        using UdpDatagramTransport transport = UdpDatagramTransport.Connect(
            new IPEndPoint(IPAddress.Loopback, port)
        );
        DtlsClientConnectionOptions options = HandshakeTests.Client(own, peer);
        options.MaximumDatagramSize = smallDatagrams ? 300 : 1200;
        await using DtlsConnection connection = await DtlsConnection
            .ConnectAsync(transport, options, TestContext.CancellationToken)
            .AsTask()
            .WaitAsync(s_timeout, TestContext.CancellationToken);

        string theirs = await server.WaitForAsync(KeyingMaterial(), TestContext.CancellationToken);
        Assert.AreEqual(
            SrtpProtectionProfile.AeadAes128Gcm,
            connection.SrtpKeyingMaterial!.Profile
        );
        Assert.AreEqual(theirs, Export(connection));

        await connection.SendAsync(
            Encoding.ASCII.GetBytes("from-dtls-net\n"),
            TestContext.CancellationToken
        );
        _ = await server.WaitForAsync("from-dtls-net", TestContext.CancellationToken);
    }

    [TestMethod]
    [DataRow(DtlsKeyType.EcdsaP256, true)]
    [DataRow(DtlsKeyType.EcdsaP384, false)]
    [DataRow(DtlsKeyType.Rsa2048, true)]
    public async Task Accept_FromOpenSslClient_AgreesOnKeys(
        DtlsKeyType keyType,
        bool cookieExchange
    )
    {
        using X509Certificate2 own = DtlsCertificates.CreateSelfSigned(keyType);
        using X509Certificate2 peer = DtlsCertificates.CreateSelfSigned(keyType);
        using TempPem pem = new(peer);
        using ListeningTransport transport = new();
        using OpenSsl client = OpenSsl.Start(
            $"s_client -dtls1_2 -connect 127.0.0.1:{transport.Port} -cert {pem.Certificate} -key {pem.Key} "
                + $"-use_srtp SRTP_AES128_CM_SHA1_80 -keymatexport EXTRACTOR-dtls_srtp -keymatexportlen {KeyingMaterialLength}"
        );
        try
        {
            await AcceptAsync(own, peer, transport, cookieExchange, client);
        }
        catch (Exception error) when (error is not AssertFailedException)
        {
            Assert.Fail($"{error}\nopenssl:\n{client.Output}");
        }
    }

    private async Task AcceptAsync(
        X509Certificate2 own,
        X509Certificate2 peer,
        ListeningTransport transport,
        bool cookieExchange,
        OpenSsl client
    )
    {
        DtlsServerConnectionOptions options = HandshakeTests.Server(own, peer, cookieExchange);
        await using DtlsConnection connection = await DtlsConnection
            .AcceptAsync(transport, options, TestContext.CancellationToken)
            .AsTask()
            .WaitAsync(s_timeout, TestContext.CancellationToken);

        string theirs = await client.WaitForAsync(KeyingMaterial(), TestContext.CancellationToken);
        Assert.AreEqual(
            SrtpProtectionProfile.Aes128CmHmacSha180,
            connection.SrtpKeyingMaterial!.Profile
        );
        Assert.AreEqual(theirs, Export(connection));

        await connection.SendAsync(
            Encoding.ASCII.GetBytes("to-openssl\n"),
            TestContext.CancellationToken
        );
        _ = await client.WaitForAsync("to-openssl", TestContext.CancellationToken);
        await client.WriteLineAsync("to-dtls-net");
        byte[] buffer = new byte[2048];
        int length = await connection
            .ReceiveAsync(buffer, TestContext.CancellationToken)
            .AsTask()
            .WaitAsync(s_timeout, TestContext.CancellationToken);
        StringAssert.StartsWith(Encoding.ASCII.GetString(buffer, 0, length), "to-dtls-net");
    }

    private static string Export(DtlsConnection connection)
    {
        byte[] ours = new byte[KeyingMaterialLength];
        connection.ExportKeyingMaterial("EXTRACTOR-dtls_srtp", ours);
        return Convert.ToHexString(ours);
    }

    private static int FreePort()
    {
        using Socket probe = new(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        probe.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        return ((IPEndPoint)probe.LocalEndPoint!).Port;
    }

    [GeneratedRegex(@"Keying material: ([0-9A-F]+)")]
    private static partial Regex KeyingMaterial();

    // A certificate and its key as PEM files for OpenSSL.
    private sealed class TempPem : IDisposable
    {
        public TempPem(X509Certificate2 certificate)
        {
            Certificate = Path.GetTempFileName();
            Key = Path.GetTempFileName();
            File.WriteAllText(Certificate, certificate.ExportCertificatePem());
            AsymmetricAlgorithm key =
                (AsymmetricAlgorithm?)certificate.GetECDsaPrivateKey()
                ?? certificate.GetRSAPrivateKey()!;
            using (key)
            {
                File.WriteAllText(Key, key.ExportPkcs8PrivateKeyPem());
            }
        }

        public string Certificate { get; }

        public string Key { get; }

        public void Dispose()
        {
            File.Delete(Certificate);
            File.Delete(Key);
        }
    }

    // An openssl process whose output is watched line by line.
    private sealed class OpenSsl : IDisposable
    {
        private readonly Process _process;
        private readonly StringBuilder _output = new();

        private OpenSsl(Process process) => _process = process;

        public static OpenSsl Start(string arguments)
        {
            ProcessStartInfo start = new("openssl", arguments)
            {
                RedirectStandardInput = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
            };
            Process process;
            try
            {
                process = Process.Start(start)!;
            }
            catch (System.ComponentModel.Win32Exception)
            {
                Assert.Inconclusive("openssl is not on the PATH.");
                throw;
            }

            OpenSsl openSsl = new(process);
            process.OutputDataReceived += (_, e) => openSsl.Append(e.Data);
            process.ErrorDataReceived += (_, e) => openSsl.Append(e.Data);
            process.BeginOutputReadLine();
            process.BeginErrorReadLine();
            return openSsl;
        }

        public string Output
        {
            get
            {
                lock (_output)
                {
                    return _output.ToString();
                }
            }
        }

        public Task WriteLineAsync(string line) => _process.StandardInput.WriteLineAsync(line);

        public Task<string> WaitForAsync(string text, CancellationToken cancellationToken) =>
            WaitForAsync(new Regex(Regex.Escape(text)), cancellationToken);

        public async Task<string> WaitForAsync(Regex pattern, CancellationToken cancellationToken)
        {
            long deadline =
                Stopwatch.GetTimestamp() + (long)(s_timeout.TotalSeconds * Stopwatch.Frequency);
            while (Stopwatch.GetTimestamp() < deadline)
            {
                string output;
                lock (_output)
                {
                    output = _output.ToString();
                }

                Match match = pattern.Match(output);
                if (match.Success)
                {
                    return match.Groups.Count > 1 ? match.Groups[1].Value : match.Value;
                }

                await Task.Delay(50, cancellationToken);
            }

            lock (_output)
            {
                Assert.Fail($"openssl did not print {pattern}. Its output:\n{_output}");
            }

            return "";
        }

        public void Dispose()
        {
            if (!_process.HasExited)
            {
                _process.Kill();
                _process.WaitForExit();
            }

            _process.Dispose();
        }

        private void Append(string? line)
        {
            if (line is not null)
            {
                lock (_output)
                {
                    _ = _output.AppendLine(line);
                }
            }
        }
    }

    // A server's UDP socket that learns its peer from the first datagram, as a listener does.
    private sealed class ListeningTransport : IDatagramTransport, IDisposable
    {
        private readonly Socket _socket = new(
            AddressFamily.InterNetwork,
            SocketType.Dgram,
            ProtocolType.Udp
        );
        private EndPoint? _peer;

        public ListeningTransport() => _socket.Bind(new IPEndPoint(IPAddress.Loopback, 0));

        public int Port => ((IPEndPoint)_socket.LocalEndPoint!).Port;

        public async ValueTask SendAsync(
            ReadOnlyMemory<byte> datagram,
            CancellationToken cancellationToken
        ) => _ = await _socket.SendToAsync(datagram, SocketFlags.None, _peer!, cancellationToken);

        public async ValueTask<int> ReceiveAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken
        )
        {
            SocketReceiveFromResult result = await _socket.ReceiveFromAsync(
                buffer,
                SocketFlags.None,
                new IPEndPoint(IPAddress.Any, 0),
                cancellationToken
            );
            _peer ??= result.RemoteEndPoint;
            return result.ReceivedBytes;
        }

        public void Dispose() => _socket.Dispose();
    }
}
