using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;

namespace Dtls.NET.Tests;

// A peer program whose output is watched line by line.
internal sealed class PeerProcess : IDisposable
{
    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(60);

    private readonly Process _process;
    private readonly StringBuilder _output = new();

    private PeerProcess(Process process) => _process = process;

    public static PeerProcess Start(string fileName, string arguments)
    {
        ProcessStartInfo start = new(fileName, arguments)
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
            Assert.Inconclusive($"{fileName} is not on the PATH.");
            throw;
        }

        PeerProcess peer = new(process);
        process.OutputDataReceived += (_, e) => peer.Append(e.Data);
        process.ErrorDataReceived += (_, e) => peer.Append(e.Data);
        process.BeginOutputReadLine();
        process.BeginErrorReadLine();
        return peer;
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
            Stopwatch.GetTimestamp() + (long)(Timeout.TotalSeconds * Stopwatch.Frequency);
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
            Assert.Fail(
                $"{_process.StartInfo.FileName} did not print {pattern}. Its output:\n{_output}"
            );
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
internal sealed class ListeningTransport : IDatagramTransport, IDisposable
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
