using System.Threading.Channels;

namespace Dtls.NET.Tests;

// Two ends of an in-memory datagram path. Each direction can lose datagrams on purpose: the filter
// sees every datagram with its index in that direction and says whether it arrives.
internal sealed class DatagramPair
{
    public DatagramPair(
        Func<int, byte[], bool>? toServer = null,
        Func<int, byte[], bool>? toClient = null
    )
    {
        Channel<byte[]> clientToServer = Channel.CreateUnbounded<byte[]>();
        Channel<byte[]> serverToClient = Channel.CreateUnbounded<byte[]>();
        Client = new End(clientToServer.Writer, serverToClient.Reader, toServer);
        Server = new End(serverToClient.Writer, clientToServer.Reader, toClient);
    }

    public End Client { get; }

    public End Server { get; }

    public sealed class End(
        ChannelWriter<byte[]> outgoing,
        ChannelReader<byte[]> incoming,
        Func<int, byte[], bool>? filter
    ) : IDatagramTransport
    {
        private int _sent;

        public int Sent => Volatile.Read(ref _sent);

        public ValueTask SendAsync(
            ReadOnlyMemory<byte> datagram,
            CancellationToken cancellationToken
        )
        {
            byte[] copy = datagram.ToArray();
            int index = Interlocked.Increment(ref _sent) - 1;
            if (filter is null || filter(index, copy))
            {
                _ = outgoing.TryWrite(copy);
            }

            return ValueTask.CompletedTask;
        }

        public async ValueTask<int> ReceiveAsync(
            Memory<byte> buffer,
            CancellationToken cancellationToken
        )
        {
            byte[] datagram = await incoming.ReadAsync(cancellationToken);
            datagram.CopyTo(buffer);
            return datagram.Length;
        }

        // Sends a datagram to the peer as this end, past the filter.
        public void Inject(byte[] datagram) => _ = outgoing.TryWrite(datagram);
    }
}
