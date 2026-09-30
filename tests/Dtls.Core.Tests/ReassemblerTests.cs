using Dtls.Core.Handshake;

namespace Dtls.Core.Tests;

[TestClass]
public sealed class ReassemblerTests
{
    [TestMethod]
    public void Add_OutOfOrderOverlappingFragments_DeliverTheMessage()
    {
        HandshakeReassembler reassembler = new(1024);
        byte[] body = [.. Enumerable.Range(0, 100).Select(static i => (byte)i)];

        Assert.IsTrue(Add(reassembler, body, 60, 40, authenticated: true));
        Assert.IsTrue(Add(reassembler, body, 0, 70, authenticated: true));

        Assert.IsTrue(reassembler.TryDequeue(out HandshakeMessage message));
        CollectionAssert.AreEqual(body, message.Body);
    }

    [TestMethod]
    public void Add_ContradictingAuthenticatedFragment_IsAProtocolError()
    {
        HandshakeReassembler reassembler = new(1024);
        byte[] body = new byte[100];
        _ = Add(reassembler, body, 0, 60, authenticated: true);
        byte[] other = new byte[100];
        other[50] = 1;

        DtlsException error = Assert.ThrowsExactly<DtlsException>(() =>
            Add(reassembler, other, 40, 60, authenticated: true)
        );
        Assert.AreEqual(DtlsAlert.IllegalParameter, error.Alert);
    }

    [TestMethod]
    public void Add_ContradictingUnauthenticatedFragment_StartsTheMessageOver()
    {
        // A forged fragment got in first; the genuine one, retransmitted whole, still wins.
        HandshakeReassembler reassembler = new(1024);
        byte[] forged = new byte[100];
        forged[50] = 1;
        _ = Add(reassembler, forged, 0, 60, authenticated: false);
        byte[] body = new byte[100];

        Assert.IsTrue(Add(reassembler, body, 0, 100, authenticated: false));
        Assert.IsTrue(reassembler.TryDequeue(out HandshakeMessage message));
        CollectionAssert.AreEqual(body, message.Body);
    }

    [TestMethod]
    public void Add_DeclaredLengthOverTheLimit_AllocatesNothing()
    {
        HandshakeReassembler reassembler = new(1024);

        Assert.IsFalse(
            Add(reassembler, new byte[10], 0, 10, authenticated: false, length: 0xFFFFFF)
        );
        Assert.ThrowsExactly<DtlsException>(() =>
            Add(reassembler, new byte[10], 0, 10, authenticated: true, length: 0xFFFFFF)
        );
    }

    private static bool Add(
        HandshakeReassembler reassembler,
        byte[] body,
        int offset,
        int count,
        bool authenticated,
        int? length = null
    )
    {
        HandshakeFragment fragment = new(
            HandshakeType.Certificate,
            length ?? body.Length,
            0,
            offset,
            body.AsSpan(offset, count)
        );
        return reassembler.Add(fragment, authenticated);
    }
}
