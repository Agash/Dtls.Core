using Dtls.Core.Handshake;

namespace Dtls.Core.Protocol;

// Connection IDs (RFC 9146, RFC 9147 section 9) and record size limits (RFC 8449), the same in both
// versions: each side asks for the CID it wants in the records it receives, and states the most plaintext
// it takes in a protected record. Both take effect on the record layer as soon as they are known; they
// only touch protected records, which come later.
internal sealed partial class DtlsProtocol
{
    private bool _recordSizeLimitOffered;
    private bool _cidAgreed;

    // The CID this side's records carry, empty when none; the one the peer's carry, empty when none.
    public ReadOnlyMemory<byte> RemoteConnectionId { get; private set; }

    public ReadOnlyMemory<byte> LocalConnectionId { get; private set; }

    // RFC 9146 §6: the last datagram held a record that authenticated, carried this side's CID, and was
    // newer than any before it, so the peer may be followed to the address it came from.
    public bool PeerMayHaveMoved => LocalConnectionId.Length > 0 && _records.AdvancedNewest;

    // The peer's record size limit, or the protocol's when it stated none.
    public int PeerRecordSizeLimit => _records.PeerRecordLimit;

    // Client: the server's answer agrees on CIDs when it carries the extension.
    private void AcceptConnectionId(Extensions extensions)
    {
        if (
            _localConnectionId is not null
            && extensions.TryGet(ExtensionType.ConnectionId, out ReadOnlySpan<byte> data)
        )
        {
            UseConnectionIds(HelloExtensions.ReadConnectionId(data), _localConnectionId);
        }
    }

    // Either side: the peer's record size limit, when it states one.
    private void AcceptRecordSizeLimit(Extensions extensions)
    {
        if (extensions.TryGet(ExtensionType.RecordSizeLimit, out ReadOnlySpan<byte> data))
        {
            _recordSizeLimitOffered = true;
            _records.LimitRecords(HelloExtensions.ReadRecordSizeLimit(data));
        }
    }

    // Server: a client offering the extension gets this side's CID back, when this side uses them.
    private void SelectConnectionId(Extensions extensions)
    {
        if (
            _localConnectionId is not null
            && extensions.TryGet(ExtensionType.ConnectionId, out ReadOnlySpan<byte> data)
        )
        {
            UseConnectionIds(HelloExtensions.ReadConnectionId(data), _localConnectionId);
        }
    }

    // Server: the ServerHello's answer, when CIDs were agreed.
    private void AnswerConnectionId(Extensions extensions)
    {
        if (_cidAgreed)
        {
            _ = extensions.Add(
                ExtensionType.ConnectionId,
                HelloExtensions.ConnectionId(LocalConnectionId.Span)
            );
        }
    }

    // Server: its own limit, only in answer to the client's (an extension the client did not offer
    // cannot be answered).
    private void AnswerRecordSizeLimit(Extensions extensions)
    {
        if (_recordSizeLimitOffered)
        {
            _ = extensions.Add(
                ExtensionType.RecordSizeLimit,
                HelloExtensions.RecordSizeLimit(_settings.RecordSizeLimit)
            );
        }
    }

    private void UseConnectionIds(byte[] send, byte[] receive)
    {
        _cidAgreed = true;
        RemoteConnectionId = send;
        LocalConnectionId = receive;
        _records.UseConnectionIds(send, receive);
    }
}
