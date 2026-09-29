namespace Dtls.NET.Records;

// Anti-replay for one epoch (RFC 6347 §4.1.2.6, after RFC 4303 §3.4.3): the highest sequence number
// seen and a 64-record bitmap behind it. A record is accepted once; one older than the window is
// dropped. A record is only marked seen after it authenticates, so forged records cannot move the
// window.
internal struct ReplayWindow
{
    private const int Size = 64;
    private ulong _highest;
    private ulong _seen;
    private bool _any;

    // One past the highest sequence number seen: where a DTLS 1.3 sequence number is reconstructed from.
    public readonly ulong NextExpected => _any ? _highest + 1 : 0;

    public readonly bool IsFresh(ulong sequence)
    {
        if (!_any || sequence > _highest)
        {
            return true;
        }

        ulong behind = _highest - sequence;
        return behind < Size && (_seen & (1UL << (int)behind)) == 0;
    }

    public void MarkSeen(ulong sequence)
    {
        if (!_any)
        {
            _any = true;
            _highest = sequence;
            _seen = 1;
            return;
        }

        if (sequence > _highest)
        {
            ulong ahead = sequence - _highest;
            _seen = ahead >= Size ? 1 : (_seen << (int)ahead) | 1;
            _highest = sequence;
            return;
        }

        ulong behind = _highest - sequence;
        if (behind < Size)
        {
            _seen |= 1UL << (int)behind;
        }
    }
}
