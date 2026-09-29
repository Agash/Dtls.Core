using System.Security.Cryptography;
using System.Text;

namespace Dtls.NET.Crypto;

// TLS 1.3's key schedule (RFC 8446 §7.1) as DTLS 1.3 runs it: HKDF with the suite's hash, and every
// label prefixed "dtls13" rather than "tls13 " (RFC 9147 §5.9). Without a pre-shared key the early
// secret is HKDF-Extract(0, 0); the ECDHE secret is mixed in for the handshake secret, and the master
// secret follows from it.
internal sealed class KeySchedule13 : IDisposable
{
    // RFC 9147 §5.9.
    public const string DtlsPrefix = "dtls13";

    private readonly HashAlgorithmName _hash;
    private readonly string _prefix;
    private byte[] _secret;

    public KeySchedule13(HashAlgorithmName hash, string prefix = DtlsPrefix)
    {
        _hash = hash;
        _prefix = prefix;
        HashLength = Prf.HashSize(hash);
        _secret = new byte[HashLength];
        _ = HKDF.Extract(hash, new byte[HashLength], new byte[HashLength], _secret);
    }

    public int HashLength { get; }

    // The current stage's secret: early, then handshake, then master.
    public ReadOnlySpan<byte> Secret => _secret;

    // Advances to the next stage: Extract(Derive-Secret(secret, "derived", ""), input). The handshake
    // stage takes the ECDHE shared secret; the master stage takes zeros.
    public void Advance(ReadOnlySpan<byte> input)
    {
        Span<byte> emptyHash = stackalloc byte[HashLength];
        _ = Hash(_hash, [], emptyHash);
        byte[] derived = DeriveSecret("derived", emptyHash);
        byte[] next = new byte[HashLength];
        ReadOnlySpan<byte> ikm = input.IsEmpty ? new byte[HashLength] : input;
        _ = HKDF.Extract(_hash, ikm, derived, next);
        CryptographicOperations.ZeroMemory(derived);
        CryptographicOperations.ZeroMemory(_secret);
        _secret = next;
    }

    // Derive-Secret(secret, label, messages) with the transcript's hash already taken.
    public byte[] DeriveSecret(string label, ReadOnlySpan<byte> transcriptHash) =>
        ExpandLabel(_hash, _prefix, _secret, label, transcriptHash, HashLength);

    public static byte[] ExpandLabel(
        HashAlgorithmName hash,
        string prefix,
        ReadOnlySpan<byte> secret,
        string label,
        ReadOnlySpan<byte> context,
        int length
    )
    {
        byte[] output = new byte[length];
        ExpandLabel(hash, prefix, secret, label, context, output);
        return output;
    }

    // HKDF-Expand-Label: HkdfLabel { uint16 length; opaque label<7..255> = prefix + label; opaque
    // context<0..255> }.
    public static void ExpandLabel(
        HashAlgorithmName hash,
        string prefix,
        ReadOnlySpan<byte> secret,
        string label,
        ReadOnlySpan<byte> context,
        Span<byte> output
    )
    {
        int labelLength = Encoding.ASCII.GetByteCount(prefix) + Encoding.ASCII.GetByteCount(label);
        Span<byte> info = stackalloc byte[2 + 1 + labelLength + 1 + context.Length];
        info[0] = (byte)(output.Length >> 8);
        info[1] = (byte)output.Length;
        info[2] = (byte)labelLength;
        int at = 3 + Encoding.ASCII.GetBytes(prefix, info[3..]);
        at += Encoding.ASCII.GetBytes(label, info[at..]);
        info[at++] = (byte)context.Length;
        context.CopyTo(info[at..]);
        HKDF.Expand(hash, secret, output, info);
    }

    // The traffic keys of a traffic secret (RFC 8446 §7.3, RFC 9147 §4.2.3): write key, IV and the key
    // that masks record numbers.
    public static TrafficKeys Keys(
        CipherSuiteInfo suite,
        string prefix,
        ReadOnlySpan<byte> trafficSecret
    ) =>
        new(
            ExpandLabel(suite.PrfHash, prefix, trafficSecret, "key", [], suite.KeyLength),
            ExpandLabel(suite.PrfHash, prefix, trafficSecret, "iv", [], suite.FixedIvLength),
            ExpandLabel(suite.PrfHash, prefix, trafficSecret, "sn", [], suite.KeyLength)
        );

    // The secret after a KeyUpdate (RFC 8446 §7.2).
    public static byte[] NextTrafficSecret(
        HashAlgorithmName hash,
        string prefix,
        ReadOnlySpan<byte> trafficSecret
    ) => ExpandLabel(hash, prefix, trafficSecret, "traffic upd", [], Prf.HashSize(hash));

    // Finished's verify_data (RFC 8446 §4.4.4): HMAC(finished_key, transcript hash).
    public static byte[] VerifyData(
        HashAlgorithmName hash,
        string prefix,
        ReadOnlySpan<byte> baseKey,
        ReadOnlySpan<byte> transcriptHash
    )
    {
        byte[] finishedKey = ExpandLabel(hash, prefix, baseKey, "finished", [], Prf.HashSize(hash));
        try
        {
            return hash == HashAlgorithmName.SHA384
                ? HMACSHA384.HashData(finishedKey, transcriptHash)
                : HMACSHA256.HashData(finishedKey, transcriptHash);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(finishedKey);
        }
    }

    // TLS-Exporter (RFC 8446 §7.5): HKDF-Expand-Label(Derive-Secret(exporter_master_secret, label, ""),
    // "exporter", Hash(context), length). TLS 1.3 does not tell an empty context from none.
    public static void Export(
        HashAlgorithmName hash,
        string prefix,
        ReadOnlySpan<byte> exporterMasterSecret,
        string label,
        ReadOnlySpan<byte> context,
        Span<byte> destination
    )
    {
        int length = Prf.HashSize(hash);
        Span<byte> emptyHash = stackalloc byte[length];
        _ = Hash(hash, [], emptyHash);
        byte[] secret = ExpandLabel(hash, prefix, exporterMasterSecret, label, emptyHash, length);
        Span<byte> contextHash = stackalloc byte[length];
        _ = Hash(hash, context, contextHash);
        ExpandLabel(hash, prefix, secret, "exporter", contextHash, destination);
        CryptographicOperations.ZeroMemory(secret);
    }

    public static int Hash(
        HashAlgorithmName hash,
        ReadOnlySpan<byte> data,
        Span<byte> destination
    ) =>
        hash == HashAlgorithmName.SHA384
            ? SHA384.HashData(data, destination)
            : SHA256.HashData(data, destination);

    public void Dispose() => CryptographicOperations.ZeroMemory(_secret);
}

// A traffic secret's keys; secrets, zeroed on Dispose.
internal sealed record TrafficKeys(byte[] Key, byte[] Iv, byte[] SequenceKey) : IDisposable
{
    public void Dispose()
    {
        CryptographicOperations.ZeroMemory(Key);
        CryptographicOperations.ZeroMemory(Iv);
        CryptographicOperations.ZeroMemory(SequenceKey);
    }
}
