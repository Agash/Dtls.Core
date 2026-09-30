using System.Security.Cryptography;
using System.Text;

namespace Dtls.Core.Crypto;

// The TLS 1.2 pseudorandom function (RFC 5246 §5): P_hash(secret, label || seed) with the cipher
// suite's PRF hash, expanded to the length asked for. Every key, Finished value and exported keying
// material of the connection comes from here. Scratch space is on the stack for the seeds TLS uses
// and zeroed after use.
internal static class Prf
{
    private const int StackLimit = 512;
    private const int MaximumHashSize = 48;

    public static void Compute(
        HashAlgorithmName hash,
        ReadOnlySpan<byte> secret,
        string label,
        ReadOnlySpan<byte> seed,
        Span<byte> output
    )
    {
        int labelLength = Encoding.ASCII.GetByteCount(label);
        int length = labelLength + seed.Length;
        Span<byte> labelAndSeed = length <= StackLimit ? stackalloc byte[length] : new byte[length];
        _ = Encoding.ASCII.GetBytes(label, labelAndSeed);
        seed.CopyTo(labelAndSeed[labelLength..]);
        Expand(hash, secret, labelAndSeed, output);
        CryptographicOperations.ZeroMemory(labelAndSeed);
    }

    // Two seeds, as most uses concatenate the client and server randoms.
    public static void Compute(
        HashAlgorithmName hash,
        ReadOnlySpan<byte> secret,
        string label,
        ReadOnlySpan<byte> seed1,
        ReadOnlySpan<byte> seed2,
        Span<byte> output
    )
    {
        int length = seed1.Length + seed2.Length;
        Span<byte> seed = length <= StackLimit ? stackalloc byte[length] : new byte[length];
        seed1.CopyTo(seed);
        seed2.CopyTo(seed[seed1.Length..]);
        Compute(hash, secret, label, seed, output);
    }

    // P_hash: A(0) = seed, A(i) = HMAC(secret, A(i-1)); output = HMAC(secret, A(1) || seed) ||
    // HMAC(secret, A(2) || seed) || ..., truncated to the output's length.
    private static void Expand(
        HashAlgorithmName hash,
        ReadOnlySpan<byte> secret,
        ReadOnlySpan<byte> seed,
        Span<byte> output
    )
    {
        int size = HashSize(hash);
        Span<byte> a = stackalloc byte[MaximumHashSize];
        a = a[..size];
        Span<byte> block = stackalloc byte[MaximumHashSize];
        block = block[..size];
        int inputLength = size + seed.Length;
        Span<byte> input =
            inputLength <= StackLimit ? stackalloc byte[inputLength] : new byte[inputLength];
        seed.CopyTo(input[size..]);

        // A(1) = HMAC(secret, seed).
        _ = Hmac(hash, secret, seed, a);
        int written = 0;
        while (written < output.Length)
        {
            a.CopyTo(input);
            _ = Hmac(hash, secret, input, block);
            int take = Math.Min(size, output.Length - written);
            block[..take].CopyTo(output[written..]);
            written += take;
            // A(i+1) = HMAC(secret, A(i)), into scratch: HMAC does not promise in-place output.
            _ = Hmac(hash, secret, a, block);
            block.CopyTo(a);
        }

        CryptographicOperations.ZeroMemory(a);
        CryptographicOperations.ZeroMemory(block);
        CryptographicOperations.ZeroMemory(input);
    }

    public static int HashSize(HashAlgorithmName hash) =>
        hash == HashAlgorithmName.SHA256 ? SHA256.HashSizeInBytes
        : hash == HashAlgorithmName.SHA384 ? SHA384.HashSizeInBytes
        : throw new ArgumentException($"{hash} is not a TLS 1.2 PRF hash.", nameof(hash));

    public static byte[] Hash(HashAlgorithmName hash, ReadOnlySpan<byte> data) =>
        hash == HashAlgorithmName.SHA256 ? SHA256.HashData(data)
        : hash == HashAlgorithmName.SHA384 ? SHA384.HashData(data)
        : throw new ArgumentException($"{hash} is not a TLS 1.2 PRF hash.", nameof(hash));

    private static int Hmac(
        HashAlgorithmName hash,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> data,
        Span<byte> destination
    ) =>
        hash == HashAlgorithmName.SHA256 ? HMACSHA256.HashData(key, data, destination)
        : hash == HashAlgorithmName.SHA384 ? HMACSHA384.HashData(key, data, destination)
        : throw new ArgumentException($"{hash} is not a TLS 1.2 PRF hash.", nameof(hash));
}
