using System.Buffers.Binary;
using System.Numerics;

namespace Dtls.Core;

// SHA-224 (FIPS 180-4 sections 5.3.2 and 6.3): SHA-256's compression from its own initial hash value,
// truncated to 28 bytes. The BCL has no SHA-224, and RFC 8122 section 5 lists it among the fingerprint
// hash functions an endpoint recognises.
internal static class Sha224
{
    public const int HashSize = 28;

    private static ReadOnlySpan<uint> Initial =>
        [
            0xc1059ed8,
            0x367cd507,
            0x3070dd17,
            0xf70e5939,
            0xffc00b31,
            0x68581511,
            0x64f98fa7,
            0xbefa4fa4,
        ];

    private static ReadOnlySpan<uint> K =>
        [
            0x428a2f98,
            0x71374491,
            0xb5c0fbcf,
            0xe9b5dba5,
            0x3956c25b,
            0x59f111f1,
            0x923f82a4,
            0xab1c5ed5,
            0xd807aa98,
            0x12835b01,
            0x243185be,
            0x550c7dc3,
            0x72be5d74,
            0x80deb1fe,
            0x9bdc06a7,
            0xc19bf174,
            0xe49b69c1,
            0xefbe4786,
            0x0fc19dc6,
            0x240ca1cc,
            0x2de92c6f,
            0x4a7484aa,
            0x5cb0a9dc,
            0x76f988da,
            0x983e5152,
            0xa831c66d,
            0xb00327c8,
            0xbf597fc7,
            0xc6e00bf3,
            0xd5a79147,
            0x06ca6351,
            0x14292967,
            0x27b70a85,
            0x2e1b2138,
            0x4d2c6dfc,
            0x53380d13,
            0x650a7354,
            0x766a0abb,
            0x81c2c92e,
            0x92722c85,
            0xa2bfe8a1,
            0xa81a664b,
            0xc24b8b70,
            0xc76c51a3,
            0xd192e819,
            0xd6990624,
            0xf40e3585,
            0x106aa070,
            0x19a4c116,
            0x1e376c08,
            0x2748774c,
            0x34b0bcb5,
            0x391c0cb3,
            0x4ed8aa4a,
            0x5b9cca4f,
            0x682e6ff3,
            0x748f82ee,
            0x78a5636f,
            0x84c87814,
            0x8cc70208,
            0x90befffa,
            0xa4506ceb,
            0xbef9a3f7,
            0xc67178f2,
        ];

    public static byte[] HashData(ReadOnlySpan<byte> data)
    {
        Span<uint> state = stackalloc uint[8];
        Initial.CopyTo(state);

        int whole = data.Length / 64;
        for (int block = 0; block < whole; block++)
        {
            Compress(state, data.Slice(block * 64, 64));
        }

        // The remainder, a one bit, zeros, and the message length in bits (section 5.1.1).
        Span<byte> tail = stackalloc byte[128];
        tail.Clear();
        ReadOnlySpan<byte> rest = data[(whole * 64)..];
        rest.CopyTo(tail);
        tail[rest.Length] = 0x80;
        int tailLength = rest.Length + 9 <= 64 ? 64 : 128;
        BinaryPrimitives.WriteUInt64BigEndian(tail[(tailLength - 8)..], (ulong)data.Length * 8);
        for (int offset = 0; offset < tailLength; offset += 64)
        {
            Compress(state, tail.Slice(offset, 64));
        }

        byte[] hash = new byte[HashSize];
        for (int i = 0; i < 7; i++)
        {
            BinaryPrimitives.WriteUInt32BigEndian(hash.AsSpan(i * 4), state[i]);
        }

        return hash;
    }

    // Section 6.2.2: one 512-bit block.
    private static void Compress(Span<uint> state, ReadOnlySpan<byte> block)
    {
        Span<uint> w = stackalloc uint[64];
        for (int t = 0; t < 16; t++)
        {
            w[t] = BinaryPrimitives.ReadUInt32BigEndian(block[(t * 4)..]);
        }

        for (int t = 16; t < 64; t++)
        {
            uint s0 =
                BitOperations.RotateRight(w[t - 15], 7)
                ^ BitOperations.RotateRight(w[t - 15], 18)
                ^ (w[t - 15] >> 3);
            uint s1 =
                BitOperations.RotateRight(w[t - 2], 17)
                ^ BitOperations.RotateRight(w[t - 2], 19)
                ^ (w[t - 2] >> 10);
            w[t] = w[t - 16] + s0 + w[t - 7] + s1;
        }

        uint a = state[0],
            b = state[1],
            c = state[2],
            d = state[3],
            e = state[4],
            f = state[5],
            g = state[6],
            h = state[7];
        for (int t = 0; t < 64; t++)
        {
            uint sum1 =
                BitOperations.RotateRight(e, 6)
                ^ BitOperations.RotateRight(e, 11)
                ^ BitOperations.RotateRight(e, 25);
            uint choose = (e & f) ^ (~e & g);
            uint t1 = h + sum1 + choose + K[t] + w[t];
            uint sum0 =
                BitOperations.RotateRight(a, 2)
                ^ BitOperations.RotateRight(a, 13)
                ^ BitOperations.RotateRight(a, 22);
            uint majority = (a & b) ^ (a & c) ^ (b & c);
            uint t2 = sum0 + majority;
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }

        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
        state[4] += e;
        state[5] += f;
        state[6] += g;
        state[7] += h;
    }
}
