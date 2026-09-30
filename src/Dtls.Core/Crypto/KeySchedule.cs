using System.Security.Cryptography;
using Dtls.Core.Records;

namespace Dtls.Core.Crypto;

// TLS 1.2's key schedule (RFC 5246 §6.3, §7.4.9, §8.1) with the extended master secret of RFC 7627
// and the keying material exporter of RFC 5705.
internal static class KeySchedule
{
    public const int MasterSecretLength = 48;
    public const int VerifyDataLength = 12;

    // With the extended master secret the secret is bound to the whole handshake up to the client's
    // key exchange (its session hash), not just the two randoms.
    public static byte[] MasterSecret(
        CipherSuiteInfo suite,
        ReadOnlySpan<byte> premasterSecret,
        bool extended,
        ReadOnlySpan<byte> sessionHash,
        ReadOnlySpan<byte> clientRandom,
        ReadOnlySpan<byte> serverRandom
    )
    {
        byte[] master = new byte[MasterSecretLength];
        if (extended)
        {
            Prf.Compute(
                suite.PrfHash,
                premasterSecret,
                "extended master secret",
                sessionHash,
                master
            );
        }
        else
        {
            Prf.Compute(
                suite.PrfHash,
                premasterSecret,
                "master secret",
                clientRandom,
                serverRandom,
                master
            );
        }

        return master;
    }

    // The record ciphers of epoch 1: key_block = PRF(master, "key expansion", server_random ||
    // client_random), split into client key, server key, client IV, server IV.
    public static (RecordCipher Client, RecordCipher Server) RecordCiphers(
        CipherSuiteInfo suite,
        ReadOnlySpan<byte> masterSecret,
        ReadOnlySpan<byte> clientRandom,
        ReadOnlySpan<byte> serverRandom
    )
    {
        int key = suite.KeyLength;
        int iv = suite.FixedIvLength;
        byte[] block = new byte[(2 * key) + (2 * iv)];
        try
        {
            Prf.Compute(
                suite.PrfHash,
                masterSecret,
                "key expansion",
                serverRandom,
                clientRandom,
                block
            );
            ReadOnlySpan<byte> blockSpan = block;
            RecordCipher client = RecordCipher.Create(
                suite,
                blockSpan[..key],
                blockSpan.Slice(2 * key, iv)
            );
            RecordCipher server = RecordCipher.Create(
                suite,
                blockSpan.Slice(key, key),
                blockSpan.Slice((2 * key) + iv, iv)
            );
            return (client, server);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(block);
        }
    }

    // A Finished message's verify_data over the transcript's hash.
    public static byte[] VerifyData(
        CipherSuiteInfo suite,
        ReadOnlySpan<byte> masterSecret,
        bool client,
        ReadOnlySpan<byte> transcriptHash
    )
    {
        byte[] verifyData = new byte[VerifyDataLength];
        Prf.Compute(
            suite.PrfHash,
            masterSecret,
            client ? "client finished" : "server finished",
            transcriptHash,
            verifyData
        );
        return verifyData;
    }

    // RFC 5705 §4: PRF(master, label, client_random || server_random [|| context length || context]).
    public static void Export(
        CipherSuiteInfo suite,
        ReadOnlySpan<byte> masterSecret,
        string label,
        ReadOnlySpan<byte> clientRandom,
        ReadOnlySpan<byte> serverRandom,
        ReadOnlySpan<byte> context,
        bool useContext,
        Span<byte> destination
    )
    {
        int length =
            clientRandom.Length + serverRandom.Length + (useContext ? 2 + context.Length : 0);
        Span<byte> seed = length <= 256 ? stackalloc byte[length] : new byte[length];
        clientRandom.CopyTo(seed);
        serverRandom.CopyTo(seed[clientRandom.Length..]);
        if (useContext)
        {
            int at = clientRandom.Length + serverRandom.Length;
            seed[at] = (byte)(context.Length >> 8);
            seed[at + 1] = (byte)context.Length;
            context.CopyTo(seed[(at + 2)..]);
        }

        Prf.Compute(suite.PrfHash, masterSecret, label, seed, destination);
    }
}
