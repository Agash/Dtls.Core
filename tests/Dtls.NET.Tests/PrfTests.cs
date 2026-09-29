using System.Security.Cryptography;
using Dtls.NET.Crypto;

namespace Dtls.NET.Tests;

[TestClass]
public sealed class PrfTests
{
    [TestMethod]
    public void Compute_Sha256Vector_MatchesOpenSsl()
    {
        // The widely used TLS 1.2 PRF test vector; OpenSSL's TLS1-PRF KDF gives the same output.
        byte[] secret = Convert.FromHexString("9bbe436ba940f017b17652849a71db35");
        byte[] seed = Convert.FromHexString("a0ba9f936cda311827a6f796ffd5198c");
        byte[] expected = Convert.FromHexString(
            "e3f229ba727be17b8d122620557cd453c2aab21d07c3d495329b52d4e61edb5a6b301791e90d35c9c9a46b4e14baf9af"
                + "0fa022f7077def17abfd3797c0564bab4fbc91666e9def9b97fce34f796789baa48082d122ee42c5a72e5a5110fff70187347b66"
        );
        byte[] output = new byte[expected.Length];

        Prf.Compute(HashAlgorithmName.SHA256, secret, "test label", seed, output);

        CollectionAssert.AreEqual(expected, output);
    }

    [TestMethod]
    public void Compute_TwoSeeds_EqualsTheirConcatenation()
    {
        byte[] secret = RandomNumberGenerator.GetBytes(48);
        byte[] first = RandomNumberGenerator.GetBytes(32);
        byte[] second = RandomNumberGenerator.GetBytes(32);
        byte[] a = new byte[77];
        byte[] b = new byte[77];

        Prf.Compute(HashAlgorithmName.SHA384, secret, "key expansion", first, second, a);
        Prf.Compute(HashAlgorithmName.SHA384, secret, "key expansion", [.. first, .. second], b);

        CollectionAssert.AreEqual(a, b);
        CollectionAssert.AreNotEqual(new byte[77], a);
    }
}
