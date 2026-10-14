using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Dtls.Core.Tests;

[TestClass]
public sealed class FingerprintTests
{
    [TestMethod]
    public void Parse_FormattedFingerprint_RoundTripsToAnEqualValue()
    {
        using X509Certificate2 certificate = DtlsCertificates.CreateSelfSigned();
        DtlsFingerprint computed = DtlsFingerprint.Compute(certificate);

        DtlsFingerprint parsed = DtlsFingerprint.Parse(computed.ToString());

        Assert.AreEqual(computed, parsed);
        Assert.AreEqual(computed.GetHashCode(), parsed.GetHashCode());
        Assert.IsTrue(parsed.Matches(certificate));
    }

    [TestMethod]
    public void Equals_SameBytesInDifferentArrays_IsTrue()
    {
        byte[] hash = SHA256.HashData([1, 2, 3]);
        DtlsFingerprint first = new(HashAlgorithmName.SHA256, [.. hash]);
        DtlsFingerprint second = new(HashAlgorithmName.SHA256, [.. hash]);

        Assert.IsTrue(first == second);
        Assert.AreNotEqual(first, second with { Algorithm = HashAlgorithmName.SHA384 });
    }

    [TestMethod]
    public void Parse_LowerCaseSdpValue_IsAccepted()
    {
        using X509Certificate2 certificate = DtlsCertificates.CreateSelfSigned();
        string value = DtlsFingerprint.Compute(certificate).ToString().ToLowerInvariant();

        Assert.IsTrue(DtlsFingerprint.Parse(value).Matches(certificate));
    }

    [TestMethod]
    [DataRow("")]
    [DataRow("sha-256")]
    [DataRow("md5 AB:CD")]
    [DataRow("sha-256 AB:CD")]
    [DataRow("sha-256 ABCD")]
    public void TryParse_Malformed_ReturnsFalse(string value) =>
        Assert.IsFalse(DtlsFingerprint.TryParse(value, out _));

    // FIPS 180-4's SHA-224 examples (NIST CSRC "SHA224.pdf"), the 448-bit one crossing a block.
    [TestMethod]
    [DataRow("abc", "23097D223405D8228642A477BDA255B32AADBCE4BDA0B3F7E36C9DA7")]
    [DataRow("", "D14A028C2A3A2BC9476102BB288234C415A2B01F828EA62AC5B3E42F")]
    [DataRow(
        "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        "75388B16512776CC5DBA5DA1FD890150B0C6455CB4F58B1952522525"
    )]
    public void Sha224_FipsExamples_Match(string message, string expected) =>
        Assert.AreEqual(
            expected,
            Convert.ToHexString(Sha224.HashData(System.Text.Encoding.ASCII.GetBytes(message)))
        );

    [TestMethod]
    public void Sha224_MillionAs_MatchesTheFipsExample() =>
        Assert.AreEqual(
            "20794655980C91D8BBB4C1EA97618A4BF03F42581948B2EE4EE7AD67",
            Convert.ToHexString(
                Sha224.HashData(
                    new byte[1_000_000]
                        .Select(static _ => (byte)'a')
                        .ToArray()
                )
            )
        );

    // RFC 8122 section 5: every hash function it defines except MD5 and MD2 computes, prints and parses.
    [TestMethod]
    [DataRow("SHA1", "sha-1", 20)]
    [DataRow("SHA224", "sha-224", 28)]
    [DataRow("SHA256", "sha-256", 32)]
    [DataRow("SHA384", "sha-384", 48)]
    [DataRow("SHA512", "sha-512", 64)]
    public void Compute_EveryRfc8122Function_RoundTripsThroughSdp(
        string algorithm,
        string name,
        int size
    )
    {
        using X509Certificate2 certificate = DtlsCertificates.CreateSelfSigned();
        DtlsFingerprint computed = DtlsFingerprint.Compute(
            certificate,
            new HashAlgorithmName(algorithm)
        );

        Assert.AreEqual(size, computed.Hash.Length);
        Assert.StartsWith(name + " ", computed.ToString());
        Assert.IsTrue(DtlsFingerprint.Parse(computed.ToString()).Matches(certificate));
    }

    [TestMethod]
    [DataRow("md5 AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89")]
    [DataRow("md2 AB:CD:EF:01:23:45:67:89:AB:CD:EF:01:23:45:67:89")]
    public void TryParse_Md5OrMd2_IsRefused(string value) =>
        Assert.IsFalse(DtlsFingerprint.TryParse(value, out _));

    // RFC 8122 section 5.1: the certificate has to match one of the fingerprints with the most preferred
    // hash function offered; weaker ones do not count once a stronger one is there.
    [TestMethod]
    public void CreateValidationCallback_SeveralFingerprints_UsesTheStrongestHashOffered()
    {
        using X509Certificate2 presented = DtlsCertificates.CreateSelfSigned();
        using X509Certificate2 other = DtlsCertificates.CreateSelfSigned();
        DtlsFingerprint presentedSha1 = DtlsFingerprint.Compute(presented, HashAlgorithmName.SHA1);
        DtlsFingerprint presentedSha256 = DtlsFingerprint.Compute(presented);
        DtlsFingerprint otherSha256 = DtlsFingerprint.Compute(other);
        DtlsFingerprint otherSha512 = DtlsFingerprint.Compute(other, HashAlgorithmName.SHA512);

        Assert.IsTrue(
            Validates([presentedSha1, presentedSha256, otherSha256], presented),
            "one of the sha-256 set"
        );
        Assert.IsFalse(
            Validates([presentedSha1, otherSha256], presented),
            "sha-256 is preferred to sha-1"
        );
        Assert.IsFalse(
            Validates([presentedSha256, otherSha512], presented),
            "sha-512 is preferred to sha-256"
        );
        Assert.IsFalse(Validates([], presented));

        static bool Validates(DtlsFingerprint[] fingerprints, X509Certificate2 certificate) =>
            DtlsFingerprint.CreateValidationCallback(fingerprints)(
                new object(),
                certificate,
                null,
                System.Net.Security.SslPolicyErrors.None
            );
    }

    [TestMethod]
    public void Matches_OtherCertificate_IsFalse()
    {
        using X509Certificate2 mine = DtlsCertificates.CreateSelfSigned();
        using X509Certificate2 other = DtlsCertificates.CreateSelfSigned();

        Assert.IsFalse(DtlsFingerprint.Compute(mine).Matches(other));
        Assert.IsFalse(default(DtlsFingerprint).Matches(mine));
    }
}
