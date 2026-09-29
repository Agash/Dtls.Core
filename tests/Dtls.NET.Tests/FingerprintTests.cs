using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Dtls.NET.Tests;

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

    [TestMethod]
    public void Matches_OtherCertificate_IsFalse()
    {
        using X509Certificate2 mine = DtlsCertificates.CreateSelfSigned();
        using X509Certificate2 other = DtlsCertificates.CreateSelfSigned();

        Assert.IsFalse(DtlsFingerprint.Compute(mine).Matches(other));
        Assert.IsFalse(default(DtlsFingerprint).Matches(mine));
    }
}
