using Dtls.Core.Crypto;
using Dtls.Core.Handshake;

namespace Dtls.Core.Tests;

// RFC 8446 section 7.4.2 and RFC 8422 section 5.11: X25519 shares are 32 raw bytes, and a share whose
// shared secret is all zeros (a low-order point) ends the handshake.
[TestClass]
public sealed class KeyShareTests
{
    [TestMethod]
    public void X25519_IsPreferred_WhereThePlatformHasIt()
    {
        Assert.IsTrue(System.Security.Cryptography.X25519DiffieHellman.IsSupported);
        Assert.AreEqual(NamedGroup.X25519, KeyShare.SupportedGroups.First());
    }

    [TestMethod]
    public void X25519_TwoShares_AgreeOnTheSecret()
    {
        using KeyShare a = KeyShare.Create(NamedGroup.X25519);
        using KeyShare b = KeyShare.Create(NamedGroup.X25519);

        Assert.HasCount(32, a.PublicKey);
        CollectionAssert.AreEqual(a.DeriveSecret(b.PublicKey), b.DeriveSecret(a.PublicKey));
    }

    // RFC 7748 section 6.1: the all-zero point (and the other low-order points) give an all-zero secret.
    [TestMethod]
    [DataRow("0000000000000000000000000000000000000000000000000000000000000000")]
    [DataRow("0100000000000000000000000000000000000000000000000000000000000000")]
    [DataRow("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800")]
    public void X25519_LowOrderShare_IsRefused(string point)
    {
        using KeyShare share = KeyShare.Create(NamedGroup.X25519);

        DtlsException refused = Assert.ThrowsExactly<DtlsException>(() =>
            share.DeriveSecret(Convert.FromHexString(point))
        );
        Assert.AreEqual(DtlsAlert.IllegalParameter, refused.Alert);
    }

    [TestMethod]
    public void X25519_ShareOfAnotherLength_IsRefused()
    {
        using KeyShare share = KeyShare.Create(NamedGroup.X25519);

        _ = Assert.ThrowsExactly<DtlsException>(() => share.DeriveSecret(new byte[65]));
    }
}
