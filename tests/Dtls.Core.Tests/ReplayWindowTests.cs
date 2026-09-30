using Dtls.Core.Records;

namespace Dtls.Core.Tests;

[TestClass]
public sealed class ReplayWindowTests
{
    [TestMethod]
    public void IsFresh_SeenOrTooOld_IsFalse()
    {
        ReplayWindow window = default;
        window.MarkSeen(100);
        window.MarkSeen(98);

        Assert.IsFalse(window.IsFresh(100));
        Assert.IsFalse(window.IsFresh(98));
        Assert.IsTrue(window.IsFresh(99));
        Assert.IsTrue(window.IsFresh(101));
        Assert.IsTrue(window.IsFresh(37));
        Assert.IsFalse(window.IsFresh(36));
    }

    [TestMethod]
    public void MarkSeen_FarAhead_SlidesTheWindow()
    {
        ReplayWindow window = default;
        window.MarkSeen(1);
        window.MarkSeen(1000);

        Assert.IsFalse(window.IsFresh(1));
        Assert.IsTrue(window.IsFresh(999));
        Assert.IsFalse(window.IsFresh(1000));
    }
}
