using WinAppGuard.Models;
using WinAppGuard.Service;

namespace WinAppGuard.Architecture.Tests;

public sealed class RuleSnapshotCacheTests
{
    [Fact]
    public void LoadsOnceAndReusesSnapshot()
    {
        var cache = new RuleSnapshotCache();
        var calls = 0;

        var first = cache.Get(Load);
        var second = cache.Get(Load);

        Assert.Same(first, second);
        Assert.Equal(1, calls);
        Assert.Equal(0, cache.Revision);

        IReadOnlyList<FirewallRuleItem> Load()
        {
            calls++;
            return Array.Empty<FirewallRuleItem>();
        }
    }

    [Fact]
    public void InvalidateDropsCacheAndBumpsRevision()
    {
        var cache = new RuleSnapshotCache();
        var calls = 0;

        _ = cache.Get(Load);
        cache.Invalidate();
        _ = cache.Get(Load);

        Assert.Equal(2, calls);
        Assert.Equal(1, cache.Revision);
        Assert.False(string.IsNullOrWhiteSpace(cache.Epoch));

        IReadOnlyList<FirewallRuleItem> Load()
        {
            calls++;
            return Array.Empty<FirewallRuleItem>();
        }
    }
}
