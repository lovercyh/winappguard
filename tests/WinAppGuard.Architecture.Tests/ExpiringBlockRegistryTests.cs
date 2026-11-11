using WinAppGuard.Core.Features;
using WinAppGuard.Core.Time;

namespace WinAppGuard.Architecture.Tests;

public sealed class ExpiringBlockRegistryTests
{
    [Fact]
    public void AddReleaseAndExpire()
    {
        var clock = new FakeClock();
        var registry = new ExpiringBlockRegistry<string>(10, TimeSpan.FromMinutes(10), clock);

        var added = registry.TryAdd("a", TimeSpan.FromMinutes(5), "test");

        Assert.Equal(BlockAddStatus.Added, added.Status);
        Assert.True(registry.IsBlocked("a"));
        Assert.Single(registry.Snapshot());

        clock.Advance(TimeSpan.FromMinutes(6));

        Assert.False(registry.IsBlocked("a"));
        Assert.Equal(1, registry.PurgeExpired());
        Assert.Empty(registry.Snapshot());
    }

    [Fact]
    public void UpdatesExistingEntry()
    {
        var clock = new FakeClock();
        var registry = new ExpiringBlockRegistry<string>(10, TimeSpan.FromMinutes(10), clock);

        registry.TryAdd("a", TimeSpan.FromMinutes(5), "first");
        var updated = registry.TryAdd("a", TimeSpan.FromMinutes(2), "second");

        Assert.Equal(BlockAddStatus.Updated, updated.Status);
        Assert.Single(registry.Snapshot());
        Assert.Equal("second", registry.Snapshot()[0].Reason);
    }

    [Fact]
    public void EvictsEarliestExpiryAtLimit()
    {
        var clock = new FakeClock();
        var registry = new ExpiringBlockRegistry<string>(2, TimeSpan.FromMinutes(10), clock);

        registry.TryAdd("a", TimeSpan.FromMinutes(1), "a");
        registry.TryAdd("b", TimeSpan.FromMinutes(2), "b");
        var result = registry.TryAdd("c", TimeSpan.FromMinutes(3), "c");

        Assert.Equal(BlockAddStatus.EvictedOldest, result.Status);
        Assert.Equal("a", result.EvictedKey);
        Assert.False(registry.IsBlocked("a"));
        Assert.True(registry.IsBlocked("b"));
        Assert.True(registry.IsBlocked("c"));
    }

    [Fact]
    public void TtlIsClampedToMaximum()
    {
        var clock = new FakeClock();
        var registry = new ExpiringBlockRegistry<string>(10, TimeSpan.FromMinutes(5), clock);

        registry.TryAdd("a", TimeSpan.FromHours(1), "test");
        var entry = Assert.Single(registry.Snapshot());

        Assert.Equal(clock.UtcNow.AddMinutes(5), entry.ExpiresUtc);
    }

    private sealed class FakeClock : IClock
    {
        public DateTime UtcNow { get; private set; }
            = new DateTime(2026, 11, 11, 12, 0, 0, DateTimeKind.Utc);

        public void Advance(TimeSpan duration) => UtcNow = UtcNow.Add(duration);
    }
}
