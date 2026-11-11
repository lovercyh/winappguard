using WinAppGuard.Core.Features;

namespace WinAppGuard.Architecture.Tests;

public sealed class BaselineTests
{
    [Fact]
    public void CompareReportsAddedRemovedAndUnchanged()
    {
        var baseline = new Baseline<string>(new[] { "a", "b", "c" });

        var diff = baseline.Compare(new[] { "b", "c", "d" });

        Assert.Equal(new[] { "d" }, diff.Added);
        Assert.Equal(new[] { "a" }, diff.Removed);
        Assert.Equal(new[] { "b", "c" }, diff.Unchanged);
    }

    [Fact]
    public void TrustAndUntrust()
    {
        var baseline = new Baseline<string>();

        Assert.True(baseline.Trust("a"));
        Assert.False(baseline.Trust("a"));
        Assert.True(baseline.Contains("a"));
        Assert.True(baseline.Untrust("a"));
        Assert.False(baseline.Contains("a"));
    }

    [Fact]
    public void ResetReplacesItems()
    {
        var baseline = new Baseline<string>(new[] { "a" });

        baseline.Reset(new[] { "b", "c" });

        Assert.False(baseline.Contains("a"));
        Assert.True(baseline.Contains("b"));
        Assert.True(baseline.Contains("c"));
    }
}
