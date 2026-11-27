using WinAppGuard.Core;
using WinAppGuard.Models;

namespace WinAppGuard.Architecture.Tests;

/// <summary>
/// 5.15：严格模式按白名单规则的范围放行。
/// </summary>
public sealed class StrictAllowPlannerTests
{
    [Fact]
    public void ScopedRulesAreKept()
    {
        var path = FullPath("chrome.exe");
        var entries = StrictAllowPlanner.Build(
            new[]
            {
                (path, Tcp(443)),
                (path, Tcp(80)),
            },
            Array.Empty<string>(),
            Array.Empty<string>());

        Assert.Equal(2, entries.Count);
        Assert.All(entries, entry => Assert.Equal(path, entry.Path));
        Assert.Contains(entries, entry => entry.Scope.PortFrom == 443);
        Assert.Contains(entries, entry => entry.Scope.PortFrom == 80);
    }

    [Fact]
    public void UnscopedRuleCollapsesScopedOnes()
    {
        var path = FullPath("chrome.exe");
        var entries = StrictAllowPlanner.Build(
            new[]
            {
                (path, Tcp(443)),
                (path, RuleScope.Any),
            },
            Array.Empty<string>(),
            Array.Empty<string>());

        var entry = Assert.Single(entries);
        Assert.True(entry.Scope.IsAny);
    }

    [Fact]
    public void SystemAndExtraProgramsAreAlwaysUnscoped()
    {
        var system = FullPath("svchost.exe");
        var extra = FullPath("WinAppGuard.exe");

        var entries = StrictAllowPlanner.Build(
            Array.Empty<(string, RuleScope)>(),
            new[] { system },
            new[] { extra });

        Assert.Equal(2, entries.Count);
        Assert.All(entries, entry => Assert.True(entry.Scope.IsAny));
    }

    [Fact]
    public void DuplicateScopesAreDropped()
    {
        var path = FullPath("app.exe");
        var entries = StrictAllowPlanner.Build(
            new[]
            {
                (path, Tcp(443)),
                (path, Tcp(443)),
            },
            Array.Empty<string>(),
            Array.Empty<string>());

        Assert.Single(entries);
    }

    private static RuleScope Tcp(int port) => new(RuleProtocol.Tcp, port, port);

    private static string FullPath(string name)
        => Path.Combine(Path.GetTempPath(), "wag-planner", name);
}
