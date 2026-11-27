using WinAppGuard.Core;
using WinAppGuard.Models;

namespace WinAppGuard.Architecture.Tests;

/// <summary>
/// 5.15：导入按「动作 + 路径 + 范围」去重，同一程序的多条范围规则都要保留。
/// </summary>
public sealed class RuleImportPlannerTests
{
    [Fact]
    public void SameProgramWithDifferentScopesIsKept()
    {
        var path = FullPath("chrome.exe");

        var plan = Plan(
            new[]
            {
                Entry(path, Tcp(443)),
                Entry(path, Tcp(80)),
            },
            Array.Empty<FirewallRuleItem>());

        Assert.Equal(2, plan.ToCreate.Count);
        Assert.Equal(0, plan.Skipped);

        var names = plan.ToCreate
            .Select(item => RuleNaming.BuildBlockRuleName(
                item.Entry.Value, item.Scope))
            .ToList();

        Assert.Equal(2, names.Distinct(StringComparer.OrdinalIgnoreCase).Count());
    }

    [Fact]
    public void DuplicateEntryInSameFileIsSkipped()
    {
        var path = FullPath("chrome.exe");

        var plan = Plan(
            new[]
            {
                Entry(path, Tcp(443)),
                Entry(path, Tcp(443)),
            },
            Array.Empty<FirewallRuleItem>());

        Assert.Single(plan.ToCreate);
        Assert.Equal(1, plan.Skipped);
    }

    [Fact]
    public void ExistingScopedRuleIsSkipped()
    {
        var path = FullPath("chrome.exe");
        var existing = Existing(path, Tcp(443));

        var plan = Plan(new[] { Entry(path, Tcp(443)) }, new[] { existing });

        Assert.Empty(plan.ToCreate);
        Assert.Equal(1, plan.Skipped);
    }

    [Fact]
    public void DifferentExistingScopeDoesNotBlockNewScope()
    {
        var path = FullPath("chrome.exe");
        var existing = Existing(path, Tcp(443));

        var plan = Plan(new[] { Entry(path, Tcp(80)) }, new[] { existing });

        Assert.Single(plan.ToCreate);
        Assert.Equal(0, plan.Skipped);
    }

    [Fact]
    public void AllowIpEntryIsRejected()
    {
        var plan = RuleImportPlanner.Plan(
            new[]
            {
                new RuleExportEntry
                {
                    Kind = "ip",
                    Value = "203.0.113.9",
                    Action = "allow",
                },
            },
            FirewallAction.Allow,
            Array.Empty<FirewallRuleItem>(),
            _ => false);

        Assert.Empty(plan.ToCreate);
        Assert.Equal(1, plan.Invalid);
    }

    private static RuleImportPlan Plan(
        IReadOnlyList<RuleExportEntry> entries,
        IEnumerable<FirewallRuleItem> existing)
        => RuleImportPlanner.Plan(
            entries, FirewallAction.Block, existing, _ => false);

    private static RuleExportEntry Entry(string path, RuleScope scope) => new()
    {
        Kind = "program",
        Value = path,
        Action = "block",
        Scope = scope.Encode(),
        Group = "g1",
    };

    private static FirewallRuleItem Existing(string path, RuleScope scope) => new()
    {
        Name = RuleNaming.BuildBlockRuleName(path, scope),
        ApplicationPath = path,
        Description = string.Empty,
        Grouping = string.Empty,
        Enabled = true,
        Action = FirewallAction.Block,
        Direction = FirewallDirection.Outbound,
        Protocol = 256,
        Scope = scope,
    };

    private static RuleScope Tcp(int port) => new(RuleProtocol.Tcp, port, port);

    private static string FullPath(string name)
        => Path.Combine(Path.GetTempPath(), "wag-import-planner", name);
}
