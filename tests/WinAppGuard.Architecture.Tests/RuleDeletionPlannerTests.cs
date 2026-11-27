using WinAppGuard.Core;
using WinAppGuard.Models;

namespace WinAppGuard.Architecture.Tests;

/// <summary>
/// 5.15：「解除阻止」只删除阻止规则，不能删掉白名单。
/// </summary>
public sealed class RuleDeletionPlannerTests
{
    [Fact]
    public void SelectsOnlyBlockRulesForProgram()
    {
        var path = FullPath("game.exe");

        var rules = new[]
        {
            Rule("block-1", path, FirewallAction.Block),
            Rule("block-2", path, FirewallAction.Block),
            Rule("allow-1", path, FirewallAction.Allow),
            Rule("block-other", FullPath("other.exe"), FirewallAction.Block),
        };

        var selected = RuleDeletionPlanner.SelectRulesForProgram(
            rules, path, FirewallAction.Block);

        Assert.Equal(new[] { "block-1", "block-2" }, selected);
    }

    [Fact]
    public void SelectsOnlyAllowRulesWhenRequested()
    {
        var path = FullPath("game.exe");

        var selected = RuleDeletionPlanner.SelectRulesForProgram(
            new[]
            {
                Rule("block-1", path, FirewallAction.Block),
                Rule("allow-1", path, FirewallAction.Allow),
                Rule("allow-2", path, FirewallAction.Allow),
            },
            path,
            FirewallAction.Allow);

        Assert.Equal(new[] { "allow-1", "allow-2" }, selected);
    }

    [Fact]
    public void KeepsAllowRuleWhenNoBlockRuleExists()
    {
        var path = FullPath("game.exe");

        var selected = RuleDeletionPlanner.SelectRulesForProgram(
            new[] { Rule("allow-1", path, FirewallAction.Allow) },
            path,
            FirewallAction.Block);

        Assert.Empty(selected);
    }

    private static FirewallRuleItem Rule(
        string name, string path, FirewallAction action) => new()
    {
        Name = name,
        ApplicationPath = path,
        Description = string.Empty,
        Grouping = string.Empty,
        Enabled = true,
        Action = action,
        Direction = FirewallDirection.Outbound,
        Protocol = 256,
    };

    private static string FullPath(string name)
        => Path.Combine(Path.GetTempPath(), "wag-deletion-planner", name);
}
