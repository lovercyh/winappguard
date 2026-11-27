using WinAppGuard.Models;

namespace WinAppGuard.Core;

/// <summary>
/// 5.15：「解除阻止」只选择阻止规则。
///
/// 之前调用的 DeleteRulesForProgram 会把同一程序的白名单/允许规则一起删掉，
/// 和界面承诺的“只删除下面这些阻止规则”不一致。
/// </summary>
internal static class RuleDeletionPlanner
{
    internal static List<string> SelectRulesForProgram(
        IEnumerable<FirewallRuleItem> rules,
        string programPath,
        FirewallAction action)
    {
        var fullPath = TryNormalize(programPath);

        if (fullPath is null)
        {
            return new List<string>();
        }

        return rules
            .Where(rule => rule.Action == action
                           && string.Equals(
                               TryNormalize(rule.ApplicationPath),
                               fullPath,
                               StringComparison.OrdinalIgnoreCase))
            .Select(rule => rule.Name)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static string? TryNormalize(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return null;
        }

        try
        {
            return Path.GetFullPath(path.Trim());
        }
        catch (Exception)
        {
            return null;
        }
    }
}
