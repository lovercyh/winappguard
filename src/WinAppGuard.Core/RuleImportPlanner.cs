using System.Net;
using WinAppGuard.Models;

namespace WinAppGuard.Core;

/// <summary>导入计划里的一条待创建规则。</summary>
internal sealed record RuleImportPlanItem(RuleExportEntry Entry, RuleScope Scope);

/// <summary>导入计划的统计与待创建列表。</summary>
internal sealed class RuleImportPlan
{
    internal List<RuleImportPlanItem> ToCreate { get; } = new();

    /// <summary>因为已存在 / 文件内重复 / 受保护而跳过的条数。</summary>
    internal int Skipped { get; set; }

    /// <summary>因为内容不合法而失败的条数。</summary>
    internal int Invalid { get; set; }
}

/// <summary>
/// 5.15：导入规则的纯规划器。
///
/// 5.13/5.14 的导入用「不带范围的基础规则名」去重，导致同一程序的不同
/// 端口范围只会导入第一条，而且分组会写到不存在的规则名上。
///
/// 这里把身份定义成：
///   - 程序：动作 + 完整路径 + 范围（scope.Encode()）
///   - IP：地址
/// 既能在文件内去重，也能和服务里已有的规则正确比较。
/// </summary>
internal static class RuleImportPlanner
{
    internal static RuleImportPlan Plan(
        IReadOnlyList<RuleExportEntry> entries,
        FirewallAction expected,
        IEnumerable<FirewallRuleItem> existingRules,
        Func<string, bool> isProtected)
    {
        var plan = new RuleImportPlan();
        var identities = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var rule in existingRules)
        {
            identities.Add(IdentityOfExisting(rule));
        }

        foreach (var entry in entries)
        {
            if (string.Equals(entry.Kind, "ip", StringComparison.OrdinalIgnoreCase))
            {
                // 本工具的 IP 规则只有「阻止」一种；allow + ip 属于无效组合。
                if (expected != FirewallAction.Block)
                {
                    plan.Invalid++;
                    continue;
                }

                var address = NormalizeIp(entry.Value);

                if (address is null)
                {
                    plan.Invalid++;
                    continue;
                }

                if (!identities.Add($"ip|{address}"))
                {
                    plan.Skipped++;
                    continue;
                }

                plan.ToCreate.Add(new RuleImportPlanItem(entry, RuleScope.Any));
                continue;
            }

            var key = IdentityOfProgram(expected, entry.Value, entry.Scope, out var scope);

            if (key is null)
            {
                plan.Invalid++;
                continue;
            }

            if (isProtected(entry.Value))
            {
                plan.Skipped++;
                continue;
            }

            if (!identities.Add(key))
            {
                plan.Skipped++;
                continue;
            }

            plan.ToCreate.Add(new RuleImportPlanItem(entry, scope));
        }

        return plan;
    }

    private static string IdentityOfExisting(FirewallRuleItem rule)
    {
        if (!string.IsNullOrWhiteSpace(rule.IpAddress))
        {
            return $"ip|{NormalizeIp(rule.IpAddress) ?? rule.IpAddress.Trim()}";
        }

        return IdentityOfProgram(rule.Action, rule.ApplicationPath, rule.Scope)
               ?? $"program|{rule.ApplicationPath.ToLowerInvariant()}|";
    }

    private static string? IdentityOfProgram(
        FirewallAction action,
        string value,
        string encodedScope,
        out RuleScope scope)
    {
        scope = RuleScope.Any;

        if (!RuleScope.TryParse(encodedScope, out var parsed))
        {
            return null;
        }

        scope = parsed;

        var path = TryNormalizePath(value);

        return path is null
            ? null
            : $"program|{action}|{path}|{parsed.Encode()}";
    }

    private static string? IdentityOfProgram(
        FirewallAction action, string value, RuleScope scope)
    {
        var path = TryNormalizePath(value);

        return path is null
            ? null
            : $"program|{action}|{path}|{scope.Encode()}";
    }

    private static string? TryNormalizePath(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        try
        {
            return Path.GetFullPath(value.Trim()).ToLowerInvariant();
        }
        catch (Exception)
        {
            return null;
        }
    }

    private static string? NormalizeIp(string value)
    {
        if (!IPAddress.TryParse(value.Trim(), out var address))
        {
            return null;
        }

        return address.ToString();
    }
}
