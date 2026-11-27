using WinAppGuard.Models;

namespace WinAppGuard.Core;

/// <summary>严格模式里的一条放行项：程序路径 + 允许的范围。</summary>
internal sealed record StrictAllowEntry(string Path, RuleScope Scope);

/// <summary>
/// 5.15：把白名单规则整理成严格模式会话要的放行清单。
///
/// 关键规则：
///   - 同一程序如果有一条「任意范围」的允许规则，就只放行整个程序（范围被覆盖）；
///   - 否则不同范围各生成一条，严格模式只放行这些端口/协议；
///   - 系统必需程序 / 界面自身 / 额外放行项始终是「任意范围」；
///   - 路径去重、大小写不敏感。
///
/// 单独放在 Core 是为了可以脱离 WFP 做单元测试。
/// </summary>
internal static class StrictAllowPlanner
{
    internal static List<StrictAllowEntry> Build(
        IEnumerable<(string Path, RuleScope Scope)> allowRules,
        IEnumerable<string> systemPaths,
        IEnumerable<string> extraPrograms)
    {
        var order = new List<string>();
        var programs = new Dictionary<string, ProgramEntry>(StringComparer.OrdinalIgnoreCase);

        void Track(string? rawPath, RuleScope scope, bool forceAny)
        {
            var fullPath = TryNormalize(rawPath);

            if (fullPath is null)
            {
                return;
            }

            if (!programs.TryGetValue(fullPath, out var entry))
            {
                entry = new ProgramEntry();
                programs[fullPath] = entry;
                order.Add(fullPath);
            }

            if (forceAny || scope.IsAny)
            {
                entry.Any = true;
                return;
            }

            var encoded = scope.Encode();

            if (!entry.Scopes.Any(existing => string.Equals(
                    existing.Encode(), encoded, StringComparison.Ordinal)))
            {
                entry.Scopes.Add(scope);
            }
        }

        foreach (var (path, scope) in allowRules)
        {
            Track(path, scope, forceAny: false);
        }

        foreach (var path in extraPrograms)
        {
            Track(path, RuleScope.Any, forceAny: true);
        }

        foreach (var path in systemPaths)
        {
            Track(path, RuleScope.Any, forceAny: true);
        }

        var result = new List<StrictAllowEntry>(order.Count);

        foreach (var path in order)
        {
            var entry = programs[path];

            // 有一条“任意范围”就覆盖其它范围：避免留下多余的窄规则。
            if (entry.Any)
            {
                result.Add(new StrictAllowEntry(path, RuleScope.Any));
                continue;
            }

            foreach (var scope in entry.Scopes)
            {
                result.Add(new StrictAllowEntry(path, scope));
            }
        }

        return result;
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

    private sealed class ProgramEntry
    {
        internal bool Any { get; set; }

        internal List<RuleScope> Scopes { get; } = new();
    }
}
