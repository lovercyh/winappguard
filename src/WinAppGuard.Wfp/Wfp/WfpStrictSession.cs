using WinAppGuard.Interop;
using WinAppGuard.Models;

namespace WinAppGuard.Core.Wfp;

/// <summary>
/// 严格模式的**实时会话**：一个动态 WFP 会话，里面是「阻止全部 + 白名单放行」。
///
/// ==================== 为什么用动态会话 ====================
/// 动态会话里的对象在**会话结束**（进程正常退出、崩溃、被任务管理器强杀）时
/// 由 BFE 自动删除 —— 这一点已用 POC 实测（强杀子进程后过滤器 0 条、连接恢复）。
/// 于是 1.x 那套「落盘意图 + 三条还原路径」全部不需要了：
/// **进程不在了，限制就不在了**。
///
/// ==================== 权重怎么排 ====================
/// 同一子层里权重大的先命中：
/// <code>
///   白名单放行   0x1000   ← 先放行
///   阻止全部     0       ← 其余一律阻止
/// </code>
/// 两者都带 TERMINATING 标志，所以命中即定论，不会漏到下面的子层去。
///
/// ==================== 5.15：按范围放行 ====================
/// 允许规则可以带协议/远端端口范围。会话按这些范围生成放行过滤器，
/// 不再把“只允许 443”变成“允许整个程序”。
/// </summary>
internal sealed class WfpStrictSession : IDisposable
{
    private readonly WfpEngine _engine;
    private List<Guid> _filterKeys = new();
    private List<StrictAllowEntry> _entries = new();

    private WfpStrictSession(WfpEngine engine)
    {
        _engine = engine;
    }

    /// <summary>本次会话加了哪些过滤器（自检用来核对条数）。</summary>
    internal IReadOnlyList<Guid> FilterKeys => _filterKeys;

    /// <summary>实际放行的程序（已去重、已确认文件存在；不区分范围）。</summary>
    internal IReadOnlyList<string> PermittedPrograms { get; private set; } = Array.Empty<string>();

    /// <summary>
    /// 建立会话：先铺白名单放行，再盖一层“阻止全部”。
    /// </summary>
    internal static WfpStrictSession Start(IEnumerable<StrictAllowEntry> entries)
    {
        var engine = WfpEngine.Open(dynamicSession: true);

        try
        {
            engine.EnsureSublayer(persistent: false);

            var session = new WfpStrictSession(engine);
            var normalized = Normalize(entries);
            var keys = new List<Guid>();

            engine.RunInTransaction(() => session.AddFilters(normalized, keys));

            session._filterKeys = keys;
            session._entries = normalized;
            session.PermittedPrograms = DistinctPrograms(normalized);

            return session;
        }
        catch
        {
            // 失败就把会话关掉：动态会话一关，已经加进去的过滤器会自动消失。
            engine.Dispose();
            throw;
        }
    }

    /// <summary>
    /// 5.15：在**同一个动态会话**里原子地替换放行清单。
    ///
    /// 事务提交前旧过滤器仍然有效；任何一步失败都会 Abort，
    /// 旧白名单原样保留，不会出现“刷新失败 = 全网放行”。
    /// </summary>
    internal void Rebuild(IEnumerable<StrictAllowEntry> entries)
    {
        var normalized = Normalize(entries);
        var oldKeys = _filterKeys.ToList();
        var oldEntries = _entries;
        var newKeys = new List<Guid>();

        _engine.RunInTransaction(
            () =>
            {
                foreach (var key in oldKeys)
                {
                    _engine.TryDeleteFilter(key);
                }

                AddFilters(normalized, newKeys);
            },
            rollback: () =>
            {
                // 仅在没有 WFP 事务的降级路径上使用：清掉半写入，再按旧清单恢复。
                foreach (var key in newKeys)
                {
                    _engine.TryDeleteFilter(key);
                }

                var restored = new List<Guid>();
                AddFilters(oldEntries, restored);
            },
            allowDirectFallback: false);

        _filterKeys = newKeys;
        _entries = normalized;
        PermittedPrograms = DistinctPrograms(normalized);
    }

    /// <summary>结束会话 —— 这一下就把严格模式撤干净了，不需要任何"还原"逻辑。</summary>
    public void Dispose() => _engine.Dispose();

    private void AddFilters(
        IReadOnlyList<StrictAllowEntry> entries, List<Guid> keys)
    {
        // 先放行、后阻止全部。
        foreach (var entry in entries)
        {
            foreach (var layer in WfpRuleStore.OutboundLayers)
            {
                var scopeToken = entry.Scope.Encode();
                var key = WfpEngine.BuildFilterKey(
                    $"strict|allow|{entry.Path}|{scopeToken}|{layer}");
                var displayName = entry.Scope.IsAny
                    ? "WinAppGuard 严格模式放行：" + Path.GetFileName(entry.Path)
                    : $"WinAppGuard 严格模式放行：{Path.GetFileName(entry.Path)}（{entry.Scope.Describe()}）";

                if (entry.Scope.IsAny)
                {
                    _engine.AddAppIdFilter(
                        key,
                        displayName,
                        null,
                        entry.Path,
                        layer,
                        WfpNativeMethods.FWP_ACTION_PERMIT,
                        WfpRuleStore.WeightAllow,
                        persistent: false);
                }
                else
                {
                    _engine.AddScopedAppIdFilter(
                        key,
                        displayName,
                        null,
                        entry.Path,
                        layer,
                        WfpNativeMethods.FWP_ACTION_PERMIT,
                        WfpRuleStore.WeightAllow,
                        persistent: false,
                        entry.Scope);
                }

                keys.Add(key);
            }
        }

        foreach (var layer in WfpRuleStore.OutboundLayers)
        {
            var key = WfpEngine.BuildFilterKey($"strict|blockall|{layer}");

            _engine.AddBlockAllFilter(
                key,
                "WinAppGuard 严格模式：阻止全部出站",
                layer,
                WfpNativeMethods.FWP_ACTION_BLOCK,
                WfpRuleStore.WeightBlockAll);

            keys.Add(key);
        }
    }

    /// <summary>去重 + 确认文件存在；同一程序有“任意范围”时覆盖更窄的范围。</summary>
    private static List<StrictAllowEntry> Normalize(IEnumerable<StrictAllowEntry> entries)
    {
        var order = new List<string>();
        var programs = new Dictionary<string, ProgramEntry>(StringComparer.OrdinalIgnoreCase);

        foreach (var entry in entries)
        {
            if (string.IsNullOrWhiteSpace(entry.Path))
            {
                continue;
            }

            string fullPath;

            try
            {
                fullPath = Path.GetFullPath(entry.Path);
            }
            catch (Exception)
            {
                continue;
            }

            if (!File.Exists(fullPath))
            {
                continue;
            }

            if (!programs.TryGetValue(fullPath, out var program))
            {
                program = new ProgramEntry();
                programs[fullPath] = program;
                order.Add(fullPath);
            }

            if (entry.Scope.IsAny)
            {
                program.Any = true;
                continue;
            }

            var encoded = entry.Scope.Encode();

            if (!program.Scopes.Any(existing => string.Equals(
                    existing.Encode(), encoded, StringComparison.Ordinal)))
            {
                program.Scopes.Add(entry.Scope);
            }
        }

        var result = new List<StrictAllowEntry>();

        foreach (var path in order)
        {
            var program = programs[path];

            if (program.Any)
            {
                result.Add(new StrictAllowEntry(path, RuleScope.Any));
                continue;
            }

            foreach (var scope in program.Scopes)
            {
                result.Add(new StrictAllowEntry(path, scope));
            }
        }

        return result;
    }

    private static List<string> DistinctPrograms(IReadOnlyList<StrictAllowEntry> entries)
        => entries
            .Select(entry => entry.Path)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

    private sealed class ProgramEntry
    {
        internal bool Any { get; set; }

        internal List<RuleScope> Scopes { get; } = new();
    }
}
