using WinAppGuard.Interop;

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
/// 这正是"真白名单"与 1.x（默认阻止出站、但系统/其它软件的允许规则仍然生效）的区别。
/// </summary>
internal sealed class WfpStrictSession : IDisposable
{
    private readonly WfpEngine _engine;
    private readonly List<Guid> _filterKeys = new();

    private WfpStrictSession(WfpEngine engine)
    {
        _engine = engine;
    }

    /// <summary>本次会话加了哪些过滤器（自检用来核对条数）。</summary>
    internal IReadOnlyList<Guid> FilterKeys => _filterKeys;

    /// <summary>实际放行的程序（已去重、已确认文件存在）。</summary>
    internal IReadOnlyList<string> PermittedPrograms { get; private set; } = Array.Empty<string>();

    /// <summary>
    /// 建立会话：先铺白名单放行，再盖一层"阻止全部"。
    /// </summary>
    /// <param name="permittedPrograms">要放行的程序（调用方应把本程序和系统清单一起并进来）。</param>
    internal static WfpStrictSession Start(IEnumerable<string> permittedPrograms)
    {
        var engine = WfpEngine.Open(dynamicSession: true);

        try
        {
            engine.EnsureSublayer(persistent: false);

            var session = new WfpStrictSession(engine)
            {
                PermittedPrograms = Normalize(permittedPrograms),
            };

            // 先放行、后阻止全部。
            // 权重已经决定了优先级，顺序其实无关；之所以先放行，是为了
            // "中途失败"时宁可少挡一会儿，也不要出现只挡不放的瞬间。
            foreach (var program in session.PermittedPrograms)
            {
                foreach (var layer in WfpRuleStore.OutboundLayers)
                {
                    var key = WfpEngine.BuildFilterKey($"strict|allow|{program}|{layer}");

                    engine.AddAppIdFilter(
                        key,
                        "WinAppGuard 严格模式放行：" + Path.GetFileName(program),
                        null,
                        program,
                        layer,
                        WfpNativeMethods.FWP_ACTION_PERMIT,
                        WfpRuleStore.WeightAllow,
                        persistent: false);

                    session._filterKeys.Add(key);
                }
            }

            foreach (var layer in WfpRuleStore.OutboundLayers)
            {
                var key = WfpEngine.BuildFilterKey($"strict|blockall|{layer}");

                engine.AddBlockAllFilter(
                    key,
                    "WinAppGuard 严格模式：阻止全部出站",
                    layer,
                    WfpNativeMethods.FWP_ACTION_BLOCK,
                    WfpRuleStore.WeightBlockAll);

                session._filterKeys.Add(key);
            }

            return session;
        }
        catch
        {
            // 失败就把会话关掉：动态会话一关，已经加进去的过滤器会自动消失。
            engine.Dispose();
            throw;
        }
    }

    /// <summary>结束会话 —— 这一下就把严格模式撤干净了，不需要任何"还原"逻辑。</summary>
    public void Dispose() => _engine.Dispose();

    /// <summary>去重 + 确认文件存在。路径无效的直接丢掉（给不存在的文件取程序身份会失败）。</summary>
    private static List<string> Normalize(IEnumerable<string> programs)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var result = new List<string>();

        foreach (var program in programs)
        {
            if (string.IsNullOrWhiteSpace(program))
            {
                continue;
            }

            string fullPath;
            try
            {
                fullPath = Path.GetFullPath(program);
            }
            catch (Exception)
            {
                continue;
            }

            if (!File.Exists(fullPath))
            {
                continue;
            }

            if (seen.Add(fullPath))
            {
                result.Add(fullPath);
            }
        }

        return result;
    }
}
