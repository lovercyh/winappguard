using WinAppGuard.Core.Wfp;

namespace WinAppGuard.Core;

/// <summary>开启 / 关闭严格模式的结果。</summary>
/// <param name="Success">是否真的做成了。</param>
/// <param name="Message">给人看的一句话（失败时说明原因，成功时说明做了什么）。</param>
public sealed record StrictModeChangeResult(bool Success, string Message);

/// <summary>启动兜底的结果。</summary>
/// <param name="WasLeftOn">上次是不是「没还原就退出了」。</param>
/// <param name="Restored">这次是不是成功还原了（<paramref name="WasLeftOn"/> 为 false 时无意义）。</param>
/// <param name="Message">给人看的一句话。</param>
public sealed record StrictModeRecoveryResult(bool WasLeftOn, bool Restored, string Message);

/// <summary>
/// 「严格模式」的策略层（2.0：WFP 动态会话 + 真白名单）。
///
/// ==================== 它做什么 ====================
/// 在一个**动态** WFP 会话里放两样东西：
///   - 白名单程序的放行过滤器（权重 0x1000）；
///   - 一条不带条件的「阻止全部」（权重 0）。
/// 于是只有白名单能上网，其它程序的新连接一律被拦。
///
/// 白名单 = 本工具建的允许规则（界面上的「加入白名单」）
///          + 本程序自己（否则它查不了 IP 归属）
///          + <see cref="SystemAllowList"/> 里的系统必需程序（DNS、时间同步、Windows 更新…）。
///
/// ==================== 为什么不再需要"三条还原路径" ====================
/// 1.x 改的是 Windows 防火墙的**全局默认出站动作**，那是系统级设置、不随程序退出恢复，
/// 所以必须落盘意图、启动兜底、删除全部规则前先还原……
/// 2.0 把这些全换成**会话内**的过滤器：进程一结束（正常退出 / 崩溃 / 被强杀），
/// BFE 就把它们全部删掉（POC 实测）。**进程不在了，限制就不在了。**
///
/// 唯一保留的兜底是给**从 1.x 升级上来**的机器用的：
/// 如果设置文件里还留着"上次开了严格模式没还原"的标志，启动时把全局策略还原成「允许」。
/// 2.0 自己永远不会写那两个标志。
///
/// 线程要求：只应在界面线程（STA）上调用。
/// </summary>
public static class StrictModeManager
{
    private static WfpStrictSession? _session;

    /// <summary>
    /// 除"本程序 + 白名单 + 系统必需程序"之外还要放行的程序。
    /// 3.0-c 起严格模式由服务持有会话，而真正要联网的是**界面**（查 IP 归属等），
    /// 所以服务调用 <see cref="Enable"/> 时会把界面路径作为额外放行项传进来。
    /// 记住它，<see cref="RefreshIfEnabled"/> 重建会话时不会漏掉。
    /// </summary>
    private static IReadOnlyList<string> _extraPrograms = Array.Empty<string>();

    /// <summary>严格模式当前是否生效（本次会话）。</summary>
    public static bool IsEnabled => _session is not null;

    /// <summary>
    /// 当前实际放行的程序（会话建立时算好的一份快照）。
    /// 白名单变了要调用 <see cref="RefreshIfEnabled"/> 重建会话，否则清单不会更新。
    /// </summary>
    public static IReadOnlyList<string> PermittedPrograms
        => _session?.PermittedPrograms ?? Array.Empty<string>();

    /// <summary>
    /// 本程序自身在 1.x 里那条放行规则的名字（只在「从 1.x 升级」的兜底里用到）。
    /// </summary>
    public static string? SelfAllowRuleName
    {
        get
        {
            var selfPath = Environment.ProcessPath;
            return string.IsNullOrEmpty(selfPath)
                ? null
                : RuleNaming.BuildAllowRuleName(selfPath);
        }
    }

    /// <summary>
    /// 开启严格模式：建立一个动态会话，放进「白名单放行 + 阻止全部」。
    /// </summary>
    /// <param name="extraPrograms">
    /// 额外放行的程序（3.0-c：服务代界面开启时传入界面 exe）。
    /// 传 null 表示沿用上次记住的清单。
    /// </param>
    public static StrictModeChangeResult Enable(IEnumerable<string>? extraPrograms = null)
    {
        if (IsEnabled)
        {
            return new StrictModeChangeResult(false, "严格模式已经在生效了。");
        }

        if (extraPrograms is not null)
        {
            _extraPrograms = extraPrograms
                .Where(path => !string.IsNullOrWhiteSpace(path))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
        }

        // ---- 收集白名单 ----
        List<string> candidates;

        try
        {
            candidates = RuleEngine.GetAllowRulePrograms();
        }
        catch (Exception ex)
        {
            LocalLog.Error("[WAG-STRICT-010] Failed to read the allowlist.", ex);
            return new StrictModeChangeResult(false, $"读取白名单失败：{ex.Message}");
        }

        var selfPath = Environment.ProcessPath;
        if (!string.IsNullOrEmpty(selfPath))
        {
            candidates.Add(selfPath);
        }

        candidates.AddRange(_extraPrograms);

        var systemPaths = SystemAllowList.GetPaths();
        candidates.AddRange(systemPaths);

        // ---- 建会话 ----
        try
        {
            _session = WfpStrictSession.Start(candidates);
        }
        catch (Exception ex)
        {
            _session?.Dispose();
            _session = null;
            LocalLog.Error("[WAG-STRICT-011] Failed to create the strict-mode session.", ex);
            return new StrictModeChangeResult(false, $"开启严格模式失败：{ex.Message}");
        }

        var message =
            $"严格模式已开启：只放行 {_session.PermittedPrograms.Count} 个程序" +
            $"（白名单 + 本程序 + {systemPaths.Count} 个系统必需程序）。" +
            "程序退出或崩溃时会自动撤销。";

        LocalLog.Operation($"[WAG-STRICT-012] Strict mode enabled: {_session.PermittedPrograms.Count} programs permitted.");
        return new StrictModeChangeResult(true, message);
    }

    /// <summary>
    /// 关闭严格模式：结束会话即可 —— 限制由系统自动删除，不需要"还原"。
    /// </summary>
    public static StrictModeChangeResult Disable()
    {
        if (_session is null)
        {
            return new StrictModeChangeResult(false, "严格模式当前没有生效，无需关闭。");
        }

        _session.Dispose();
        _session = null;

        LocalLog.Operation("[WAG-STRICT-013] Strict mode disabled (session ended; restrictions removed by the system).");
        return new StrictModeChangeResult(true, "严格模式已关闭：所有程序恢复联网（白名单规则本身保留）。");
    }

    /// <summary>
    /// 白名单变了就重建会话 —— 动态会话里的放行清单是**建立时算好**的，
    /// 不重建的话，新加的白名单程序在严格模式下仍然上不了网。
    /// 重建期间有毫秒级的空档，可以忽略。
    /// </summary>
    public static StrictModeChangeResult? RefreshIfEnabled()
    {
        if (!IsEnabled)
        {
            return null;
        }

        Disable();
        return Enable();
    }

    /// <summary>
    /// 启动兜底（**只为从 1.x 升级上来的机器保留**）：
    /// 如果设置文件里还留着"上次开了严格模式没还原"的标志，
    /// 把 Windows 防火墙的全局「默认出站动作」还原成「允许」。
    ///
    /// 2.0 自己不再写这两个标志，所以新机器上这个方法永远什么都不做。
    /// </summary>
    public static StrictModeRecoveryResult RecoverIfLeftOn(string? settingsPath = null)
    {
        var settings = AppSettings.Load(settingsPath);

        if (!settings.StrictModeLeftOn)
        {
            return new StrictModeRecoveryResult(false, false, string.Empty);
        }

        var before = FirewallManager.GetOutboundDefaultAllowed();

        FirewallManager.SetOutboundDefaultAllowed(true);
        var after = FirewallManager.GetOutboundDefaultAllowed();

        var deletedSelfAllow = DeleteSelfAllowIfWeCreatedIt(settings);
        ClearPersistedFlags(settings, settingsPath);

        var message =
            "上次（1.x）没有正常退出，严格模式留下的「默认阻止出站」已经被自动还原。" +
            $"（{before.Describe()} → {after.Describe()}）" +
            (deletedSelfAllow ? " 本程序自己的白名单规则也已删掉。" : string.Empty);

        if (after.AllAllowed)
        {
            LocalLog.Warning("[WAG-STRICT-014] Legacy strict-mode recovery succeeded: outbound is Allow for all three profiles.");
        }
        else
        {
            // 极少见，但必须说清楚 —— 这种情况下用户是真的上不了网。
            LocalLog.Error(
                $"[WAG-STRICT-015] Legacy strict-mode recovery failed: outbound default is not Allow for all profiles "
                + $"(domain={after.DomainAllowed}, private={after.PrivateAllowed}, public={after.PublicAllowed}).");
            message += " ⚠ 但还原没有完全成功，请手工把三套配置文件的「出站连接」都改成「允许」。";
        }

        return new StrictModeRecoveryResult(true, after.AllAllowed, message);
    }

    // ==================================================================
    // 1.x 遗留的收尾（只被 RecoverIfLeftOn 使用）
    // ==================================================================

    /// <summary>删掉 1.x「我们替本程序自己建」的那条放行规则。</summary>
    private static bool DeleteSelfAllowIfWeCreatedIt(AppSettings settings)
    {
        if (!settings.StrictModeSelfAllowCreated)
        {
            return false;
        }

        var name = SelfAllowRuleName;
        if (name is null)
        {
            return false;
        }

        try
        {
            // 2.0 的规则在 WFP 里，1.x 的规则在 Windows 防火墙里 —— 这条只在后者。
            if (!FirewallManager.DeleteRule(name))
            {
                LocalLog.Info($"[WAG-STRICT-016] Legacy self-allow rule {name} no longer exists; nothing to delete.");
                return false;
            }

            return true;
        }
        catch (Exception ex)
        {
            LocalLog.Error($"[WAG-STRICT-017] Failed to delete legacy self-allow rule {name}.", ex);
            return false;
        }
    }

    /// <summary>把 1.x 的两个标志清掉。</summary>
    private static void ClearPersistedFlags(AppSettings settings, string? settingsPath)
    {
        settings.StrictModeLeftOn = false;
        settings.StrictModeSelfAllowCreated = false;
        settings.Save(settingsPath);
    }
}
