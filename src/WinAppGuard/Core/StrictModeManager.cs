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
/// 「严格模式」的策略层：把 Windows 防火墙的**默认出站动作**临时改成「阻止」，
/// 于是「没匹配到任何允许规则」的出站流量全部被拦掉，只有白名单能上网。
///
/// 白名单 = 本工具建的 <c>AppGuard_Allow_*</c> 规则（用户在界面上「加入白名单」）
///          + Windows 自带的允许规则 + 其它软件建的允许规则。
/// 最后那一项**必须在界面上如实可见** —— 它意味着"严格模式"不是绝对白名单，
/// 而挡不住"别人早就放行过"的程序（详见 docs/安全说明.md）。
///
/// ==================== 为什么这个类必须写得这么小心 ====================
/// 「默认出站动作」是**系统级设置，不随本程序退出而恢复**。一旦改了又没还原，
/// 用户会直接上不了网 —— 而他很可能正是不敢碰 wf.msc 的那类人。
/// 所以本类把「还原」当成第一公民，靠四件事兜住：
///
///   1. **只从「三套全允许」开启**：只要有一套本来就不是允许，说明机器上已经有
///      别人的「默认阻止出站」策略（多半是别的安全软件），我们**拒绝开启**，
///      绝不覆盖别人的设置；
///   2. **先落盘意图，再动系统**：先把「我开启了」写进 settings.json，再去改防火墙。
///      这样即使刚改完就断电，下次启动也知道要还原；
///   3. **三条还原路径**：正常关闭、启动兜底（上次没正常退出）、
///      `--cleanup` / 界面上的「删除全部规则」（后者会先把白名单删光，不还原就等于断网）；
///   4. **本身就是会话级的**：程序退出即不再生效（产品负责人的决定）。
///      这既符合"本工具是手动运行的工具"这个定位，
///      也把「崩溃把人锁在断网状态」的时间窗压到最短。
/// ======================================================================
///
/// 线程要求：与 <see cref="FirewallManager"/> 相同，只应在界面线程（STA）上调用。
/// </summary>
public static class StrictModeManager
{
    /// <summary>严格模式当前是否生效（本次会话）。</summary>
    public static bool IsEnabled { get; private set; }

    /// <summary>
    /// 本次开启时记下的原值，只用于**显示与日志**。
    ///
    /// 还原不依赖它：因为只允许从「三套全允许」开启，所以还原动作永远是「三套全允许」。
    /// 不落盘也是同理 —— 一个"本来就一定是 true"的布尔值没有存的价值。
    /// </summary>
    public static OutboundDefaultState? OriginalState { get; private set; }

    /// <summary>
    /// 本程序自身在严格模式下那条放行规则的名字；拿不到自身路径时返回 null。
    /// </summary>
    public static string? SelfAllowRuleName
    {
        get
        {
            var selfPath = Environment.ProcessPath;
            return string.IsNullOrEmpty(selfPath)
                ? null
                : FirewallManager.BuildAllowRuleName(selfPath);
        }
    }

    /// <summary>本程序自身当前是否已经在白名单里。</summary>
    public static bool IsSelfWhitelisted()
    {
        var name = SelfAllowRuleName;
        return name is not null && FirewallManager.GetAppGuardRules()
            .Any(rule => string.Equals(rule.Name, name, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// 开启严格模式：默认出站动作 → 「阻止」，并放行本程序自己。
    /// </summary>
    /// <param name="settingsPath">
    /// 设置文件路径，仅自检工具用来指向临时文件。产品传 null（用用户的真实设置）。
    /// </param>
    public static StrictModeChangeResult Enable(string? settingsPath = null)
    {
        if (IsEnabled)
        {
            return new StrictModeChangeResult(false, "严格模式已经在生效了。");
        }

        // ---- 1. 先看现状：三套必须都是「允许」----
        var original = FirewallManager.GetOutboundDefaultAllowed();

        if (!original.AllAllowed)
        {
            var refused =
                $"拒绝开启：三套网络配置文件的「默认出站动作」现在是 {original.Describe()}，" +
                "不是全部「允许」。\n\n" +
                "这说明这台机器上已经有别的「默认阻止出站」策略（可能是别的安全软件，" +
                "也可能是手工设置的）。WinAppGuard 不会去覆盖别人的设置，" +
                "所以这种情况下不能开启严格模式。";

            LocalLog.Warning($"严格模式开启被拒绝：原值 {original.Describe()}");
            return new StrictModeChangeResult(false, refused);
        }

        // ---- 2. 判断要不要替自己建放行规则（用户早就加过的话就不动它）----
        var needCreateSelfAllow = !IsSelfWhitelisted();

        // ---- 3. 先落盘意图，再动系统 ----
        //
        // 顺序不能反：如果先改防火墙、再落盘，那么「刚改完就断电」这种情形下
        // 下次启动就不知道要还原了 —— 用户会被永久锁在断网状态。
        var settings = AppSettings.Load(settingsPath);
        settings.StrictModeLeftOn = true;
        settings.StrictModeSelfAllowCreated = needCreateSelfAllow;
        settings.Save(settingsPath);

        // ---- 4. 动系统：默认出站 → 阻止 ----
        FirewallManager.SetOutboundDefaultAllowed(false);

        // ---- 5. 放行本程序自己，否则严格模式下它连 IP 归属都查不了 ----
        string selfAllowNote;

        if (needCreateSelfAllow)
        {
            try
            {
                var ruleName = FirewallManager.CreateAllowRule(Environment.ProcessPath!);
                selfAllowNote = $"并已把本程序自己加入白名单（{ruleName}）—— " +
                                "否则严格模式下它连 IP 归属都查不了";
            }
            catch (Exception ex)
            {
                // 这一条失败不影响严格模式本身（拦的目的已经达到），但要如实记下来。
                LocalLog.Error("严格模式：放行本程序自己失败（IP 归属查询将不可用）", ex);
                selfAllowNote = "但没能把本程序自己加入白名单（严格模式下 IP 归属查询会失败）";
            }
        }
        else
        {
            selfAllowNote = "本程序自己早就在白名单里，未改动";
        }

        IsEnabled = true;
        OriginalState = original;

        LocalLog.Operation($"严格模式已开启（原值 {original.Describe()}）；{selfAllowNote}");
        return new StrictModeChangeResult(true, $"严格模式已开启。{selfAllowNote}。");
    }

    /// <summary>
    /// 关闭严格模式：默认出站动作 → 「允许」，并把我们替自己建的那条放行规则删掉。
    ///
    /// 只有在 <see cref="IsEnabled"/> 为 true 时才动系统 —— 没开却去改全局策略，
    /// 可能覆盖掉别人（或用户手工）的设置。
    /// </summary>
    /// <param name="settingsPath">同 <see cref="Enable"/>。</param>
    public static StrictModeChangeResult Disable(string? settingsPath = null)
    {
        if (!IsEnabled)
        {
            return new StrictModeChangeResult(false, "严格模式当前没有生效，无需关闭。");
        }

        var settings = AppSettings.Load(settingsPath);
        var notes = new List<string>();

        // 先还原全局策略。这一步抛异常的话，下面的清除标志**不会**执行 ——
        // 这正是我们要的：下次启动还能靠标志再试一次。
        FirewallManager.SetOutboundDefaultAllowed(true);
        notes.Add("默认出站动作已还原为「允许」");

        if (DeleteSelfAllowIfWeCreatedIt(settings))
        {
            notes.Add("已删掉本程序自己的白名单规则");
        }

        ClearPersistedFlags(settings, settingsPath);

        IsEnabled = false;
        OriginalState = null;

        var message = string.Join("；", notes);
        LocalLog.Operation($"严格模式已关闭：{message}");
        return new StrictModeChangeResult(true, $"严格模式已关闭：{message}。");
    }

    /// <summary>
    /// 启动兜底：如果上次「开了严格模式却没还原就退出」（崩溃 / 被强杀 / 断电），
    /// 现在把「默认出站动作」还原成「允许」。
    ///
    /// 本方法**总是从设置文件重新读**，不依赖内存状态 —— 因为它天生要跨进程生效。
    /// </summary>
    /// <param name="settingsPath">同 <see cref="Enable"/>。</param>
    public static StrictModeRecoveryResult RecoverIfLeftOn(string? settingsPath = null)
    {
        var settings = AppSettings.Load(settingsPath);

        if (!settings.StrictModeLeftOn)
        {
            // 上次是正常退出，什么都不用做（这是绝大多数情况）。
            return new StrictModeRecoveryResult(false, false, string.Empty);
        }

        var before = FirewallManager.GetOutboundDefaultAllowed();

        FirewallManager.SetOutboundDefaultAllowed(true);
        var after = FirewallManager.GetOutboundDefaultAllowed();

        var deletedSelfAllow = DeleteSelfAllowIfWeCreatedIt(settings);
        ClearPersistedFlags(settings, settingsPath);

        IsEnabled = false;
        OriginalState = null;

        var message =
            "上次没有正常退出，严格模式留下的「默认阻止出站」已经被自动还原。" +
            $"（{before.Describe()} → {after.Describe()}）" +
            (deletedSelfAllow ? " 本程序自己的白名单规则也已删掉。" : string.Empty);

        if (after.AllAllowed)
        {
            LocalLog.Warning($"严格模式启动兜底成功：{message}");
        }
        else
        {
            // 极少见，但必须说清楚 —— 这种情况下用户是真的上不了网。
            LocalLog.Error($"严格模式启动兜底失败：还原后是 {after.Describe()}，不是全部「允许」。");
            message += " ⚠ 但还原没有完全成功，请手工把三套配置文件的「出站连接」都改成「允许」。";
        }

        return new StrictModeRecoveryResult(true, after.AllAllowed, message);
    }

    // ==================================================================
    // 内部实现
    // ==================================================================

    /// <summary>
    /// 删掉「我们替本程序自己建」的那条放行规则。
    /// 返回是否真的删掉了一条（用户自己加的白名单不会被误删，因为标志区分了来源）。
    /// </summary>
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
            if (!FirewallManager.DeleteRule(name))
            {
                // 规则已经不在（用户手工删过）—— 不算失败，记一笔就够。
                LocalLog.Info($"严格模式收尾：本程序自身的白名单规则 {name} 已不存在，无需删除");
                return false;
            }

            return true;
        }
        catch (Exception ex)
        {
            LocalLog.Error($"严格模式收尾：删除本程序自身的白名单规则失败（{name}）", ex);
            return false;
        }
    }

    /// <summary>把「我开着严格模式」这两个标志清掉。</summary>
    private static void ClearPersistedFlags(AppSettings settings, string? settingsPath)
    {
        settings.StrictModeLeftOn = false;
        settings.StrictModeSelfAllowCreated = false;
        settings.Save(settingsPath);
    }
}
