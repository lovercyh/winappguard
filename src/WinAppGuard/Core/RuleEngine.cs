using WinAppGuard.Core.Wfp;
using WinAppGuard.Models;

namespace WinAppGuard.Core;

/// <summary>
/// 2.0 的规则入口：界面、命令行、严格模式都只跟它打交道。
///
/// 底下是 WFP（<c>Core/Wfp/*</c>），上层完全看不到"过滤器 / 子层 / 层"这些概念 ——
/// 对外仍然返回 <see cref="FirewallRuleItem"/>，所以界面代码几乎不用改，
/// 换掉的只是"这些规则存在哪里"。
///
/// 每次调用都新开一个引擎会话、用完就关。这样最简单、也不怕会话被别处关掉；
/// 代价是每次多一次 RPC 往返（实测枚举几百条过滤器是毫秒级，界面上感觉不到）。
/// </summary>
internal static class RuleEngine
{
    /// <summary>读出全部规则（界面列表、命令行列表都用它）。</summary>
    internal static List<FirewallRuleItem> GetRules()
    {
        using var engine = OpenEngine();

        var items = WfpRuleStore.List(engine).Select(ToRuleItem).ToList();
        items.AddRange(WfpRuleStore.ListIpRules(engine).Select(ToRuleItem));

        return items;
    }

    /// <summary>这个程序当前是不是被阻止。</summary>
    internal static bool IsProgramBlocked(string programPath)
    {
        var fullPath = TryGetFullPath(programPath);
        if (fullPath is null)
        {
            return false;
        }

        return GetRules().Any(rule =>
            rule.Action == FirewallAction.Block && PathsEqual(rule.ApplicationPath, fullPath));
    }

    /// <summary>为指定程序创建「阻止联网」规则（永久）。重复调用不会产生重复规则。</summary>
    internal static string CreateBlockRule(string programPath)
        => CreateBlockRule(programPath, RuleExpiry.Never);

    /// <summary>为指定程序创建「阻止联网」规则，并指定什么时候自动解除。</summary>
    internal static string CreateBlockRule(string programPath, RuleExpiry expiry)
        => Save(programPath, FirewallAction.Block, expiry);

    /// <summary>为指定程序创建「允许联网」规则。</summary>
    internal static string CreateAllowRule(string programPath)
        => Save(programPath, FirewallAction.Allow, RuleExpiry.Never);

    /// <summary>
    /// 创建一条「封禁 IP」规则（直接按远端 IP 拦，不做域名解析）。
    /// </summary>
    /// <param name="address">IPv4 或 IPv6 地址。</param>
    /// <returns>规则名，例如 <c>AppGuard_BlockIp_216.31.12.15</c>。</returns>
    internal static string CreateIpBlockRule(string address)
    {
        var rule = new WfpIpRule(address);

        using var engine = OpenEngine();
        WfpRuleStore.AddIp(engine, rule);

        return rule.DisplayName;
    }

    /// <summary>
    /// 按规则名删除一条规则。
    /// 规则名由 <see cref="RuleNaming"/> 从路径确定性生成，所以先按名字找出规则、再按规则删。
    /// </summary>
    /// <returns>确实删掉了返回 true；没有这条规则返回 false。</returns>
    internal static bool DeleteRule(string ruleName)
    {
        using var engine = OpenEngine();

        var rule = WfpRuleStore.List(engine)
            .FirstOrDefault(candidate => string.Equals(
                candidate.DisplayName, ruleName, StringComparison.OrdinalIgnoreCase));

        if (rule is null)
        {
            // 也可能是「封禁 IP」规则：它没有程序路径，只按名字匹配。
            var ipRule = WfpRuleStore.ListIpRules(engine)
                .FirstOrDefault(candidate => string.Equals(
                    candidate.DisplayName, ruleName, StringComparison.OrdinalIgnoreCase));

            if (ipRule is null)
            {
                return false;
            }

            WfpRuleStore.RemoveIp(engine, ipRule);
            return true;
        }

        WfpRuleStore.Remove(engine, rule);
        return true;
    }

    /// <summary>
    /// 删除某一类规则（只删阻止，或只删允许），返回删除条数。
    /// 黑名单页的「清空黑名单」和白名单页的「清空白名单」各用一半。
    /// </summary>
    internal static int DeleteRulesByAction(FirewallAction action)
    {
        var targets = GetRules().Where(rule => rule.Action == action).ToList();

        var deleted = 0;
        foreach (var rule in targets)
        {
            if (DeleteRule(rule.Name))
            {
                deleted++;
            }
        }

        return deleted;
    }

    /// <summary>删除作用于指定程序的全部规则（阻止 + 允许），返回删除的规则条数。</summary>
    internal static int DeleteRulesForProgram(string programPath)
    {
        var fullPath = TryGetFullPath(programPath);
        if (fullPath is null)
        {
            return 0;
        }

        using var engine = OpenEngine();

        var targets = WfpRuleStore.List(engine)
            .Where(rule => PathsEqual(rule.ApplicationPath, fullPath))
            .ToList();

        var deleted = 0;
        foreach (var rule in targets)
        {
            WfpRuleStore.Remove(engine, rule);
            deleted++;
        }

        return deleted;
    }

    /// <summary>删除本程序创建的全部规则，返回删除的规则条数（不是过滤器条数）。</summary>
    internal static int DeleteAllRules()
    {
        using var engine = OpenEngine();

        var count = WfpRuleStore.List(engine).Count;
        WfpRuleStore.RemoveAll(engine);
        return count;
    }

    /// <summary>
    /// 删掉所有已到期的规则，返回被删掉的（规则名 + 目标程序）。
    ///
    /// 语义与 1.x 完全一致：只有"限期"和"下次重启"两类会到期，永久规则永远不动。
    /// </summary>
    internal static List<(string RuleName, string ProgramPath)> PurgeExpiredRules(
        DateTime nowUtc,
        DateTime currentBootTimeUtc,
        bool freshLogonSession = false)
    {
        using var engine = OpenEngine();

        var expired = WfpRuleStore.List(engine)
            .Where(rule => !rule.Expiry.IsPermanent
                           && rule.Expiry.IsExpired(nowUtc, currentBootTimeUtc, freshLogonSession))
            .ToList();

        var removed = new List<(string RuleName, string ProgramPath)>();

        foreach (var rule in expired)
        {
            WfpRuleStore.Remove(engine, rule);
            removed.Add((rule.DisplayName, rule.ApplicationPath));
        }

        return removed;
    }

    /// <summary>
    /// 过滤器 ID → 规则名 的映射。
    ///
    /// 审计里的"拦截"事件带的是 WFP 的 **filterId**（不是规则名）。
    /// 一条规则在 V4/V6 各有一条过滤器，两个 ID 都映射到同一个规则名。
    /// </summary>
    internal static Dictionary<ulong, string> GetFilterIdToRuleName()
    {
        var map = new Dictionary<ulong, string>();

        using var engine = OpenEngine();

        foreach (var filter in engine.ListOurFilters())
        {
            if (filter.FilterId == 0)
            {
                continue;
            }

            if (WfpRule.TryParse(filter.Description, out var rule))
            {
                map[filter.FilterId] = rule.DisplayName;
            }
            else if (WfpIpRule.TryParse(filter.Description, out var ipRule))
            {
                map[filter.FilterId] = ipRule.DisplayName;
            }
        }

        return map;
    }

    /// <summary>
    /// 本工具当前**所有**过滤器的 ID（含没有说明字段的，例如严格模式的"阻止全部"）。
    ///
    /// 审计的拦截事件来自 WFP 的全局 `CLASSIFY_DROP` —— 里面混着 Windows 防火墙、
    /// 其它安全软件拦掉的连接。只有用这张表过滤，才能保证"审计里出现的拦截＝本工具拦的"。
    /// </summary>
    internal static HashSet<ulong> GetOurFilterIds()
    {
        var ids = new HashSet<ulong>();

        using var engine = OpenEngine();

        foreach (var filter in engine.ListOurFilters())
        {
            if (filter.FilterId != 0)
            {
                ids.Add(filter.FilterId);
            }
        }

        return ids;
    }

    /// <summary>当前「允许联网」规则覆盖的程序路径（严格模式白名单用）。</summary>
    internal static List<string> GetAllowRulePrograms()
        => GetRules()
            .Where(rule => rule.Action == FirewallAction.Allow)
            .Select(rule => rule.ApplicationPath)
            .ToList();

    // ------------------------------------------------------------------
    // 内部
    // ------------------------------------------------------------------

    private static string Save(string programPath, FirewallAction action, RuleExpiry expiry)
    {
        // 路径合法性、自我保护、系统关键进程保护都在这里统一把关 ——
        // 2.0 换掉了存储方式，但**这些安全闸一条都没有放宽**。
        var fullPath = FirewallManager.ValidateProgramPath(
            programPath,
            forBlocking: action == FirewallAction.Block);

        var rule = new WfpRule(fullPath, action, expiry);

        using var engine = OpenEngine();
        WfpRuleStore.Add(engine, rule);

        return rule.DisplayName;
    }

    private static WfpEngine OpenEngine()
    {
        var engine = WfpEngine.Open();
        try
        {
            // 规则都挂在我们的子层下面，所以每次进来都确保它在。
            // 已经存在时不会改动它（权重之类的设置以现有为准）。
            engine.EnsureSublayer(persistent: true);
        }
        catch
        {
            engine.Dispose();
            throw;
        }

        return engine;
    }

    private static FirewallRuleItem ToRuleItem(WfpRule rule) => new()
    {
        Name = rule.DisplayName,
        ApplicationPath = rule.ApplicationPath,

        // 说明字段里存的是机器可读的规则内容（含到期标记），
        // 界面上显示它反而看得懂"什么时候解除"，也方便用户直接核对。
        Description = rule.Description,
        Grouping = AppConstants.RuleGroupingName,
        Enabled = true,
        Action = rule.Action,
        Direction = FirewallDirection.Outbound,
        Protocol = 256,
        Expiry = rule.Expiry,
    };

    /// <summary>把「封禁 IP」规则映射成界面使用的规则项。</summary>
    private static FirewallRuleItem ToRuleItem(WfpIpRule rule) => new()
    {
        Name = rule.DisplayName,

        // 路径列也放 IP：表格里两列都显示同一个地址，比留空更好认。
        ApplicationPath = rule.Address,
        IpAddress = rule.Address,
        Description = rule.Description,
        Grouping = AppConstants.RuleGroupingName,
        Enabled = true,
        Action = FirewallAction.Block,
        Direction = FirewallDirection.Outbound,
        Protocol = 256,
        Expiry = RuleExpiry.Never,
    };

    private static string? TryGetFullPath(string programPath)
    {
        if (string.IsNullOrWhiteSpace(programPath))
        {
            return null;
        }

        try
        {
            return Path.GetFullPath(programPath);
        }
        catch (Exception)
        {
            return null;
        }
    }

    private static bool PathsEqual(string left, string right)
        => string.Equals(left, right, StringComparison.OrdinalIgnoreCase);
}
