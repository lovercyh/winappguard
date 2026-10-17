using WinAppGuard.Models;

namespace WinAppGuard.Core.Wfp;

/// <summary>一次迁移的结果，供日志和界面展示。</summary>
/// <param name="Migrated">成功迁移的规则条数。</param>
/// <param name="Skipped">明确跳过（2.0 表达不了，或程序已不存在）的条数。</param>
/// <param name="Failed">尝试了但失败的条数。</param>
/// <param name="FirewallRulesDeleted">实际从 Windows 防火墙里删掉的旧规则条数。</param>
/// <param name="Details">逐条说明，直接写进日志。</param>
internal sealed record WfpMigrationReport(
    int Migrated,
    int Skipped,
    int Failed,
    int FirewallRulesDeleted,
    IReadOnlyList<string> Details)
{
    /// <summary>是不是没有失败项。</summary>
    internal bool Succeeded => Failed == 0;
}

/// <summary>
/// 把 1.x 的 Windows 防火墙规则（<c>AppGuard_*</c>）一次性迁到 2.0 的 WFP 规则上。
///
/// ==================== 顺序是安全的关键 ====================
/// 每条规则都是「**先写新规则，再删旧规则**」：
///   - 中途断电/崩溃：旧规则还在，下次启动会再迁一次（写入是幂等的）；
///   - 反过来先删后写：一旦写入失败，这条规则就**凭空消失**了，用户的程序会被放行。
///
/// 单条失败**不会**中断整批：一条坏规则不该拖住其余几十条。
///
/// 这个类只负责"迁移"本身：读哪些规则由调用方决定，
/// 因此在自检里可以只把"自己造的那两条"交给它，完全不碰用户的真实规则。
/// 调用前请确保子层已经建好（<see cref="WfpEngine.EnsureSublayer"/>）。
/// </summary>
internal static class WfpMigration
{
    /// <summary>
    /// 判断一条 1.x 规则能不能被 2.0 表达。
    /// </summary>
    /// <returns>能迁移返回 null；不能则返回给用户看的原因。</returns>
    internal static string? Validate(FirewallRuleItem rule)
    {
        if (!rule.Enabled)
        {
            // 迁移一条"停用"的规则会把它的动作变成生效 —— 等于偷偷改了用户的行为。
            return "规则处于停用状态";
        }

        if (rule.Direction != FirewallDirection.Outbound)
        {
            return $"方向是「{rule.DirectionText}」，2.0 目前只做程序级出站规则";
        }

        if (rule.Protocol != 256)
        {
            return $"带协议限制（{rule.Protocol}），2.0 的规则只按程序匹配";
        }

        if (string.IsNullOrWhiteSpace(rule.ApplicationPath))
        {
            return "规则没有指定程序（对所有程序生效），2.0 不支持";
        }

        if (!File.Exists(rule.ApplicationPath))
        {
            // 程序已经卸载了。留着这条旧规则没有意义，但也不能凭空删 ——
            // 交给调用方决定（这里只报告跳过）。
            return "程序文件已经不存在";
        }

        return null;
    }

    /// <summary>
    /// 执行迁移。只处理传入的这批规则，不自己去读系统里的其它规则。
    /// </summary>
    /// <param name="engine">已经打开、并且子层已就绪的 WFP 引擎。</param>
    /// <param name="rules">要迁移的 1.x 规则。</param>
    internal static WfpMigrationReport Migrate(WfpEngine engine, IReadOnlyList<FirewallRuleItem> rules)
    {
        var migrated = 0;
        var skipped = 0;
        var failed = 0;
        var deleted = 0;
        var details = new List<string>();

        foreach (var item in rules)
        {
            var reason = Validate(item);
            if (reason is not null)
            {
                skipped++;
                details.Add($"跳过「{item.Name}」：{reason}");
                continue;
            }

            var actionText = item.Action == FirewallAction.Block ? "阻止" : "允许";

            // ---- 第一步：写新规则 ----
            try
            {
                WfpRuleStore.Add(engine, new WfpRule(item.ApplicationPath, item.Action, item.Expiry));
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                failed++;
                details.Add($"失败「{item.Name}」：{ex.Message}（旧规则保留，未删除）");
                continue;
            }

            migrated++;
            details.Add(
                $"迁移「{item.Name}」→ {actionText} {item.ApplicationPath}" +
                (item.Expiry.IsPermanent ? "（永久）" : $"（{item.Expiry.DescribeSchedule()}）"));

            // ---- 第二步：删旧规则 ----
            // 新规则已经在生效了。这一步失败最多留下一份多余但无害的旧规则
            // （WFP 的判定会先于 Windows 防火墙的 allow），所以只记录、不中断。
            try
            {
                if (FirewallManager.DeleteRule(item.Name))
                {
                    deleted++;
                }
                else
                {
                    details.Add($"  注意：「{item.Name}」在 Windows 防火墙里已经不在了");
                }
            }
            catch (Exception ex) when (ex is not OutOfMemoryException)
            {
                details.Add($"  注意：「{item.Name}」删除失败：{ex.Message}（新规则已生效，多余的一条无害）");
            }
        }

        return new WfpMigrationReport(migrated, skipped, failed, deleted, details);
    }
}
