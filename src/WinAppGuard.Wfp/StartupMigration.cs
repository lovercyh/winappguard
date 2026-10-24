using WinAppGuard.Core.Wfp;
using WinAppGuard.Models;

namespace WinAppGuard.Core;

/// <summary>
/// 启动时的兼容处理：把 1.x 留在 Windows 防火墙里的 <c>AppGuard_*</c> 规则迁到 2.0。
///
/// 为什么放在启动时、而不是做一次性版本判断：
///   - 迁移本身是幂等的（同名规则写入是"先删后加"），重复执行没有副作用；
///   - 1.x 的规则被删掉之后，这里自然就什么都不做，不需要额外记录"已迁移"状态；
///   - 万一某次迁移中途失败，下次启动会自动续上 —— 这是最容易做对的方式。
///
/// 任何失败都**不阻止程序启动**：旧规则原样保留，功能退回到"1.x 的规则仍然生效"，
/// 而 2.0 自己的规则一条都不会丢。
/// </summary>
internal static class StartupMigration
{
    /// <summary>有 1.x 规则就迁移，没有就立即返回。</summary>
    /// <param name="error">失败原因；成功或无事可做时为 null。</param>
    /// <returns>迁移报告；没有旧规则时返回 null。</returns>
    internal static WfpMigrationReport? RunIfNeeded(out string? error)
    {
        error = null;

        List<FirewallRuleItem> legacy;

        try
        {
            legacy = FirewallManager.GetAppGuardRules();
        }
        catch (Exception ex)
        {
            // 读不到旧规则不影响使用（2.0 的规则在 WFP 里，和这里无关）。
            LocalLog.Error("[WAG-DATA-030] Failed to read 1.x rules; migration skipped (retried on next start).", ex);
            error = ex.Message;
            return null;
        }

        if (legacy.Count == 0)
        {
            return null;
        }

        try
        {
            using var engine = WfpEngine.Open();
            engine.EnsureSublayer(persistent: true);

            var report = WfpMigration.Migrate(engine, legacy);

            LocalLog.Operation(
                $"[WAG-DATA-031] 1.x rule migration: migrated {report.Migrated}, skipped {report.Skipped}, "
                + $"failed {report.Failed}, legacy firewall rules deleted {report.FirewallRulesDeleted}.");

            if (!LocalLog.English)
            {
                // 服务日志固定英文，而迁移明细是面向界面的中文句子：只在非服务模式记录。
                foreach (var line in report.Details)
                {
                    LocalLog.Info("  migration: " + line);
                }
            }

            return report;
        }
        catch (Exception ex)
        {
            LocalLog.Error("[WAG-DATA-033] 1.x rule migration failed; all legacy rules kept and retried on next start.", ex);
            error = ex.Message;
            return null;
        }
    }
}
