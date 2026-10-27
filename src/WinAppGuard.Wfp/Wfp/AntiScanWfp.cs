using System.Net;
using WinAppGuard.Interop;

namespace WinAppGuard.Core.Wfp;

/// <summary>
/// 4.0：反扫描的入站临时封禁。
///
/// 只使用 <c>ALE_AUTH_RECV_ACCEPT_V4/V6</c>：拦住新入站连接，不影响已经建立的连接。
/// 过滤器不持久化：服务重启后由 <c>AntiScanHost</c> 按状态文件恢复未到期的封禁，
/// 避免服务崩溃后留下永久封禁。
/// </summary>
internal static class AntiScanWfp
{
    private const string DescriptionPrefix = "AppGuard|1|AntiScanBlockIp|";

    /// <summary>同一个 IP 使用确定性的过滤器 key，重复封禁是幂等的。</summary>
    internal static Guid FilterKey(IPAddress address)
        => WfpEngine.BuildFilterKey($"antiscan|{address}");

    internal static void Add(IPAddress address)
    {
        using var engine = WfpEngine.Open();
        var key = FilterKey(address);

        engine.TryDeleteFilter(key);

        engine.AddIpFilter(
            key,
            $"{AppConstants.RulePrefix}AntiScan_{address}",
            $"{DescriptionPrefix}{address}|",
            address,
            WfpNativeMethods.FWP_ACTION_BLOCK,
            WfpRuleStore.WeightBlock,
            persistent: false,
            inbound: true);
    }

    internal static bool Remove(IPAddress address)
    {
        using var engine = WfpEngine.Open();
        return engine.TryDeleteFilter(FilterKey(address));
    }

    /// <summary>服务启动时清掉上一次运行留下的反扫描过滤器。</summary>
    internal static int RemoveAll()
    {
        using var engine = WfpEngine.Open();
        var removed = 0;

        foreach (var filter in engine.ListOurFilters())
        {
            if (filter.Description is null
                || !filter.Description.StartsWith(DescriptionPrefix, StringComparison.Ordinal))
            {
                continue;
            }

            if (engine.TryDeleteFilter(filter.Key))
            {
                removed++;
            }
        }

        return removed;
    }
}
