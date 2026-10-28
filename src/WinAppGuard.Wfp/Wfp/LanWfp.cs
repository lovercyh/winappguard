using System.Net;
using WinAppGuard.Interop;

namespace WinAppGuard.Core.Wfp;

/// <summary>
/// 4.2：临时阻断某个 DHCP 服务器（只拦来自该 IP 的 DHCP 应答，UDP 67 → 68）。
///
/// 过滤器不持久化：服务停止时删除，未到期的阻断由状态文件在下次启动时恢复。
/// </summary>
internal static class LanWfp
{
    private const string DescriptionPrefix = "AppGuard|1|LanDhcpBlock|";

    internal static Guid FilterKey(IPAddress address)
        => WfpEngine.BuildFilterKey($"lan-dhcp|{address}");

    internal static void Add(IPAddress address)
    {
        using var engine = WfpEngine.Open();
        var key = FilterKey(address);

        engine.TryDeleteFilter(key);

        engine.AddDhcpInboundFilter(
            key,
            $"{AppConstants.RulePrefix}LanDhcp_{address}",
            $"{DescriptionPrefix}{address}|",
            address,
            WfpNativeMethods.FWP_ACTION_BLOCK,
            WfpRuleStore.WeightBlock,
            persistent: false);
    }

    internal static bool Remove(IPAddress address)
    {
        using var engine = WfpEngine.Open();
        return engine.TryDeleteFilter(FilterKey(address));
    }

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
