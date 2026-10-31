using System.Net;
using WinAppGuard.Interop;

namespace WinAppGuard.Core.Wfp;

/// <summary>
/// 4.4 WFP POC：临时阻断 non-trusted IPv6 路由器 / DHCPv6 服务器。
///
/// 只在 POC 命令里使用；产品 UI 在 POC 通过前不提供阻断。
/// - RA：ICMPv6 protocol 58 + 远端链路本地 + ICMP type 134；
///   如果 WFP 不接受 ICMP type 条件，退化为阻断该地址的全部 ICMPv6。
/// - DHCPv6：UDP protocol 17 + 远端地址 + 远端端口 547 + 本地端口 546；
///   如果本地端口条件不可用，退化为只按远端地址 + 547。
/// </summary>
internal static class Ipv6Wfp
{
    private const string DescriptionPrefix = "AppGuard|1|Ipv6Block|";

    internal static Guid RouterKey(IPAddress address)
        => WfpEngine.BuildFilterKey($"ipv6-ra|{address}");

    internal static Guid DhcpKey(IPAddress address)
        => WfpEngine.BuildFilterKey($"ipv6-dhcp|{address}");

    internal static bool AddRouter(IPAddress address, out string scope)
    {
        using var engine = WfpEngine.Open();
        engine.EnsureSublayer(persistent: false);
        var key = RouterKey(address);
        engine.TryDeleteFilter(key);

        try
        {
            engine.AddTransportInboundFilter(
                key,
                $"{AppConstants.RulePrefix}Ipv6Ra_{address}",
                $"{DescriptionPrefix}ra|{address}|",
                address,
                protocol: 58,
                remotePort: null,
                localPort: 134,
                WfpNativeMethods.FWP_ACTION_BLOCK,
                WfpRuleStore.WeightBlock,
                persistent: false);
            scope = "ICMPv6 type 134";
            return true;
        }
        catch (WfpException)
        {
            // 某些 Windows 版本的 ALE 层不暴露 ICMP type；退化为该地址的全部 ICMPv6。
            engine.AddTransportInboundFilter(
                key,
                $"{AppConstants.RulePrefix}Ipv6Ra_{address}",
                $"{DescriptionPrefix}ra|{address}|",
                address,
                protocol: 58,
                remotePort: null,
                localPort: null,
                WfpNativeMethods.FWP_ACTION_BLOCK,
                WfpRuleStore.WeightBlock,
                persistent: false);
            scope = "all ICMPv6 from this address";
            return true;
        }
    }

    internal static bool AddDhcp(IPAddress address, out string scope)
    {
        using var engine = WfpEngine.Open();
        engine.EnsureSublayer(persistent: false);
        var key = DhcpKey(address);
        engine.TryDeleteFilter(key);

        try
        {
            engine.AddTransportInboundFilter(
                key,
                $"{AppConstants.RulePrefix}Ipv6Dhcp_{address}",
                $"{DescriptionPrefix}dhcp|{address}|",
                address,
                protocol: 17,
                remotePort: 547,
                localPort: 546,
                WfpNativeMethods.FWP_ACTION_BLOCK,
                WfpRuleStore.WeightBlock,
                persistent: false);
            scope = "UDP 547->546";
            return true;
        }
        catch (WfpException)
        {
            engine.AddTransportInboundFilter(
                key,
                $"{AppConstants.RulePrefix}Ipv6Dhcp_{address}",
                $"{DescriptionPrefix}dhcp|{address}|",
                address,
                protocol: 17,
                remotePort: 547,
                localPort: null,
                WfpNativeMethods.FWP_ACTION_BLOCK,
                WfpRuleStore.WeightBlock,
                persistent: false);
            scope = "UDP from this address to remote port 547";
            return true;
        }
    }

    internal static bool RemoveRouter(IPAddress address)
    {
        using var engine = WfpEngine.Open();
        return engine.TryDeleteFilter(RouterKey(address));
    }

    internal static bool RemoveDhcp(IPAddress address)
    {
        using var engine = WfpEngine.Open();
        return engine.TryDeleteFilter(DhcpKey(address));
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

    internal static int Count()
    {
        using var engine = WfpEngine.Open();
        return engine.ListOurFilters().Count(filter =>
            filter.Description is not null
            && filter.Description.StartsWith(DescriptionPrefix, StringComparison.Ordinal));
    }
}
