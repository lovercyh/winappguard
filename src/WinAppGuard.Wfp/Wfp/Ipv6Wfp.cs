using System.Net;
using WinAppGuard.Interop;

namespace WinAppGuard.Core.Wfp;

/// <summary>
/// 4.4 WFP：临时阻断 non-trusted IPv6 路由器 / DHCPv6 服务器。
///
/// - POC 命令用 <see cref="AddRouter"/> / <see cref="AddDhcp"/>（每次开一个引擎）；
/// - 服务进程用 <see cref="Ipv6BlockHost"/>（一个长期动态会话，进程退出自动清过滤器）。
///
/// RA：ICMPv6 protocol 58 + 远端链路本地 + ICMP type 134（仅 ALE 层支持 ICMP type）；
/// 传输层 / 数据报层不支持 ICMP type，退化为阻断该地址的全部 ICMPv6。
/// DHCPv6：UDP protocol 17 + 远端地址 + 远端端口 547 + 本地端口 546。
///
/// ★ 层选择：ALE 入站授权是"每条流授权一次"，DHCPv6 客户端套接字长期存在，
///   过滤器加之前已经建立过流，ADVERTISE 会直接吃旧缓存，表现为
///   "过滤器明明在，地址照样拿到"（2026-10-31 实测）。传输层是逐包判定，
///   POC 与服务阻断都用 <see cref="BlockLayer.Transport"/>。
/// </summary>
internal static class Ipv6Wfp
{
    private const string DescriptionPrefix = "AppGuard|1|Ipv6Block|";

    /// <summary>4.4 可以挂的 WFP 层。</summary>
    internal enum BlockLayer
    {
        /// <summary>FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6（按流授权，POC 对照用）。</summary>
        Ale,

        /// <summary>FWPM_LAYER_INBOUND_TRANSPORT_V6（逐包）。</summary>
        Transport,

        /// <summary>FWPM_LAYER_DATAGRAM_DATA_V6（逐包，更靠近套接字）。</summary>
        Datagram,
    }

    internal static string LayerName(BlockLayer layer) => layer switch
    {
        BlockLayer.Transport => "transport",
        BlockLayer.Datagram => "datagram",
        _ => "ale",
    };

    internal static bool TryParseLayer(string? text, out BlockLayer layer)
    {
        switch (text?.Trim().ToLowerInvariant())
        {
            case null or "":
            case "ale":
                layer = BlockLayer.Ale;
                return true;
            case "transport":
            case "inbound-transport":
                layer = BlockLayer.Transport;
                return true;
            case "datagram":
            case "datagram-data":
                layer = BlockLayer.Datagram;
                return true;
            default:
                layer = BlockLayer.Transport;
                return false;
        }
    }

    private static Guid LayerKey(BlockLayer layer) => layer switch
    {
        BlockLayer.Transport => WfpNativeMethods.LayerInboundTransportV6,
        BlockLayer.Datagram => WfpNativeMethods.LayerDatagramDataV6,
        _ => WfpNativeMethods.LayerAleAuthRecvAcceptV6,
    };

    internal static Guid RouterKey(IPAddress address, BlockLayer layer)
        => WfpEngine.BuildFilterKey($"ipv6-ra|{LayerName(layer)}|{address}");

    internal static Guid DhcpKey(IPAddress address, BlockLayer layer)
        => WfpEngine.BuildFilterKey($"ipv6-dhcp|{LayerName(layer)}|{address}");

    /// <summary>POC 用：自己开引擎加一条 RA 过滤器。</summary>
    internal static bool AddRouter(IPAddress address, BlockLayer layer, out string scope)
    {
        using var engine = WfpEngine.Open();
        Prepare(engine);
        return AddRouterCore(engine, address, layer, out scope);
    }

    /// <summary>POC 用：自己开引擎加一条 DHCPv6 过滤器。</summary>
    internal static bool AddDhcp(IPAddress address, BlockLayer layer, out string scope)
    {
        using var engine = WfpEngine.Open();
        Prepare(engine);
        return AddDhcpCore(engine, address, layer, out scope);
    }

    /// <summary>确保子层存在（已存在时只读取实际状态）。</summary>
    internal static void Prepare(WfpEngine engine)
    {
        engine.EnsureSublayer(persistent: false);
    }

    internal static bool AddRouterCore(
        WfpEngine engine, IPAddress address, BlockLayer layer, out string scope)
    {
        var key = RouterKey(address, layer);
        engine.TryDeleteFilter(key);

        var layerText = LayerName(layer);
        var icmpTypeSupported = layer == BlockLayer.Ale;

        try
        {
            engine.AddTransportInboundFilter(
                key,
                $"{AppConstants.RulePrefix}Ipv6Ra_{address}",
                $"{DescriptionPrefix}ra|{layerText}|{address}|",
                address,
                protocol: 58,
                remotePort: null,
                localPort: icmpTypeSupported ? (ushort)134 : null,
                WfpNativeMethods.FWP_ACTION_BLOCK,
                WfpRuleStore.WeightBlock,
                persistent: false,
                layerKey: LayerKey(layer));
            scope = icmpTypeSupported
                ? $"ICMPv6 type 134（{layerText} 层）"
                : $"该地址的全部 ICMPv6（{layerText} 层不支持 ICMP type）";
            return true;
        }
        catch (WfpException) when (icmpTypeSupported)
        {
            // 某些 Windows 版本的 ALE 层不暴露 ICMP type；退化为该地址的全部 ICMPv6。
            engine.AddTransportInboundFilter(
                key,
                $"{AppConstants.RulePrefix}Ipv6Ra_{address}",
                $"{DescriptionPrefix}ra|{layerText}|{address}|",
                address,
                protocol: 58,
                remotePort: null,
                localPort: null,
                WfpNativeMethods.FWP_ACTION_BLOCK,
                WfpRuleStore.WeightBlock,
                persistent: false,
                layerKey: LayerKey(layer));
            scope = $"该地址的全部 ICMPv6（{layerText} 层，ICMP type 条件不可用）";
            return true;
        }
    }

    internal static bool AddDhcpCore(
        WfpEngine engine, IPAddress address, BlockLayer layer, out string scope)
    {
        var key = DhcpKey(address, layer);
        engine.TryDeleteFilter(key);

        var layerText = LayerName(layer);

        try
        {
            engine.AddTransportInboundFilter(
                key,
                $"{AppConstants.RulePrefix}Ipv6Dhcp_{address}",
                $"{DescriptionPrefix}dhcp|{layerText}|{address}|",
                address,
                protocol: 17,
                remotePort: 547,
                localPort: 546,
                WfpNativeMethods.FWP_ACTION_BLOCK,
                WfpRuleStore.WeightBlock,
                persistent: false,
                layerKey: LayerKey(layer));
            scope = $"UDP 547->546（{layerText} 层）";
            return true;
        }
        catch (WfpException)
        {
            engine.AddTransportInboundFilter(
                key,
                $"{AppConstants.RulePrefix}Ipv6Dhcp_{address}",
                $"{DescriptionPrefix}dhcp|{layerText}|{address}|",
                address,
                protocol: 17,
                remotePort: 547,
                localPort: null,
                WfpNativeMethods.FWP_ACTION_BLOCK,
                WfpRuleStore.WeightBlock,
                persistent: false,
                layerKey: LayerKey(layer));
            scope = $"UDP from this address to remote port 547（{layerText} 层，本地端口条件不可用）";
            return true;
        }
    }

    /// <summary>按层删除；层未知时删除该地址在所有层上的过滤器。</summary>
    internal static bool RemoveRouter(IPAddress address, BlockLayer? layer = null)
    {
        using var engine = WfpEngine.Open();

        if (layer is { } single)
        {
            return engine.TryDeleteFilter(RouterKey(address, single));
        }

        var removed = false;

        foreach (var item in Enum.GetValues<BlockLayer>())
        {
            removed |= engine.TryDeleteFilter(RouterKey(address, item));
        }

        return removed;
    }

    internal static bool RemoveDhcp(IPAddress address, BlockLayer? layer = null)
    {
        using var engine = WfpEngine.Open();

        if (layer is { } single)
        {
            return engine.TryDeleteFilter(DhcpKey(address, single));
        }

        var removed = false;

        foreach (var item in Enum.GetValues<BlockLayer>())
        {
            removed |= engine.TryDeleteFilter(DhcpKey(address, item));
        }

        return removed;
    }

    internal static bool RemoveDhcp(WfpEngine engine, IPAddress address, BlockLayer layer)
        => engine.TryDeleteFilter(DhcpKey(address, layer));

    internal static int RemoveAll()
    {
        using var engine = WfpEngine.Open();
        return RemoveAll(engine);
    }

    internal static int RemoveAll(WfpEngine engine)
    {
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

/// <summary>
/// 4.4：服务进程持有的 IPv6 阻断会话。
///
/// ★ 为什么用动态会话：非持久过滤器不会随进程退出自动消失（POC 里过滤器在
///   进程结束后还在，必须显式删）。动态会话（<c>FWPM_SESSION_FLAG_DYNAMIC</c>）
///   的过滤器会在会话结束时由 WFP 自动删除 —— 服务崩溃也不会留下永久阻断，
///   和"只阻断 10 分钟"的语义一致。
///
/// 只在服务里用；POC 和自检仍然用静态方法（一次性进程）。
/// </summary>
internal sealed class Ipv6BlockHost : IDisposable
{
    private readonly object _gate = new();
    private readonly WfpEngine _engine;
    private bool _disposed;

    internal Ipv6BlockHost()
    {
        _engine = WfpEngine.Open(dynamicSession: true);
        Ipv6Wfp.Prepare(_engine);
    }

    internal bool AddDhcp(IPAddress address, out string scope)
    {
        lock (_gate)
        {
            ThrowIfDisposed();
            return Ipv6Wfp.AddDhcpCore(_engine, address, Ipv6Wfp.BlockLayer.Transport, out scope);
        }
    }

    internal bool RemoveDhcp(IPAddress address)
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return false;
            }

            return Ipv6Wfp.RemoveDhcp(_engine, address, Ipv6Wfp.BlockLayer.Transport);
        }
    }

    /// <summary>删除本会话里所有 IPv6 阻断过滤器（服务停止时用）。</summary>
    internal int RemoveAll()
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return 0;
            }

            return Ipv6Wfp.RemoveAll(_engine);
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            _engine.Dispose();
        }
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(Ipv6BlockHost));
        }
    }
}
