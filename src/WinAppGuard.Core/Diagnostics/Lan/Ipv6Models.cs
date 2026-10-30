namespace WinAppGuard.Core.Diagnostics.Lan;

/// <summary>4.4：IPv6 邻接安全事件种类。</summary>
public static class Ipv6EventKinds
{
    public const string RaUnexpectedRouter = "ipv6_ra_unexpected_router";
    public const string RaMultipleRouters = "ipv6_ra_multiple_routers";
    public const string RaPrefixChanged = "ipv6_ra_prefix_changed";
    public const string RaFlagsOrLifetimeChanged = "ipv6_ra_flags_or_lifetime_changed";
    public const string RaFlood = "ipv6_ra_flood";

    public const string DhcpUnexpectedServer = "ipv6_dhcpv6_unexpected_server";
    public const string DhcpMultipleServers = "ipv6_dhcpv6_multiple_servers";
    public const string DhcpOptionMismatch = "ipv6_dhcpv6_option_mismatch";
    public const string DhcpShortLease = "ipv6_dhcpv6_short_lease";

    public const string NaRouterMacChanged = "ipv6_na_router_mac_changed";
    public const string NaCacheMismatch = "ipv6_na_cache_mismatch";
    public const string NaMacBehavior = "ipv6_na_mac_behavior";
    public const string NaUnsolicitedBurst = "ipv6_na_unsolicited_burst";
    public const string NdSenderMismatch = "ipv6_nd_sender_mismatch";
    public const string RedirectUnexpected = "ipv6_redirect_unexpected";
    public const string DadConflict = "ipv6_dad_conflict";
}

/// <summary>4.4：RA 前缀信息。</summary>
public sealed class Ipv6PrefixInfo
{
    public string Prefix { get; init; } = string.Empty;

    public int PrefixLength { get; init; }

    public uint ValidLifetime { get; init; }

    public uint PreferredLifetime { get; init; }

    public bool OnLink { get; init; }

    public bool Autonomous { get; init; }
}

/// <summary>4.4：RA 路由信息。</summary>
public sealed class Ipv6RouteInfo
{
    public string Prefix { get; init; } = string.Empty;

    public int PrefixLength { get; init; }

    public uint RouteLifetime { get; init; }
}

/// <summary>4.4：DHCPv6 IA_NA / IA_PD 地址。</summary>
public sealed class Ipv6IaInfo
{
    public string Address { get; init; } = string.Empty;

    public int PrefixLength { get; init; } = 128;

    public uint PreferredLifetime { get; init; }

    public uint ValidLifetime { get; init; }
}

/// <summary>4.4：一条路由器通告。</summary>
public sealed class Ipv6RaMessage
{
    public DateTime TimeUtc { get; init; }

    public string Adapter { get; init; } = string.Empty;

    public string SourceAddress { get; init; } = string.Empty;

    public string DestinationAddress { get; init; } = string.Empty;

    public string? SourceMac { get; init; }

    public byte HopLimit { get; init; }

    public bool Managed { get; init; }

    public bool Other { get; init; }

    public bool HomeAgent { get; init; }

    public ushort RouterLifetime { get; init; }

    public uint ReachableTime { get; init; }

    public uint RetransTimer { get; init; }

    public uint Mtu { get; init; }

    public List<Ipv6PrefixInfo> Prefixes { get; init; } = new();

    public List<Ipv6RouteInfo> Routes { get; init; } = new();

    public List<string> DnsServers { get; init; } = new();

    public List<string> DnsDomains { get; init; } = new();
}

/// <summary>4.4：一条 NS / NA / Redirect。</summary>
public sealed class Ipv6NdMessage
{
    public DateTime TimeUtc { get; init; }

    public string Adapter { get; init; } = string.Empty;

    /// <summary>135 = NS，136 = NA，137 = Redirect。</summary>
    public int Type { get; init; }

    public string SourceAddress { get; init; } = string.Empty;

    public string DestinationAddress { get; init; } = string.Empty;

    public string? SourceMac { get; init; }

    public string TargetAddress { get; init; } = string.Empty;

    /// <summary>SLLA / TLLA 里的 MAC（与以太网源 MAC 对照）。</summary>
    public string? TargetMac { get; init; }

    public bool Router { get; init; }

    public bool Solicited { get; init; }

    public bool Override { get; init; }

    public string? RedirectTarget { get; init; }
}

/// <summary>4.4：一条 DHCPv6 消息（只取检测需要的字段）。</summary>
public sealed class Ipv6DhcpMessage
{
    public DateTime TimeUtc { get; init; }

    public string Adapter { get; init; } = string.Empty;

    public bool ServerToClient { get; init; }

    public string SourceAddress { get; init; } = string.Empty;

    public string DestinationAddress { get; init; } = string.Empty;

    public ushort SourcePort { get; init; }

    public ushort DestinationPort { get; init; }

    public string? SourceMac { get; init; }

    public byte MessageType { get; init; }

    public string? ServerId { get; init; }

    public string? ClientId { get; init; }

    public List<string> DnsServers { get; init; } = new();

    public List<string> Domains { get; init; } = new();

    public List<Ipv6IaInfo> IaAddresses { get; init; } = new();

    public uint MinPreferredLifetime { get; init; }

    public uint MinValidLifetime { get; init; }
}

/// <summary>4.4：基线里的一个 IPv6 路由器。</summary>
public sealed class Ipv6Router
{
    public string LinkLocal { get; set; } = string.Empty;

    public string Mac { get; set; } = string.Empty;

    public List<Ipv6PrefixInfo> Prefixes { get; set; } = new();

    public bool Managed { get; set; }

    public bool Other { get; set; }

    public bool HomeAgent { get; set; }

    public ushort RouterLifetime { get; set; }

    public DateTime FirstSeenUtc { get; set; }

    public DateTime LastSeenUtc { get; set; }

    /// <summary>true = 基线内；false = 基线之后才出现（疑似 rogue）。</summary>
    public bool Baseline { get; set; }
}

/// <summary>4.4：基线里的一个 DHCPv6 服务器。</summary>
public sealed class Ipv6DhcpServer
{
    public string ServerId { get; set; } = string.Empty;

    public string Address { get; set; } = string.Empty;

    public string? Mac { get; set; }

    public List<string> DnsServers { get; set; } = new();

    public List<string> Domains { get; set; } = new();

    public List<Ipv6IaInfo> IaAddresses { get; set; } = new();

    public uint MinPreferredLifetime { get; set; }

    public uint MinValidLifetime { get; set; }

    public DateTime FirstSeenUtc { get; set; }

    public DateTime LastSeenUtc { get; set; }

    public bool Baseline { get; set; }
}

/// <summary>4.4：基线里的一个 IPv6 邻居。</summary>
public sealed class Ipv6Neighbor
{
    public string Address { get; set; } = string.Empty;

    public string Mac { get; set; } = string.Empty;

    public bool IsRouter { get; set; }

    public DateTime FirstSeenUtc { get; set; }

    public DateTime LastSeenUtc { get; set; }
}

/// <summary>4.4：`ipv6/state.json` 的内容。</summary>
public sealed class Ipv6State
{
    public DateTime? BaselineReadyUtc { get; set; }

    public List<Ipv6Router> Routers { get; set; } = new();

    public List<Ipv6DhcpServer> DhcpServers { get; set; } = new();

    public List<Ipv6Neighbor> Neighbors { get; set; } = new();

    /// <summary>信任键：<c>link-local|mac</c>。</summary>
    public List<string> TrustedRouters { get; set; } = new();

    /// <summary>信任键：<c>server-id|mac</c>。</summary>
    public List<string> TrustedDhcpServers { get; set; } = new();
}

/// <summary>4.4：一次 IPv6 安全快照。</summary>
public sealed class Ipv6SecuritySnapshot
{
    public List<LanEvent> Events { get; init; } = new();

    public List<Ipv6Router> Routers { get; init; } = new();

    public List<Ipv6DhcpServer> DhcpServers { get; init; } = new();

    public List<Ipv6Neighbor> Neighbors { get; init; } = new();

    public bool BaselineReady { get; init; }

    public DateTime? BaselineUtc { get; init; }
}

/// <summary>4.4：路由器/DHCPv6 信任键。</summary>
public static class Ipv6TrustKeys
{
    public static string Router(string linkLocal, string mac)
        => $"{linkLocal}|{mac}";

    public static string Dhcp(string serverId, string? mac)
        => $"{serverId}|{mac}";
}
