using System.Net;

namespace WinAppGuard.Core.Diagnostics.Lan;

/// <summary>4.2：一条 ARP 帧（只含检测需要的字段）。</summary>
public readonly record struct ArpFrame(
    DateTime TimeUtc,
    string Adapter,
    string EthernetSourceMac,
    string SenderMac,
    string SenderIp,
    string TargetIp,
    bool IsReply,
    bool IsGratuitous);

/// <summary>4.2：一条 DHCP 服务器应答（OFFER / ACK）。</summary>
public readonly record struct DhcpMessage(
    DateTime TimeUtc,
    string Adapter,
    string SourceMac,
    string ServerIp,
    string? Router,
    string? Dns,
    int LeaseSeconds,
    bool IsOffer);

/// <summary>4.2：规则 id。</summary>
public static class LanEventKinds
{
    public const string ArpGatewayMacChanged = "arp_gateway_mac_changed";
    public const string ArpGatewayCacheMismatch = "arp_gateway_cache_mismatch";
    public const string ArpMacClaimsManyIps = "arp_mac_claims_many_ips";
    public const string ArpIpMacFlapping = "arp_ip_mac_flapping";
    public const string ArpSenderMismatch = "arp_sender_mismatch";
    public const string ArpGratuitousBurst = "arp_gratuitous_burst";
    public const string DhcpUnexpectedServer = "dhcp_unexpected_server";
    public const string DhcpMultipleServers = "dhcp_multiple_servers";
    public const string DhcpOptionMismatch = "dhcp_option_mismatch";
    public const string DhcpShortLease = "dhcp_short_lease";
    public const string DhcpServerNotGateway = "dhcp_server_not_gateway";
}

/// <summary>4.2：事件级别。</summary>
public static class LanSeverity
{
    public const string High = "high";
    public const string Medium = "medium";
    public const string Low = "low";
}

/// <summary>4.2：一条局域网事件。</summary>
public sealed class LanEvent
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");

    public DateTime TimeUtc { get; set; }

    public string Kind { get; set; } = string.Empty;

    public string Severity { get; set; } = LanSeverity.Medium;

    public string Adapter { get; set; } = string.Empty;

    public string Detail { get; set; } = string.Empty;

    public string? SourceMac { get; set; }

    public string? TargetIp { get; set; }

    public string? TargetMac { get; set; }

    public bool Blocked { get; set; }
}

/// <summary>4.2：网关基线。</summary>
public sealed class LanGateway
{
    public string Adapter { get; set; } = string.Empty;

    public string Ip { get; set; } = string.Empty;

    public string Mac { get; set; } = string.Empty;

    public DateTime LearnedUtc { get; set; }

    public bool Trusted { get; set; }
}

/// <summary>4.2：观察到的 DHCP 服务器。</summary>
public sealed class LanDhcpServer
{
    public string ServerIp { get; set; } = string.Empty;

    public string? Mac { get; set; }

    public string Adapter { get; set; } = string.Empty;

    public string? Gateway { get; set; }

    public string? Dns { get; set; }

    public int LeaseSeconds { get; set; }

    public DateTime FirstSeenUtc { get; set; }

    public bool Trusted { get; set; }
}

/// <summary>4.2：临时阻断的 DHCP 服务器。</summary>
public sealed class LanBlock
{
    public string ServerIp { get; set; } = string.Empty;

    public DateTime UntilUtc { get; set; }

    public string Reason { get; set; } = string.Empty;

    public string? EventId { get; set; }
}

/// <summary>4.2：局域网检测设置。</summary>
public sealed class LanSettings
{
    public int RetentionDays { get; set; } = 7;

    public bool DhcpBlockEnabled { get; set; }
}

/// <summary>4.2：落盘状态（基线 / 服务器 / 信任 / 设置 / 阻断）。</summary>
public sealed class LanState
{
    public LanSettings Settings { get; set; } = new();

    public List<LanGateway> Gateways { get; set; } = new();

    public List<LanDhcpServer> DhcpServers { get; set; } = new();

    public List<LanBlock> Blocks { get; set; } = new();

    /// <summary>基线学习完成时间；null = 还在学习。</summary>
    public DateTime? BaselineReadyUtc { get; set; }
}

/// <summary>4.2：一次快照。</summary>
public sealed class LanSnapshot
{
    public List<LanEvent> Events { get; init; } = new();

    public List<LanGateway> Gateways { get; init; } = new();

    public List<LanDhcpServer> DhcpServers { get; init; } = new();

    public List<LanBlock> Blocks { get; init; } = new();

    public bool BaselineReady { get; init; }

    public DateTime? BaselineUtc { get; init; }
}

/// <summary>4.2：网关提示（由网卡枚举提供）。</summary>
public readonly record struct LanGatewayHint(string Adapter, string Ip);

/// <summary>4.2：网卡信息（用于界面显示与排除判断）。</summary>
public readonly record struct LanAdapterInfo(string Id, string Description, string Type);
