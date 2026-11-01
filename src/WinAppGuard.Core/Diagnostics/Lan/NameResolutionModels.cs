namespace WinAppGuard.Core.Diagnostics.Lan;

/// <summary>4.5：名称解析协议。</summary>
public static class NameProtocols
{
    public const string Llmnr = "llmnr";
    public const string Nbns = "nbns";
    public const string Mdns = "mdns";

    public const ushort LlmnrPort = 5355;
    public const ushort NbnsPort = 137;
    public const ushort MdnsPort = 5353;

    public static bool IsNamePort(ushort port)
        => port is LlmnrPort or NbnsPort or MdnsPort;

    public static string FromPort(ushort port) => port switch
    {
        LlmnrPort => Llmnr,
        NbnsPort => Nbns,
        _ => Mdns,
    };

    public static string ToText(string protocol) => protocol switch
    {
        Nbns => "NBNS",
        Mdns => "mDNS",
        _ => "LLMNR",
    };
}

/// <summary>4.5：一条 LLMNR / NBNS / mDNS 报文（只取名称与地址）。</summary>
public sealed class NameMessage
{
    public DateTime TimeUtc { get; init; }

    public string Adapter { get; init; } = string.Empty;

    public string Protocol { get; init; } = NameProtocols.Llmnr;

    public string SourceAddress { get; init; } = string.Empty;

    public string DestinationAddress { get; init; } = string.Empty;

    public string? SourceMac { get; init; }

    public bool IsResponse { get; init; }

    public ushort TransactionId { get; init; }

    /// <summary>名称（小写，不含结尾点）。</summary>
    public string Name { get; init; } = string.Empty;

    /// <summary>A / AAAA 地址。</summary>
    public List<string> Addresses { get; init; } = new();

    public uint Ttl { get; init; }
}

/// <summary>4.5：一个名称解析来源。</summary>
public sealed class NameSource
{
    public string Address { get; set; } = string.Empty;

    public string Mac { get; set; } = string.Empty;

    /// <summary>逗号分隔的协议（LLMNR / NBNS / mDNS）。</summary>
    public string Protocols { get; set; } = string.Empty;

    /// <summary>最近应答的名称摘要。</summary>
    public string AnswerSummary { get; set; } = string.Empty;

    public int ResponseCount { get; set; }

    public DateTime LastSeenUtc { get; set; }
}

/// <summary>4.5：一条名称解析告警（由分析器生成）。</summary>
public sealed class NameAlert
{
    public string Id { get; } = Guid.NewGuid().ToString("N");

    public DateTime TimeUtc { get; init; }

    public string Kind { get; init; } = string.Empty;

    public string Severity { get; init; } = LanSeverity.Medium;

    public string Protocol { get; init; } = string.Empty;

    public string Name { get; init; } = string.Empty;

    public string SourceAddress { get; init; } = string.Empty;

    public string? SourceMac { get; init; }

    public string Detail { get; init; } = string.Empty;
}

/// <summary>4.5：名称解析事件种类（存 lan/，kind 前缀 name_）。</summary>
public static class NameEventKinds
{
    public const string Conflict = "name_conflict";
    public const string Unsolicited = "name_unsolicited";
    public const string ManyNames = "name_many_names";
    public const string Wpad = "name_wpad";
    public const string MdnsConflict = "name_mdns_conflict";
}
