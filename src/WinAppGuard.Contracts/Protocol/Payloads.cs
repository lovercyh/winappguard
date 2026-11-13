namespace WinAppGuard.Contracts.Protocol;

/// <summary>
/// 5.11：v4 请求载荷。
///
/// 只放对应命令真正需要的字段；属性名与 `ServiceRequest` 保持兼容，
/// 服务端读出后仍映射到 ServiceRequest，Handler 不需要为每条命令写一套参数。
/// </summary>
public abstract class RequestPayload
{
}

public sealed class EmptyPayload : RequestPayload
{
}

public sealed class RulesQuery : RequestPayload
{
    public long? SinceRevision { get; set; }

    public int? Page { get; set; }

    public int? Size { get; set; }
}

public sealed class RuleAdd : RequestPayload
{
    public string? Value { get; set; }

    public string? Action { get; set; }

    public string? Expiry { get; set; }

    public string? Scope { get; set; }

    public string? Group { get; set; }
}

public sealed class RuleDelete : RequestPayload
{
    public string? RuleName { get; set; }
}

public sealed class RuleDeleteForProgram : RequestPayload
{
    public string? Value { get; set; }
}

public sealed class RuleClear : RequestPayload
{
    public string? Action { get; set; }
}

public sealed class RuleImport : RequestPayload
{
    public string? Json { get; set; }

    public bool FreshLogonSession { get; set; }
}

public sealed class RuleSetGroup : RequestPayload
{
    public string? RuleName { get; set; }

    public string? Group { get; set; }
}

public sealed class StrictCommand : RequestPayload
{
    public bool Enable { get; set; }

    public bool? ExtraPrograms { get; set; }

    public int? LockdownSeconds { get; set; }

    public string? Value { get; set; }
}

public sealed class PidsQuery : RequestPayload
{
    public List<int>? Pids { get; set; }
}

public sealed class AuditSettings : RequestPayload
{
    public bool? AuditEnabled { get; set; }

    public bool? AuditDomainLookup { get; set; }

    public int? AuditRetentionDays { get; set; }
}

public sealed class TrafficConfig : RequestPayload
{
    public bool? TrafficPaused { get; set; }
}

public sealed class IdsCommand : RequestPayload
{
    public WinAppGuard.Contracts.IdsSettingsDto? IdsSettings { get; set; }

    public string? IdsAlertId { get; set; }

    public WinAppGuard.Contracts.IdsSuppressionDto? IdsSuppression { get; set; }

    public bool IdsRemoveSuppression { get; set; }

    public List<string>? IdsRemoveSuppressionIds { get; set; }
}

public sealed class NetworkSettings : RequestPayload
{
    public WinAppGuard.Contracts.NetworkDetectionSettingsDto? NetworkDetectionSettings { get; set; }

    public string? NetworkAlertId { get; set; }

    public string? NetworkBlockKind { get; set; }

    public string? NetworkBlockTarget { get; set; }

    public int NetworkBlockMinutes { get; set; } = 10;

    public string? NetworkBlockId { get; set; }

    public bool NetworkBlockReleaseAll { get; set; }
}

public sealed class GuardDecision : RequestPayload
{
    public string? Value { get; set; }
}

public sealed class AntiScanCommand : RequestPayload
{
    public WinAppGuard.Contracts.AntiScanSettingsDto? AntiScanSettings { get; set; }

    public string? AntiScanAddress { get; set; }

    public bool AntiScanReleaseAll { get; set; }
}

public sealed class LanCommand : RequestPayload
{
    public WinAppGuard.Contracts.LanSettingsDto? LanSettings { get; set; }

    public string? LanTrustKind { get; set; }

    public string? LanTrustValue { get; set; }

    public string? LanBlockServerIp { get; set; }

    public bool LanBlockEnabled { get; set; }

    public bool LanResetBaseline { get; set; }
}

public sealed class DnsTrust : RequestPayload
{
    public string? DnsTrustAddress { get; set; }

    public bool DnsTrustEnabled { get; set; }
}

public sealed class Ipv6Trust : RequestPayload
{
    public string? Ipv6TrustKind { get; set; }

    public string? Ipv6TrustValue { get; set; }

    public string? Ipv6TrustMac { get; set; }

    public bool Ipv6TrustEnabled { get; set; }

    public string? Ipv6BlockKind { get; set; }

    public string? Ipv6BlockAddress { get; set; }

    public int Ipv6BlockMinutes { get; set; } = 10;

    public bool Ipv6BlockEnabled { get; set; }
}

public sealed class NameBlock : RequestPayload
{
    public string? NameBlockAddress { get; set; }

    public int NameBlockMinutes { get; set; } = 10;

    public bool NameBlockEnabled { get; set; }
}

public sealed class ClearOnly : RequestPayload
{
    public string? Scope { get; set; }
}

public sealed class Rebaseline : RequestPayload
{
    public string? Scope { get; set; }
}


// ---------------------------------------------------------------- responses

/// <summary>
/// 5.11：所有 v4 响应的公共信封。
///
/// 只放**与具体特性无关**的传输元数据（成功/错误、修订号、影响条数）；
/// 特性数据必须放进对应的结果类型（QueryView / TrafficView / RulesView ...），
/// 新增检测特性不允许再往这里加字段。
/// </summary>
public abstract class ResponsePayload
{
    public bool Ok { get; set; } = true;

    public string? Error { get; set; }

    public string? ErrorCode { get; set; }

    /// <summary>本次操作影响的条数（删除 / 导入 / 清空）。</summary>
    public int Affected { get; set; }

    public long Revision { get; set; }

    public string? RevisionEpoch { get; set; }
}

/// <summary>失败响应：不携带任何业务数据。</summary>
public sealed class ErrorView : ResponsePayload
{
}

/// <summary>通用写命令结果（增删规则、清空记录等）。</summary>
public sealed class WriteResult : ResponsePayload
{
    public string? Detail { get; set; }

    public string? Message { get; set; }
}

/// <summary>服务状态、严格模式、审计设置等命令的结果。</summary>
public sealed class StatusView : ResponsePayload
{
    public WinAppGuard.Contracts.ServiceStatus? Status { get; set; }

    public List<WinAppGuard.Contracts.ModuleStatusDto>? Modules { get; set; }

    public string? Message { get; set; }
}

/// <summary>规则列表（rules.list / 到期清理）。</summary>
public sealed class RulesView : ResponsePayload
{
    public List<WinAppGuard.Contracts.RuleDto>? Rules { get; set; }

    public QueryMeta? Meta { get; set; }
}

/// <summary>过滤器 id → 规则名（rules.filterMap）。</summary>
public sealed class FilterMapView : ResponsePayload
{
    public Dictionary<string, string>? FilterMap { get; set; }
}

/// <summary>本工具与系统/其它软件的放行目标（rules.allowTargets）。</summary>
public sealed class AllowTargetsView : ResponsePayload
{
    public List<string>? Programs { get; set; }

    public List<string>? OtherPrograms { get; set; }

    public int ProgramlessRuleCount { get; set; }
}

/// <summary>PID → 映像路径（query.processPaths）。</summary>
public sealed class ProcessPathsView : ResponsePayload
{
    public List<WinAppGuard.Contracts.ProcessPathDto>? Paths { get; set; }
}

/// <summary>精确流量（query.traffic / configure.traffic / clear.traffic）。</summary>
public sealed class TrafficView : ResponsePayload
{
    public List<WinAppGuard.Contracts.TrafficDto>? Programs { get; set; }

    public DateTime? TrafficStartedUtc { get; set; }

    public WinAppGuard.Contracts.TrafficStatusDto? Status { get; set; }

    public WinAppGuard.Contracts.TrafficSeriesDto? Series { get; set; }

    public QueryMeta? Meta { get; set; }
}

/// <summary>
/// 检测/记录类查询结果（query.* 以及修改检测设置后的回显）。
/// </summary>
public sealed class QueryView : ResponsePayload
{
    public QueryMeta? Meta { get; set; }

    // ---- IDS ----

    public List<WinAppGuard.Contracts.IdsAlertDto>? IdsAlerts { get; set; }

    public List<WinAppGuard.Contracts.IdsSuppressionDto>? IdsSuppressions { get; set; }

    public WinAppGuard.Contracts.IdsSettingsDto? IdsSettings { get; set; }

    public WinAppGuard.Contracts.IdsStatusDto? IdsStatus { get; set; }

    // ---- 网络被动检测 ----

    public List<WinAppGuard.Contracts.NetworkAlertDto>? NetworkAlerts { get; set; }

    public List<WinAppGuard.Contracts.NetworkBlockDto>? NetworkBlocks { get; set; }

    public WinAppGuard.Contracts.NetworkDetectionSettingsDto? NetworkDetectionSettings { get; set; }

    public WinAppGuard.Contracts.NetworkDetectionStatusDto? NetworkDetectionStatus { get; set; }

    // ---- 反扫描 ----

    public List<WinAppGuard.Contracts.AntiScanEventDto>? AntiScanEvents { get; set; }

    public List<WinAppGuard.Contracts.AntiScanBlockDto>? AntiScanBlocks { get; set; }

    public WinAppGuard.Contracts.AntiScanSettingsDto? AntiScanSettings { get; set; }

    public WinAppGuard.Contracts.AntiScanStatusDto? AntiScanStatus { get; set; }

    // ---- 局域网 ----

    public List<WinAppGuard.Contracts.LanEventDto>? LanEvents { get; set; }

    public List<WinAppGuard.Contracts.LanGatewayDto>? LanGateways { get; set; }

    public List<WinAppGuard.Contracts.LanDhcpServerDto>? LanDhcpServers { get; set; }

    public List<WinAppGuard.Contracts.LanBlockDto>? LanBlocks { get; set; }

    public WinAppGuard.Contracts.LanSettingsDto? LanSettings { get; set; }

    public WinAppGuard.Contracts.LanStatusDto? LanStatus { get; set; }

    // ---- DNS 安全 ----

    public List<WinAppGuard.Contracts.DnsSecurityServerDto>? DnsSecurityServers { get; set; }

    public List<WinAppGuard.Contracts.LanEventDto>? DnsSecurityEvents { get; set; }

    public WinAppGuard.Contracts.DnsSecurityStatusDto? DnsSecurityStatus { get; set; }

    // ---- IPv6 邻接安全 ----

    public List<WinAppGuard.Contracts.Ipv6RouterDto>? Ipv6Routers { get; set; }

    public List<WinAppGuard.Contracts.Ipv6DhcpServerDto>? Ipv6DhcpServers { get; set; }

    public List<WinAppGuard.Contracts.Ipv6NeighborDto>? Ipv6Neighbors { get; set; }

    public List<WinAppGuard.Contracts.LanEventDto>? Ipv6SecurityEvents { get; set; }

    public WinAppGuard.Contracts.Ipv6SecurityStatusDto? Ipv6SecurityStatus { get; set; }

    // ---- 本机配置完整性 ----

    public List<WinAppGuard.Contracts.ConfigItemDto>? ConfigItems { get; set; }

    public List<WinAppGuard.Contracts.LanEventDto>? ConfigIntegrityEvents { get; set; }

    public WinAppGuard.Contracts.ConfigIntegrityStatusDto? ConfigIntegrityStatus { get; set; }

    // ---- 局域网名称解析 ----

    public List<WinAppGuard.Contracts.NameSourceDto>? NameSources { get; set; }

    public List<WinAppGuard.Contracts.LanEventDto>? NameResolutionEvents { get; set; }

    public WinAppGuard.Contracts.NameResolutionStatusDto? NameResolutionStatus { get; set; }

    // ---- DNS 记录 ----

    public List<WinAppGuard.Contracts.DnsDto>? DnsRecords { get; set; }

    // ---- 流量快照 ----

    public List<WinAppGuard.Contracts.TrafficDto>? Traffic { get; set; }

    public DateTime? TrafficStartedUtc { get; set; }

    public WinAppGuard.Contracts.TrafficStatusDto? TrafficStatus { get; set; }

    public WinAppGuard.Contracts.TrafficSeriesDto? TrafficSeries { get; set; }
}

/// <summary>查询结果的附加元数据。</summary>
public sealed class QueryMeta
{
    public DateTime GeneratedAtUtc { get; set; } = DateTime.UtcNow;

    public long Revision { get; set; }

    public string? RevisionEpoch { get; set; }

    public bool Truncated { get; set; }

    public int? Total { get; set; }

    public bool NotModified { get; set; }
}
