using System.Text.Json;

namespace WinAppGuard.Contracts.Protocol;

/// <summary>
/// 5.11：v4 请求载荷。
///
/// 只放对应命令真正需要的字段；属性名与旧 `ServiceRequest` 保持兼容，
/// 迁移期由 `LegacyPayloadAdapter` 转成旧处理器可读的请求。
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

public abstract class ResponsePayload
{
    public long Revision { get; set; }

    public string? RevisionEpoch { get; set; }
}

public sealed class WriteResult : ResponsePayload
{
    public int Affected { get; set; }

    public string? Detail { get; set; }

    public JsonElement? Legacy { get; set; }
}

public sealed class QueryView : ResponsePayload
{
    public QueryStatus? Status { get; set; }

    public JsonElement? Settings { get; set; }

    public List<JsonElement>? Events { get; set; }

    public List<JsonElement>? Blocks { get; set; }

    public JsonElement? Baseline { get; set; }

    public QueryMeta? Meta { get; set; }

    // ---- 12 个检测特性的真正响应载荷 ----

    public List<WinAppGuard.Contracts.IdsAlertDto>? IdsAlerts { get; set; }

    public List<WinAppGuard.Contracts.IdsSuppressionDto>? IdsSuppressions { get; set; }

    public WinAppGuard.Contracts.IdsSettingsDto? IdsSettings { get; set; }

    public WinAppGuard.Contracts.IdsStatusDto? IdsStatus { get; set; }

    public List<WinAppGuard.Contracts.NetworkAlertDto>? NetworkAlerts { get; set; }

    public List<WinAppGuard.Contracts.NetworkBlockDto>? NetworkBlocks { get; set; }

    public WinAppGuard.Contracts.NetworkDetectionSettingsDto? NetworkDetectionSettings { get; set; }

    public WinAppGuard.Contracts.NetworkDetectionStatusDto? NetworkDetectionStatus { get; set; }

    public List<WinAppGuard.Contracts.AntiScanEventDto>? AntiScanEvents { get; set; }

    public List<WinAppGuard.Contracts.AntiScanBlockDto>? AntiScanBlocks { get; set; }

    public WinAppGuard.Contracts.AntiScanSettingsDto? AntiScanSettings { get; set; }

    public WinAppGuard.Contracts.AntiScanStatusDto? AntiScanStatus { get; set; }

    public List<WinAppGuard.Contracts.LanEventDto>? LanEvents { get; set; }

    public List<WinAppGuard.Contracts.LanGatewayDto>? LanGateways { get; set; }

    public List<WinAppGuard.Contracts.LanDhcpServerDto>? LanDhcpServers { get; set; }

    public List<WinAppGuard.Contracts.LanBlockDto>? LanBlocks { get; set; }

    public WinAppGuard.Contracts.LanSettingsDto? LanSettings { get; set; }

    public WinAppGuard.Contracts.LanStatusDto? LanStatus { get; set; }

    public List<WinAppGuard.Contracts.DnsSecurityServerDto>? DnsSecurityServers { get; set; }

    public List<WinAppGuard.Contracts.LanEventDto>? DnsSecurityEvents { get; set; }

    public WinAppGuard.Contracts.DnsSecurityStatusDto? DnsSecurityStatus { get; set; }

    public List<WinAppGuard.Contracts.Ipv6RouterDto>? Ipv6Routers { get; set; }

    public List<WinAppGuard.Contracts.Ipv6DhcpServerDto>? Ipv6DhcpServers { get; set; }

    public List<WinAppGuard.Contracts.Ipv6NeighborDto>? Ipv6Neighbors { get; set; }

    public List<WinAppGuard.Contracts.LanEventDto>? Ipv6SecurityEvents { get; set; }

    public WinAppGuard.Contracts.Ipv6SecurityStatusDto? Ipv6SecurityStatus { get; set; }

    public List<WinAppGuard.Contracts.ConfigItemDto>? ConfigItems { get; set; }

    public List<WinAppGuard.Contracts.LanEventDto>? ConfigIntegrityEvents { get; set; }

    public WinAppGuard.Contracts.ConfigIntegrityStatusDto? ConfigIntegrityStatus { get; set; }

    public List<WinAppGuard.Contracts.NameSourceDto>? NameSources { get; set; }

    public List<WinAppGuard.Contracts.LanEventDto>? NameResolutionEvents { get; set; }

    public WinAppGuard.Contracts.NameResolutionStatusDto? NameResolutionStatus { get; set; }

    public List<WinAppGuard.Contracts.DnsDto>? DnsRecords { get; set; }

    public List<WinAppGuard.Contracts.TrafficDto>? Traffic { get; set; }

    public DateTime? TrafficStartedUtc { get; set; }

    public WinAppGuard.Contracts.TrafficStatusDto? TrafficStatus { get; set; }

    public WinAppGuard.Contracts.TrafficSeriesDto? TrafficSeries { get; set; }

    /// <summary>迁移期：旧 UI 仍需要的完整响应形状；5.12 删除。</summary>
    public JsonElement? Legacy { get; set; }
}

public sealed class QueryStatus
{
    public string Health { get; set; } = "unknown";

    public bool Collecting { get; set; }

    public string? Detail { get; set; }
}

public sealed class QueryMeta
{
    public DateTime GeneratedAtUtc { get; set; } = DateTime.UtcNow;

    public long Revision { get; set; }

    public string? RevisionEpoch { get; set; }

    public bool Truncated { get; set; }

    public int? Total { get; set; }

    public bool NotModified { get; set; }
}

public sealed class StatusView : ResponsePayload
{
    public StatusCore? Core { get; set; }

    public JsonElement? Rules { get; set; }

    public JsonElement? Counters { get; set; }

    public List<WinAppGuard.Contracts.ModuleStatusDto>? Modules { get; set; }

    public JsonElement? Legacy { get; set; }
}

public sealed class StatusCore
{
    public string ServiceVersion { get; set; } = "0.0.0";

    public int Protocol { get; set; }

    public long Revision { get; set; }

    public string? RevisionEpoch { get; set; }

    public bool SublayerPresent { get; set; }

    public long UptimeSeconds { get; set; }
}

public sealed class RulesView : ResponsePayload
{
    public List<WinAppGuard.Contracts.RuleDto>? Rules { get; set; }

    public JsonElement? Groups { get; set; }

    public QueryMeta? Meta { get; set; }

    public JsonElement? Legacy { get; set; }
}

public sealed class ProcessPathsView : ResponsePayload
{
    public List<WinAppGuard.Contracts.ProcessPathDto>? Paths { get; set; }

    public JsonElement? Legacy { get; set; }
}

public sealed class TrafficView : ResponsePayload
{
    public List<WinAppGuard.Contracts.TrafficDto>? Programs { get; set; }

    public WinAppGuard.Contracts.TrafficStatusDto? Status { get; set; }

    public WinAppGuard.Contracts.TrafficSeriesDto? Series { get; set; }

    public QueryMeta? Meta { get; set; }

    public JsonElement? Legacy { get; set; }
}
