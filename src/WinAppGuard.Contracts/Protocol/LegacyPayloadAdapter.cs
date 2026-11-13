using System.Text.Json;

namespace WinAppGuard.Contracts.Protocol;

/// <summary>
/// 5.11：v4 载荷与旧处理器/旧 UI 之间的临时适配层。
///
/// 服务端用 <see cref="ToRequest"/> 把新载荷交给现有 Handler；
/// 客户端用 <see cref="ToResponse"/> 把新响应还原成旧 UI 可用的 ServiceResponse。
/// 5.12 删除。
/// </summary>
public static class LegacyPayloadAdapter
{
    public static JsonElement CreateRequestPayload(string command, ServiceRequest request)
    {
        var type = PayloadCatalog.RequestTypeFor(command);
        var element = JsonSerializer.SerializeToElement(request, ServiceProtocol.JsonOptions);
        var typed = element.Deserialize(type, ServiceProtocol.JsonOptions);

        return JsonSerializer.SerializeToElement(
            typed, type, ServiceProtocol.JsonOptions);
    }

    public static ServiceRequest ToRequest(
        string command, string? id, JsonElement payload)
    {
        var request = payload.Deserialize<ServiceRequest>(ServiceProtocol.JsonOptions)
                      ?? new ServiceRequest();

        request.Id = string.IsNullOrWhiteSpace(id) ? request.Id : id;
        request.Command = command;
        request.ProtocolVersion = ServiceProtocol.Version;
        return request;
    }

    public static ResponsePayload CreateResponse(
        string command,
        ServiceResponse response,
        long revision,
        string? revisionEpoch)
    {
        var legacy = JsonSerializer.SerializeToElement(response, ServiceProtocol.JsonOptions);
        var type = PayloadCatalog.ResponseTypeFor(command);

        if (type == typeof(StatusView))
        {
            var status = response.Status;

            return new StatusView
            {
                Revision = revision,
                RevisionEpoch = revisionEpoch,
                Core = status is null
                    ? null
                    : new StatusCore
                    {
                        ServiceVersion = status.ServiceVersion,
                        Protocol = status.ProtocolVersion,
                        Revision = status.Revision,
                        RevisionEpoch = status.RevisionEpoch,
                        SublayerPresent = status.SublayerPresent,
                        UptimeSeconds = Math.Max(0, (long)(DateTime.UtcNow - _startedUtc).TotalSeconds),
                    },
                Rules = JsonSerializer.SerializeToElement(new
                {
                    block = status?.BlockRuleCount ?? 0,
                    allow = status?.AllowRuleCount ?? 0,
                    ip = status?.IpRuleCount ?? 0,
                    strict = status?.StrictModeActive ?? false,
                    lockdown = status?.StrictModeLockdownActive ?? false,
                }, ServiceProtocol.JsonOptions),
                Counters = JsonSerializer.SerializeToElement(new
                {
                    idsAlertsNew = status?.IdsAlertsNew ?? 0,
                    trafficPps = status?.TrafficPps ?? 0,
                    trafficDropped = status?.TrafficDropped ?? 0,
                }, ServiceProtocol.JsonOptions),
                Modules = status?.Modules,
                Legacy = legacy,
            };
        }

        if (type == typeof(RulesView))
        {
            return new RulesView
            {
                Revision = revision,
                RevisionEpoch = revisionEpoch,
                Rules = response.Rules,
                Meta = Meta(revision, revisionEpoch),
                Legacy = legacy,
            };
        }

        if (type == typeof(ProcessPathsView))
        {
            return new ProcessPathsView
            {
                Revision = revision,
                RevisionEpoch = revisionEpoch,
                Paths = response.ProcessPaths,
                Legacy = legacy,
            };
        }

        if (type == typeof(TrafficView))
        {
            return new TrafficView
            {
                Revision = revision,
                RevisionEpoch = revisionEpoch,
                Programs = response.Traffic,
                Status = response.TrafficStatus,
                Series = response.TrafficSeries,
                Meta = Meta(revision, revisionEpoch),
                Legacy = legacy,
            };
        }

        if (type == typeof(QueryView))
        {
            return new QueryView
            {
                Revision = revision,
                RevisionEpoch = revisionEpoch,
                Meta = Meta(revision, revisionEpoch),
                IdsAlerts = response.IdsAlerts,
                IdsSuppressions = response.IdsSuppressions,
                IdsSettings = response.IdsSettings,
                IdsStatus = response.IdsStatus,
                NetworkAlerts = response.NetworkAlerts,
                NetworkBlocks = response.NetworkBlocks,
                NetworkDetectionSettings = response.NetworkDetectionSettings,
                NetworkDetectionStatus = response.NetworkDetectionStatus,
                AntiScanEvents = response.AntiScanEvents,
                AntiScanBlocks = response.AntiScanBlocks,
                AntiScanSettings = response.AntiScanSettings,
                AntiScanStatus = response.AntiScanStatus,
                LanEvents = response.LanEvents,
                LanGateways = response.LanGateways,
                LanDhcpServers = response.LanDhcpServers,
                LanBlocks = response.LanBlocks,
                LanSettings = response.LanSettings,
                LanStatus = response.LanStatus,
                DnsSecurityServers = response.DnsSecurityServers,
                DnsSecurityEvents = response.DnsSecurityEvents,
                DnsSecurityStatus = response.DnsSecurityStatus,
                Ipv6Routers = response.Ipv6Routers,
                Ipv6DhcpServers = response.Ipv6DhcpServers,
                Ipv6Neighbors = response.Ipv6Neighbors,
                Ipv6SecurityEvents = response.Ipv6SecurityEvents,
                Ipv6SecurityStatus = response.Ipv6SecurityStatus,
                ConfigItems = response.ConfigItems,
                ConfigIntegrityEvents = response.ConfigIntegrityEvents,
                ConfigIntegrityStatus = response.ConfigIntegrityStatus,
                NameSources = response.NameSources,
                NameResolutionEvents = response.NameResolutionEvents,
                NameResolutionStatus = response.NameResolutionStatus,
                DnsRecords = response.DnsRecords,
                Traffic = response.Traffic,
                TrafficStartedUtc = response.TrafficStartedUtc,
                TrafficStatus = response.TrafficStatus,
                TrafficSeries = response.TrafficSeries,
                Legacy = legacy,
            };
        }

        return new WriteResult
        {
            Revision = revision,
            RevisionEpoch = revisionEpoch,
            Affected = response.Affected,
            Legacy = legacy,
        };
    }

    public static ServiceResponse ToResponse(JsonElement data)
    {
        if (data.TryGetProperty("legacy", out var legacy)
            && legacy.ValueKind == JsonValueKind.Object)
        {
            var response = legacy.Deserialize<ServiceResponse>(ServiceProtocol.JsonOptions);

            if (response is not null)
            {
                return response;
            }
        }

        return data.Deserialize<ServiceResponse>(ServiceProtocol.JsonOptions)
               ?? new ServiceResponse
               {
                   Ok = false,
                   Error = "v4 响应载荷无法解析。",
                   ErrorCode = nameof(ProtocolErrorCode.Internal),
               };
    }

    private static QueryMeta Meta(long revision, string? epoch) => new()
    {
        GeneratedAtUtc = DateTime.UtcNow,
        Revision = revision,
        RevisionEpoch = epoch,
    };

    // 仅用于 status.core.uptimeSeconds；不影响协议。
    private static readonly DateTime _startedUtc = DateTime.UtcNow;
}
