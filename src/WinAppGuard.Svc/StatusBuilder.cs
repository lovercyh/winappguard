using System.Diagnostics;
using WinAppGuard.Contracts;
using WinAppGuard.Core;
using WinAppGuard.Core.Diagnostics.Processes;
using WinAppGuard.Core.Wfp;
using WinAppGuard.Models;

namespace WinAppGuard.Service;

/// <summary>
/// 5.11：服务状态快照。ControlServer 只保留生命周期和分发，
/// 状态字段从各个 Host 汇总到这里，避免 ControlServer 继续膨胀。
/// </summary>
internal static class StatusBuilder
{
    private static readonly TimeSpan CacheLifetime = TimeSpan.FromSeconds(1);
    private static readonly object CacheGate = new();

    private static DateTime _sublayerCheckedUtc = DateTime.MinValue;
    private static bool _sublayerPresent;
    private static DateTime _modulesCheckedUtc = DateTime.MinValue;
    private static IReadOnlyList<ModuleHealth>? _modules;

    internal static ServiceStatus Build()
    {
        var watch = Stopwatch.StartNew();
        var protectedMode = ControlServer.CurrentProtectedMode;
        var rules = ControlServer.RuleHandler;

        var status = new ServiceStatus
        {
            ServiceVersion = ControlServer.RuntimeVersion,
            ProtocolVersion = ServiceProtocol.Version,
            ProtectedMode = protectedMode is not null,
            ProtectedModeOwner = protectedMode?.OwnerName,
            ProtectedModeOwnerSid = protectedMode?.OwnerSid,
            ProtectedModeFingerprint = protectedMode?.Fingerprint,
            AuthRejectedCount = ControlServer.AuthRejectedCount,
            Revision = rules.RuleRevision,
            RevisionEpoch = rules.RuleRevisionEpoch,
            Modules = GetModules(),
        };

        var etw = ProcessEtwHost.Snapshot();
        status.ProcessEtw = new ProcessEtwStatusDto
        {
            Enabled = etw.Enabled,
            Running = etw.Running,
            Fallback = etw.Fallback,
            TableEntries = etw.TableEntries,
            EventsSeen = etw.EventsSeen,
            ParseFailures = etw.ParseFailures,
            LastError = etw.LastError,
            LastEventUtc = etw.LastEventUtc,
        };

        // 5.12：规则计数来自 RuleSnapshotCache（缓存命中时不开 WFP），
        // 子层存在性单独缓存 1 秒，避免每个 status 都打开 BFE 会话。
        status.SublayerPresent = GetSublayerPresent();

        try
        {
            var snapshot = rules.GetRuleSnapshot();
            status.BlockRuleCount = snapshot.Count(rule => rule.Action == FirewallAction.Block);
            status.AllowRuleCount = snapshot.Count(rule => rule.Action == FirewallAction.Allow);
            status.IpRuleCount = snapshot.Count(rule => !string.IsNullOrEmpty(rule.IpAddress));
        }
        catch (Exception ex)
        {
            ServiceLog.Warning("WAG-SVC-010", "Failed to read service status.", ex);
        }

        status.StrictModeActive = StrictModeHost.IsEnabled;
        status.StrictModePermittedCount = StrictModeHost.PermittedCount;
        status.StrictModeLockdownActive = LockdownHost.IsActive;
        status.StrictModeLockdownExpiresUtc = LockdownHost.ExpiresUtc;
        status.StrictModeLockdownRemainingSeconds = LockdownHost.RemainingSeconds;

        var audit = AuditHost.Snapshot();
        status.AuditEnabled = audit.Enabled;
        status.AuditDomainLookup = audit.DomainLookup;
        status.AuditRetentionDays = audit.RetentionDays;
        status.AuditCollecting = AuditHost.Collecting;
        status.AuditEventsWritten = AuditHost.EventsWritten;

        var traffic = TrafficCaptureHost.GetStatus();
        status.TrafficCollecting = traffic.Collecting;
        status.TrafficEventsSeen = TrafficHost.EventsSeen;
        status.TrafficPps = traffic.Pps;
        status.TrafficDropped = traffic.Dropped;
        status.TrafficSampled = traffic.Sampled;
        status.DnsCollecting = DnsHost.Collecting;

        var ids = IdsHost.GetStatus();
        status.IdsEnabled = ids.Enabled;
        status.IdsCollecting = ids.Collecting;
        status.IdsAlertsNew = ids.AlertsNew;
        status.IdsFlowCount = ids.FlowCount;
        status.IdsEventsSeen = ids.EventsSeen;

        var antiScan = AntiScanHost.GetStatus();
        status.AntiScanEnabled = antiScan.Enabled;
        status.AntiScanCollecting = antiScan.Collecting;
        status.AntiScanNpcapAvailable = antiScan.NpcapAvailable;
        status.AntiScanBlockedCount = antiScan.BlockedCount;

        var lan = LanHost.GetStatus();
        status.LanCollecting = lan.Collecting;
        status.LanEventCount = lan.EventCount;
        status.LanBlockedCount = lan.BlockedCount;
        status.LanBaselineReady = lan.BaselineReady;

        status.DnsSecurityCollecting = lan.DnsSecurityCollecting;
        status.DnsSecurityEventCount = lan.DnsSecurityEventCount;
        status.Ipv6SecurityCollecting = lan.Ipv6SecurityCollecting;
        status.Ipv6SecurityEventCount = lan.Ipv6SecurityEventCount;

        status.TamperRebuiltCount = rules.TamperRebuiltCount;
        status.LastTamperUtc = rules.LastTamperUtc;
        status.ExpiredPurgedCount = rules.ExpiredPurgedCount;
        status.LastPurgedPrograms = rules.LastPurgedPrograms;

        watch.Stop();

        if (watch.ElapsedMilliseconds > 40)
        {
            ServiceLog.Warning("WAG-PERF-STATUS", $"Status build took {watch.ElapsedMilliseconds} ms.");
        }

        return status;
    }

    private static bool GetSublayerPresent()
    {
        lock (CacheGate)
        {
            if (DateTime.UtcNow - _sublayerCheckedUtc < CacheLifetime)
            {
                return _sublayerPresent;
            }

            _sublayerCheckedUtc = DateTime.UtcNow;

            try
            {
                using var engine = WfpEngine.Open();
                _ = engine.ReadSublayer();
                _sublayerPresent = true;
            }
            catch (Exception)
            {
                _sublayerPresent = false;
            }

            return _sublayerPresent;
        }
    }

    private static List<ModuleStatusDto>? GetModules()
    {
        lock (CacheGate)
        {
            if (DateTime.UtcNow - _modulesCheckedUtc >= CacheLifetime)
            {
                _modulesCheckedUtc = DateTime.UtcNow;
                _modules = ControlServer.CurrentModules?.Snapshot();
            }

            return _modules?.Select(ToDto).ToList();
        }
    }

    private static ModuleStatusDto ToDto(ModuleHealth item) => new()
    {
        Name = item.Name,
        Order = item.Order,
        State = item.State.ToString(),
        Detail = item.Detail,
        LastError = item.LastError,
        Restarts = item.RestartCount,
    };
}
