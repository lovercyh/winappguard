using WinAppGuard.Contracts;
using WinAppGuard.Core;
using WinAppGuard.Core.Wfp;
using WinAppGuard.Models;

namespace WinAppGuard.Service;

/// <summary>
/// 5.11：服务状态快照。ControlServer 只保留生命周期和分发，
/// 状态字段从各个 Host 汇总到这里，避免 ControlServer 继续膨胀。
/// </summary>
internal static class StatusBuilder
{
    internal static ServiceStatus Build()
    {
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
            Modules = ControlServer.CurrentModules?.Snapshot()
                .Select(item => new ModuleStatusDto
                {
                    Name = item.Name,
                    Order = item.Order,
                    State = item.State.ToString(),
                    Detail = item.Detail,
                    LastError = item.LastError,
                    Restarts = item.RestartCount,
                })
                .ToList(),
        };

        try
        {
            using var engine = WfpEngine.Open();

            try
            {
                _ = engine.ReadSublayer();
                status.SublayerPresent = true;
            }
            catch (WfpException)
            {
                status.SublayerPresent = false;
            }

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

        return status;
    }
}
