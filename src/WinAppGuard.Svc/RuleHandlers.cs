using System.Text.Json;
using WinAppGuard.Contracts;
using WinAppGuard.Core;
using WinAppGuard.Core.Wfp;
using WinAppGuard.Models;

namespace WinAppGuard.Service;

/// <summary>
/// 规则命令的处理（3.0-b）。
///
/// 所有写操作都走 <see cref="RuleEngine"/>，因此受保护进程、路径校验等安全闸
/// 一条都不会被绕过 —— 与 2.x 界面直接调用时是**同一套**校验。
/// </summary>
internal sealed class RuleHandlers
{
    private readonly RuleGroupStore _groups = new(ServicePaths.RuleGroupsFile);

    /// <summary>本次服务运行以来自动重建的规则条数。</summary>
    private int _tamperRebuilt;

    /// <summary>最近一次检测到外部删除的时间（UTC）。</summary>
    private DateTime? _lastTamperUtc;

    /// <summary>服务启动以来自动解除的到期规则总数。</summary>
    private int _expiredPurged;

    /// <summary>最近一次自动解除的程序路径。</summary>
    private List<string> _lastPurgedPrograms = new();

    internal int TamperRebuiltCount
    {
        get { lock (Gate) { return _tamperRebuilt; } }
    }

    internal DateTime? LastTamperUtc
    {
        get { lock (Gate) { return _lastTamperUtc; } }
    }

    internal int ExpiredPurgedCount
    {
        get { lock (Gate) { return _expiredPurged; } }
    }

    internal List<string> LastPurgedPrograms
    {
        get { lock (Gate) { return _lastPurgedPrograms.ToList(); } }
    }

    /// <summary>
    /// WFP / 规则文件都不是线程安全的：管道每个连接一个线程，必须串行化。
    /// 规则操作本身只有几毫秒，串行不会影响体验。
    /// </summary>
    internal static readonly object Gate = new();

    internal ServiceResponse Handle(ServiceRequest request)
    {
        lock (Gate)
        {
            return HandleCore(request);
        }
    }

    private ServiceResponse HandleCore(ServiceRequest request)
    {
        try
        {
            return request.Command switch
            {
                ServiceProtocol.Commands.ListRules => List(request),
                ServiceProtocol.Commands.FilterMap => FilterMap(request),
                ServiceProtocol.Commands.AllowTargets => AllowTargets(request),

                ServiceProtocol.Commands.AddProgramRule => AddProgram(request),
                ServiceProtocol.Commands.AddIpRule => AddIp(request),
                ServiceProtocol.Commands.DeleteRule => Delete(request),
                ServiceProtocol.Commands.DeleteRulesForProgram => DeleteForProgram(request),
                ServiceProtocol.Commands.ClearBlocklist => Clear(request, FirewallAction.Block),
                ServiceProtocol.Commands.ClearWhitelist => Clear(request, FirewallAction.Allow),
                ServiceProtocol.Commands.ClearAllRules => ClearAll(request),
                ServiceProtocol.Commands.SetGroup => SetGroup(request),
                ServiceProtocol.Commands.ImportRules => Import(request),
                ServiceProtocol.Commands.PurgeExpiredRules => PurgeExpired(request),
                ServiceProtocol.Commands.ImportGroups => ImportGroups(request),

                ServiceProtocol.Commands.StrictEnable => Strict(request, enable: true),
                ServiceProtocol.Commands.StrictDisable => Strict(request, enable: false),
                ServiceProtocol.Commands.StrictRefresh => StrictRefresh(request),
                ServiceProtocol.Commands.StrictRecoverLegacy => StrictRecoverLegacy(request),

                ServiceProtocol.Commands.AuditConfigure => AuditConfigure(request),
                ServiceProtocol.Commands.AuditClear => AuditClear(request),

                _ => Fail(request, $"不支持的命令：{request.Command}"),
            };
        }
        catch (Exception ex)
        {
            ServiceLog.Warning("WAG-RULE-900", $"Rule command {request.Command} failed.", ex);
            return Fail(request, ex.Message);
        }
    }

    private ServiceResponse AllowTargets(ServiceRequest request)
    {
        // 界面不再自己枚举防火墙规则：这里把两类信息一次读齐。
        var ours = RuleEngine.GetAllowRulePrograms();
        var targets = FirewallManager.GetOutboundAllowTargets();

        return new ServiceResponse
        {
            Id = request.Id,
            Ok = true,
            Programs = ours.ToList(),
            OtherPrograms = targets.OtherSoftwareAllowRulePrograms.ToList(),
            ProgramlessRuleCount = targets.ProgramlessAllowRuleCount,
        };
    }

    private ServiceResponse Strict(ServiceRequest request, bool enable)
    {
        var result = enable ? StrictModeHost.Enable() : StrictModeHost.Disable();

        return new ServiceResponse
        {
            Id = request.Id,
            Ok = result.Success,
            Error = result.Success ? null : result.Message,
            Message = result.Message,
            Status = ControlServer.BuildStatus(),
        };
    }

    private ServiceResponse StrictRefresh(ServiceRequest request)
    {
        StrictModeHost.RefreshIfEnabled();

        return new ServiceResponse
        {
            Id = request.Id,
            Ok = true,
            Status = ControlServer.BuildStatus(),
        };
    }

    private ServiceResponse StrictRecoverLegacy(ServiceRequest request)
    {
        var settingsPath = request.Value?.Trim() ?? string.Empty;

        if (settingsPath.Length == 0)
        {
            return Fail(request, "没有提供设置文件路径。");
        }

        var result = StrictModeHost.RecoverLegacy(settingsPath);

        return new ServiceResponse
        {
            Id = request.Id,
            Ok = true,
            Message = result.Message,
            Affected = result.WasLeftOn ? 1 : 0,
        };
    }

    private ServiceResponse AuditConfigure(ServiceRequest request)
    {
        var settings = AuditHost.Snapshot();

        if (request.AuditEnabled is { } enabled)
        {
            settings.Enabled = enabled;
        }

        if (request.AuditDomainLookup is { } lookup)
        {
            settings.DomainLookup = lookup;
        }

        if (request.AuditRetentionDays is { } days)
        {
            settings.RetentionDays = days;
        }

        var applied = AuditHost.Apply(settings);

        ServiceLog.Operation(
            "WAG-AUDIT-011",
            $"Audit settings updated (enabled={applied.Enabled}, retention={applied.RetentionDays} days, domainLookup={applied.DomainLookup}).");

        return new ServiceResponse
        {
            Id = request.Id,
            Ok = true,
            Message = "记录设置已更新。",
            Status = ControlServer.BuildStatus(),
        };
    }

    private ServiceResponse AuditClear(ServiceRequest request)
    {
        var deleted = AuditHost.Clear();

        return new ServiceResponse
        {
            Id = request.Id,
            Ok = true,
            Affected = deleted,
            Status = ControlServer.BuildStatus(),
        };
    }

    private void RecordPurged(IReadOnlyList<(string RuleName, string ProgramPath)> removed)
    {
        if (removed.Count == 0)
        {
            return;
        }

        _expiredPurged += removed.Count;
        _lastPurgedPrograms = removed
            .Select(item => item.ProgramPath)
            .Where(path => !string.IsNullOrWhiteSpace(path))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(20)
            .ToList();
    }

    /// <summary>
    /// 篡改防护（3.0-c）：拿权威副本（rules.json）和实际过滤器比对。
    ///
    /// 规则被外部删除（刮掉过滤器、重建子层、第三方工具清理等）时：
    ///   - 子层缺失 → 先重建子层；
    ///   - 快照里有、实际没有的规则 → 按快照重建（跳过已到期的）；
    ///   - 记录次数与时间，界面探测到后弹托盘提示。
    ///
    /// 服务自己的删除会先更新快照（在同一个锁里），不会误报。
    /// </summary>
    internal void CheckTamper()
    {
        lock (Gate)
        {
            try
            {
                var sublayerRecreated = false;

                try
                {
                    using var probe = WfpEngine.Open();
                    probe.ReadSublayer();
                }
                catch (Exception)
                {
                    using var probe = WfpEngine.Open();
                    probe.EnsureSublayer(persistent: true);
                    sublayerRecreated = true;
                    ServiceLog.Warning("WAG-RULE-910", "Tamper protection: sublayer was missing and has been recreated.");
                }

                var snapshot = RuleSnapshotFile.TryRead(ServicePaths.RulesSnapshotFile);

                if (snapshot is null || snapshot.Rules.Count == 0)
                {
                    return;
                }

                List<FirewallRuleItem> actual;

                try
                {
                    actual = RuleEngine.GetRules();
                }
                catch (Exception ex)
                {
                    ServiceLog.Warning("WAG-RULE-911", "Tamper protection: failed to read the actual rules.", ex);
                    return;
                }

                var names = new HashSet<string>(
                    actual.Select(rule => rule.Name), StringComparer.OrdinalIgnoreCase);

                var missing = snapshot.Rules
                    .Where(rule => !names.Contains(rule.Name))
                    .ToList();

                if (missing.Count == 0)
                {
                    if (sublayerRecreated)
                    {
                        _lastTamperUtc = DateTime.UtcNow;
                    }

                    return;
                }

                var rebuilt = 0;

                foreach (var item in missing)
                {
                    try
                    {
                        var expiry = RuleExpiry.Parse(item.Expiry);

                        if (expiry.IsExpired(
                                DateTime.UtcNow, SystemUptime.BootTimeUtc, freshLogonSession: false))
                        {
                            // 本来就该到期了：不重建，让正常清理逻辑处理。
                            continue;
                        }

                        string name;

                        if (string.Equals(item.Kind, "ip", StringComparison.OrdinalIgnoreCase))
                        {
                            name = RuleEngine.CreateIpBlockRule(item.Value);
                        }
                        else
                        {
                            var scope = RuleScope.TryParse(item.Scope, out var parsed)
                                ? parsed
                                : RuleScope.Any;

                            name = string.Equals(item.Action, "allow", StringComparison.OrdinalIgnoreCase)
                                ? RuleEngine.CreateAllowRule(item.Value, expiry, scope)
                                : RuleEngine.CreateBlockRule(item.Value, expiry, scope);
                        }

                        if (!string.IsNullOrWhiteSpace(item.Group))
                        {
                            _groups.SetGroup(name, item.Group);
                        }

                        rebuilt++;
                    }
                    catch (Exception ex)
                    {
                        ServiceLog.Warning("WAG-RULE-912", $"Tamper protection: failed to rebuild rule {item.Name}.", ex);
                    }
                }

                if (rebuilt > 0)
                {
                    _groups.Save();
                    _tamperRebuilt += rebuilt;
                    _lastTamperUtc = DateTime.UtcNow;

                    // 白名单可能被重建过：严格模式会话要跟着更新。
                    StrictModeHost.RefreshIfEnabled();

                    SaveSnapshotNow();
                    ServiceLog.Warning(
                        "WAG-RULE-913",
                        $"Tamper protection: {missing.Count} rules were deleted externally; {rebuilt} rebuilt.");
                }
            }
            catch (Exception ex)
            {
                ServiceLog.Warning("WAG-RULE-914", "Tamper protection check failed.", ex);
            }
        }
    }

    /// <summary>
    /// 到期清理（服务自己的定时器用）：失败只记日志，不打扰任何客户端。
    /// 与 IPC 命令共用同一把锁，避免和规则写入交叉。
    /// </summary>
    internal void PurgeExpiredQuietly()
    {
        lock (Gate)
        {
            try
            {
                var removed = RuleEngine.PurgeExpiredRules(
                    DateTime.UtcNow, SystemUptime.BootTimeUtc, freshLogonSession: false);

                if (removed.Count == 0)
                {
                    return;
                }

                _groups.Prune(RuleEngine.GetRules().Select(rule => rule.Name));
                _groups.Save();
                SaveSnapshotNow();
                RecordPurged(removed);

                ServiceLog.Operation("WAG-RULE-920", $"Rules: expired rules purged by the service timer: {removed.Count}.");
            }
            catch (Exception ex)
            {
                ServiceLog.Warning("WAG-RULE-921", "Failed to purge expired rules on the service timer.", ex);
            }
        }
    }

    private ServiceResponse List(ServiceRequest request)
    {
        var list = BuildRuleDtos();

        return new ServiceResponse { Id = request.Id, Ok = true, Rules = list };
    }

    /// <summary>把当前规则 + 分组映射成 IPC 用的 DTO（列表与快照共用）。</summary>
    private List<RuleDto> BuildRuleDtos()
    {
        var rules = RuleEngine.GetRules();

        return rules.Select(rule => new RuleDto
        {
            Name = rule.Name,
            Kind = string.IsNullOrEmpty(rule.IpAddress) ? "program" : "ip",
            Value = string.IsNullOrEmpty(rule.IpAddress) ? rule.ApplicationPath : rule.IpAddress,
            Action = rule.Action == FirewallAction.Block ? "block" : "allow",
            Expiry = rule.Expiry.Encode(),
            Scope = rule.Scope.Encode(),
            Group = _groups.GetGroup(rule.Name),
            Enabled = rule.Enabled,
        }).ToList();
    }

    /// <summary>
    /// 更新权威副本（%ProgramData%\WinAppGuard\rules.json）。
    /// 写失败只记日志：它是"离线时给用户看"的辅助数据，不能反过来让规则操作失败。
    /// </summary>
    internal void SaveSnapshotNow()
    {
        lock (Gate)
        {
            try
            {
                RuleSnapshotFile.Write(
                    ServicePaths.RulesSnapshotFile,
                    new RuleSnapshot { Rules = BuildRuleDtos() });
            }
            catch (Exception ex)
            {
                ServiceLog.Warning("WAG-RULE-922", "Failed to write the rule snapshot.", ex);
            }
        }
    }

    private ServiceResponse FilterMap(ServiceRequest request)
    {
        var map = RuleEngine.GetFilterIdToRuleName()
            .ToDictionary(pair => pair.Key.ToString(), pair => pair.Value);

        return new ServiceResponse { Id = request.Id, Ok = true, FilterMap = map };
    }

    private ServiceResponse AddProgram(ServiceRequest request)
    {
        var path = request.Value?.Trim() ?? string.Empty;

        if (path.Length == 0)
        {
            return Fail(request, "没有提供程序路径。");
        }

        var action = ParseAction(request.Action, out var actionError);

        if (action is null)
        {
            return Fail(request, actionError);
        }

        var expiry = RuleExpiry.Parse(request.Expiry);

        if (!RuleScope.TryParse(request.Scope, out var scope))
        {
            return Fail(request, "作用范围格式不对。");
        }

        var name = action.Value == FirewallAction.Block
            ? RuleEngine.CreateBlockRule(path, expiry, scope)
            : RuleEngine.CreateAllowRule(path, expiry, scope);

        ApplyGroup(name, request.Group);

        // 严格模式开着时，白名单变化必须重建会话，否则新加的程序仍然上不了网。
        if (action.Value == FirewallAction.Allow)
        {
            StrictModeHost.RefreshIfEnabled();
        }

        SaveSnapshotNow();
        ServiceLog.Operation("WAG-RULE-001", $"Rule {(action.Value == FirewallAction.Block ? "block" : "allow")}: {path} ({name}).");

        return new ServiceResponse { Id = request.Id, Ok = true, Affected = 1 };
    }

    private ServiceResponse AddIp(ServiceRequest request)
    {
        var address = request.Value?.Trim() ?? string.Empty;

        if (address.Length == 0)
        {
            return Fail(request, "没有提供 IP。");
        }

        var name = RuleEngine.CreateIpBlockRule(address);
        ApplyGroup(name, request.Group);

        SaveSnapshotNow();
        ServiceLog.Operation("WAG-RULE-002", $"Rule block IP: {address} ({name}).");

        return new ServiceResponse { Id = request.Id, Ok = true, Affected = 1 };
    }

    private ServiceResponse Delete(ServiceRequest request)
    {
        var name = request.RuleName?.Trim() ?? string.Empty;

        if (name.Length == 0)
        {
            return Fail(request, "没有提供规则名。");
        }

        if (!RuleEngine.DeleteRule(name))
        {
            return Fail(request, $"没有找到规则：{name}");
        }

        _groups.SetGroup(name, string.Empty);
        _groups.Save();

        StrictModeHost.RefreshIfEnabled();
        SaveSnapshotNow();

        ServiceLog.Operation("WAG-RULE-003", $"Rule deleted: {name}.");

        return new ServiceResponse { Id = request.Id, Ok = true, Affected = 1 };
    }

    private ServiceResponse DeleteForProgram(ServiceRequest request)
    {
        var path = request.Value?.Trim() ?? string.Empty;

        if (path.Length == 0)
        {
            return Fail(request, "没有提供程序路径。");
        }

        var deleted = RuleEngine.DeleteRulesForProgram(path);

        if (deleted == 0)
        {
            return Fail(request, "该程序当前没有被本工具阻止。");
        }

        _groups.Prune(RuleEngine.GetRules().Select(rule => rule.Name));
        _groups.Save();
        SaveSnapshotNow();

        ServiceLog.Operation("WAG-RULE-004", $"Rule unblock: {path} ({deleted} rules deleted).");

        return new ServiceResponse { Id = request.Id, Ok = true, Affected = deleted };
    }

    private ServiceResponse Clear(ServiceRequest request, FirewallAction action)
    {
        var deleted = RuleEngine.DeleteRulesByAction(action);

        // 删掉对应规则的孤儿分组记录。
        _groups.Prune(RuleEngine.GetRules().Select(rule => rule.Name));
        _groups.Save();

        if (action == FirewallAction.Allow)
        {
            StrictModeHost.RefreshIfEnabled();
        }

        SaveSnapshotNow();
        ServiceLog.Operation("WAG-RULE-005", $"Rules cleared ({(action == FirewallAction.Block ? "blocklist" : "allowlist")}): {deleted}.");

        return new ServiceResponse { Id = request.Id, Ok = true, Affected = deleted };
    }

    /// <summary>CLI --unblock-all：删除本工具创建的全部规则（阻止 + 允许 + IP）。</summary>
    private ServiceResponse ClearAll(ServiceRequest request)
    {
        var deleted = RuleEngine.DeleteAllRules();

        _groups.Prune(RuleEngine.GetRules().Select(rule => rule.Name));
        _groups.Save();

        // 白名单可能被一起删掉；严格模式会话要重建。
        StrictModeHost.RefreshIfEnabled();

        SaveSnapshotNow();
        ServiceLog.Operation("WAG-RULE-006", $"Rules cleared by CLI: {deleted}.");

        return new ServiceResponse { Id = request.Id, Ok = true, Affected = deleted };
    }

    private ServiceResponse SetGroup(ServiceRequest request)
    {
        var name = request.RuleName?.Trim() ?? string.Empty;

        if (name.Length == 0)
        {
            return Fail(request, "没有提供规则名。");
        }

        _groups.SetGroup(name, request.Group);
        _groups.Save();
        SaveSnapshotNow();

        ServiceLog.Operation("WAG-RULE-007", $"Rule group: {name} -> {(string.IsNullOrWhiteSpace(request.Group) ? "(none)" : request.Group)}.");

        return new ServiceResponse { Id = request.Id, Ok = true };
    }

    private ServiceResponse PurgeExpired(ServiceRequest request)
    {
        var removed = RuleEngine.PurgeExpiredRules(
            DateTime.UtcNow, SystemUptime.BootTimeUtc, request.FreshLogonSession);

        if (removed.Count > 0)
        {
            _groups.Prune(RuleEngine.GetRules().Select(rule => rule.Name));
            _groups.Save();
            SaveSnapshotNow();
            RecordPurged(removed);

            ServiceLog.Operation("WAG-RULE-008", $"Expired temporary rules purged: {removed.Count}.");
        }

        return new ServiceResponse
        {
            Id = request.Id,
            Ok = true,
            Affected = removed.Count,
            Rules = removed
                .Select(item => new RuleDto { Name = item.RuleName, Value = item.ProgramPath })
                .ToList(),
        };
    }

    private ServiceResponse Import(ServiceRequest request)
    {
        var expected = ParseAction(request.Action, out var actionError);

        if (expected is null)
        {
            return Fail(request, actionError);
        }

        if (!RuleExport.TryParse(request.Json, out var document, out var parseError) || document is null)
        {
            return Fail(request, parseError);
        }

        if (!RuleExport.TryMatchScope(document, expected.Value, out var scopeError))
        {
            return Fail(request, scopeError);
        }

        var existing = new HashSet<string>(
            RuleEngine.GetRules().Select(rule => rule.Name), StringComparer.OrdinalIgnoreCase);

        var created = 0;
        var skipped = 0;
        var failed = 0;

        foreach (var entry in document.Rules)
        {
            try
            {
                string ruleName;

                if (entry.Kind == "ip")
                {
                    ruleName = new WinAppGuard.Core.Wfp.WfpIpRule(entry.Value).DisplayName;

                    if (!existing.Add(ruleName))
                    {
                        skipped++;
                        continue;
                    }

                    RuleEngine.CreateIpBlockRule(entry.Value);
                }
                else
                {
                    if (ProtectedProcesses.IsProtected(entry.Value, out _))
                    {
                        skipped++;
                        continue;
                    }

                    RuleScope.TryParse(entry.Scope, out var scope);
                    var expiry = RuleExpiry.Parse(entry.Expiry);

                    ruleName = expected.Value == FirewallAction.Block
                        ? RuleNaming.BuildBlockRuleName(entry.Value)
                        : RuleNaming.BuildAllowRuleName(entry.Value);

                    if (!existing.Add(ruleName))
                    {
                        skipped++;
                        continue;
                    }

                    if (expected.Value == FirewallAction.Block)
                    {
                        RuleEngine.CreateBlockRule(entry.Value, expiry, scope);
                    }
                    else
                    {
                        RuleEngine.CreateAllowRule(entry.Value, expiry, scope);
                    }
                }

                if (entry.Group.Length > 0)
                {
                    _groups.SetGroup(ruleName, entry.Group);
                }

                created++;
            }
            catch (Exception ex)
            {
                failed++;
                ServiceLog.Warning("WAG-RULE-030", $"Import of one entry failed: {entry.Value}.", ex);
            }
        }

        _groups.Save();

        if (expected.Value == FirewallAction.Allow)
        {
            StrictModeHost.RefreshIfEnabled();
        }

        SaveSnapshotNow();
        ServiceLog.Operation("WAG-RULE-031", $"Rules imported: created {created}, skipped {skipped}, failed {failed}.");

        return new ServiceResponse
        {
            Id = request.Id,
            Ok = true,
            Affected = created,
            Error = failed > 0 ? $"有 {failed} 条失败（详见服务日志）。" : null,
        };
    }

    private ServiceResponse ImportGroups(ServiceRequest request)
    {
        var imported = _groups.ImportJson(request.Json);
        _groups.Save();
        SaveSnapshotNow();

        ServiceLog.Operation("WAG-RULE-032", $"Legacy rule groups imported: {imported}.");

        return new ServiceResponse { Id = request.Id, Ok = true, Affected = imported };
    }

    private void ApplyGroup(string ruleName, string? group)
    {
        if (!string.IsNullOrWhiteSpace(group))
        {
            _groups.SetGroup(ruleName, group);
            _groups.Save();
        }
    }

    private static FirewallAction? ParseAction(string? action, out string error)
    {
        error = string.Empty;

        if (string.Equals(action, "block", StringComparison.OrdinalIgnoreCase))
        {
            return FirewallAction.Block;
        }

        if (string.Equals(action, "allow", StringComparison.OrdinalIgnoreCase))
        {
            return FirewallAction.Allow;
        }

        error = "动作必须是 block 或 allow。";
        return null;
    }

    private static ServiceResponse Fail(ServiceRequest request, string error)
        => new() { Id = request.Id, Ok = false, Error = error };
}
