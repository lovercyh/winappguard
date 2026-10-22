using System.Text.Json;
using WinAppGuard.Contracts;
using WinAppGuard.Core;
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
            ServiceLog.Warning($"规则命令 {request.Command} 失败：{ex.Message}");
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

        ServiceLog.Info(
            $"记录：设置已更新（{(applied.Enabled ? "开" : "关")}，" +
            $"保留 {applied.RetentionDays} 天，域名推测{(applied.DomainLookup ? "开" : "关")}）");

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

                ServiceLog.Info($"规则：服务定时清理到期规则 {removed.Count} 条");
            }
            catch (Exception ex)
            {
                ServiceLog.Warning($"服务定时清理到期规则失败：{ex.Message}");
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
                ServiceLog.Warning($"写入规则快照失败：{ex.Message}");
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
        ServiceLog.Info($"规则：{(action.Value == FirewallAction.Block ? "阻止" : "允许")} {path}（{name}）");

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
        ServiceLog.Info($"规则：封禁 IP {address}（{name}）");

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

        ServiceLog.Info($"规则：删除 {name}");

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

        ServiceLog.Info($"规则：解除阻止 {path}（删除 {deleted} 条）");

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
        ServiceLog.Info($"规则：清空{(action == FirewallAction.Block ? "黑名单" : "白名单")} {deleted} 条");

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

        ServiceLog.Info($"规则：分组 {name} → {(string.IsNullOrWhiteSpace(request.Group) ? "未分组" : request.Group)}");

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

            ServiceLog.Info($"规则：清理到期临时规则 {removed.Count} 条");
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
                ServiceLog.Warning($"导入单条失败：{entry.Value} — {ex.Message}");
            }
        }

        _groups.Save();

        if (expected.Value == FirewallAction.Allow)
        {
            StrictModeHost.RefreshIfEnabled();
        }

        SaveSnapshotNow();
        ServiceLog.Info($"规则：导入 {created} 条（跳过 {skipped}，失败 {failed}）");

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

        ServiceLog.Info($"规则：导入旧分组记录 {imported} 条");

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
