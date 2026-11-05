using System.Text;
using WinAppGuard.Contracts;
using WinAppGuard.Core.Audit;
using WinAppGuard.Core.Diagnostics.AntiScan;
using WinAppGuard.Core.Diagnostics.NetworkDetection;
using WinAppGuard.Core.Diagnostics.Traffic;
using WinAppGuard.Core.ProtectedMode;
using WinAppGuard.Core.Wfp;
using WinAppGuard.Localization;
using WinAppGuard.Models;

namespace WinAppGuard.Core;

/// <summary>
/// 命令行模式（无人值守）的实现。
///
/// ==================== 为什么这里不弹确认框 ====================
/// 项目的硬性约定是「所有会改系统状态的操作必须弹确认框」，而命令行模式的全部意义
/// 就是**无人值守** —— 弹一个框就把自动化废了。
///
/// 所以这里的约定是：「**命令行参数本身就是明确指令**」，和 netsh / iptables
/// 那类工具的习惯一致。补偿措施有三道：
///   1. 写命令要求管理员权限（未提权时直接返回 3，不静默）；
///   2. 批量 / 不可逆操作额外要求 <c>--yes</c>，并支持 <c>--dry-run</c>；
///   3. 每条命令都逐条打印它做了什么，并给出明确的退出码。
///
/// **图形界面里的操作一条都没放宽** —— 那边照旧每条都要确认。
/// ==========================================================
/// </summary>
internal static class CliRunner
{
    internal const int ExitOk = 0;
    internal const int ExitUsage = 1;
    internal const int ExitFailed = 2;
    internal const int ExitNotAdmin = 3;
    internal const int ExitNotFound = 4;

    /// <summary>当前程序版本（不带 +commit）。</summary>
    internal static string VersionText => BuildVersionText();

    /// <summary>执行一条命令行指令，返回进程退出码。</summary>
    internal static int Run(CommandLineOptions options)
    {
        switch (options.Kind)
        {
            case CommandKind.Help:
                Console.Write(CliText.Usage);
                return ExitOk;

            case CommandKind.Invalid:
                return Fail(options, "BAD_ARGUMENT",
                    Localizer.IsEnglish
                        ? $"Bad argument: {options.Error}"
                        : $"参数错误：{options.Error}",
                    ExitUsage, showUsage: true);

            case CommandKind.Version:
                return RunVersion(options);

            case CommandKind.LogPath:
                return RunLogPath(options);

            case CommandKind.AuditTail:
                return RunAuditTail(options);
        }

        var needsElevation = options.Kind is CommandKind.Block
            or CommandKind.Unblock
            or CommandKind.UnblockAll
            or CommandKind.Migrate
            or CommandKind.Recover
            or CommandKind.ImportRules
            or CommandKind.NetworkBlock
            or CommandKind.NetworkUnblock
            or CommandKind.NetworkUnblockAll
            or CommandKind.NetworkSetAdapter
            or CommandKind.NetworkSetCategories;

        // 预览不写系统，不应因为没提权就直接拒绝。
        if (options.DryRun
            && options.Kind is (CommandKind.Block or CommandKind.Unblock or CommandKind.ImportRules))
        {
            needsElevation = false;
        }

        // 批量阻止未带 --yes 时只做预览，也不写系统。
        if (options.Kind == CommandKind.Block
            && !options.Confirmed
            && options.ProgramPath?.StartsWith('@') == true)
        {
            needsElevation = false;
        }

        if (needsElevation && !AdminHelper.IsRunningAsAdmin())
        {
            return Fail(options, "NOT_ELEVATED",
                Localizer.IsEnglish
                    ? "Administrator rights required: run this from an elevated terminal."
                    : "需要管理员权限：请从「以管理员身份运行」的终端里执行本命令。",
                ExitNotAdmin);
        }

        if (options.Kind is not (CommandKind.Migrate or CommandKind.Recover)
            && !ProtectedModeClient.TryConfigureSigner(out _, out var authError))
        {
            return Fail(options, "OWNER_KEY_UNAVAILABLE",
                Localizer.IsEnglish
                    ? $"This account is not the owner, or the key is unavailable: {authError}"
                    : $"当前账户不是所有者，或密钥不可用：{authError}",
                ExitFailed);
        }

        try
        {
            return options.Kind switch
            {
                CommandKind.Block => RunBlock(options),
                CommandKind.ListBlocked => RunListBlocked(options),
                CommandKind.UnblockAll => RunUnblockAll(options),
                CommandKind.Migrate => RunMigrate(options),
                CommandKind.Recover => RunRecover(options),
                CommandKind.Status => RunStatus(options),
                CommandKind.ServiceStatus => RunStatus(options),
                CommandKind.ListRules => RunListRules(options),
                CommandKind.Unblock => RunUnblock(options),
                CommandKind.ExportRules => RunExportRules(options),
                CommandKind.ImportRules => RunImportRules(options),
                CommandKind.NetworkStatus => RunNetworkStatus(options),
                CommandKind.NetworkAlerts => RunNetworkAlerts(options),
                CommandKind.NetworkAck => RunNetworkAck(options),
                CommandKind.NetworkClear => RunNetworkClear(options),
                CommandKind.NetworkBlock => RunNetworkBlock(options),
                CommandKind.NetworkUnblock => RunNetworkUnblock(options),
                CommandKind.NetworkUnblockAll => RunNetworkUnblockAll(options),
                CommandKind.NetworkSetAdapter => RunNetworkSetAdapter(options),
                CommandKind.NetworkSetCategories => RunNetworkSetCategories(options),
                CommandKind.Doctor => RunDoctor(options),
                _ => ExitOk,
            };
        }
        catch (Exception ex)
        {
            // 命令行模式绝不能把异常抛给 Windows 的崩溃框 —— 无人值守时会卡住。
            return Fail(options, "EXECUTION_FAILED",
                Localizer.IsEnglish
                    ? $"Execution failed: {ex.Message}"
                    : $"执行失败：{ex.Message}",
                ExitFailed);
        }
    }

    // ==================================================================
    // 只读命令
    // ==================================================================

    private static int RunVersion(CommandLineOptions options)
    {
        var data = new
        {
            version = VersionText,
            protocolVersion = ServiceProtocol.Version,
        };

        if (IsJson(options))
        {
            CliJson.WriteSuccess(data, VersionText);
        }
        else
        {
            Console.WriteLine($"WinAppGuard {VersionText}");
        }

        return ExitOk;
    }

    private static int RunLogPath(CommandLineOptions options)
    {
        var serviceLog = Path.Combine(ServicePaths.DataDirectory, "logs");
        var data = new
        {
            localLog = LocalLog.LogDirectory,
            serviceLog,
        };

        if (IsJson(options))
        {
            CliJson.WriteSuccess(data, VersionText);
        }
        else
        {
            Console.WriteLine($"# {T("本地日志", "Local log")}\t{LocalLog.LogDirectory}");
            Console.WriteLine($"# {T("服务日志", "Service log")}\t{serviceLog}");
        }

        return ExitOk;
    }

    private static int RunStatus(CommandLineOptions options)
    {
        var status = ServiceClient.TryGetStatus(TimeSpan.FromSeconds(5));

        if (status is null)
        {
            return Fail(options, "SERVICE_UNAVAILABLE",
                Localizer.IsEnglish
                    ? "The guard service is not responding."
                    : "防护服务没有响应。",
                ExitFailed);
        }

        var network = QueryNetwork(out var networkError);
        var ids = QueryIds(out var idsError);

        if (IsJson(options))
        {
            CliJson.WriteSuccess(new
            {
                service = BuildStatusSummary(status),
                network = network?.Status,
                networkError,
                ids = ids?.IdsStatus,
                idsError,
            }, VersionText);

            return ExitOk;
        }

        if (!options.Quiet)
        {
            Console.WriteLine($"# WinAppGuard {VersionText} · {T("协议", "protocol")} {status.ProtocolVersion}");
            Console.WriteLine($"{T("服务版本", "Service version")}\t{status.ServiceVersion}");
            Console.WriteLine($"{T("WFP 子层", "WFP sublayer")}\t{(status.SublayerPresent ? T("存在", "present") : T("缺失", "missing"))}");
            Console.WriteLine($"{T("规则", "Rules")}\t{T("阻止", "block")} {status.BlockRuleCount} · {T("允许", "allow")} {status.AllowRuleCount} · IP {status.IpRuleCount}");
            Console.WriteLine($"{T("严格模式", "Strict mode")}\t{(status.StrictModeActive ? T("开启", "on") : T("关闭", "off"))}");
            Console.WriteLine($"{T("临时锁网", "Timed lockdown")}\t{(status.StrictModeLockdownActive ? $"{status.StrictModeLockdownRemainingSeconds} {T("秒", "s")}" : T("无", "none"))}");
            Console.WriteLine($"{T("审计", "Audit")}\t{(status.AuditCollecting ? T("采集中", "collecting") : T("关闭", "off"))}");
            Console.WriteLine($"{T("流量", "Traffic")}\t{(status.TrafficCollecting ? T("采集中", "collecting") : T("关闭", "off"))} · {T("事件", "events")} {status.TrafficEventsSeen}");
            Console.WriteLine($"{T("IDS", "IDS")}\t{(status.IdsEnabled ? T("开启", "on") : T("关闭", "off"))} · {T("未读", "unread")} {status.IdsAlertsNew} · flow {status.IdsFlowCount}");
            Console.WriteLine($"{T("网络检测", "Network detection")}\t{(network?.Status is { Running: true } ? T("运行中", "running") : T("未运行", "not running"))}" +
                              (network?.Status?.CaptureDeviceName is { Length: > 0 } name
                                  ? $" · {T("监听", "capturing on")} {name}"
                                  : string.Empty));
            Console.WriteLine($"{T("告警", "Alerts")}\t{network?.Alerts.Count ?? 0} · {T("活动拦截", "active blocks")} {network?.Blocks.Count ?? 0}");
            Console.WriteLine($"{T("Npcap", "Npcap")}\t{(NpcapLocator.IsAvailable ? T("可用", "available") : T("不可用", "unavailable"))}");
            Console.WriteLine($"{T("所有者", "Owner")}\t{status.ProtectedModeOwner ?? T("未知", "unknown")}");
            Console.WriteLine($"{T("服务日志", "Service log")}\t{Path.Combine(ServicePaths.DataDirectory, "logs")}");
        }

        return ExitOk;
    }

    private static int RunListBlocked(CommandLineOptions options)
    {
        var all = QueryRules(out var error);

        if (all is null)
        {
            return Fail(options, "RULES_UNAVAILABLE",
                Localizer.IsEnglish
                    ? $"Failed to read rules: {error}"
                    : $"读取规则失败：{error}",
                ExitFailed);
        }

        var blocked = all
            .Where(rule => string.Equals(rule.Action, "block", StringComparison.OrdinalIgnoreCase))
            .ToList();
        var allowCount = all.Count - blocked.Count;

        if (IsJson(options))
        {
            CliJson.WriteSuccess(new
            {
                blocked = blocked.Count,
                allow = allowCount,
                rules = blocked,
            }, VersionText);

            return ExitOk;
        }

        if (!options.Quiet)
        {
            Console.Write(CliText.BuildListBlockedOutput(blocked, allowCount, VersionText));
        }

        return ExitOk;
    }

    private static int RunListRules(CommandLineOptions options)
    {
        var all = QueryRules(out var error);

        if (all is null)
        {
            return Fail(options, "RULES_UNAVAILABLE",
                Localizer.IsEnglish
                    ? $"Failed to read rules: {error}"
                    : $"读取规则失败：{error}",
                ExitFailed);
        }

        var action = options.Action ?? "all";
        var rules = action == "all"
            ? all
            : all.Where(rule => string.Equals(
                    rule.Action, action, StringComparison.OrdinalIgnoreCase))
                .ToList();

        if (options.LimitSpecified)
        {
            rules = rules.Take(options.Limit).ToList();
        }

        if (IsJson(options))
        {
            CliJson.WriteSuccess(new
            {
                action,
                count = rules.Count,
                rules,
            }, VersionText);

            return ExitOk;
        }

        if (!options.Quiet)
        {
            Console.WriteLine($"# WinAppGuard {VersionText} — {T("规则", "rules")}：{rules.Count} {T("条", "entry/entries")}（{action}）");
            Console.WriteLine(T(
                "# 规则名\t程序路径 / IP\t动作\t自动解除\t分组\t范围",
                "# name\tprogram / IP\taction\texpiry\tgroup\tscope"));

            foreach (var rule in rules)
            {
                Console.WriteLine(
                    $"{rule.Name}\t{rule.Value}\t{rule.Action}\t{DescribeExpiry(rule.Expiry)}\t{rule.Group}\t{rule.Scope}");
            }
        }

        return ExitOk;
    }

    // ==================================================================
    // 写命令
    // ==================================================================

    private static int RunBlock(CommandLineOptions options)
    {
        var expiry = options.Minutes is { } minutes
            ? RuleExpiry.At(DateTime.UtcNow.AddMinutes(minutes)).Encode()
            : options.UntilReboot
                ? RuleExpiry.OnNextBoot(SystemUptime.BootTimeUtc).Encode()
                : null;

        if (options.ProgramPath!.StartsWith('@'))
        {
            return RunBlockBatch(options, options.ProgramPath[1..], expiry);
        }

        // 路径校验仍在客户端做一次（服务端会再做一次，安全闸没有放宽）。
        var fullPath = FirewallManager.ValidateProgramPath(options.ProgramPath!, forBlocking: true);

        if (options.DryRun)
        {
            if (IsJson(options))
            {
                CliJson.WriteSuccess(new
                {
                    changed = false,
                    dryRun = true,
                    path = fullPath,
                    expiry,
                }, VersionText);
            }
            else if (!options.Quiet)
            {
                Console.WriteLine($"# 预览：将阻止 {fullPath}" +
                                  (string.IsNullOrEmpty(expiry) ? "（永久）" : $"（{DescribeExpiry(expiry)}）"));
            }

            return ExitOk;
        }

        var before = QueryRules(out var queryError);

        if (before is null)
        {
            return Fail(options, "RULES_UNAVAILABLE",
                Localizer.IsEnglish
                    ? $"Failed to read rules: {queryError}"
                    : $"读取规则失败：{queryError}",
                ExitFailed);
        }

        var alreadyBlocked = before.Any(rule =>
            string.Equals(rule.Action, "block", StringComparison.OrdinalIgnoreCase)
            && string.Equals(rule.Value, fullPath, StringComparison.OrdinalIgnoreCase));

        var response = ServiceClient.TryRequest(
            new ServiceRequest
            {
                Command = ServiceProtocol.Commands.AddProgramRule,
                Value = fullPath,
                Action = "block",
                Expiry = expiry,
            },
            TimeSpan.FromSeconds(15),
            out var error);

        if (response is not { Ok: true })
        {
            return Fail(options, "BLOCK_FAILED",
                Localizer.IsEnglish
                    ? $"Block failed: {response?.Error ?? error}"
                    : $"阻止失败：{response?.Error ?? error}",
                ExitFailed);
        }

        var after = QueryRules(out _);
        var ruleName = after?
            .FirstOrDefault(rule =>
                string.Equals(rule.Action, "block", StringComparison.OrdinalIgnoreCase)
                && string.Equals(rule.Value, fullPath, StringComparison.OrdinalIgnoreCase))?
            .Name ?? "(服务未返回规则名)";

        if (IsJson(options))
        {
            CliJson.WriteSuccess(new
            {
                changed = !alreadyBlocked,
                path = fullPath,
                ruleName,
                expiry,
            }, VersionText);
        }
        else if (!options.Quiet)
        {
            Console.WriteLine(alreadyBlocked
                ? $"该程序已经在阻止列表中：{fullPath}"
                : $"已阻止：{fullPath}");

            Console.WriteLine(Localizer.IsEnglish
                ? $"  Rule name: {ruleName}"
                : $"  规则名：{ruleName}");

            if (!string.IsNullOrEmpty(expiry))
            {
                Console.WriteLine(Localizer.IsEnglish
                    ? $"  Expiry: {DescribeExpiry(expiry)}"
                    : $"  自动解除：{DescribeExpiry(expiry)}");
            }
        }

        LocalLog.Operation($"命令行：阻止联网 {fullPath}（规则 {ruleName}）");
        return ExitOk;
    }

    private static int RunBlockBatch(
        CommandLineOptions options, string listPath, string? expiry)
    {
        string[] lines;

        try
        {
            lines = File.ReadAllLines(Path.GetFullPath(listPath), Encoding.UTF8);
        }
        catch (Exception ex)
        {
            return Fail(options, "BATCH_READ_FAILED",
                Localizer.IsEnglish
                    ? $"Cannot read the list: {ex.Message}"
                    : $"读取列表失败：{ex.Message}",
                ExitFailed);
        }

        var paths = lines
            .Select(line => line.Trim())
            .Where(line => line.Length > 0 && !line.StartsWith('#'))
            .ToList();

        if (paths.Count == 0)
        {
            return Fail(options, "BATCH_EMPTY",
                Localizer.IsEnglish
                    ? "The list contains no program paths."
                    : "列表里没有程序路径。",
                ExitUsage);
        }

        var valid = new List<string>();
        var invalid = new List<string>();

        foreach (var path in paths)
        {
            try
            {
                valid.Add(FirewallManager.ValidateProgramPath(path, forBlocking: true));
            }
            catch (Exception ex)
            {
                invalid.Add($"{path}: {ex.Message}");
            }
        }

        if (options.DryRun)
        {
            if (IsJson(options))
            {
                CliJson.WriteSuccess(new
                {
                    dryRun = true,
                    valid,
                    invalid,
                    expiry,
                }, VersionText);
            }
            else if (!options.Quiet)
            {
                Console.WriteLine($"# 预览：将阻止 {valid.Count} 个程序" +
                                  (string.IsNullOrEmpty(expiry) ? "（永久）" : $"（{DescribeExpiry(expiry)}）"));

                foreach (var path in valid)
                {
                    Console.WriteLine($"  {path}");
                }

                foreach (var error in invalid)
                {
                    Console.WriteLine($"  ! {error}");
                }
            }

            return invalid.Count == 0 ? ExitOk : ExitFailed;
        }

        if (!options.Confirmed)
        {
            if (IsJson(options))
            {
                CliJson.WriteError(
                    "CONFIRMATION_REQUIRED",
                    Localizer.IsEnglish
                        ? "Add --yes to block all programs in the list."
                        : "确认批量阻止请加 --yes。");
            }
            else
            {
                Console.WriteLine($"# 将阻止 {valid.Count} 个程序" +
                                  (string.IsNullOrEmpty(expiry) ? "（永久）" : $"（{DescribeExpiry(expiry)}）"));

                foreach (var path in valid)
                {
                    Console.WriteLine($"  {path}");
                }

                foreach (var error in invalid)
                {
                    Console.WriteLine($"  ! {error}");
                }

                Console.WriteLine(Localizer.IsEnglish
                    ? "Nothing was changed. Add --yes to confirm:"
                    : "没有改动任何东西。确认要批量阻止就再加一个 --yes：");
                Console.WriteLine(
                    $"  WinAppGuard.exe --block \"@{listPath}\" --yes");
            }

            return ExitUsage;
        }

        var created = 0;
        var failures = new List<string>(invalid);

        foreach (var path in valid)
        {
            var response = ServiceClient.TryRequest(
                new ServiceRequest
                {
                    Command = ServiceProtocol.Commands.AddProgramRule,
                    Value = path,
                    Action = "block",
                    Expiry = expiry,
                },
                TimeSpan.FromSeconds(15),
                out var error);

            if (response is { Ok: true })
            {
                created++;
            }
            else
            {
                failures.Add($"{path}: {response?.Error ?? error}");
            }
        }

        if (IsJson(options))
        {
            CliJson.WriteSuccess(new
            {
                changed = created > 0,
                created,
                failed = failures.Count,
                failures,
                expiry,
            }, VersionText);
        }
        else if (!options.Quiet)
        {
            Console.WriteLine(Localizer.IsEnglish
                ? $"Blocked {created} program(s)."
                : $"已阻止 {created} 个程序。");

            foreach (var failure in failures)
            {
                Console.Error.WriteLine($"  ! {failure}");
            }
        }

        LocalLog.Operation($"命令行：批量阻止 {created} 个程序（失败 {failures.Count}）");
        return failures.Count == 0 ? ExitOk : ExitFailed;
    }

    private static int RunUnblock(CommandLineOptions options)
    {
        var all = QueryRules(out var error);

        if (all is null)
        {
            return Fail(options, "RULES_UNAVAILABLE",
                Localizer.IsEnglish
                    ? $"Failed to read rules: {error}"
                    : $"读取规则失败：{error}",
                ExitFailed);
        }

        List<RuleDto> matched;

        if (!string.IsNullOrWhiteSpace(options.RuleName))
        {
            matched = all.Where(rule =>
                    string.Equals(rule.Name, options.RuleName, StringComparison.OrdinalIgnoreCase)
                    && string.Equals(rule.Action, "block", StringComparison.OrdinalIgnoreCase))
                .ToList();
        }
        else
        {
            var path = TryResolvePath(options.ProgramPath!);

            matched = all.Where(rule =>
                    string.Equals(rule.Action, "block", StringComparison.OrdinalIgnoreCase)
                    && (string.Equals(rule.Value, path, StringComparison.OrdinalIgnoreCase)
                        || string.Equals(rule.Value, options.ProgramPath, StringComparison.OrdinalIgnoreCase)))
                .ToList();
        }

        if (matched.Count == 0)
        {
            if (options.RequireMatch)
            {
                return Fail(options, "NOT_FOUND",
                    Localizer.IsEnglish
                        ? "No matching block rule was found."
                        : "没有找到匹配的阻止规则。",
                    ExitNotFound);
            }

            if (IsJson(options))
            {
                CliJson.WriteSuccess(new { changed = false, deleted = 0 }, VersionText);
            }
            else if (!options.Quiet)
            {
                Console.WriteLine(Localizer.IsEnglish
                    ? "No matching block rule was found; nothing changed."
                    : "没有找到匹配的阻止规则；没有改动任何东西。");
            }

            return ExitOk;
        }

        if (options.DryRun)
        {
            if (IsJson(options))
            {
                CliJson.WriteSuccess(new
                {
                    changed = false,
                    dryRun = true,
                    wouldDelete = matched,
                }, VersionText);
            }
            else if (!options.Quiet)
            {
                Console.WriteLine($"# 预览：将删除 {matched.Count} 条阻止规则");
                foreach (var rule in matched)
                {
                    Console.WriteLine(CliText.FormatRuleLine(rule));
                }
            }

            return ExitOk;
        }

        var deleted = 0;
        var failures = new List<string>();

        foreach (var rule in matched)
        {
            var response = ServiceClient.TryRequest(
                new ServiceRequest
                {
                    Command = ServiceProtocol.Commands.DeleteRule,
                    RuleName = rule.Name,
                },
                TimeSpan.FromSeconds(15),
                out var deleteError);

            if (response is { Ok: true })
            {
                deleted++;
            }
            else
            {
                failures.Add($"{rule.Name}: {response?.Error ?? deleteError}");
            }
        }

        if (IsJson(options))
        {
            CliJson.WriteSuccess(new
            {
                changed = deleted > 0,
                deleted,
                failed = failures.Count,
                failures,
            }, VersionText);
        }
        else if (!options.Quiet)
        {
            Console.WriteLine(Localizer.IsEnglish
                ? $"Deleted {deleted} block rule(s)."
                : $"已删除 {deleted} 条阻止规则。");

            foreach (var failure in failures)
            {
                Console.Error.WriteLine($"  ! {failure}");
            }
        }

        if (deleted > 0)
        {
            LocalLog.Operation($"命令行：解除阻止 {deleted} 条");
        }

        return failures.Count == 0 ? ExitOk : ExitFailed;
    }

    private static int RunExportRules(CommandLineOptions options)
    {
        var all = QueryRules(out var error);

        if (all is null)
        {
            return Fail(options, "RULES_UNAVAILABLE",
                Localizer.IsEnglish
                    ? $"Failed to read rules: {error}"
                    : $"读取规则失败：{error}",
                ExitFailed);
        }

        var action = options.Action ?? "block";
        var document = new RuleExportDocument
        {
            Scope = action,
            ExportedUtc = DateTime.UtcNow,
        };

        foreach (var rule in all.Where(rule => string.Equals(
                     rule.Action, action, StringComparison.OrdinalIgnoreCase)))
        {
            document.Rules.Add(new RuleExportEntry
            {
                Kind = rule.Kind,
                Value = rule.Value,
                Action = rule.Action,
                Expiry = rule.Expiry,
                Group = rule.Group,
                Scope = rule.Scope,
            });
        }

        var path = Path.GetFullPath(options.ProgramPath!);

        if (File.Exists(path) && !options.Confirmed)
        {
            return Fail(options, "FILE_EXISTS",
                Localizer.IsEnglish
                    ? $"The file already exists: {path}. Add --yes to overwrite."
                    : $"文件已存在：{path}。确认覆盖请加 --yes。",
                ExitUsage);
        }

        try
        {
            File.WriteAllText(path, RuleExport.Serialize(document), new UTF8Encoding(false));
        }
        catch (Exception ex)
        {
            return Fail(options, "EXPORT_FAILED",
                Localizer.IsEnglish
                    ? $"Export failed: {ex.Message}"
                    : $"导出失败：{ex.Message}",
                ExitFailed);
        }

        if (IsJson(options))
        {
            CliJson.WriteSuccess(new
            {
                path,
                action,
                count = document.Rules.Count,
            }, VersionText);
        }
        else if (!options.Quiet)
        {
            Console.WriteLine(Localizer.IsEnglish
                ? $"Exported {document.Rules.Count} {action} rule(s) to {path}."
                : $"已导出 {document.Rules.Count} 条{action}规则到 {path}。");
        }

        return ExitOk;
    }

    private static int RunImportRules(CommandLineOptions options)
    {
        var path = Path.GetFullPath(options.ProgramPath!);
        string json;

        try
        {
            json = File.ReadAllText(path, Encoding.UTF8);
        }
        catch (Exception ex)
        {
            return Fail(options, "IMPORT_FAILED",
                Localizer.IsEnglish
                    ? $"Cannot read the file: {ex.Message}"
                    : $"读取文件失败：{ex.Message}",
                ExitFailed);
        }

        if (!RuleExport.TryParse(json, out var document, out var parseError)
            || document is null)
        {
            return Fail(options, "IMPORT_INVALID",
                Localizer.IsEnglish
                    ? $"Invalid rule file: {parseError}"
                    : $"规则文件不合法：{parseError}",
                ExitFailed);
        }

        var action = options.Action ?? "block";
        var expected = action == "allow" ? FirewallAction.Allow : FirewallAction.Block;

        if (!RuleExport.TryMatchScope(document, expected, out var scopeError))
        {
            return Fail(options, "IMPORT_SCOPE_MISMATCH", scopeError, ExitFailed);
        }

        if (options.DryRun)
        {
            if (IsJson(options))
            {
                CliJson.WriteSuccess(new
                {
                    dryRun = true,
                    action,
                    count = document.Rules.Count,
                    summary = RuleExport.Summarize(document),
                }, VersionText);
            }
            else if (!options.Quiet)
            {
                Console.WriteLine($"# 预览：将导入 {document.Rules.Count} 条{action}规则");
                Console.WriteLine(RuleExport.Summarize(document));
            }

            return ExitOk;
        }

        if (!options.Confirmed)
        {
            if (IsJson(options))
            {
                CliJson.WriteError(
                    "CONFIRMATION_REQUIRED",
                    Localizer.IsEnglish
                        ? "Add --yes to import rules."
                        : "确认导入请加 --yes。");
            }
            else
            {
                Console.WriteLine($"# 将导入 {document.Rules.Count} 条{action}规则");
                Console.WriteLine(RuleExport.Summarize(document));
                Console.WriteLine(Localizer.IsEnglish
                    ? "Nothing was imported. Add --yes to confirm:"
                    : "没有导入任何东西。确认要导入就再加一个 --yes：");
                Console.WriteLine($"  WinAppGuard.exe --import-rules \"{path}\" --action {action} --yes");
            }

            return ExitUsage;
        }

        var response = ServiceClient.TryRequest(
            new ServiceRequest
            {
                Command = ServiceProtocol.Commands.ImportRules,
                Json = json,
                Action = action,
            },
            TimeSpan.FromSeconds(30),
            out var error);

        if (response is not { Ok: true })
        {
            return Fail(options, "IMPORT_FAILED",
                Localizer.IsEnglish
                    ? $"Import failed: {response?.Error ?? error}"
                    : $"导入失败：{response?.Error ?? error}",
                ExitFailed);
        }

        if (IsJson(options))
        {
            CliJson.WriteSuccess(new
            {
                changed = response.Affected > 0,
                action,
                created = response.Affected,
                warning = response.Error,
            }, VersionText);
        }
        else if (!options.Quiet)
        {
            Console.WriteLine(Localizer.IsEnglish
                ? $"Imported {response.Affected} rule(s)."
                : $"已导入 {response.Affected} 条规则。");

            if (!string.IsNullOrEmpty(response.Error))
            {
                Console.Error.WriteLine($"  ! {response.Error}");
            }
        }

        return ExitOk;
    }

    // ==================================================================
    // 反网络攻击
    // ==================================================================

    private static int RunNetworkStatus(CommandLineOptions options)
    {
        var snapshot = QueryNetwork(out var error);

        if (snapshot is null)
        {
            return Fail(options, "NETWORK_UNAVAILABLE",
                Localizer.IsEnglish
                    ? $"Failed to read network detection status: {error}"
                    : $"读取反网络攻击状态失败：{error}",
                ExitFailed);
        }

        if (IsJson(options))
        {
            CliJson.WriteSuccess(new
            {
                status = snapshot.Status,
                settings = snapshot.Settings,
                alerts = snapshot.Alerts.Count,
                activeBlocks = snapshot.Blocks.Count,
            }, VersionText);

            return ExitOk;
        }

        var status = snapshot.Status;

        if (!options.Quiet)
        {
            Console.WriteLine($"# WinAppGuard {VersionText} — {T("反网络攻击", "anti-network attack")}");
            Console.WriteLine($"{T("开关", "Enabled")}\t{(status?.Enabled == true ? T("开启", "on") : T("关闭", "off"))}");
            Console.WriteLine($"Suricata\t{(status?.Running == true ? T("运行中", "running") : T("未运行", "not running"))} · {status?.SuricataVersion ?? T("未知", "unknown")}");
            Console.WriteLine($"{T("规则", "Rules")}\t{status?.RuleCount ?? 0}（{status?.RuleProfile ?? "standard"}）");
            Console.WriteLine($"{T("监听", "Capture")}\t{status?.CaptureDeviceName ?? T("自动", "auto")}");
            Console.WriteLine($"{T("告警", "Alerts")}\t{snapshot.Alerts.Count} · {T("未读", "unread")} {snapshot.Alerts.Count(alert => alert.Status == "new")}");
            Console.WriteLine($"{T("活动拦截", "Active blocks")}\t{snapshot.Blocks.Count}");

            if (!string.IsNullOrWhiteSpace(status?.LastError))
            {
                Console.WriteLine($"{T("最近错误", "Last error")}\t{status.LastError}");
            }
        }

        return ExitOk;
    }

    private static int RunNetworkAlerts(CommandLineOptions options)
    {
        var snapshot = QueryNetwork(out var error);

        if (snapshot is null)
        {
            return Fail(options, "NETWORK_UNAVAILABLE",
                Localizer.IsEnglish
                    ? $"Failed to read network alerts: {error}"
                    : $"读取网络告警失败：{error}",
                ExitFailed);
        }

        var alerts = snapshot.Alerts
            .Where(alert => !options.UnreadOnly || alert.Status == "new")
            .Take(options.Limit)
            .ToList();

        if (IsJson(options))
        {
            CliJson.WriteSuccess(new
            {
                count = alerts.Count,
                unreadOnly = options.UnreadOnly,
                alerts,
            }, VersionText);

            return ExitOk;
        }

        if (!options.Quiet)
        {
            Console.WriteLine($"# WinAppGuard {VersionText} — {T("网络告警", "network alerts")}：{alerts.Count} {T("条", "entry/entries")}");
            Console.WriteLine(T(
                "# 时间\t级别\t状态\t规则\t远端\t进程\t证据",
                "# time\tseverity\tstatus\trule\tremote\tprocess\tevidence"));

            foreach (var alert in alerts)
            {
                var statusText = alert.Status switch
                {
                    "new" => T("未读", "unread"),
                    "ack" => T("已读", "read"),
                    _ => alert.Status,
                };

                Console.WriteLine(
                    $"{alert.TimeUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss}\t" +
                    $"{alert.Severity}\t{statusText}\t{alert.Signature}\t" +
                    $"{alert.RemoteAddress}:{alert.RemotePort}\t" +
                    $"{alert.ProcessName}\t{alert.Evidence}");
            }
        }

        return ExitOk;
    }

    private static int RunNetworkAck(CommandLineOptions options)
    {
        var response = ServiceClient.TryRequest(
            new ServiceRequest
            {
                Command = ServiceProtocol.Commands.AlertNetworkAck,
                NetworkAlertId = options.ProgramPath,
            },
            TimeSpan.FromSeconds(10),
            out var error);

        if (response is not { Ok: true })
        {
            return Fail(options, "ACK_FAILED",
                Localizer.IsEnglish
                    ? $"Acknowledge failed: {response?.Error ?? error}"
                    : $"标记已读失败：{response?.Error ?? error}",
                ExitFailed);
        }

        if (IsJson(options))
        {
            CliJson.WriteSuccess(new { changed = true, id = options.ProgramPath }, VersionText);
        }
        else if (!options.Quiet)
        {
            Console.WriteLine(Localizer.IsEnglish
                ? $"Marked alert {options.ProgramPath} as read."
                : $"已标记告警 {options.ProgramPath} 为已读。");
        }

        return ExitOk;
    }

    private static int RunNetworkClear(CommandLineOptions options)
    {
        if (!options.Confirmed)
        {
            if (IsJson(options))
            {
                CliJson.WriteError(
                    "CONFIRMATION_REQUIRED",
                    Localizer.IsEnglish
                        ? "Add --yes to clear all anti-network attack alerts."
                        : "确认清空反网络攻击告警请加 --yes。");
            }
            else
            {
                Console.WriteLine(Localizer.IsEnglish
                    ? "No alerts were cleared. Add --yes to confirm:"
                    : "没有清空任何告警。确认要清空就再加一个 --yes：");
                Console.WriteLine("  WinAppGuard.exe --network-clear --yes");
            }

            return ExitUsage;
        }

        var response = ServiceClient.TryRequest(
            new ServiceRequest { Command = ServiceProtocol.Commands.AlertNetworkClear },
            TimeSpan.FromSeconds(15),
            out var error);

        if (response is not { Ok: true })
        {
            return Fail(options, "CLEAR_FAILED",
                Localizer.IsEnglish
                    ? $"Clear failed: {response?.Error ?? error}"
                    : $"清空失败：{response?.Error ?? error}",
                ExitFailed);
        }

        if (IsJson(options))
        {
            CliJson.WriteSuccess(new { changed = response.Affected > 0, cleared = response.Affected }, VersionText);
        }
        else if (!options.Quiet)
        {
            Console.WriteLine(Localizer.IsEnglish
                ? $"Cleared {response.Affected} alert(s)."
                : $"已清空 {response.Affected} 条告警。");
        }

        return ExitOk;
    }

    private static int RunNetworkBlock(CommandLineOptions options)
    {
        if (!options.Confirmed)
        {
            if (IsJson(options))
            {
                CliJson.WriteError(
                    "CONFIRMATION_REQUIRED",
                    Localizer.IsEnglish
                        ? "Add --yes to create a WFP block."
                        : "确认创建 WFP 拦截请加 --yes。");
            }
            else
            {
                Console.WriteLine(Localizer.IsEnglish
                    ? "No block was created. Add --yes to confirm:"
                    : "没有创建拦截。确认要拦截就再加一个 --yes：");
                Console.WriteLine(
                    $"  WinAppGuard.exe --network-block {options.ProgramPath} " +
                    $"--scope {options.Scope} --minutes {options.Minutes ?? 10} --yes");
            }

            return ExitUsage;
        }

        var snapshot = QueryNetwork(out var error);
        var alert = snapshot?.Alerts.FirstOrDefault(item =>
            string.Equals(item.Id, options.ProgramPath, StringComparison.Ordinal));

        if (alert is null)
        {
            return Fail(options, "ALERT_NOT_FOUND",
                Localizer.IsEnglish
                    ? $"Alert {options.ProgramPath} was not found."
                    : $"找不到告警 {options.ProgramPath}。",
                ExitNotFound);
        }

        var kind = options.Scope!;
        var target = kind switch
        {
            "connection" => string.Join('|',
                alert.Protocol,
                alert.LocalAddress,
                alert.LocalPort,
                alert.RemoteAddress,
                alert.RemotePort),
            "ip" => alert.RemoteAddress,
            _ => string.Join('|', alert.RemoteAddress, alert.RemotePort, alert.Protocol),
        };

        var minutes = options.Minutes ?? 10;

        if (minutes is < 1 or > 60)
        {
            return Fail(options, "BAD_MINUTES",
                Localizer.IsEnglish
                    ? "--network-block minutes must be between 1 and 60."
                    : "--network-block 的 --minutes 必须在 1–60 之间。",
                ExitUsage);
        }

        var response = ServiceClient.TryRequest(
            new ServiceRequest
            {
                Command = ServiceProtocol.Commands.NetworkDetectionBlock,
                NetworkAlertId = alert.Id,
                NetworkBlockKind = kind,
                NetworkBlockTarget = target,
                NetworkBlockMinutes = minutes,
            },
            TimeSpan.FromSeconds(15),
            out var blockError);

        if (response is not { Ok: true })
        {
            return Fail(options, "BLOCK_FAILED",
                Localizer.IsEnglish
                    ? $"Block failed: {response?.Error ?? blockError}"
                    : $"拦截失败：{response?.Error ?? blockError}",
                ExitFailed);
        }

        if (IsJson(options))
        {
            CliJson.WriteSuccess(new
            {
                changed = true,
                kind,
                target,
                minutes,
                alertId = alert.Id,
            }, VersionText);
        }
        else if (!options.Quiet)
        {
            Console.WriteLine(Localizer.IsEnglish
                ? $"Blocked {kind} {target} for {minutes} minute(s)."
                : $"已拦截 {kind} {target}，{minutes} 分钟。");
        }

        return ExitOk;
    }

    private static int RunNetworkUnblock(CommandLineOptions options)
    {
        var snapshot = QueryNetwork(out var error);
        var block = snapshot?.Blocks.FirstOrDefault(item =>
            string.Equals(item.Id, options.ProgramPath, StringComparison.Ordinal));

        if (block is null)
        {
            return Fail(options, "BLOCK_NOT_FOUND",
                Localizer.IsEnglish
                    ? $"Block {options.ProgramPath} was not found."
                    : $"找不到拦截 {options.ProgramPath}。",
                ExitNotFound);
        }

        var response = ServiceClient.TryRequest(
            new ServiceRequest
            {
                Command = ServiceProtocol.Commands.NetworkDetectionRelease,
                NetworkBlockId = block.Id,
                NetworkAlertId = block.AlertId,
            },
            TimeSpan.FromSeconds(15),
            out var releaseError);

        if (response is not { Ok: true })
        {
            return Fail(options, "RELEASE_FAILED",
                Localizer.IsEnglish
                    ? $"Release failed: {response?.Error ?? releaseError}"
                    : $"释放失败：{response?.Error ?? releaseError}",
                ExitFailed);
        }

        if (IsJson(options))
        {
            CliJson.WriteSuccess(new { changed = true, id = block.Id }, VersionText);
        }
        else if (!options.Quiet)
        {
            Console.WriteLine(Localizer.IsEnglish
                ? $"Released block {block.Id}."
                : $"已释放拦截 {block.Id}。");
        }

        return ExitOk;
    }

    private static int RunNetworkUnblockAll(CommandLineOptions options)
    {
        if (!options.Confirmed)
        {
            if (IsJson(options))
            {
                CliJson.WriteError(
                    "CONFIRMATION_REQUIRED",
                    Localizer.IsEnglish
                        ? "Add --yes to release all blocks."
                        : "确认释放全部拦截请加 --yes。");
            }
            else
            {
                Console.WriteLine(Localizer.IsEnglish
                    ? "Nothing was released. Add --yes to confirm:"
                    : "没有释放任何拦截。确认要释放就再加一个 --yes：");
                Console.WriteLine("  WinAppGuard.exe --network-unblock-all --yes");
            }

            return ExitUsage;
        }

        var response = ServiceClient.TryRequest(
            new ServiceRequest
            {
                Command = ServiceProtocol.Commands.NetworkDetectionReleaseAll,
                NetworkBlockReleaseAll = true,
            },
            TimeSpan.FromSeconds(15),
            out var error);

        if (response is not { Ok: true })
        {
            return Fail(options, "RELEASE_FAILED",
                Localizer.IsEnglish
                    ? $"Release failed: {response?.Error ?? error}"
                    : $"释放失败：{response?.Error ?? error}",
                ExitFailed);
        }

        if (IsJson(options))
        {
            CliJson.WriteSuccess(new { changed = true, released = response.Affected }, VersionText);
        }
        else if (!options.Quiet)
        {
            Console.WriteLine(Localizer.IsEnglish
                ? $"Released {response.Affected} block(s)."
                : $"已释放 {response.Affected} 个拦截。");
        }

        return ExitOk;
    }

    private static int RunNetworkSetAdapter(CommandLineOptions options)
    {
        var value = options.ProgramPath!.Trim();
        var auto = string.Equals(value, "auto", StringComparison.OrdinalIgnoreCase);

        if (!auto)
        {
            var adapters = NetworkCaptureDevices.Enumerate();
            var adapter = adapters.FirstOrDefault(item =>
                string.Equals(item.Id, value, StringComparison.OrdinalIgnoreCase));

            if (adapter is null)
            {
                return Fail(options, "ADAPTER_NOT_FOUND",
                    Localizer.IsEnglish
                        ? $"Capture adapter {value} was not found."
                        : $"找不到监听网卡 {value}。",
                    ExitNotFound);
            }
        }

        var snapshot = QueryNetwork(out var error);

        if (snapshot?.Settings is null)
        {
            return Fail(options, "NETWORK_UNAVAILABLE",
                Localizer.IsEnglish
                    ? $"Failed to read network detection settings: {error}"
                    : $"读取反网络攻击设置失败：{error}",
                ExitFailed);
        }

        var settings = snapshot.Settings;
        settings.CaptureDeviceId = auto ? string.Empty : value;

        var response = ServiceClient.TryRequest(
            new ServiceRequest
            {
                Command = ServiceProtocol.Commands.NetworkDetectionConfigure,
                NetworkDetectionSettings = settings,
            },
            TimeSpan.FromSeconds(20),
            out var configureError);

        if (response is not { Ok: true })
        {
            return Fail(options, "CONFIGURE_FAILED",
                Localizer.IsEnglish
                    ? $"Failed to set adapter: {response?.Error ?? configureError}"
                    : $"设置监听网卡失败：{response?.Error ?? configureError}",
                ExitFailed);
        }

        if (IsJson(options))
        {
            CliJson.WriteSuccess(new { adapter = auto ? "auto" : value }, VersionText);
        }
        else if (!options.Quiet)
        {
            Console.WriteLine(Localizer.IsEnglish
                ? $"Capture adapter set to {(auto ? "auto" : value)}."
                : $"监听网卡已设置为 {(auto ? "自动" : value)}。");
        }

        return ExitOk;
    }

    private static int RunNetworkSetCategories(CommandLineOptions options)
    {
        var requested = (options.ProgramPath ?? string.Empty)
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var unknown = requested.Where(id => !NetworkRuleCategories.IsKnown(id)).ToList();

        if (unknown.Count > 0 || requested.Count == 0)
        {
            return Fail(options, "BAD_CATEGORIES",
                Localizer.IsEnglish
                    ? "Unknown or empty rule category list."
                    : "规则分类为空或包含未知分类。",
                ExitUsage);
        }

        var snapshot = QueryNetwork(out var error);

        if (snapshot?.Settings is null)
        {
            return Fail(options, "NETWORK_UNAVAILABLE",
                Localizer.IsEnglish
                    ? $"Failed to read network detection settings: {error}"
                    : $"读取反网络攻击设置失败：{error}",
                ExitFailed);
        }

        var settings = snapshot.Settings;
        settings.EnabledRuleCategories = requested;

        var response = ServiceClient.TryRequest(
            new ServiceRequest
            {
                Command = ServiceProtocol.Commands.NetworkDetectionConfigure,
                NetworkDetectionSettings = settings,
            },
            TimeSpan.FromSeconds(20),
            out var configureError);

        if (response is not { Ok: true })
        {
            return Fail(options, "CONFIGURE_FAILED",
                Localizer.IsEnglish
                    ? $"Failed to set categories: {response?.Error ?? configureError}"
                    : $"设置规则分类失败：{response?.Error ?? configureError}",
                ExitFailed);
        }

        if (IsJson(options))
        {
            CliJson.WriteSuccess(new { categories = requested }, VersionText);
        }
        else if (!options.Quiet)
        {
            Console.WriteLine(Localizer.IsEnglish
                ? $"Rule categories set to: {string.Join(", ", requested)}"
                : $"规则分类已设置为：{string.Join(", ", requested)}");
        }

        return ExitOk;
    }

    // ==================================================================
    // 诊断
    // ==================================================================

    private static int RunDoctor(CommandLineOptions options)
    {
        var checks = new List<DoctorCheck>();
        var status = ServiceClient.TryGetStatus(TimeSpan.FromSeconds(5));

        checks.Add(new DoctorCheck(
            "service",
            status is null ? "FAIL" : "OK",
            status is null
                ? (Localizer.IsEnglish ? "Service is not responding." : "服务没有响应。")
                : (Localizer.IsEnglish ? "Service is running." : "服务正在运行。")));

        if (status is not null)
        {
            checks.Add(new DoctorCheck(
                "protected-mode",
                status.ProtectedMode ? "OK" : "FAIL",
                status.ProtectedMode
                    ? (Localizer.IsEnglish ? "Owner key loaded." : "所有者密钥已加载。")
                    : (Localizer.IsEnglish ? "Owner key is not loaded." : "所有者密钥未加载。")));

            checks.Add(new DoctorCheck(
                "wfp-sublayer",
                status.SublayerPresent ? "OK" : "FAIL",
                status.SublayerPresent
                    ? (Localizer.IsEnglish ? "WFP sublayer is present." : "WFP 子层存在。")
                    : (Localizer.IsEnglish ? "WFP sublayer is missing." : "WFP 子层缺失。")));

            checks.Add(new DoctorCheck(
                "rules",
                "OK",
                Localizer.IsEnglish
                    ? $"block {status.BlockRuleCount}, allow {status.AllowRuleCount}, ip {status.IpRuleCount}"
                    : $"阻止 {status.BlockRuleCount}，允许 {status.AllowRuleCount}，IP {status.IpRuleCount}"));

            checks.Add(new DoctorCheck(
                "traffic",
                status.TrafficCollecting ? "OK" : "WARN",
                status.TrafficCollecting
                    ? (Localizer.IsEnglish ? "Traffic collection is running." : "流量采集运行中。")
                    : (Localizer.IsEnglish ? "Traffic collection is not running." : "流量采集未运行。")));

            checks.Add(new DoctorCheck(
                "ids",
                status.IdsCollecting ? "OK" : "WARN",
                status.IdsCollecting
                    ? (Localizer.IsEnglish ? "IDS is collecting." : "IDS 采集中。")
                    : (Localizer.IsEnglish ? "IDS is not collecting." : "IDS 未采集。")));

            var network = QueryNetwork(out var networkError);

            checks.Add(new DoctorCheck(
                "network-detection",
                network?.Status is { Running: true } ? "OK" : "WARN",
                network?.Status is { Running: true }
                    ? (Localizer.IsEnglish
                        ? $"Suricata running; capture adapter: {network.Status.CaptureDeviceName ?? "auto"}."
                        : $"Suricata 运行中；监听网卡：{network.Status.CaptureDeviceName ?? "自动"}。")
                    : (networkError ?? (Localizer.IsEnglish ? "Suricata is not running." : "Suricata 未运行。"))));
        }

        var state = NpcapLocator.GetState(out var npcapVersion);
        var npcapUsable = state is NpcapState.Ok or NpcapState.Unknown;
        checks.Add(new DoctorCheck(
            "npcap",
            state == NpcapState.Ok ? "OK" : npcapUsable ? "WARN" : "FAIL",
            npcapUsable
                ? (Localizer.IsEnglish
                    ? $"Npcap {npcapVersion ?? "installed"}."
                    : $"Npcap {npcapVersion ?? "已安装"}。")
                : NpcapLocator.GetUnavailableReason()));

        if (npcapUsable)
        {
            var opened = false;
            string? openError = null;

            try
            {
                opened = NpcapProbe.TryOpen(out openError);
            }
            catch (Exception ex)
            {
                openError = ex.Message;
            }

            checks.Add(new DoctorCheck(
                "npcap-open",
                opened ? "OK" : "WARN",
                opened
                    ? (Localizer.IsEnglish
                        ? "Npcap can open a capture device."
                        : "Npcap 能打开抓包设备。")
                    : (openError ?? (Localizer.IsEnglish
                        ? "Npcap could not open a capture device."
                        : "Npcap 打不开抓包设备。"))));
        }

        var logDirectory = LocalLog.LogDirectory;
        checks.Add(new DoctorCheck(
            "local-log",
            Directory.Exists(logDirectory) ? "OK" : "WARN",
            logDirectory));

        if (IsJson(options))
        {
            CliJson.WriteSuccess(new { checks }, VersionText);
        }
        else
        {
            foreach (var check in checks)
            {
                Console.WriteLine($"[{check.Status}] {check.Name}\t{check.Detail}");
            }
        }

        return checks.Any(check => check.Status == "FAIL") ? ExitFailed : ExitOk;
    }

    private static int RunAuditTail(CommandLineOptions options)
    {
        using var store = new AuditStore(ServicePaths.AuditDirectory);
        var events = store.ReadRecent(options.Limit);

        if (IsJson(options))
        {
            CliJson.WriteSuccess(new
            {
                count = events.Count,
                events = events.Select(item => new
                {
                    timeUtc = item.TimeUtc,
                    kind = item.Kind == AuditEventKind.Blocked ? "blocked" : "connect",
                    processPath = item.ProcessPath,
                    pid = item.ProcessId,
                    remoteAddress = item.RemoteAddress,
                    remotePort = item.RemotePort,
                    protocol = item.Protocol,
                    domain = item.Domain,
                    domainIsGuess = item.DomainIsGuess,
                }),
            }, VersionText);

            return ExitOk;
        }

        if (!options.Quiet)
        {
            Console.WriteLine($"# {T("最近审计记录", "recent audit events")}：{events.Count} {T("条", "entry/entries")}");

            foreach (var item in events)
            {
                if (Localizer.IsEnglish)
                {
                    var action = item.Kind == AuditEventKind.Blocked ? "blocked" : "connect";
                    var process = string.IsNullOrEmpty(item.ProcessPath)
                        ? "(unknown)"
                        : Path.GetFileName(item.ProcessPath);
                    var domain = string.IsNullOrEmpty(item.Domain) ? "unknown domain" : item.Domain;

                    Console.WriteLine(
                        $"{item.TimeUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss} {action} {process} -> " +
                        $"{item.RemoteAddress}:{item.RemotePort} ({domain})");
                }
                else
                {
                    Console.WriteLine(item.Describe());
                }
            }
        }

        return ExitOk;
    }

    // ==================================================================
    // 原有恢复命令
    // ==================================================================

    private static int RunUnblockAll(CommandLineOptions options)
    {
        // 1.x 的兜底：如果上次（1.x 时代）没正常退出，先把「默认阻止出站」还原成「允许」。
        // 2.0 自己不再写这个标志，所以新机器上这一步永远什么都不做。
        // 否则紧接着把白名单删光，等于让整台机器断网。
        var recovery = StrictModeManager.RecoverIfLeftOn();

        var rules = QueryRules(out var error);

        if (rules is null)
        {
            return Fail(options, "RULES_UNAVAILABLE",
                Localizer.IsEnglish
                    ? $"Failed to read rules: {error}"
                    : $"读取规则失败：{error}",
                ExitFailed);
        }

        if (rules.Count == 0)
        {
            if (IsJson(options))
            {
                CliJson.WriteSuccess(new { changed = false, deleted = 0 }, VersionText);
            }
            else if (!options.Quiet)
            {
                Console.WriteLine(Localizer.IsEnglish
                    ? "There are no AppGuard rules to clean up."
                    : "当前没有任何 AppGuard 规则，无需清理。");

                if (recovery.WasLeftOn)
                {
                    Console.WriteLine($"已顺带还原严格模式：{recovery.Message}");
                }
            }

            return ExitOk;
        }

        if (IsJson(options) && !options.Confirmed)
        {
            CliJson.WriteError(
                "CONFIRMATION_REQUIRED",
                Localizer.IsEnglish
                    ? "Add --yes to delete all rules."
                    : "确认删除全部规则请加 --yes。");
            return ExitUsage;
        }

        if (!options.Quiet && !options.Confirmed)
        {
            Console.Write(CliText.BuildUnblockPreview(rules));
            Console.WriteLine();
            Console.WriteLine(Localizer.IsEnglish
                ? "Nothing was deleted. Add --yes to confirm:"
                : "没有删除任何东西。确认要删就再加一个 --yes：");
            Console.WriteLine("  WinAppGuard.exe --unblock-all --yes");
            return ExitUsage;
        }

        var response = ServiceClient.TryRequest(
            new ServiceRequest { Command = ServiceProtocol.Commands.ClearAllRules },
            TimeSpan.FromSeconds(30),
            out var deleteError);

        if (response is not { Ok: true })
        {
            return Fail(options, "DELETE_FAILED",
                Localizer.IsEnglish
                    ? $"Delete failed: {response?.Error ?? deleteError}"
                    : $"删除失败：{response?.Error ?? deleteError}",
                ExitFailed);
        }

        var deleted = response.Affected;

        if (IsJson(options))
        {
            CliJson.WriteSuccess(new { changed = deleted > 0, deleted }, VersionText);
        }
        else if (!options.Quiet)
        {
            Console.WriteLine();
            Console.WriteLine(Localizer.IsEnglish
                ? $"Deleted {deleted} rules."
                : $"已删除 {deleted} 条规则。");
            Console.WriteLine("# 其他软件的规则、以及本工具在 WFP 里创建的过滤器之外的东西都没有受到影响。");

            if (recovery.WasLeftOn)
            {
                Console.WriteLine("1.x 遗留的「默认阻止出站」已还原成「允许」（上次没有正常退出）。");
            }
        }

        LocalLog.Operation($"命令行：删除全部 AppGuard 规则，实际删除 {deleted} 条");
        return ExitOk;
    }

    private static int RunMigrate(CommandLineOptions options)
    {
        var report = StartupMigration.RunIfNeeded(out var error);

        if (error is not null)
        {
            return Fail(options, "MIGRATE_FAILED",
                Localizer.IsEnglish
                    ? $"Migration failed: {error}"
                    : $"迁移失败：{error}",
                ExitFailed);
        }

        if (report is null)
        {
            if (IsJson(options))
            {
                CliJson.WriteSuccess(new { changed = false, migrated = 0 }, VersionText);
            }
            else if (!options.Quiet)
            {
                Console.WriteLine("没有需要迁移的 1.x 规则（Windows 防火墙里没有 AppGuard_ 规则）。");
            }

            return ExitOk;
        }

        if (IsJson(options))
        {
            CliJson.WriteSuccess(new
            {
                changed = report.Migrated > 0,
                migrated = report.Migrated,
                skipped = report.Skipped,
                failed = report.Failed,
                firewallRulesDeleted = report.FirewallRulesDeleted,
                succeeded = report.Succeeded,
                details = report.Details,
            }, VersionText);
        }
        else if (!options.Quiet)
        {
            Console.WriteLine(
                $"迁移完成：成功 {report.Migrated} 条，跳过 {report.Skipped} 条，" +
                $"失败 {report.Failed} 条，删除旧规则 {report.FirewallRulesDeleted} 条。");

            foreach (var line in report.Details)
            {
                Console.WriteLine("  " + line);
            }
        }

        if (!report.Succeeded)
        {
            if (!IsJson(options))
            {
                Console.Error.WriteLine("有一次迁移失败：失败的规则保留在 Windows 防火墙里，可以再执行一次。");
            }

            return ExitFailed;
        }

        return ExitOk;
    }

    private static int RunRecover(CommandLineOptions options)
    {
        // 3.4：WFP 对象只允许所有者删除；非所有者先拒绝，避免只清了一半。
        if (WfpRecovery.HasOurObjects() && !ProtectedModeClient.IsCurrentUserOwner())
        {
            return Fail(options, "NOT_OWNER",
                Localizer.IsEnglish
                    ? "This account is not the owner. WFP rules created by WinAppGuard 3.4+ can only be deleted by the owner; sign in as the owner and run --recover again."
                    : "当前账户不是所有者。3.4 起本工具的 WFP 规则只允许所有者删除；请用所有者账户登录后重新运行 --recover。",
                ExitFailed);
        }

        var report = WfpRecovery.Recover();
        var strict = StrictModeManager.RecoverIfLeftOn();
        var legacy = FirewallManager.GetAppGuardRules();
        var deleted = 0;

        foreach (var rule in legacy)
        {
            if (FirewallManager.DeleteRule(rule.Name))
            {
                deleted++;
            }
        }

        if (IsJson(options))
        {
            CliJson.WriteSuccess(new
            {
                changed = deleted > 0 || strict.WasLeftOn,
                wfp = report.Describe(),
                legacyStrictRecovered = strict.WasLeftOn,
                legacyStrictMessage = strict.Message,
                legacyFirewallRulesDeleted = deleted,
            }, VersionText);
        }
        else if (!options.Quiet)
        {
            Console.WriteLine(report.Describe());
            Console.WriteLine(strict.WasLeftOn
                ? $"已还原 1.x 遗留的全局出站策略：{strict.Message}"
                : "1.x 的全局出站策略正常（没有遗留的「默认阻止」）。");

            Console.WriteLine(deleted > 0
                ? $"另外删除了 {deleted} 条 1.x 遗留的 Windows 防火墙规则。"
                : "没有 1.x 遗留的 Windows 防火墙规则。");

            Console.WriteLine();
            Console.WriteLine("# 其他软件和系统自带的规则 / WFP 对象没有受到影响。");
        }

        LocalLog.Operation($"命令行：恢复（WFP：{report.Describe()}；1.x 规则删除 {deleted} 条）");
        return ExitOk;
    }

    // ==================================================================
    // 辅助
    // ==================================================================

    private static bool IsJson(CommandLineOptions options)
        => options.Json || string.Equals(options.Format, "json", StringComparison.OrdinalIgnoreCase);

    private static string T(string chinese, string english)
        => Localizer.IsEnglish ? english : chinese;

    private static int Fail(
        CommandLineOptions options,
        string code,
        string message,
        int exitCode,
        bool showUsage = false)
    {
        if (IsJson(options))
        {
            CliJson.WriteError(code, message);
        }
        else
        {
            Console.Error.WriteLine(Localizer.IsEnglish
                ? $"Error: {message}"
                : $"错误：{message}");

            if (showUsage)
            {
                Console.Error.WriteLine();
                Console.Error.Write(CliText.Usage);
            }
        }

        return exitCode;
    }

    private static object BuildStatusSummary(ServiceStatus status)
        => new
        {
            serviceVersion = status.ServiceVersion,
            protocolVersion = status.ProtocolVersion,
            running = true,
            sublayerPresent = status.SublayerPresent,
            blockRuleCount = status.BlockRuleCount,
            allowRuleCount = status.AllowRuleCount,
            ipRuleCount = status.IpRuleCount,
            strictModeActive = status.StrictModeActive,
            strictModePermittedCount = status.StrictModePermittedCount,
            strictModeLockdownActive = status.StrictModeLockdownActive,
            strictModeLockdownRemainingSeconds = status.StrictModeLockdownRemainingSeconds,
            auditCollecting = status.AuditCollecting,
            trafficCollecting = status.TrafficCollecting,
            dnsCollecting = status.DnsCollecting,
            idsEnabled = status.IdsEnabled,
            idsCollecting = status.IdsCollecting,
            idsAlertsNew = status.IdsAlertsNew,
            idsFlowCount = status.IdsFlowCount,
            antiScanCollecting = status.AntiScanCollecting,
            antiScanNpcapAvailable = status.AntiScanNpcapAvailable,
            lanCollecting = status.LanCollecting,
            lanEventCount = status.LanEventCount,
            dnsSecurityCollecting = status.DnsSecurityCollecting,
            ipv6SecurityCollecting = status.Ipv6SecurityCollecting,
            owner = status.ProtectedModeOwner,
            fingerprintPrefix = status.ProtectedModeFingerprint is { Length: >= 16 } fingerprint
                ? fingerprint[..16]
                : status.ProtectedModeFingerprint,
            tamperRebuiltCount = status.TamperRebuiltCount,
            expiredPurgedCount = status.ExpiredPurgedCount,
            authRejectedCount = status.AuthRejectedCount,
        };

    private static List<RuleDto>? QueryRules(out string? error)
    {
        var response = ServiceClient.TryRequest(
            new ServiceRequest { Command = ServiceProtocol.Commands.ListRules },
            TimeSpan.FromSeconds(15),
            out error);

        if (response is not { Ok: true })
        {
            error = response?.Error ?? error ?? "服务没有返回规则。";
            return null;
        }

        return response.Rules ?? new List<RuleDto>();
    }

    private static NetworkSnapshot? QueryNetwork(out string? error)
    {
        var response = ServiceClient.TryRequest(
            new ServiceRequest { Command = ServiceProtocol.Commands.QueryNetworkDetection },
            TimeSpan.FromSeconds(10),
            out error);

        if (response is not { Ok: true })
        {
            error = response?.Error ?? error ?? "服务没有返回反网络攻击数据。";
            return null;
        }

        return new NetworkSnapshot(
            response.NetworkAlerts ?? new List<NetworkAlertDto>(),
            response.NetworkBlocks ?? new List<NetworkBlockDto>(),
            response.NetworkDetectionSettings,
            response.NetworkDetectionStatus);
    }

    private static ServiceResponse? QueryIds(out string? error)
    {
        var response = ServiceClient.TryRequest(
            new ServiceRequest { Command = ServiceProtocol.Commands.QueryIdsAlerts },
            TimeSpan.FromSeconds(10),
            out error);

        if (response is not { Ok: true })
        {
            error = response?.Error ?? error;
            return null;
        }

        return response;
    }

    private static string DescribeExpiry(string encoded)
    {
        var expiry = RuleExpiry.Parse(encoded);
        return expiry.Kind switch
        {
            RuleExpiryKind.Never => Localizer.IsEnglish ? "Permanent" : "永久",
            RuleExpiryKind.OnNextBoot => Localizer.IsEnglish ? "Until next restart" : "到下次重启",
            _ => expiry.ExpiresAtUtc is { } at
                ? at.ToLocalTime().ToString("yyyy-MM-dd HH:mm")
                : (Localizer.IsEnglish ? "Timed" : "限时"),
        };
    }

    /// <summary>把用户给的路径转成完整路径，仅用于回显（合法性仍由 FirewallManager 判定）。</summary>
    private static string TryResolvePath(string programPath)
    {
        try
        {
            return Path.GetFullPath(programPath);
        }
        catch (Exception)
        {
            return programPath;
        }
    }

    /// <summary>版本号（<c>1.4.0+&lt;commit&gt;</c> 里只取前面那段）。</summary>
    private static string BuildVersionText()
    {
        var entry = System.Reflection.Assembly.GetEntryAssembly();
        var informational = entry?
            .GetCustomAttributes(typeof(System.Reflection.AssemblyInformationalVersionAttribute), false)
            .OfType<System.Reflection.AssemblyInformationalVersionAttribute>()
            .FirstOrDefault()?
            .InformationalVersion;

        if (string.IsNullOrEmpty(informational))
        {
            return entry?.GetName().Version?.ToString(3) ?? "0.0.0";
        }

        var plus = informational.IndexOf('+');
        return plus > 0 ? informational[..plus] : informational;
    }

    private sealed record NetworkSnapshot(
        List<NetworkAlertDto> Alerts,
        List<NetworkBlockDto> Blocks,
        NetworkDetectionSettingsDto? Settings,
        NetworkDetectionStatusDto? Status);

    private sealed record DoctorCheck(string Name, string Status, string Detail);
}
