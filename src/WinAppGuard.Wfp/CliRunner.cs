using WinAppGuard.Contracts;
using WinAppGuard.Core.ProtectedMode;
using WinAppGuard.Localization;
using WinAppGuard.Core.Wfp;
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
///   1. 程序要求管理员权限（未提权时 Windows 会先弹 UAC）；
///   2. 唯一不可逆的批量操作 <c>--unblock-all</c> 额外要求 <c>--yes</c>；
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

    /// <summary>执行一条命令行指令，返回进程退出码。</summary>
    internal static int Run(CommandLineOptions options)
    {
        switch (options.Kind)
        {
            case CommandKind.Help:
                Console.Write(CliText.Usage);
                return ExitOk;

            case CommandKind.Invalid:
                Console.Error.WriteLine($"参数错误：{options.Error}");
                Console.Error.WriteLine();
                Console.Error.Write(CliText.Usage);
                return ExitUsage;

            case CommandKind.Block:
            case CommandKind.ListBlocked:
            case CommandKind.UnblockAll:
            case CommandKind.Migrate:
            case CommandKind.Recover:
                // 读/改防火墙都要管理员权限。
                if (!AdminHelper.IsRunningAsAdmin())
                {
                    Console.Error.WriteLine(Localizer.IsEnglish
                ? "Administrator rights required: run this from an elevated terminal."
                : "需要管理员权限：请从「以管理员身份运行」的终端里执行本命令。");
                    return ExitNotAdmin;
                }

                try
                {
                    // 3.1：block / list / unblock 改为签名 IPC，不再直接写 WFP。
                    // migrate / recover 是管理员恢复命令，保留直接 WFP（文档写明）。
                    if (options.Kind is CommandKind.Block
                        or CommandKind.ListBlocked
                        or CommandKind.UnblockAll)
                    {
                        if (!ProtectedModeClient.TryConfigureSigner(
                                out _, out var authError))
                        {
                            Console.Error.WriteLine(
                                $"当前账户不是所有者，或密钥不可用：{authError}");
                            Console.Error.WriteLine(
                                "请用安装时的所有者账户运行；密钥损坏时用 --rotate-key 重建。");
                            return ExitFailed;
                        }
                    }

                    return options.Kind switch
                    {
                        CommandKind.Block => RunBlock(options.ProgramPath!),
                        CommandKind.ListBlocked => RunListBlocked(),
                        CommandKind.Migrate => RunMigrate(),
                        CommandKind.Recover => RunRecover(),
                        _ => RunUnblockAll(options.Confirmed),
                    };
                }
                catch (Exception ex)
                {
                    // 命令行模式绝不能把异常抛给 Windows 的崩溃框 —— 无人值守时会卡住。
                    Console.Error.WriteLine(Localizer.IsEnglish
                ? $"Execution failed: {ex.Message}"
                : $"执行失败：{ex.Message}");
                    LocalLog.Error($"命令行模式执行失败（{options.Kind}）", ex);
                    return ExitFailed;
                }

            default:
                return ExitOk;
        }
    }

    private static int RunBlock(string programPath)
    {
        // 路径校验仍在客户端做一次（服务端会再做一次，安全闸没有放宽）。
        var fullPath = FirewallManager.ValidateProgramPath(programPath, forBlocking: true);

        var before = QueryRules(out var queryError);

        if (before is null)
        {
            Console.Error.WriteLine(Localizer.IsEnglish
            ? $"Failed to read rules: {queryError}"
            : $"读取规则失败：{queryError}");
            return ExitFailed;
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
            },
            TimeSpan.FromSeconds(15),
            out var error);

        if (response is not { Ok: true })
        {
            Console.Error.WriteLine(Localizer.IsEnglish
            ? $"Block failed: {response?.Error ?? error}"
            : $"阻止失败：{response?.Error ?? error}");
            return ExitFailed;
        }

        // 服务不返回规则名；再查一次，保持原来的输出格式。
        var after = QueryRules(out _);
        var ruleName = after?
            .FirstOrDefault(rule =>
                string.Equals(rule.Action, "block", StringComparison.OrdinalIgnoreCase)
                && string.Equals(rule.Value, fullPath, StringComparison.OrdinalIgnoreCase))?
            .Name ?? "(服务未返回规则名)";

        Console.WriteLine(alreadyBlocked
            ? $"该程序已经在阻止列表中：{fullPath}"
            : $"已阻止：{fullPath}");

        Console.WriteLine(Localizer.IsEnglish
            ? $"  Rule name: {ruleName}"
            : $"  规则名：{ruleName}");

        LocalLog.Operation($"命令行：阻止联网 {fullPath}（规则 {ruleName}）");
        return ExitOk;
    }

    private static int RunListBlocked()
    {
        var all = QueryRules(out var error);

        if (all is null)
        {
            Console.Error.WriteLine(Localizer.IsEnglish
            ? $"Failed to read rules: {error}"
            : $"读取规则失败：{error}");
            return ExitFailed;
        }

        var blocked = all
            .Where(rule => string.Equals(
                rule.Action, "block", StringComparison.OrdinalIgnoreCase))
            .ToList();
        var allowCount = all.Count - blocked.Count;

        Console.Write(CliText.BuildListBlockedOutput(blocked, allowCount, BuildVersionText()));
        return ExitOk;
    }

    private static int RunUnblockAll(bool confirmed)
    {
        // 1.x 的兜底：如果上次（1.x 时代）没正常退出，先把「默认阻止出站」还原成「允许」。
        // 2.0 自己不再写这个标志，所以新机器上这一步永远什么都不做。
        // 否则紧接着把白名单删光，等于让整台机器断网。
        var recovery = StrictModeManager.RecoverIfLeftOn();

        var rules = QueryRules(out var error);

        if (rules is null)
        {
            Console.Error.WriteLine(Localizer.IsEnglish
            ? $"Failed to read rules: {error}"
            : $"读取规则失败：{error}");
            return ExitFailed;
        }

        if (rules.Count == 0)
        {
            Console.WriteLine(Localizer.IsEnglish
            ? "There are no AppGuard rules to clean up."
            : "当前没有任何 AppGuard 规则，无需清理。");

            if (recovery.WasLeftOn)
            {
                Console.WriteLine($"已顺带还原严格模式：{recovery.Message}");
            }

            return ExitOk;
        }

        Console.Write(CliText.BuildUnblockPreview(rules));

        if (!confirmed)
        {
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
            Console.Error.WriteLine(Localizer.IsEnglish
            ? $"Delete failed: {response?.Error ?? deleteError}"
            : $"删除失败：{response?.Error ?? deleteError}");
            return ExitFailed;
        }

        var deleted = response.Affected;

        Console.WriteLine();
        Console.WriteLine(Localizer.IsEnglish
            ? $"Deleted {deleted} rules."
            : $"已删除 {deleted} 条规则。");
        Console.WriteLine("# 其他软件的规则、以及本工具在 WFP 里创建的过滤器之外的东西都没有受到影响。");

        if (recovery.WasLeftOn)
        {
            Console.WriteLine("1.x 遗留的「默认阻止出站」已还原成「允许」（上次没有正常退出）。");
        }

        LocalLog.Operation($"命令行：删除全部 AppGuard 规则，实际删除 {deleted} 条");
        return ExitOk;
    }

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

    /// <summary>
    /// 救命命令：把本程序留在系统里的一切都清掉。
    ///
    /// 三样东西缺一不可：
    ///   1. 2.0 在 WFP 里的对象（过滤器 + 子层）；
    ///   2. 1.x 遗留的「全局默认出站 = 阻止」—— 这一项最要命，它会让整台机器断网，
    ///      而且和"规则"看起来毫无关系，用户很难自己想到；
    ///   3. 1.x 遗留的 <c>AppGuard_*</c> Windows 防火墙规则。
    ///
    /// 只删本程序自己的东西：WFP 按子层 GUID 过滤，防火墙按 <c>AppGuard_</c> 前缀
    /// （安全闸在 <see cref="FirewallManager.DeleteRule"/> 里），别的软件和系统自带的一概不碰。
    /// </summary>
    private static int RunRecover()
    {
        // 1) 2.0 的对象。
        var report = WfpRecovery.Recover();
        Console.WriteLine(report.Describe());

        // 2) 1.x 的全局策略。
        var strict = StrictModeManager.RecoverIfLeftOn();
        Console.WriteLine(strict.WasLeftOn
            ? $"已还原 1.x 遗留的全局出站策略：{strict.Message}"
            : "1.x 的全局出站策略正常（没有遗留的「默认阻止」）。");

        // 3) 1.x 的规则。
        var legacy = FirewallManager.GetAppGuardRules();
        var deleted = 0;
        foreach (var rule in legacy)
        {
            if (FirewallManager.DeleteRule(rule.Name))
            {
                deleted++;
            }
        }

        Console.WriteLine(deleted > 0
            ? $"另外删除了 {deleted} 条 1.x 遗留的 Windows 防火墙规则。"
            : "没有 1.x 遗留的 Windows 防火墙规则。");

        Console.WriteLine();
        Console.WriteLine("# 其他软件和系统自带的规则 / WFP 对象没有受到影响。");

        LocalLog.Operation($"命令行：恢复（WFP：{report.Describe()}；1.x 规则删除 {deleted} 条）");
        return ExitOk;
    }

    private static int RunMigrate()
    {
        var report = StartupMigration.RunIfNeeded(out var error);

        if (error is not null)
        {
            Console.Error.WriteLine($"迁移失败：{error}");
            Console.Error.WriteLine("旧规则没有被动过；下次启动程序时会自动重试。");
            return ExitFailed;
        }

        if (report is null)
        {
            Console.WriteLine("没有需要迁移的 1.x 规则（Windows 防火墙里没有 AppGuard_ 规则）。");
            return ExitOk;
        }

        Console.WriteLine(
            $"迁移完成：成功 {report.Migrated} 条，跳过 {report.Skipped} 条，" +
            $"失败 {report.Failed} 条，删除旧规则 {report.FirewallRulesDeleted} 条。");

        foreach (var line in report.Details)
        {
            Console.WriteLine("  " + line);
        }

        if (!report.Succeeded)
        {
            Console.Error.WriteLine("有一次迁移失败：失败的规则保留在 Windows 防火墙里，可以再执行一次。");
            return ExitFailed;
        }

        return ExitOk;
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
        // ⚠️ 这里原本用 System.Windows.Forms.Application.ProductVersion。
        //    3.0 起 Core 是独立类库（服务也要引用它），不能依赖 WinForms；
        //    改成读入口程序集的 InformationalVersion，语义不变。
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
}
