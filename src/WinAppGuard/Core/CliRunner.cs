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
                // 读/改防火墙都要管理员权限。
                if (!AdminHelper.IsRunningAsAdmin())
                {
                    Console.Error.WriteLine("需要管理员权限：请从「以管理员身份运行」的终端里执行本命令。");
                    return ExitNotAdmin;
                }

                try
                {
                    return options.Kind switch
                    {
                        CommandKind.Block => RunBlock(options.ProgramPath!),
                        CommandKind.ListBlocked => RunListBlocked(),
                        _ => RunUnblockAll(options.Confirmed),
                    };
                }
                catch (Exception ex)
                {
                    // 命令行模式绝不能把异常抛给 Windows 的崩溃框 —— 无人值守时会卡住。
                    Console.Error.WriteLine($"执行失败：{ex.Message}");
                    LocalLog.Error($"命令行模式执行失败（{options.Kind}）", ex);
                    return ExitFailed;
                }

            default:
                return ExitOk;
        }
    }

    private static int RunBlock(string programPath)
    {
        var fullPath = TryResolvePath(programPath);

        // 非法路径这里返回 false（不抛），所以正好拿来判断"是不是已经拦过了"。
        var alreadyBlocked = FirewallManager.IsProgramBlocked(fullPath);

        var ruleName = FirewallManager.CreateBlockRule(fullPath);

        Console.WriteLine(alreadyBlocked
            ? $"该程序已经在阻止列表中：{fullPath}"
            : $"已阻止：{fullPath}");

        Console.WriteLine($"  规则名：{ruleName}");

        LocalLog.Operation($"命令行：阻止联网 {fullPath}（规则 {ruleName}）");
        return ExitOk;
    }

    private static int RunListBlocked()
    {
        var all = FirewallManager.GetAppGuardRules();
        var blocked = all.Where(rule => rule.Action == FirewallAction.Block).ToList();
        var allowCount = all.Count - blocked.Count;

        Console.Write(CliText.BuildListBlockedOutput(blocked, allowCount, BuildVersionText()));
        return ExitOk;
    }

    private static int RunUnblockAll(bool confirmed)
    {
        // 严格模式的兜底：如果上次没正常退出，先把「默认阻止出站」还原成「允许」。
        // 否则紧接着把白名单删光，等于让整台机器断网。
        var recovery = StrictModeManager.RecoverIfLeftOn();

        var rules = FirewallManager.GetAppGuardRules();

        if (rules.Count == 0)
        {
            Console.WriteLine("当前没有任何 AppGuard 规则，无需清理。");

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
            Console.WriteLine("没有删除任何东西。确认要删就再加一个 --yes：");
            Console.WriteLine("  WinAppGuard.exe --unblock-all --yes");
            return ExitUsage;
        }

        var deleted = FirewallManager.DeleteAllAppGuardRules();

        Console.WriteLine();
        Console.WriteLine($"已删除 {deleted} 条规则。");
        Console.WriteLine("# 其他软件和系统自带的防火墙规则没有受到影响。");

        if (recovery.WasLeftOn)
        {
            Console.WriteLine("严格模式的「默认阻止出站」已还原成「允许」（上次没有正常退出）。");
        }

        LocalLog.Operation($"命令行：删除全部 AppGuard 规则，实际删除 {deleted} 条");
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
        var version = System.Windows.Forms.Application.ProductVersion;
        var plus = version.IndexOf('+');
        return plus > 0 ? version[..plus] : version;
    }
}
