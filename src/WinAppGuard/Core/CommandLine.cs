namespace WinAppGuard.Core;

/// <summary>命令行模式要执行的命令。</summary>
public enum CommandKind
{
    /// <summary>没有命令行指令 —— 照常启动图形界面（双击就是这个路径）。</summary>
    None,

    /// <summary><c>--block &lt;程序路径&gt;</c></summary>
    Block,

    /// <summary><c>--list-blocked</c></summary>
    ListBlocked,

    /// <summary><c>--unblock-all [--yes]</c></summary>
    UnblockAll,

    /// <summary><c>--migrate</c>：把 1.x 的规则迁到 2.0（通常不用手动执行）。</summary>
    Migrate,

    /// <summary><c>--help</c></summary>
    Help,

    /// <summary>参数写错了。</summary>
    Invalid,
}

/// <summary>解析后的命令行选项。</summary>
/// <param name="Kind">要执行的命令。</param>
/// <param name="ProgramPath"><c>--block</c> 的目标程序路径；其它命令为 null。</param>
/// <param name="Confirmed">是否带了 <c>--yes</c>（只有 <c>--unblock-all</c> 用）。</param>
/// <param name="IsAutostart">是否由「开机自启」计划任务拉起（命令行含 <c>--autostart</c>）。</param>
/// <param name="Error">参数错误时的说明；没错时为 null。</param>
public sealed record CommandLineOptions(
    CommandKind Kind,
    string? ProgramPath,
    bool Confirmed,
    bool IsAutostart,
    string? Error);

/// <summary>
/// 命令行参数解析。
///
/// 为什么单独做成一个**纯函数**类：解析规则是最容易出错、又最该被断言钉住的一块
/// （比如「--block 后面漏了路径」「多写了个 --yes」）。
/// 把它和控制台输出、防火墙操作分开，自检就能在**不需要管理员、不碰系统**的情况下
/// 把各种参数组合全测一遍。
///
/// 约定：
///   - 参数不区分大小写（Windows 习惯）；
///   - 只有 <c>--autostart</c> 被忽略掉之后**没有任何其它参数**时，才启动图形界面；
///   - 其余无法识别的参数一律算错 —— 静默忽略拼错的参数会让脚本"看起来成功了"。
/// </summary>
public static class CommandLine
{
    public const string BlockSwitch = "--block";
    public const string ListBlockedSwitch = "--list-blocked";
    public const string UnblockAllSwitch = "--unblock-all";
    public const string MigrateSwitch = "--migrate";
    public const string YesSwitch = "--yes";
    public const string HelpSwitch = "--help";
    public const string AutostartSwitch = "--autostart";

    /// <summary>解析命令行。</summary>
    /// <param name="args">命令行参数（不含程序名本身）。</param>
    public static CommandLineOptions Parse(IReadOnlyList<string> args)
    {
        var isAutostart = args.Any(arg => Is(arg, AutostartSwitch));

        // --help 优先级最高：给了就问用法，不管后面还写了什么。
        if (args.Any(arg => Is(arg, HelpSwitch) || Is(arg, "-h") || Is(arg, "/?")))
        {
            return new CommandLineOptions(CommandKind.Help, null, false, isAutostart, null);
        }

        // 除了 --autostart 之外的，才是真正的指令。
        var tokens = args.Where(arg => !Is(arg, AutostartSwitch)).ToList();

        if (tokens.Count == 0)
        {
            return new CommandLineOptions(CommandKind.None, null, false, isAutostart, null);
        }

        switch (tokens[0].ToLowerInvariant())
        {
            case BlockSwitch:
                if (tokens.Count < 2 || string.IsNullOrWhiteSpace(tokens[1]))
                {
                    return Invalid(isAutostart,
                        $"{BlockSwitch} 后面要跟程序的完整路径，例如：--block \"C:\\Tools\\a.exe\"");
                }

                return tokens.Count > 2
                    ? Invalid(isAutostart, $"多余的参数：{tokens[2]}")
                    : new CommandLineOptions(CommandKind.Block, tokens[1], false, isAutostart, null);

            case ListBlockedSwitch:
                return tokens.Count > 1
                    ? Invalid(isAutostart, $"多余的参数：{tokens[1]}")
                    : new CommandLineOptions(CommandKind.ListBlocked, null, false, isAutostart, null);

            case UnblockAllSwitch:
                // --yes 是"我确认要删"，可以放在命令后面任意位置。
                var confirmed = tokens.Skip(1).Any(arg => Is(arg, YesSwitch));
                var extras = tokens.Skip(1).Where(arg => !Is(arg, YesSwitch)).ToList();

                return extras.Count > 0
                    ? Invalid(isAutostart, $"无法识别的参数：{extras[0]}")
                    : new CommandLineOptions(CommandKind.UnblockAll, null, confirmed, isAutostart, null);

            case MigrateSwitch:
                return tokens.Count > 1
                    ? Invalid(isAutostart, $"多余的参数：{tokens[1]}")
                    : new CommandLineOptions(CommandKind.Migrate, null, false, isAutostart, null);

            default:
                return Invalid(isAutostart, $"无法识别的参数：{tokens[0]}");
        }
    }

    private static CommandLineOptions Invalid(bool isAutostart, string error)
        => new(CommandKind.Invalid, null, false, isAutostart, error);

    private static bool Is(string arg, string expected)
        => string.Equals(arg, expected, StringComparison.OrdinalIgnoreCase);
}
