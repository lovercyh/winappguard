using System.Text;
using WinAppGuard.Contracts;
using WinAppGuard.Localization;
using WinAppGuard.Models;

namespace WinAppGuard.Core;

/// <summary>
/// 命令行模式的**文本输出**（纯函数，不写控制台、不读系统）。
///
/// 单独抽出来是为了能被自检直接断言：输出格式一旦变了，
/// 靠脚本解析输出的用户会悄悄坏掉，而这种问题光看代码发现不了。
///
/// 格式约定（对脚本友好）：
///   - 以 <c>#</c> 开头的是说明行，脚本可以整行跳过；
///   - 规则行是**一行一条**、用 <c>\t</c> 分隔：规则名、程序路径、自动解除方式。
/// </summary>
public static class CliText
{
    /// <summary>用法说明（按 CLI 当前语言选择）。</summary>
    public static string Usage => Localizer.IsEnglish ? UsageEn : UsageZh;

    private static string UsageZh { get; } = string.Join(Environment.NewLine, new[]
    {
        "WinAppGuard —— Windows 开源防火墙（命令行模式）",
        "",
        "  WinAppGuard.exe                              启动图形界面",
        "  WinAppGuard --version                    显示版本",
        "  WinAppGuard --status [--json]            服务 / 规则 / 检测状态",
        "  WinAppGuard --block \"C:\\Tools\\a.exe\"     阻止某个程序联网（可重复执行，幂等）",
        "  WinAppGuard --block <路径> --minutes 30   限时阻止；--until-reboot 到下次重启",
        "  WinAppGuard --block @列表.txt --yes       批量阻止（先 --dry-run 预览）",
        "  WinAppGuard --unblock <路径>              解除某个程序的阻止规则",
        "  WinAppGuard --unblock @列表.txt           批量解除列表里的程序",
        "  WinAppGuard --unblock-all [--yes]         删除本工具创建的全部规则",
        "  WinAppGuard --list-blocked                列出所有「阻止」规则",
        "  WinAppGuard --list-rules [--action block|allow|all] [--json]",
        "  WinAppGuard --export-rules <文件> [--action block|allow] [--yes 覆盖]",
        "  WinAppGuard --import-rules <文件> [--action block|allow] [--dry-run] [--yes]",
        "  WinAppGuard --network-status [--json]     反网络攻击状态",
        "  WinAppGuard --network-alerts [--limit N] [--unread] [--json]",
        "  WinAppGuard --network-ack <告警 id>       标记已读",
        "  WinAppGuard --network-clear --yes         清空告警",
        "  WinAppGuard --network-block <告警 id> --scope ip-port|connection|ip [--minutes N] --yes",
        "  WinAppGuard --network-unblock <拦截 id>   释放一个拦截",
        "  WinAppGuard --network-unblock-all --yes   释放全部拦截",
        "  WinAppGuard --network-set-adapter auto|<网卡 GUID>",
        "  WinAppGuard --network-set-categories malware,exploit,dns",
        "  WinAppGuard --audit-tail [--limit N] [--json]",
        "  WinAppGuard --connections [--limit N] [--json]",
        "  WinAppGuard --dns [--limit N] [--json]",
        "  WinAppGuard --doctor [--json]             只读诊断",
        "  WinAppGuard --log-path                    显示日志目录",
        "  WinAppGuard --migrate                     把 1.x 的规则迁到 2.0（启动时也会自动做）",
        "  WinAppGuard --recover                     清掉本程序留下的一切（出问题时的救命命令）",
        "  WinAppGuard --help                        显示这段帮助",
        "  WinAppGuard --lang zh|en|auto             本次 CLI 语言（不写则跟随 GUI）",
        "",
        "通用选项：",
        "  --json / --format json     机器可读输出（不带本地化文本）",
        "  --quiet                    只输出错误和必要结果",
        "  --dry-run                  只预览，不执行（写命令）",
        "",
        "说明：",
        "  - 只读命令（status / list / export / network-status / alerts / audit-tail / doctor）",
        "    只要求所有者账户；写命令（block / unblock / import / network-block 等）需要管理员权限。",
        "  - 命令行本身就是明确指令，所以这些命令不会弹确认框；批量或不可逆操作需要 --yes。",
        "  - 图形界面里的操作仍然每一条都要确认。",
        "  - 退出码：0 成功 / 1 参数错误或未确认 / 2 执行失败 / 3 缺少管理员权限 / 4 未找到。",
        "",
    });

    private static string UsageEn { get; } = string.Join(Environment.NewLine, new[]
    {
        "WinAppGuard — Windows program network control (command line)",
        "",
        "  WinAppGuard.exe                              start the GUI",
        "  WinAppGuard --version                    show version",
        "  WinAppGuard --status [--json]            service / rules / detection status",
        "  WinAppGuard --block \"C:\\Tools\\a.exe\"     block a program (idempotent)",
        "  WinAppGuard --block <path> --minutes 30  timed block; --until-reboot for next restart",
        "  WinAppGuard --block @list.txt --yes      block a list of programs (preview with --dry-run)",
        "  WinAppGuard --unblock <path>             remove block rules for one program",
        "  WinAppGuard --unblock @list.txt          remove block rules for programs in a list",
        "  WinAppGuard --unblock-all [--yes]        delete all rules created by this tool",
        "  WinAppGuard --list-blocked               list all block rules",
        "  WinAppGuard --list-rules [--action block|allow|all] [--json]",
        "  WinAppGuard --export-rules <file> [--action block|allow] [--yes to overwrite]",
        "  WinAppGuard --import-rules <file> [--action block|allow] [--dry-run] [--yes]",
        "  WinAppGuard --network-status [--json]    anti-network attack status",
        "  WinAppGuard --network-alerts [--limit N] [--unread] [--json]",
        "  WinAppGuard --network-ack <alert id>     mark as read",
        "  WinAppGuard --network-clear --yes        clear alerts",
        "  WinAppGuard --network-block <alert id> --scope ip-port|connection|ip [--minutes N] --yes",
        "  WinAppGuard --network-unblock <block id> release one block",
        "  WinAppGuard --network-unblock-all --yes  release all blocks",
        "  WinAppGuard --network-set-adapter auto|<adapter GUID>",
        "  WinAppGuard --network-set-categories malware,exploit,dns",
        "  WinAppGuard --audit-tail [--limit N] [--json]",
        "  WinAppGuard --connections [--limit N] [--json]",
        "  WinAppGuard --dns [--limit N] [--json]",
        "  WinAppGuard --doctor [--json]            read-only diagnostics",
        "  WinAppGuard --log-path                   show log directories",
        "  WinAppGuard --migrate                    migrate 1.x rules (also runs at startup)",
        "  WinAppGuard --recover                    remove everything this tool left behind",
        "  WinAppGuard --help                       show this help",
        "  WinAppGuard --lang zh|en|auto            CLI language for this invocation (default: GUI)",
        "",
        "Common options:",
        "  --json / --format json     machine-readable output (no localized text)",
        "  --quiet                    only errors and essential results",
        "  --dry-run                  preview only (write commands)",
        "",
        "Notes:",
        "  - Read-only commands (status / list / export / network-status / alerts / audit-tail / doctor)",
        "    only require the owner account; write commands (block / unblock / import / network-block etc.)",
        "    require administrator rights.",
        "  - The command line is an explicit instruction, so these commands never prompt; batch or",
        "    irreversible actions require --yes.",
        "  - GUI actions still ask for confirmation.",
        "  - Exit codes: 0 success / 1 bad arguments or not confirmed / 2 failed / 3 not elevated / 4 not found.",
        "",
    });

    /// <summary>
    /// 一行规则：<c>规则名 \t 程序路径 \t 自动解除方式</c>。
    /// </summary>
    private static string DescribeExpiry(RuleExpiry expiry)
        => Localizer.IsEnglish
            ? expiry.Kind switch
            {
                RuleExpiryKind.Never => "Permanent",
                RuleExpiryKind.OnNextBoot => "Until next restart",
                _ => "Timed",
            }
            : expiry.Describe(DateTime.UtcNow);

    public static string FormatRuleLine(FirewallRuleItem rule)
        => $"{rule.Name}\t{rule.ApplicationPath}\t{DescribeExpiry(rule.Expiry)}";

    /// <summary>3.1：服务返回的 DTO 版本（CLI 不再直接读 WFP）。</summary>
    public static string FormatRuleLine(RuleDto rule)
    {
        var expiry = DescribeExpiry(RuleExpiry.Parse(rule.Expiry));
        return $"{rule.Name}\t{rule.Value}\t{expiry}";
    }

    /// <summary>
    /// 生成 <c>--list-blocked</c> 的完整输出。
    /// </summary>
    /// <param name="blockedRules">「阻止」规则（调用方已经筛好）。</param>
    /// <param name="allowRuleCount">
    /// 「允许」规则（白名单）的条数。这里**不列**它们，但要如实说明有多少条 ——
    /// 否则用户会以为本工具只建了阻止规则。
    /// </param>
    /// <param name="version">版本号，用在标题行里。</param>
    public static string BuildListBlockedOutput(
        IReadOnlyList<FirewallRuleItem> blockedRules,
        int allowRuleCount,
        string version)
    {
        var builder = new StringBuilder();

        builder.AppendLine(Localizer.IsEnglish
            ? $"# WinAppGuard {version} — blocked programs: {blockedRules.Count}"
            : $"# WinAppGuard {version} —— 已阻止的程序：{blockedRules.Count} 条");
        builder.AppendLine(Localizer.IsEnglish
            ? "# rule name\tprogram path\texpiry"
            : "# 规则名\t程序路径\t自动解除");

        if (blockedRules.Count == 0)
        {
            builder.AppendLine(Localizer.IsEnglish ? "# (no block rules)" : "# （没有阻止规则）");
        }
        else
        {
            foreach (var rule in blockedRules)
            {
                builder.AppendLine(FormatRuleLine(rule));
            }
        }

        if (allowRuleCount > 0)
        {
            builder.AppendLine(Localizer.IsEnglish
                ? $"# There are also {allowRuleCount} allow (whitelist) rules; this command does not list them. Manage them on the Rules page."
                : $"# 另有 {allowRuleCount} 条「允许」规则（白名单），本命令不列出；" +
                  "要管理它们在图形界面的「规则」页里看。");
        }

        return builder.ToString();
    }

    /// <summary>3.1：服务 DTO 版本的 --list-blocked 输出。</summary>
    public static string BuildListBlockedOutput(
        IReadOnlyList<RuleDto> blockedRules, int allowRuleCount, string version)
    {
        var builder = new StringBuilder();

        builder.AppendLine(Localizer.IsEnglish
            ? $"# WinAppGuard {version} — blocked programs: {blockedRules.Count}"
            : $"# WinAppGuard {version} —— 已阻止的程序：{blockedRules.Count} 条");
        builder.AppendLine(Localizer.IsEnglish
            ? "# rule name\tprogram path\texpiry"
            : "# 规则名\t程序路径\t自动解除");

        if (blockedRules.Count == 0)
        {
            builder.AppendLine(Localizer.IsEnglish ? "# (no block rules)" : "# （没有阻止规则）");
        }
        else
        {
            foreach (var rule in blockedRules)
            {
                builder.AppendLine(FormatRuleLine(rule));
            }
        }

        if (allowRuleCount > 0)
        {
            builder.AppendLine(Localizer.IsEnglish
                ? $"# There are also {allowRuleCount} allow (whitelist) rules; this command does not list them. Manage them on the Rules page."
                : $"# 另有 {allowRuleCount} 条「允许」规则（白名单），本命令不列出；"
                  + "要管理它们在图形界面的「规则」页里看。");
        }

        return builder.ToString();
    }

    /// <summary>生成 <c>--unblock-all</c> 的"待删除清单"。</summary>
    public static string BuildUnblockPreview(IReadOnlyList<FirewallRuleItem> rules)
    {
        var builder = new StringBuilder();

        builder.AppendLine(Localizer.IsEnglish
            ? $"# This will delete {rules.Count} AppGuard rules:"
            : $"# 将要删除这 {rules.Count} 条 AppGuard 规则：");
        foreach (var rule in rules)
        {
            builder.AppendLine(FormatRuleLine(rule));
        }

        return builder.ToString();
    }

    /// <summary>3.1：服务 DTO 版本的 --unblock-all 预览。</summary>
    public static string BuildUnblockPreview(IReadOnlyList<RuleDto> rules)
    {
        var builder = new StringBuilder();

        builder.AppendLine(Localizer.IsEnglish
            ? $"# This will delete {rules.Count} AppGuard rules:"
            : $"# 将要删除这 {rules.Count} 条 AppGuard 规则：");
        foreach (var rule in rules)
        {
            builder.AppendLine(FormatRuleLine(rule));
        }

        return builder.ToString();
    }
}
