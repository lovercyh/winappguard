using System.Text;
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
    /// <summary>用法说明。</summary>
    public static string Usage { get; } = string.Join(Environment.NewLine, new[]
    {
        "WinAppGuard —— Windows 程序联网控制工具（命令行模式）",
        "",
        "  WinAppGuard.exe                              启动图形界面",
        "  WinAppGuard.exe --block \"C:\\Tools\\a.exe\"     阻止某个程序联网（可重复执行，幂等）",
        "  WinAppGuard.exe --list-blocked               列出所有「阻止」规则",
        "  WinAppGuard.exe --unblock-all [--yes]        删除本工具创建的全部规则",
        "  WinAppGuard.exe --help                       显示这段帮助",
        "",
        "说明：",
        "  - 所有命令都需要管理员权限（包括 --help）：程序的清单要求提权，",
        "    请从「以管理员身份运行」的终端里执行。",
        "  - 命令行本身就是明确指令，所以这些命令不会弹确认框；",
        "    图形界面里的操作仍然每一条都要确认。",
        "  - 退出码：0 成功 / 1 参数错误或未确认 / 2 执行失败 / 3 缺少管理员权限。",
        "",
    });

    /// <summary>
    /// 一行规则：<c>规则名 \t 程序路径 \t 自动解除方式</c>。
    /// </summary>
    public static string FormatRuleLine(FirewallRuleItem rule)
        => $"{rule.Name}\t{rule.ApplicationPath}\t{rule.ExpiryText}";

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

        builder.AppendLine($"# WinAppGuard {version} —— 已阻止的程序：{blockedRules.Count} 条");
        builder.AppendLine("# 规则名\t程序路径\t自动解除");

        if (blockedRules.Count == 0)
        {
            builder.AppendLine("# （没有阻止规则）");
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
            builder.AppendLine(
                $"# 另有 {allowRuleCount} 条「允许」规则（白名单），本命令不列出；" +
                "要管理它们在图形界面的「规则」页里看。");
        }

        return builder.ToString();
    }

    /// <summary>生成 <c>--unblock-all</c> 的"待删除清单"。</summary>
    public static string BuildUnblockPreview(IReadOnlyList<FirewallRuleItem> rules)
    {
        var builder = new StringBuilder();

        builder.AppendLine($"# 将要删除这 {rules.Count} 条 AppGuard 规则：");
        foreach (var rule in rules)
        {
            builder.AppendLine(FormatRuleLine(rule));
        }

        return builder.ToString();
    }
}
