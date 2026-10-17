using System.Security.Cryptography;
using System.Text;

namespace WinAppGuard.Core;

/// <summary>
/// 规则名生成。
///
/// 1.x 与 2.0 **共用同一套命名**（例如 <c>AppGuard_Block_chrome.exe_1a2b3c4d</c>）：
/// 这样迁移前后用户看到的名字不变，日志和截图也能对得上。
///
/// 从 <see cref="FirewallManager"/> 抽出来的原因：2.0 的 WFP 规则也要用同一套名字，
/// 两边各写一份迟早会分叉。
///
/// 名字 = 前缀 + 文件名（过滤非法字符、最多 40 字）+ 路径短哈希。
/// 带哈希是因为同一个程序可能放在不同目录，光靠文件名会撞名；
/// 哈希取自完整路径（统一小写），保证"一个路径对应一个名字"。
/// </summary>
internal static class RuleNaming
{
    /// <summary>阻止规则名。</summary>
    internal static string BuildBlockRuleName(string programPath)
        => Build(AppConstants.RulePrefixBlock, programPath);

    /// <summary>允许规则名。</summary>
    internal static string BuildAllowRuleName(string programPath)
        => Build(AppConstants.RulePrefixAllow, programPath);

    /// <summary>按指定前缀生成规则名。</summary>
    internal static string Build(string prefix, string programPath)
    {
        var fileName = Path.GetFileName(programPath);
        var safeName = SanitizeForRuleName(fileName);

        if (safeName.Length > 40)
        {
            safeName = safeName[..40];
        }

        return $"{prefix}{safeName}_{ShortHash(programPath)}";
    }

    /// <summary>
    /// 规则名里只保留字母、数字和 . _ - ，其余一律换成下划线。
    /// 目的是保证规则名在各种界面里都能正常显示，不会因为特殊字符出问题。
    /// </summary>
    private static string SanitizeForRuleName(string value)
    {
        var builder = new StringBuilder(value.Length);

        foreach (var c in value)
        {
            builder.Append(char.IsLetterOrDigit(c) || c is '.' or '_' or '-' ? c : '_');
        }

        return builder.ToString();
    }

    /// <summary>
    /// 取路径的短哈希（8 个十六进制字符）。
    /// 先统一转成小写，保证同一个路径大小写不同也算同一个规则。
    /// </summary>
    private static string ShortHash(string value)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(value.ToLowerInvariant()));
        return Convert.ToHexString(bytes, 0, 4).ToLowerInvariant();
    }
}
