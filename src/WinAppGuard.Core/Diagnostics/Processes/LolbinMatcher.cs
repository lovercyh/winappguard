namespace WinAppGuard.Core.Diagnostics.Processes;

/// <summary>
/// 6.0：LOLBin 命令行匹配器。
/// 只返回规则 ID；命令行原文不写日志、不写画像、不进诊断包。
/// </summary>
internal static class LolbinMatcher
{
    internal static string? Match(string imagePath, string commandLine)
    {
        if (string.IsNullOrWhiteSpace(imagePath))
        {
            return null;
        }

        var name = Path.GetFileName(imagePath);
        var cmd = commandLine ?? string.Empty;

        if (name.Equals("powershell.exe", StringComparison.OrdinalIgnoreCase)
            || name.Equals("pwsh.exe", StringComparison.OrdinalIgnoreCase))
        {
            if (Contains(cmd, "-enc") || Contains(cmd, "-encodedcommand"))
            {
                return "LOLBIN-POWERSHELL-ENCODED";
            }

            if (Contains(cmd, "downloadstring") || Contains(cmd, "invoke-webrequest")
                || Contains(cmd, "http://") || Contains(cmd, "https://"))
            {
                return "LOLBIN-POWERSHELL-DOWNLOAD";
            }
        }

        if (name.Equals("mshta.exe", StringComparison.OrdinalIgnoreCase)
            && (Contains(cmd, "http://") || Contains(cmd, "https://")
                || Contains(cmd, "javascript:") || Contains(cmd, "vbscript:")))
        {
            return "LOLBIN-MSHTA-REMOTE";
        }

        if (name.Equals("rundll32.exe", StringComparison.OrdinalIgnoreCase)
            && Contains(cmd, "javascript:"))
        {
            return "LOLBIN-RUNDLL32-SCRIPT";
        }

        if (name.Equals("regsvr32.exe", StringComparison.OrdinalIgnoreCase)
            && (Contains(cmd, "/i:http") || Contains(cmd, "scrobj.dll")))
        {
            return "LOLBIN-REGSVR32-SQUIBLYDOO";
        }

        if (name.Equals("certutil.exe", StringComparison.OrdinalIgnoreCase)
            && (Contains(cmd, "-urlcache") || Contains(cmd, "-decode")))
        {
            return "LOLBIN-CERTUTIL-DOWNLOAD";
        }

        if (name.Equals("bitsadmin.exe", StringComparison.OrdinalIgnoreCase)
            && Contains(cmd, "/transfer"))
        {
            return "LOLBIN-BITSADMIN-TRANSFER";
        }

        return null;
    }

    private static bool Contains(string text, string value)
        => text.Contains(value, StringComparison.OrdinalIgnoreCase);
}
