using System.Diagnostics;
using Microsoft.Win32;

namespace WinAppGuard.Core.Diagnostics.AntiScan;

/// <summary>4.0：定位已安装的 Npcap。</summary>
public static class NpcapLocator
{
    public static string? FindWpcapPath()
    {
        var root = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var path = Path.Combine(root, "System32", "Npcap", "wpcap.dll");
        return File.Exists(path) ? path : null;
    }

    /// <summary>
    /// 读取 Npcap 版本。
    ///
    /// ⚠️ 不能直接用 <c>wpcap.dll</c> 的文件版本：那里写的是 libpcap 兼容层版本
    /// （例如 1.10.5），不是用户安装的 Npcap 版本（例如 1.90），显示出来会让人以为装错了。
    /// 优先读 Npcap 安装器自己写的卸载项 <c>NpcapInst</c> 的 DisplayVersion。
    /// </summary>
    public static string? GetVersion(string? wpcapPath = null)
    {
        var packageVersion = ReadPackageVersion();

        if (!string.IsNullOrWhiteSpace(packageVersion))
        {
            return packageVersion;
        }

        var path = wpcapPath ?? FindWpcapPath();

        if (path is null)
        {
            return null;
        }

        try
        {
            return FileVersionInfo.GetVersionInfo(path).FileVersion;
        }
        catch (Exception)
        {
            return null;
        }
    }

    public static bool IsAvailable => FindWpcapPath() is not null;

    private static string? ReadPackageVersion()
    {
        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            try
            {
                using var root = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
                using var key = root.OpenSubKey(
                    @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\NpcapInst");

                if (key?.GetValue("DisplayVersion") is string version
                    && !string.IsNullOrWhiteSpace(version))
                {
                    return version.Trim();
                }
            }
            catch (Exception)
            {
                // 读注册表失败时退回到文件版本，不影响功能。
            }
        }

        return null;
    }
}
