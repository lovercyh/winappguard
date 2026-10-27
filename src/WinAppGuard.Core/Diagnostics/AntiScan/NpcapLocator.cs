using System.Diagnostics;

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

    public static string? GetVersion(string? wpcapPath = null)
    {
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
}
