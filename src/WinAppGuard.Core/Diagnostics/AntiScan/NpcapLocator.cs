using System.Diagnostics;
using Microsoft.Win32;

namespace WinAppGuard.Core.Diagnostics.AntiScan;

/// <summary>4.7：Npcap 安装状态（版本低于最低要求时按“不可用”处理）。</summary>
public enum NpcapState
{
    /// <summary>没有 wpcap.dll。</summary>
    Missing,

    /// <summary>已安装，但版本低于最低要求。</summary>
    TooOld,

    /// <summary>已安装且版本满足要求。</summary>
    Ok,

    /// <summary>已安装，但读不到安装包版本（便携/企业镜像）；允许使用，界面提示建议升级。</summary>
    Unknown,
}

/// <summary>
/// 4.0：定位已安装的 Npcap；4.7 起增加最低版本检查。
///
/// 版本来源：Npcap 安装器写入的 `NpcapInst\DisplayVersion`。
/// **不要用 wpcap.dll 的文件版本**：那是 libpcap 的版本（如 1.10.5），不是 Npcap 版本。
/// </summary>
public static class NpcapLocator
{
    /// <summary>4.7：最低支持的 Npcap 版本。</summary>
    public const string MinimumVersionText = "1.80";

    private const int MinimumMajor = 1;
    private const int MinimumMinor = 80;

    public static string? FindWpcapPath()
    {
        var root = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
        var path = Path.Combine(root, "System32", "Npcap", "wpcap.dll");
        return File.Exists(path) ? path : null;
    }

    /// <summary>是否“装了”（不判断版本），用于区分“没装”和“过旧”。</summary>
    public static bool IsInstalled => FindWpcapPath() is not null;

    /// <summary>当前安装状态；version 是读到的 Npcap 版本（可能为空）。</summary>
    public static NpcapState GetState(out string? version)
    {
        version = ReadInstalledVersion();

        if (FindWpcapPath() is null)
        {
            return NpcapState.Missing;
        }

        if (string.IsNullOrWhiteSpace(version) || !TryParseVersion(version, out var major, out var minor))
        {
            return NpcapState.Unknown;
        }

        return major > MinimumMajor || (major == MinimumMajor && minor >= MinimumMinor)
            ? NpcapState.Ok
            : NpcapState.TooOld;
    }

    /// <summary>Npcap 是否可用于采集：已安装且版本达标（版本未知时按可用处理）。</summary>
    public static bool IsAvailable
        => GetState(out _) is NpcapState.Ok or NpcapState.Unknown;

    /// <summary>已安装但版本过旧。</summary>
    public static bool IsTooOld => GetState(out _) == NpcapState.TooOld;

    /// <summary>给日志/状态行用的原因说明。</summary>
    public static string GetUnavailableReason()
    {
        var state = GetState(out var version);

        return state switch
        {
            NpcapState.Missing => "Npcap 未安装。",
            NpcapState.TooOld =>
                $"Npcap {version} 版本过旧（最低 {MinimumVersionText}），请升级。",
            _ => string.Empty,
        };
    }

    /// <summary>
    /// 读取 Npcap 安装包版本；读不到返回 null。
    /// 参数 wpcapPath 仅为兼容旧调用（以前用它读 libpcap 文件版本），
    /// 4.7 起不再把 libpcap 版本当作 Npcap 版本。
    /// </summary>
    public static string? GetVersion(string? wpcapPath = null)
    {
        _ = wpcapPath;
        return ReadInstalledVersion();
    }

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
                // 读注册表失败时退化为“版本未知”，不影响已装驱动的使用。
            }
        }

        return null;
    }

    /// <summary>
    /// 4.7：优先用安装包版本；注册表缺失时读 <c>drivers\npcap.sys</c> 的文件版本。
    /// 旧版 Npcap（1.7x）有时没有 Uninstall\NpcapInst 的 DisplayVersion，
    /// 但驱动文件版本仍然是 Npcap 自己的版本（不是 libpcap 版本）。
    /// </summary>
    private static string? ReadInstalledVersion()
    {
        var packageVersion = ReadPackageVersion();

        if (!string.IsNullOrWhiteSpace(packageVersion))
        {
            return packageVersion;
        }

        try
        {
            var driver = Path.Combine(Environment.SystemDirectory, "drivers", "npcap.sys");

            if (!File.Exists(driver))
            {
                return null;
            }

            var fileVersion = FileVersionInfo.GetVersionInfo(driver).FileVersion;
            return string.IsNullOrWhiteSpace(fileVersion) ? null : fileVersion.Trim();
        }
        catch (Exception)
        {
            return null;
        }
    }

    /// <summary>
    /// 解析 Npcap 版本。Npcap 用两位次版本号（1.80 / 1.90），
    /// 但 `1.8` 这种写法也按 1.80 处理，避免误判为过旧。
    /// </summary>
    private static bool TryParseVersion(string text, out int major, out int minor)
    {
        major = 0;
        minor = 0;

        var parts = text.Trim().Split('.', StringSplitOptions.RemoveEmptyEntries);

        if (parts.Length < 2
            || !int.TryParse(parts[0], out major)
            || !int.TryParse(parts[1], out minor))
        {
            return false;
        }

        if (parts[1].Length == 1)
        {
            minor *= 10;
        }

        return true;
    }
}
