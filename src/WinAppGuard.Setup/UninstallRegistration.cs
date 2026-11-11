using System.Reflection;
using Microsoft.Win32;

namespace WinAppGuard.Setup;

/// <summary>
/// 5.9：把 WinAppGuard 注册到 Windows 的「设置 → 应用 → 已安装的应用」。
///
/// 本项目使用自己的 Setup/Uninstall 程序，不是 MSI，所以必须显式写
/// <c>HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\WinAppGuard</c>。
/// 只写标准卸载键，不写 SystemComponent，避免被 Windows 隐藏。
/// </summary>
internal static class UninstallRegistration
{
    private const string KeyName = "WinAppGuard";

    private const string KeyPath =
        @"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" + KeyName;

    internal static void Register(string installDirectory)
    {
        var ui = Path.Combine(installDirectory, "WinAppGuard.exe");
        var uninstaller = Path.Combine(installDirectory, "WinAppGuardUninstall.exe");

        using var baseKey = RegistryKey.OpenBaseKey(
            RegistryHive.LocalMachine, RegistryView.Registry64);
        using var key = baseKey.CreateSubKey(KeyPath, writable: true)
                        ?? throw new InvalidOperationException("无法创建卸载注册表项。");

        key.SetValue("DisplayName", "WinAppGuard", RegistryValueKind.String);
        key.SetValue("DisplayVersion", DisplayVersion(), RegistryValueKind.String);
        key.SetValue("Publisher", "lovercyh", RegistryValueKind.String);
        key.SetValue("InstallLocation", installDirectory, RegistryValueKind.String);
        key.SetValue("DisplayIcon", $"\"{ui}\",0", RegistryValueKind.String);
        key.SetValue(
            "UninstallString",
            $"\"{uninstaller}\" --uninstall",
            RegistryValueKind.String);
        key.SetValue(
            "QuietUninstallString",
            $"\"{uninstaller}\" --uninstall",
            RegistryValueKind.String);
        key.SetValue("InstallDate", DateTime.Now.ToString("yyyyMMdd"), RegistryValueKind.String);
        key.SetValue("URLInfoAbout", "https://github.com/lovercyh/winappguard", RegistryValueKind.String);
        key.SetValue("NoModify", 1, RegistryValueKind.DWord);
        key.SetValue("NoRepair", 1, RegistryValueKind.DWord);

        var sizeKb = EstimateSizeKb(installDirectory);

        if (sizeKb > 0)
        {
            key.SetValue("EstimatedSize", sizeKb, RegistryValueKind.DWord);
        }
    }

    internal static bool IsRegistered()
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(
                RegistryHive.LocalMachine, RegistryView.Registry64);
            using var key = baseKey.OpenSubKey(KeyPath, writable: false);

            return key?.GetValue("DisplayName") is string name
                   && string.Equals(name, "WinAppGuard", StringComparison.Ordinal);
        }
        catch (Exception)
        {
            return false;
        }
    }

    internal static void Unregister()
    {
        try
        {
            using var baseKey = RegistryKey.OpenBaseKey(
                RegistryHive.LocalMachine, RegistryView.Registry64);
            baseKey.DeleteSubKeyTree(KeyPath, throwOnMissingSubKey: false);
        }
        catch (Exception ex)
        {
            Bilingual.Fail(
                $"删除「已安装的应用」注册项失败：{ex.Message}",
                $"Failed to remove the Installed apps entry: {ex.Message}");
        }
    }

    private static string DisplayVersion()
    {
        var informational = typeof(UninstallRegistration).Assembly
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?
            .InformationalVersion;

        if (!string.IsNullOrWhiteSpace(informational))
        {
            var plus = informational.IndexOf('+');
            return plus > 0 ? informational[..plus] : informational;
        }

        var version = typeof(UninstallRegistration).Assembly.GetName().Version;
        return version is null ? "0.0.0" : version.ToString(3);
    }

    private static int EstimateSizeKb(string directory)
    {
        try
        {
            if (!Directory.Exists(directory))
            {
                return 0;
            }

            var bytes = Directory
                .EnumerateFiles(directory, "*", SearchOption.AllDirectories)
                .Sum(file =>
                {
                    try
                    {
                        return new FileInfo(file).Length;
                    }
                    catch (Exception)
                    {
                        return 0L;
                    }
                });

            return (int)Math.Min(int.MaxValue, Math.Max(0, bytes / 1024));
        }
        catch (Exception)
        {
            return 0;
        }
    }
}
