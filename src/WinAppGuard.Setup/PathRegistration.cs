using System.Runtime.InteropServices;
using Microsoft.Win32;
using WinAppGuard.Core;

namespace WinAppGuard.Setup;

/// <summary>
/// 5.4：安装时把安装目录加入系统 PATH，卸载时移除。
///
/// 关键点：
///   - 修改的是 Machine PATH，所有用户都能直接运行 WinAppGuard.exe；
///   - 保留原来的值类型（REG_EXPAND_SZ / REG_SZ），不把 %SystemRoot% 这类变量写坏；
///   - 只追加/删除安装目录，其它 PATH 项原样保留；
///   - 修改后广播 WM_SETTINGCHANGE，新开的终端能拿到新 PATH；
///   - 已经打开着的终端不会被刷新，必须重开。
/// </summary>
internal static class PathRegistration
{
    private const string EnvironmentKey =
        @"SYSTEM\CurrentControlSet\Control\Session Manager\Environment";

    private const int MaxPathLength = 30_000;

    internal static bool TryAdd(string directory, out string? error)
        => Update(directory, add: true, out error);

    internal static bool TryRemove(string directory, out string? error)
        => Update(directory, add: false, out error);

    /// <summary>只读校验：Machine PATH 里是否真的有这个目录。</summary>
    internal static bool IsRegistered(string directory, out string? error)
    {
        error = null;

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(EnvironmentKey);
            var raw = key?.GetValue(
                "Path", string.Empty, RegistryValueOptions.DoNotExpandEnvironmentNames)
                as string ?? string.Empty;

            return EnvironmentPath.Contains(raw, directory);
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    private static bool Update(string directory, bool add, out string? error)
    {
        error = null;

        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                EnvironmentKey, writable: true);

            if (key is null)
            {
                error = @"打不开系统环境变量注册表项。";
                return false;
            }

            var raw = key.GetValue(
                "Path", string.Empty, RegistryValueOptions.DoNotExpandEnvironmentNames)
                as string ?? string.Empty;

            var valueKind = RegistryValueKind.String;

            try
            {
                valueKind = key.GetValueKind("Path");
            }
            catch (Exception)
            {
                // 没有 Path 值时按普通字符串写。
            }

            var updated = add
                ? EnvironmentPath.Add(raw, directory)
                : EnvironmentPath.Remove(raw, directory);

            if (string.Equals(updated, raw, StringComparison.Ordinal))
            {
                return true;
            }

            if (updated.Length > MaxPathLength)
            {
                error = $"系统 PATH 太长（{updated.Length} 字符，上限 {MaxPathLength}），未修改。";
                return false;
            }

            key.SetValue(
                "Path",
                updated,
                valueKind == RegistryValueKind.ExpandString
                    ? RegistryValueKind.ExpandString
                    : RegistryValueKind.String);

            BroadcastEnvironmentChange();
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    private const uint HwndBroadcast = 0xFFFF;
    private const uint WmSettingChange = 0x001A;
    private const uint SmtoAbortIfHung = 0x0002;

    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr SendMessageTimeout(
        IntPtr hWnd,
        uint message,
        UIntPtr wParam,
        string lParam,
        uint flags,
        uint timeout,
        out UIntPtr result);

    private static void BroadcastEnvironmentChange()
    {
        try
        {
            _ = SendMessageTimeout(
                new IntPtr(unchecked((int)HwndBroadcast)),
                WmSettingChange,
                UIntPtr.Zero,
                "Environment",
                SmtoAbortIfHung,
                1000,
                out _);
        }
        catch (Exception)
        {
            // 广播失败不影响安装；新进程可能仍会继承旧 PATH。
        }
    }
}
