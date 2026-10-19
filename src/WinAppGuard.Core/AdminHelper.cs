using System.ComponentModel;
using System.Diagnostics;
using System.Security.Principal;

namespace WinAppGuard.Core;

/// <summary>
/// 管理员权限相关工具。
///
/// 本程序需要创建/删除 Windows 防火墙规则、注册/注销计划任务，
/// 这些操作没有管理员权限会直接失败，所以启动时必须先确认权限状态。
/// </summary>
public static class AdminHelper
{
    /// <summary>
    /// 判断当前进程是否以管理员身份运行。
    /// </summary>
    public static bool IsRunningAsAdmin()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    /// <summary>
    /// 以管理员身份重新启动本程序，并把指定参数一起传过去。
    ///
    /// 实现方式：用 ShellExecute 的 "runas" 谓词拉起自身，由系统弹出 UAC 确认框。
    /// 用户点了「否」不会抛异常，只会返回 false。
    /// </summary>
    /// <param name="arguments">要传给新进程的命令行参数（不含 exe 路径）。</param>
    /// <returns>成功拉起提权进程返回 true；用户拒绝提权返回 false。</returns>
    public static bool RestartAsAdmin(string arguments)
    {
        // 单文件发布时 Environment.ProcessPath 返回的就是 exe 自身路径。
        var exePath = Environment.ProcessPath;
        if (string.IsNullOrEmpty(exePath))
        {
            return false;
        }

        var startInfo = new ProcessStartInfo
        {
            FileName = exePath,
            // runas 谓词必须配合 UseShellExecute = true 才能生效。
            UseShellExecute = true,
            Verb = "runas",
            Arguments = arguments,
        };

        try
        {
            Process.Start(startInfo);
            return true;
        }
        catch (Win32Exception)
        {
            // 最常见的情况：用户在 UAC 窗口点击了「否」。
            return false;
        }
        catch (InvalidOperationException)
        {
            // 极少数环境（如某些受限会话）不允许 runas。
            return false;
        }
    }

    /// <summary>
    /// 以管理员身份重新启动本程序。
    /// </summary>
    /// <param name="autostart">是否把 --autostart 参数一并传给新进程。</param>
    /// <returns>成功拉起提权进程返回 true；用户拒绝提权返回 false。</returns>
    public static bool RestartAsAdmin(bool autostart)
        => RestartAsAdmin(autostart ? AppConstants.AutostartArgument : string.Empty);
}
