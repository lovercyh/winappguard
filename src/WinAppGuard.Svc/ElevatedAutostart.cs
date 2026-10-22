using WinAppGuard.Core;

namespace WinAppGuard.Service;

/// <summary>
/// 提权助手：开启 / 关闭开机自启（普通权限界面用）。
///
/// 用法：<c>WinAppGuardSvc.exe --elevated-autostart enable|disable "&lt;界面 exe&gt;"</c>
/// 以 runas 启动，运行身份仍是当前用户（只是提权），所以计划任务属于该用户，
/// 且保持 HIGHEST 运行级别（登录时不会弹 UAC）。
/// </summary>
internal static class ElevatedAutostart
{
    internal static int Run(string[] args)
    {
        if (!AdminHelper.IsRunningAsAdmin())
        {
            return 3;
        }

        var index = Array.FindIndex(
            args, arg => arg.Equals("--elevated-autostart", StringComparison.OrdinalIgnoreCase));

        if (index < 0 || index + 1 >= args.Length)
        {
            return 1;
        }

        var action = args[index + 1];

        try
        {
            if (action.Equals("enable", StringComparison.OrdinalIgnoreCase))
            {
                if (index + 2 >= args.Length)
                {
                    return 1;
                }

                var uiPath = args[index + 2];

                if (!File.Exists(uiPath))
                {
                    return 2;
                }

                AutoStartManager.Enable(uiPath);
                return 0;
            }

            if (action.Equals("disable", StringComparison.OrdinalIgnoreCase))
            {
                _ = AutoStartManager.Disable();
                return 0;
            }

            return 1;
        }
        catch (Exception)
        {
            return 2;
        }
    }
}
