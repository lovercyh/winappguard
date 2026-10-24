using System.Diagnostics;
using WinAppGuard.Core;
using WinAppGuard.Core.ProtectedMode;
using WinAppGuard.Forms;
using WinAppGuard.Interop;
using WinAppGuard.Localization;

namespace WinAppGuard;

/// <summary>
/// 程序入口。
/// </summary>
internal static class Program
{
    /// <summary>
    /// 本次启动是否由「开机自启」计划任务拉起（命令行包含 --autostart）。
    /// 该标志为 true 时，程序启动后直接最小化到托盘而不显示主窗口。
    /// </summary>
    public static bool IsAutostart { get; private set; }

    [STAThread]
    private static int Main(string[] args)
    {
        // 全局异常兜底必须放在最前面，保证后面任何地方出错都能被接住。
        // 没有这一段的话，一个没接住的异常会让 Windows 弹出「已停止工作」那种
        // 什么都不说的崩溃框，用户既看不懂也没法反馈。
        Application.SetUnhandledExceptionMode(UnhandledExceptionMode.CatchException);
        Application.ThreadException += OnUiThreadException;
        AppDomain.CurrentDomain.UnhandledException += OnDomainUnhandledException;

        // 1) 解析命令行。
        //    --autostart 仍然只管「启动后最小化到托盘」；
        //    其它指令（--block / --list-blocked / --unblock-all）属于**命令行模式**：
        //    它们不碰界面，也**不参与单实例检查** —— 否则图形界面开着时，
        //    脚本里的 --block 会先被"已有实例在运行"拦下来、静默什么都不做。
        var options = CommandLine.Parse(args);
        IsAutostart = options.IsAutostart;

        if (options.Kind != CommandKind.None)
        {
            // 3.0-c：界面程序集不再包含 WFP 代码，命令行模式交给服务 exe 代跑。
            return ForwardCliToServiceExe(args);
        }

        // 图形界面模式：控制台子系统会带出一个黑框，这里立刻收掉它。
        // 命令行模式则要**留着**控制台 —— 那正是输出要走的地方。
        NativeMethods.FreeConsole();

        // 2) 1.x → 2.0 规则迁移已移到服务启动时执行（界面不再有 WFP 访问能力）。

        // 3) 单实例检查。
        //    没有这一层的话，用户第二次双击会多出一个托盘图标，
        //    而且两个实例会同时操作防火墙和计划任务。
        if (!SingleInstance.TryAcquire())
        {
            // 已经有实例在跑：请它把主窗口显示出来，然后本次安静退出。
            //
            // 但被开机自启拉起时不要弹窗 —— 那种情况下冒出来一个窗口是打扰。
            if (!IsAutostart)
            {
                SingleInstance.RequestShowMainWindow();
            }

            LocalLog.Info($"检测到已有实例在运行，本次启动（{AppConstants.AutostartArgument}模式={IsAutostart}）直接退出。");
            return 0;
        }

        // 4) 权限：3.0-c 起界面以普通权限运行（asInvoker）。
        //    查看/审计不需要管理员；改规则时由 CallService 走一次 UAC。
        //    自启任务以「最高权限」运行，所以自启场景下 isAdmin 通常为 true。
        var isAdmin = AdminHelper.IsRunningAsAdmin();

        LocalLog.Info(
            $"程序启动：版本 {Application.ProductVersion}，" +
            $"管理员权限={isAdmin}（按需提权），" +
            $"启动模式={(IsAutostart ? AppConstants.AutostartArgument : "手动")}，" +
            $"进程路径={Environment.ProcessPath}");

        // 4.5) 3.1：加载所有者密钥，给所有 IPC 请求签名。
        //      不是所有者 / DPAPI 解不开时不要崩：界面仍能启动，
        //      但 ServiceClient 会明确返回"未配置签名密钥"，显示为离线。
        if (ProtectedModeClient.TryConfigureSigner(out var fingerprint, out var authError))
        {
            LocalLog.Info($"受保护模式：已加载签名密钥（指纹 {fingerprint?[..16]}…）。");
        }
        else
        {
            LocalLog.Warning($"受保护模式：无法加载签名密钥（{authError}）。");
        }

        // 4.6) 3.2：按上次保存的语言初始化 GUI（auto 时跟随系统）。
        Localizer.Initialize(UiState.Load().Language);

        // 5) 启动界面。
        ApplicationConfiguration.Initialize();
        Application.Run(new MainForm(IsAutostart));
        return 0;
    }

    /// <summary>
    /// 界面线程里没被接住的异常。
    /// 记日志 + 给用户一个能看懂、能照着反馈的提示，然后**让程序继续运行** ——
    /// 只是某一次操作失败了，没必要把整个工具干掉（用户可能正靠它恢复被误拦的程序）。
    /// </summary>
    /// <summary>
    /// 把命令行参数转交给服务 exe（它包含 WFP 代码，界面不包含）。
    /// 用法对用户保持不变：<c>WinAppGuard.exe --block ...</c>。
    /// </summary>
    private static int ForwardCliToServiceExe(string[] args)
    {
        var exe = Path.Combine(AppContext.BaseDirectory, "WinAppGuardSvc.exe");

        if (!File.Exists(exe))
        {
            Console.Error.WriteLine(
                $"找不到 {exe}，无法执行命令行模式。请先安装防护服务（WinAppGuardSetup.exe --install）。");
            return 1;
        }

        try
        {
            var startInfo = new ProcessStartInfo(exe)
            {
                UseShellExecute = false,
            };

            startInfo.ArgumentList.Add("--cli");

            foreach (var arg in args)
            {
                startInfo.ArgumentList.Add(arg);
            }

            using var process = Process.Start(startInfo);

            if (process is null)
            {
                return 1;
            }

            process.WaitForExit();
            return process.ExitCode;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"执行命令行模式失败：{ex.Message}");
            return 1;
        }
    }

    private static void OnUiThreadException(object sender, ThreadExceptionEventArgs e)
    {
        LocalLog.Error("界面线程发生未处理的异常", e.Exception);

        UiMessageBox.Show(
            $"WinAppGuard 遇到了一个未预期的问题，程序会继续运行。\n\n" +
            $"出错信息：{e.Exception?.Message}\n\n" +
            $"详细信息已记录在本机日志里：\n{LocalLog.LogDirectory}",
            AppConstants.AppName,
            MessageBoxButtons.OK,
            MessageBoxIcon.Error);
    }

    /// <summary>
    /// 后台线程里没被接住的异常。这种异常进程即将结束，已经没法挽回，
    /// 这里能做的只有尽量留下一条可供排查的记录。
    /// </summary>
    private static void OnDomainUnhandledException(object sender, UnhandledExceptionEventArgs e)
    {
        LocalLog.Error(
            $"发生无法恢复的未处理异常（进程即将结束，IsTerminating={e.IsTerminating}）",
            e.ExceptionObject as Exception);
    }
}
