using WinAppGuard.Core;
using WinAppGuard.Forms;
using WinAppGuard.Interop;

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
            return CliRunner.Run(options);
        }

        // 图形界面模式：控制台子系统会带出一个黑框，这里立刻收掉它。
        // 命令行模式则要**留着**控制台 —— 那正是输出要走的地方。
        NativeMethods.FreeConsole();

        // 2) 1.x → 2.0 规则迁移（没有旧规则时什么都不做；失败也不影响启动）。
        //
        //    ★ 刻意放在「单实例检查」**之前**：如果用户已经开着一个窗口，
        //      再启动一次会静默退出 —— 那时代码根本走不到迁移，用户会以为升级失败。
        //      迁移本身是幂等的（写入先删后加、删除容忍不存在），两个实例同时跑也没问题。
        StartupMigration.RunIfNeeded(out _);

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

        // 4) 管理员权限检测。
        //    正常情况下 app.manifest 已经声明了 requireAdministrator，进程启动时就已经提权；
        //    这里再做一次运行时检查，是为了兜住「被计划任务以普通权限拉起」这类异常情况。
        var isAdmin = AdminHelper.IsRunningAsAdmin();

        LocalLog.Info(
            $"程序启动：版本 {Application.ProductVersion}，" +
            $"管理员权限={isAdmin}，" +
            $"启动模式={(IsAutostart ? AppConstants.AutostartArgument : "手动")}，" +
            $"进程路径={Environment.ProcessPath}");

        if (!isAdmin)
        {
            LocalLog.Warning("未以管理员身份运行，防火墙功能将不可用。");

            if (IsAutostart)
            {
                // 自启场景下不能弹 UAC 去打扰用户，直接报告问题并退出。
                MessageBox.Show(
                    "WinAppGuard 未能以管理员身份启动，开机自启任务可能配置有误。\n" +
                    "请在「任务计划程序」中确认 WinAppGuard 任务勾选了「使用最高权限运行」。",
                    AppConstants.AppName,
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Warning);
                return 0;
            }

            // 手动启动场景：询问用户是否提权重启。
            var choice = MessageBox.Show(
                "WinAppGuard 需要管理员权限才能管理 Windows 防火墙规则。\n是否以管理员身份重新启动？",
                AppConstants.AppName,
                MessageBoxButtons.YesNo,
                MessageBoxIcon.Question);

            if (choice == DialogResult.Yes)
            {
                AdminHelper.RestartAsAdmin(autostart: false);
            }

            return 0;
        }

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
    private static void OnUiThreadException(object sender, ThreadExceptionEventArgs e)
    {
        LocalLog.Error("界面线程发生未处理的异常", e.Exception);

        MessageBox.Show(
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
