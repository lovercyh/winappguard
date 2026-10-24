using WinAppGuard.Contracts;
using WinAppGuard.Core;
using WinAppGuard.Localization;

namespace WinAppGuard.Service;

internal static class Program
{
    private static int Main(string[] args)
    {
        // 3.0-c：界面以普通权限运行时，通过这两个隐藏模式完成提权操作。
        if (args.Any(a => a.Equals("--elevated-ipc", StringComparison.OrdinalIgnoreCase)))
        {
            return ElevatedIpc.Run(args);
        }

        if (args.Any(a => a.Equals("--elevated-autostart", StringComparison.OrdinalIgnoreCase)))
        {
            return ElevatedAutostart.Run(args);
        }

        // 3.0-c：界面程序集不再包含 WFP 代码，命令行模式由服务 exe 代跑。
        // 用法：WinAppGuardSvc.exe --cli <原命令行参数…>
        if (args.Any(a => a.Equals("--cli", StringComparison.OrdinalIgnoreCase)))
        {
            var cliArgs = args
                .Where(a => !a.Equals("--cli", StringComparison.OrdinalIgnoreCase))
                .ToArray();

            var options = CommandLine.Parse(cliArgs);

            // 优先级：--lang > GUI 已生效语言 > 系统。
            if (!CliLanguage.TryResolve(
                    options.Language,
                    UiLanguageStore.ReadAppliedLanguage(),
                    out var language))
            {
                Console.Error.WriteLine(
                    "参数错误：--lang 只能是 zh / en / auto。\n" +
                    "Bad argument: --lang must be zh, en or auto.");
                return 1;
            }

            Localizer.Initialize(language);
            return CliRunner.Run(options);
        }

        ServiceLog.Initialize();

        var console = args.Any(a => a.Equals("--console", StringComparison.OrdinalIgnoreCase));

        if (console)
        {
            RunConsole();
            return 0;
        }

        if (NativeService.TryRun(out var error))
        {
            return 0;
        }

        // 1063 = ERROR_FAILED_SERVICE_CONTROLLER_CONNECT：不是由 SCM 启动的。
        // 开发时直接双击/命令行跑，走控制台模式；作为服务时不会走到这里。
        if (error == NativeService.ErrorFailedServiceControllerConnect)
        {
            RunConsole();
            return 0;
        }

        ServiceLog.Error("WAG-SVC-005", $"Service start failed: win32 error {error}.");
        return 1;
    }

    private static void RunConsole()
    {
        using var server = new ControlServer();

        server.Start();
        Console.WriteLine("WinAppGuard 防护服务（控制台模式）。按 Enter 停止。");

        if (Console.IsInputRedirected)
        {
            // 后台/自检场景没有 stdin：一直运行，直到 Ctrl+C。
            using var stop = new ManualResetEventSlim(false);
            Console.CancelKeyPress += (_, eventArgs) =>
            {
                eventArgs.Cancel = true;
                stop.Set();
            };

            stop.Wait();
        }
        else
        {
            Console.ReadLine();
        }

        server.Stop();
    }
}
