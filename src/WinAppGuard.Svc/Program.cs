using WinAppGuard.Contracts;

namespace WinAppGuard.Service;

internal static class Program
{
    private static int Main(string[] args)
    {
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

        ServiceLog.Error($"服务启动失败：Win32 错误 {error}");
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
