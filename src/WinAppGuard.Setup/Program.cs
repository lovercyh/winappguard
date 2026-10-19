using System.Text;
using WinAppGuard.Contracts;
using WinAppGuard.Core;

namespace WinAppGuard.Setup;

/// <summary>
/// 安装 / 修复 / 卸载。
///
/// 约定：
///   - 安装器旁边必须同时有 WinAppGuard.exe 与 WinAppGuardSvc.exe（发布目录就是这样）；
///   - **卸载默认删除本程序创建的全部规则**（否则卸载后规则仍在 BFE 里生效，
///     用户会以为防火墙还在偷偷工作）；可用 keep-data 保留数据目录；
///   - 任何一步失败都停下来并打印原因，不"装作成功"。
/// </summary>
internal static class Program
{
    private const string UiExeName = "WinAppGuard.exe";
    private const string ServiceExeName = "WinAppGuardSvc.exe";

    private static string InstallDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "WinAppGuard");

    private static string DataDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "WinAppGuard");

    private static int Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;

        try
        {
            if (args.Contains("--install", StringComparer.OrdinalIgnoreCase))
            {
                return Install();
            }

            if (args.Contains("--repair", StringComparer.OrdinalIgnoreCase))
            {
                return Repair();
            }

            if (args.Contains("--uninstall", StringComparer.OrdinalIgnoreCase))
            {
                return Uninstall(keepData: args.Contains("--keep-data", StringComparer.OrdinalIgnoreCase));
            }

            PrintUsage();
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"失败：{ex.Message}");
            return 1;
        }
    }

    private static void PrintUsage()
    {
        Console.WriteLine("WinAppGuard 安装工具");
        Console.WriteLine();
        Console.WriteLine("  WinAppGuardSetup.exe --install     安装（复制文件 + 创建服务 + 启动）");
        Console.WriteLine("  WinAppGuardSetup.exe --repair      修复（覆盖文件 + 重启服务，保留规则与数据）");
        Console.WriteLine("  WinAppGuardSetup.exe --uninstall   卸载（停止/删除服务 + 删除本程序规则）");
        Console.WriteLine("                       --keep-data  卸载时保留 %ProgramData%\\WinAppGuard");
        Console.WriteLine();
        Console.WriteLine("安装器旁边必须同时有 WinAppGuard.exe 和 WinAppGuardSvc.exe。");
    }

    private static int Install()
    {
        var (uiSource, serviceSource) = LocatePayload();

        Directory.CreateDirectory(InstallDirectory);

        if (ServiceControl.IsInstalled(ServiceProtocol.ServiceName))
        {
            Console.WriteLine("检测到已安装：先停止旧服务。");
            ServiceControl.Stop(ServiceProtocol.ServiceName);
        }

        CopyPayload(uiSource, serviceSource);
        Console.WriteLine($"已复制到：{InstallDirectory}");

        if (!ServiceControl.IsInstalled(ServiceProtocol.ServiceName))
        {
            ServiceControl.Install(
                ServiceProtocol.ServiceName,
                ServiceProtocol.ServiceDisplayName,
                Path.Combine(InstallDirectory, ServiceExeName),
                ServiceProtocol.ServiceDescription);

            Console.WriteLine("已创建服务（自动启动、崩溃后自动重启）。");
        }

        ServiceControl.Start(ServiceProtocol.ServiceName);
        Thread.Sleep(1200);

        if (!ServiceControl.IsRunning(ServiceProtocol.ServiceName))
        {
            Console.Error.WriteLine("服务没有进入运行状态。请查看 %ProgramData%\\WinAppGuard\\logs。");
            return 4;
        }

        Console.WriteLine("服务已启动。");
        Console.WriteLine();
        Console.WriteLine($"完成。界面程序：{Path.Combine(InstallDirectory, UiExeName)}");
        Console.WriteLine("卸载：WinAppGuardSetup.exe --uninstall");
        return 0;
    }

    private static int Repair()
    {
        var (uiSource, serviceSource) = LocatePayload();

        if (ServiceControl.IsInstalled(ServiceProtocol.ServiceName))
        {
            Console.WriteLine("停止服务…");
            ServiceControl.Stop(ServiceProtocol.ServiceName);
        }

        Directory.CreateDirectory(InstallDirectory);
        CopyPayload(uiSource, serviceSource);

        if (!ServiceControl.IsInstalled(ServiceProtocol.ServiceName))
        {
            ServiceControl.Install(
                ServiceProtocol.ServiceName,
                ServiceProtocol.ServiceDisplayName,
                Path.Combine(InstallDirectory, ServiceExeName),
                ServiceProtocol.ServiceDescription);
        }

        ServiceControl.Start(ServiceProtocol.ServiceName);
        Thread.Sleep(1200);

        Console.WriteLine(ServiceControl.IsRunning(ServiceProtocol.ServiceName)
            ? "修复完成，服务正在运行。"
            : "修复后服务仍未运行，请查看日志。");

        return ServiceControl.IsRunning(ServiceProtocol.ServiceName) ? 0 : 4;
    }

    private static int Uninstall(bool keepData)
    {
        if (ServiceControl.IsInstalled(ServiceProtocol.ServiceName))
        {
            Console.WriteLine("停止服务…");
            ServiceControl.Stop(ServiceProtocol.ServiceName);

            Console.WriteLine("删除服务…");
            ServiceControl.Uninstall(ServiceProtocol.ServiceName);
        }

        // 默认删除规则：卸载后规则仍在 BFE 里生效是最容易被误解的状态。
        var deleted = 0;
        var rulesDeleted = false;

        try
        {
            deleted = RuleEngine.DeleteAllRules();
            rulesDeleted = true;
            Console.WriteLine($"已删除 {deleted} 条由 WinAppGuard 创建的规则。");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"删除规则失败：{ex.Message}");
            Console.Error.WriteLine("服务已卸载，但规则可能仍存在。请稍后重试本工具，或运行 --recover。");
        }

        if (!keepData && Directory.Exists(DataDirectory))
        {
            try
            {
                Directory.Delete(DataDirectory, recursive: true);
                Console.WriteLine($"已删除数据目录：{DataDirectory}");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"删除数据目录失败：{ex.Message}");
            }
        }

        if (Directory.Exists(InstallDirectory))
        {
            try
            {
                Directory.Delete(InstallDirectory, recursive: true);
                Console.WriteLine($"已删除安装目录：{InstallDirectory}");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"删除安装目录失败（可能有文件仍被占用）：{ex.Message}");
                Console.Error.WriteLine("关闭界面程序后重试，或手动删除该目录。");
            }
        }

        Console.WriteLine();
        Console.WriteLine(rulesDeleted ? "卸载完成。" : "卸载完成，但规则未能全部删除（见上）。");
        return rulesDeleted ? 0 : 3;
    }

    private static (string Ui, string Service) LocatePayload()
    {
        var source = AppContext.BaseDirectory;
        var ui = Path.Combine(source, UiExeName);
        var service = Path.Combine(source, ServiceExeName);

        if (!File.Exists(ui) || !File.Exists(service))
        {
            throw new FileNotFoundException(
                $"安装器旁边必须同时有 {UiExeName} 和 {ServiceExeName}（当前目录：{source}）。");
        }

        return (ui, service);
    }

    private static void CopyPayload(string uiSource, string serviceSource)
    {
        File.Copy(uiSource, Path.Combine(InstallDirectory, UiExeName), overwrite: true);
        File.Copy(serviceSource, Path.Combine(InstallDirectory, ServiceExeName), overwrite: true);
    }
}
