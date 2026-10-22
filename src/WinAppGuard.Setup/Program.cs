using System.Text;
using WinAppGuard.Contracts;
using WinAppGuard.Core;
using WinAppGuard.Core.Audit;

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

            if (args.Contains("--start-service", StringComparer.OrdinalIgnoreCase))
            {
                return StartServiceOnly();
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
        Console.WriteLine("  WinAppGuardSetup.exe --start-service 只启动服务（顺带修正为「自动（不延迟）」）");
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

        // 老版本装的是「自动（延迟启动）」：VM 实测经常起不来，这里统一修正。
        ServiceControl.EnsureAutoStartNoDelay(ServiceProtocol.ServiceName);

        // 2.x 的审计记录在用户目录；服务读不到，装/修时顺手迁到 ProgramData。
        TryMigrateAuditRecords();

        ServiceControl.Start(ServiceProtocol.ServiceName);
        Thread.Sleep(1200);

        if (!ServiceControl.IsRunning(ServiceProtocol.ServiceName))
        {
            Console.Error.WriteLine("服务没有进入运行状态。请查看 %ProgramData%\\WinAppGuard\\logs。");
            return 4;
        }

        TryMigrateUserDataToService();
        TryRecoverLegacyStrictMode();
        ShellShortcut.CreateDesktopShortcut(Path.Combine(InstallDirectory, UiExeName));

        Console.WriteLine("服务已启动。");
        Console.WriteLine();
        Console.WriteLine($"完成。界面程序：{Path.Combine(InstallDirectory, UiExeName)}");
        Console.WriteLine($"桌面快捷方式：{ShellShortcut.DesktopShortcutPath}");
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

        // 覆盖安装不会重建服务：必须显式把「延迟启动」改掉。
        ServiceControl.EnsureAutoStartNoDelay(ServiceProtocol.ServiceName);

        TryMigrateAuditRecords();

        ServiceControl.Start(ServiceProtocol.ServiceName);
        Thread.Sleep(1200);

        if (ServiceControl.IsRunning(ServiceProtocol.ServiceName))
        {
            TryMigrateUserDataToService();
            TryRecoverLegacyStrictMode();
            ShellShortcut.CreateDesktopShortcut(Path.Combine(InstallDirectory, UiExeName));
        }

        Console.WriteLine(ServiceControl.IsRunning(ServiceProtocol.ServiceName)
            ? "修复完成，服务正在运行。"
            : "修复后服务仍未运行，请查看日志。");

        return ServiceControl.IsRunning(ServiceProtocol.ServiceName) ? 0 : 4;
    }

    /// <summary>
    /// 只启动服务（界面在"离线"状态下调用；也用于把老版本的延迟启动修正掉）。
    /// </summary>
    /// <summary>
    /// 把 2.x 的用户级数据交给服务（3.0-c：界面以普通权限运行，启动时不再做迁移）：
    ///   - 规则分组：导入后删除旧文件；
    ///   - 审计设置：仅在服务的机器级设置文件不存在时迁移一次。
    /// </summary>
    private static void TryMigrateUserDataToService()
    {
        try
        {
            var ready = false;

            for (var attempt = 0; attempt < 30; attempt++)
            {
                var status = ServiceClient.TryRequest(
                    new ServiceRequest { Command = ServiceProtocol.Commands.Status },
                    TimeSpan.FromSeconds(1),
                    out _);

                if (status is { Ok: true })
                {
                    ready = true;
                    break;
                }

                Thread.Sleep(500);
            }

            if (!ready)
            {
                Console.Error.WriteLine("服务未就绪，跳过旧数据迁移（下次 --repair 会再试）。");
                return;
            }

            var localGroups = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                AppConstants.AppDataFolderName,
                "rule-groups.json");

            if (File.Exists(localGroups))
            {
                var json = File.ReadAllText(localGroups, Encoding.UTF8);

                var response = ServiceClient.TryRequest(
                    new ServiceRequest
                    {
                        Command = ServiceProtocol.Commands.ImportGroups,
                        Json = json,
                    },
                    TimeSpan.FromSeconds(5),
                    out var error);

                if (response is { Ok: true })
                {
                    File.Delete(localGroups);
                    Console.WriteLine($"分组迁移：{response.Affected} 条。");
                }
                else
                {
                    Console.Error.WriteLine($"分组迁移失败（旧文件保留）：{response?.Error ?? error}");
                }
            }

            if (!File.Exists(ServicePaths.AuditSettingsFile))
            {
                var local = AppSettings.Load();

                var response = ServiceClient.TryRequest(
                    new ServiceRequest
                    {
                        Command = ServiceProtocol.Commands.AuditConfigure,
                        AuditEnabled = local.AuditEnabled,
                        AuditDomainLookup = local.AuditDomainLookupEnabled,
                        AuditRetentionDays = local.AuditRetentionDays,
                    },
                    TimeSpan.FromSeconds(5),
                    out var error);

                if (response is { Ok: true })
                {
                    Console.WriteLine("记录设置：已迁移到服务。");
                }
                else
                {
                    Console.Error.WriteLine($"记录设置迁移失败：{response?.Error ?? error}");
                }
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"旧数据迁移失败（不影响安装）：{ex.Message}");
        }
    }

    /// <summary>
    /// 2.x 的审计记录迁移（方案 C：复制 → 校验 → 删源）。
    /// 必须在服务启动前做：服务运行时会打开这些文件。
    /// </summary>
    private static void TryMigrateAuditRecords()
    {
        try
        {
            var source = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                AppConstants.AppDataFolderName,
                "audit");

            var result = AuditMigration.Migrate(source, ServicePaths.AuditDirectory);

            if (result.Migrated > 0 || result.Failed > 0)
            {
                Console.WriteLine(result.Message);
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"记录迁移失败（不影响安装，源文件保留）：{ex.Message}");
        }
    }

    private static int StartServiceOnly()
    {
        if (!ServiceControl.IsInstalled(ServiceProtocol.ServiceName))
        {
            Console.Error.WriteLine("防护服务尚未安装。请先运行 --install 或 --repair。");
            return 2;
        }

        ServiceControl.EnsureAutoStartNoDelay(ServiceProtocol.ServiceName);
        ServiceControl.Start(ServiceProtocol.ServiceName);

        var deadline = DateTime.UtcNow.AddSeconds(10);

        while (DateTime.UtcNow < deadline && !ServiceControl.IsRunning(ServiceProtocol.ServiceName))
        {
            Thread.Sleep(300);
        }

        if (!ServiceControl.IsRunning(ServiceProtocol.ServiceName))
        {
            Console.Error.WriteLine("服务没有在 10 秒内进入运行状态。请查看 %ProgramData%\\WinAppGuard\\logs。");
            return 4;
        }

        Console.WriteLine("服务已启动（自动启动、不延迟）。");
        return 0;
    }

    private static int Uninstall(bool keepData)
    {
        ShellShortcut.DeleteDesktopShortcut();

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

    /// <summary>
    /// 1.x 升级兜底：把残留的「默认阻止出站」还原成「允许」。
    ///
    /// 放在安装/修复里，是因为这两个动作一定以**管理员**身份、在**用户会话**里运行：
    /// 既能改 Windows 防火墙，又能读到当前用户的 settings.json。
    /// （服务的 IPC 也会做一次，但服务不知道用户目录。）
    /// </summary>
    private static void TryRecoverLegacyStrictMode()
    {
        try
        {
            var result = StrictModeManager.RecoverIfLeftOn();

            if (!result.WasLeftOn)
            {
                return;
            }

            Console.WriteLine();
            Console.WriteLine(result.Message);

            if (!result.Restored)
            {
                Console.Error.WriteLine("⚠ 自动还原没有完全成功：请手工把 wf.msc 三套配置文件的「出站连接」都改成「允许」。");
            }
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"1.x 严格模式兜底失败（不影响安装）：{ex.Message}");
        }
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

        // 把安装器自己也放进安装目录：界面在"服务未运行"时要能一键启动/修复。
        var setupSource = Path.Combine(AppContext.BaseDirectory, "WinAppGuardSetup.exe");
        var setupTarget = Path.Combine(InstallDirectory, "WinAppGuardSetup.exe");

        if (File.Exists(setupSource)
            && !string.Equals(
                Path.GetFullPath(setupSource), Path.GetFullPath(setupTarget),
                StringComparison.OrdinalIgnoreCase))
        {
            File.Copy(setupSource, setupTarget, overwrite: true);
        }
    }
}
