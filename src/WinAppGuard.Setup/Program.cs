using System.Diagnostics;
using System.Text;
using WinAppGuard.Contracts;
using WinAppGuard.Core;
using WinAppGuard.Core.Audit;
using WinAppGuard.Core.ProtectedMode;
using WinAppGuard.Core.Wfp;

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
    private const string UninstallerExeName = "WinAppGuardUninstall.exe";

    private static string InstallDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "WinAppGuard");

    private static string DataDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "WinAppGuard");

    private static int Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;

        try
        {
            var allowOwnerMismatch = args.Contains(
                "--allow-owner-mismatch", StringComparer.OrdinalIgnoreCase);

            if (args.Contains("--install", StringComparer.OrdinalIgnoreCase))
            {
                return Install(allowOwnerMismatch);
            }

            if (args.Contains("--repair", StringComparer.OrdinalIgnoreCase))
            {
                return Repair(allowOwnerMismatch);
            }

            if (args.Contains("--rotate-key", StringComparer.OrdinalIgnoreCase))
            {
                return RotateKey();
            }

            if (args.Contains("--reset-owner", StringComparer.OrdinalIgnoreCase))
            {
                return ResetOwner();
            }

            if (args.Contains("--start-service", StringComparer.OrdinalIgnoreCase))
            {
                return StartServiceOnly();
            }

            // 开发/发布验证用：把 Setup 末尾的内置载荷解出来（不安装、不改系统）。
            if (args.Contains("--extract-payload", StringComparer.OrdinalIgnoreCase))
            {
                var index = Array.FindIndex(
                    args, arg => arg.Equals("--extract-payload", StringComparison.OrdinalIgnoreCase));

                var target = index + 1 < args.Length ? args[index + 1] : null;
                var directory = EmbeddedPayload.TryExtract(target);

                if (directory is null)
                {
                    Console.Error.WriteLine("这个 exe 没有内置载荷（开发期直接运行 bin 里的 Setup 属于正常）。");
                    return 1;
                }

                Console.WriteLine(directory);
                return 0;
            }

            if (args.Contains("--uninstall", StringComparer.OrdinalIgnoreCase))
            {
                return Uninstall(
                    keepData: args.Contains("--keep-data", StringComparer.OrdinalIgnoreCase));
            }

            if (args.Length == 0)
            {
                // 双击模式：
                //   - 名字里带 Uninstall（WinAppGuardUninstall.exe）→ 交互式完整卸载；
                //   - 否则 → 未安装就安装、已安装就修复（并确保桌面快捷方式存在）。
                if (IsUninstallerInvocation())
                {
                    return RunUninstallerInteractive();
                }

                return RunSetupDefault(allowOwnerMismatch);
            }

            PrintUsage();
            PauseIfInteractive();
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
        Console.WriteLine("  双击 WinAppGuardSetup.exe            安装（未装）或修复（已装），并创建桌面快捷方式");
        Console.WriteLine("  双击 WinAppGuardUninstall.exe        完整卸载（服务 / 规则 / 快捷方式 / 记录 / 设置 / 目录）");
        Console.WriteLine();
        Console.WriteLine("  WinAppGuardSetup.exe --install     安装（复制文件 + 创建服务 + 启动）");
        Console.WriteLine("                       --allow-owner-mismatch  提权账户与登录账户不同时仍继续（所有者=提权账户）");
        Console.WriteLine("  WinAppGuardSetup.exe --repair      修复（覆盖文件 + 重启服务，保留密钥/规则/数据）");
        Console.WriteLine("  WinAppGuardSetup.exe --rotate-key  同一所有者换一把新密钥（旧密钥删除）");
        Console.WriteLine("  WinAppGuardSetup.exe --reset-owner 把当前提权账户设为新所有者（换新密钥）");
        Console.WriteLine("  WinAppGuardSetup.exe --start-service 只启动服务（顺带修正为「自动（不延迟）」）");
        Console.WriteLine("  WinAppGuardSetup.exe --uninstall   完整卸载（停止/删除服务 + 删除全部规则与数据）");
        Console.WriteLine("                       --keep-data  卸载时保留 %ProgramData%\\WinAppGuard（密钥始终删除）");
        Console.WriteLine();
        Console.WriteLine("安装器旁边必须同时有 WinAppGuard.exe 和 WinAppGuardSvc.exe。");
        Console.WriteLine("3.1 起只有安装时的提权账户（所有者）能使用界面/服务；其他账户会被拒绝。");
    }

    private static int Install(bool allowOwnerMismatch)
    {
        if (ServiceControl.IsInstalled(ServiceProtocol.ServiceName))
        {
            Console.WriteLine("检测到已安装：按修复处理（保留现有密钥与所有者）。");
            return Repair(allowOwnerMismatch);
        }

        if (!CheckOwnerMatchesInteractiveSession(allowOwnerMismatch))
        {
            return 5;
        }

        using var payload = LocatePayload();

        // 覆盖安装时界面可能正开着，占用 exe；先结束它，否则复制会失败。
        TryStopUiProcesses();

        Directory.CreateDirectory(InstallDirectory);

        CopyPayload(payload);
        Console.WriteLine($"已复制到：{InstallDirectory}");

        // 快捷方式尽早创建：即使服务启动失败，用户也找得到界面。
        ShellShortcut.CreateDesktopShortcut(Path.Combine(InstallDirectory, UiExeName));

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

        // 3.1：首次安装必须生成全新密钥；旧残留一律先删，绝不复用。
        if (!CreateFreshProtectedModeKey())
        {
            Console.Error.WriteLine("受保护模式密钥创建失败，安装中止（服务未启动）。");
            return 6;
        }

        if (!ApplyServiceDacl())
        {
            Console.Error.WriteLine("服务 DACL 设置失败，安装中止（服务未启动）。");
            return 6;
        }

        if (!ConfigureSignerForIpc())
        {
            Console.Error.WriteLine("受保护模式签名密钥加载失败，安装中止（服务未启动）。");
            return 6;
        }

        ServiceControl.Start(ServiceProtocol.ServiceName);
        Thread.Sleep(1200);

        if (!ServiceControl.IsRunning(ServiceProtocol.ServiceName))
        {
            Console.Error.WriteLine("服务没有进入运行状态。请查看 %ProgramData%\\WinAppGuard\\logs。");
            return 4;
        }

        if (!VerifyServiceAuth())
        {
            Console.Error.WriteLine("受保护模式签名自检失败，安装中止。请查看服务日志。");
            return 6;
        }

        TryMigrateUserDataToService();
        TryRecoverLegacyStrictMode();

        Console.WriteLine("服务已启动。");
        Console.WriteLine();
        Console.WriteLine($"完成。界面程序：{Path.Combine(InstallDirectory, UiExeName)}");
        Console.WriteLine($"桌面快捷方式：{ShellShortcut.DesktopShortcutPath}");
        Console.WriteLine($"卸载程序：{Path.Combine(InstallDirectory, UninstallerExeName)}");
        Console.WriteLine("卸载：WinAppGuardSetup.exe --uninstall");
        return 0;
    }

    private static int Repair(bool allowOwnerMismatch)
    {
        using var payload = LocatePayload();

        TryStopUiProcesses();

        if (ServiceControl.IsInstalled(ServiceProtocol.ServiceName))
        {
            Console.WriteLine("停止服务…");
            ServiceControl.Stop(ServiceProtocol.ServiceName);
        }

        Directory.CreateDirectory(InstallDirectory);
        CopyPayload(payload);
        ShellShortcut.CreateDesktopShortcut(Path.Combine(InstallDirectory, UiExeName));

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

        if (!EnsureProtectedModeForRepair(allowOwnerMismatch))
        {
            Console.Error.WriteLine("受保护模式准备失败，修复中止（服务未启动）。");
            return 6;
        }

        var daclApplied = ApplyServiceDacl();

        if (!daclApplied && IsCurrentUserOwner())
        {
            Console.Error.WriteLine(
                "受保护模式：当前账户是所有者，但服务 DACL 设置失败；修复中止。");
            return 6;
        }

        var signerReady = ConfigureSignerForIpc();

        if (!signerReady && IsCurrentUserOwner())
        {
            Console.Error.WriteLine(
                "受保护模式：当前账户是所有者，但签名密钥加载失败；修复中止。");
            return 6;
        }

        ServiceControl.Start(ServiceProtocol.ServiceName);
        Thread.Sleep(1200);

        if (ServiceControl.IsRunning(ServiceProtocol.ServiceName))
        {
            if (signerReady && !VerifyServiceAuth())
            {
                Console.Error.WriteLine("受保护模式签名自检失败，修复中止。请查看服务日志。");
                return 6;
            }

            TryMigrateUserDataToService();
            TryRecoverLegacyStrictMode();
        }

        Console.WriteLine(ServiceControl.IsRunning(ServiceProtocol.ServiceName)
            ? "修复完成，服务正在运行。"
            : "修复后服务仍未运行，请查看日志。");

        return ServiceControl.IsRunning(ServiceProtocol.ServiceName) ? 0 : 4;
    }

    private static OwnerKeyStore CreateOwnerKeyStore()
        => new(ServicePaths.ProtectedModeDirectory);

    private static bool IsCurrentUserOwner()
    {
        try
        {
            var config = CreateOwnerKeyStore().ReadConfig();
            return string.Equals(
                config.OwnerSid, OwnerAccount.GetCurrentSid().Value,
                StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception)
        {
            return false;
        }
    }

    /// <summary>把服务对象 DACL 收紧为 SYSTEM + 所有者（管理员只读/启动）。</summary>
    private static bool ApplyServiceDacl()
    {
        try
        {
            var config = CreateOwnerKeyStore().ReadConfig();

            if (!ServiceSecurity.TrySetOwnerOnlyDacl(
                    ServiceProtocol.ServiceName, config.OwnerSid, out var error))
            {
                Console.Error.WriteLine($"设置服务 DACL 失败：{error}");
                return false;
            }

            Console.WriteLine(
                $"服务 DACL：SYSTEM + {config.OwnerName} 完全控制；"
                + "Administrators 仅查询/启动。");
            return true;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"设置服务 DACL 失败：{ex.Message}");
            return false;
        }
    }

    /// <summary>把已安装密钥加载成 ServiceClient 的签名器。</summary>
    private static bool ConfigureSignerForIpc()
    {
        if (ProtectedModeClient.TryConfigureSigner(out var fingerprint, out var error))
        {
            Console.WriteLine(
                $"受保护模式：签名密钥已加载（指纹 {fingerprint?[..16]}…）。");
            return true;
        }

        Console.WriteLine(
            $"受保护模式：当前账户无法加载签名密钥（{error}）；"
            + "签名自检与旧数据迁移将跳过。");
        return false;
    }

    /// <summary>
    /// 安装后自检：用新密钥签名调用 status，确认服务真的认这把钥匙。
    /// 当前账户不是所有者（没有 signer）时调用方应跳过。
    /// </summary>
    private static bool VerifyServiceAuth()
    {
        if (!ServiceClient.HasSigner)
        {
            Console.WriteLine("受保护模式：没有签名能力，跳过安装后签名自检。");
            return true;
        }

        string expectedFingerprint;

        try
        {
            expectedFingerprint = CreateOwnerKeyStore().ReadConfig().Fingerprint;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"读取受保护模式配置失败：{ex.Message}");
            return false;
        }

        var deadline = DateTime.UtcNow.AddSeconds(10);
        ServiceStatus? status = null;
        string? lastError = null;

        while (DateTime.UtcNow < deadline)
        {
            var response = ServiceClient.TryRequest(
                new ServiceRequest { Command = ServiceProtocol.Commands.Status },
                TimeSpan.FromSeconds(1),
                out var error);

            lastError = response?.Error ?? error;

            if (response is { Ok: true } && response.Status is not null)
            {
                status = response.Status;
                break;
            }

            Thread.Sleep(300);
        }

        if (status is null)
        {
            Console.Error.WriteLine(
                $"签名 status 自检失败：{lastError ?? "服务没有返回状态"}");
            return false;
        }

        if (status.ProtocolVersion != ServiceProtocol.Version || !status.ProtectedMode)
        {
            Console.Error.WriteLine(
                $"签名自检失败：协议 {status.ProtocolVersion}，"
                + $"受保护模式={status.ProtectedMode}。");
            return false;
        }

        if (!string.Equals(
                status.ProtectedModeFingerprint, expectedFingerprint,
                StringComparison.OrdinalIgnoreCase))
        {
            Console.Error.WriteLine(
                "签名自检失败：服务使用的公钥指纹与本地配置不一致。");
            return false;
        }

        Console.WriteLine(
            $"受保护模式：签名自检通过（所有者 {status.ProtectedModeOwner}，"
            + $"指纹 {status.ProtectedModeFingerprint![..16]}…）。");
        return true;
    }

    /// <summary>
    /// 目录不存在 → true/空；存在且能列 → true/是否有内容；
    /// 存在但拒绝访问 → false（不当成空目录处理）。
    /// </summary>
    private static bool TryInspectProtectedModeDirectory(out bool hasEntries)
    {
        hasEntries = false;

        if (!Directory.Exists(ServicePaths.ProtectedModeDirectory))
        {
            return true;
        }

        try
        {
            hasEntries = Directory
                .EnumerateFileSystemEntries(ServicePaths.ProtectedModeDirectory)
                .Any();
            return true;
        }
        catch (Exception)
        {
            return false;
        }
    }

    /// <summary>
    /// 首次安装：删除任何残留密钥，强制生成全新的一把。
    /// 失败就中止安装，不复用旧钥匙。
    /// </summary>
    private static bool CreateFreshProtectedModeKey()
    {
        try
        {
            var owner = OwnerAccount.GetCurrentSid();
            var ownerName = OwnerAccount.GetCurrentName();
            var store = CreateOwnerKeyStore();

            if (!store.TryDeleteAll(owner, out var error, out var deleteScheduled))
            {
                Console.Error.WriteLine($"清理旧密钥失败：{error ?? "未知原因"}");

                if (deleteScheduled)
                {
                    Console.Error.WriteLine("已登记重启后删除；请重启 Windows 后再安装。");
                }

                return false;
            }

            using var key = store.Create(owner, ownerName);
            Console.WriteLine(
                $"受保护模式：已为 {ownerName} 生成新密钥（指纹 {key.Fingerprint[..16]}…）。");
            return true;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"受保护模式密钥创建失败：{ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// 修复/升级：有可用密钥就保留；缺失/损坏才重建。
    /// 当前账户不是所有者时，明确提示但**不碰**原密钥。
    /// </summary>
    private static bool EnsureProtectedModeForRepair(bool allowOwnerMismatch)
    {
        var store = CreateOwnerKeyStore();
        var owner = OwnerAccount.GetCurrentSid();
        var ownerName = OwnerAccount.GetCurrentName();

        if (!store.HasFiles)
        {
            // 目录存在但文件读不到：通常说明当前账户不是所有者。
            // 不要把它当成“没有密钥”而覆盖掉。
            if (!TryInspectProtectedModeDirectory(out var hasEntries))
            {
                Console.WriteLine(
                    "受保护模式目录存在但无法读取（当前账户不是所有者）；保留原配置。");
                return true;
            }

            if (hasEntries)
            {
                Console.WriteLine(
                    "受保护模式目录存在但没有可读配置；为安全起见保留，"
                    + "请由所有者运行 --repair，或用 --reset-owner 重建。");
                return true;
            }

            if (!CheckOwnerMatchesInteractiveSession(allowOwnerMismatch))
            {
                return false;
            }

            Console.WriteLine("受保护模式：未发现密钥（首次升级/配置缺失），按当前账户生成。");
            return CreateKeyFor(store, owner, ownerName);
        }

        try
        {
            var config = store.ReadConfig();

            if (!string.Equals(
                    config.OwnerSid, owner.Value, StringComparison.OrdinalIgnoreCase))
            {
                Console.WriteLine(
                    $"受保护模式：现有所有者是 {config.OwnerName}（{config.OwnerSid}）。");
                Console.WriteLine(
                    "当前账户不是所有者：密钥保留，当前账户仍无法使用界面/服务。");
                return true;
            }

            try
            {
                using var key = store.LoadForOwner(owner);
                Console.WriteLine(
                    $"受保护模式：保留现有密钥（指纹 {key.Fingerprint[..16]}…）。");
                return true;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"现有密钥不可用：{ex.Message}");
                Console.Error.WriteLine("按同一所有者重建密钥（旧密钥将被替换）。");
                return CreateKeyFor(store, owner, ownerName);
            }
        }
        catch (UnauthorizedAccessException ex)
        {
            Console.WriteLine($"受保护模式：无法读取配置（当前账户不是所有者？）：{ex.Message}");
            Console.WriteLine("保留原配置与密钥；当前账户仍无法使用界面/服务。");
            return true;
        }
        catch (Exception ex) when (ex is InvalidDataException or FileNotFoundException)
        {
            Console.Error.WriteLine($"受保护模式配置缺失/损坏：{ex.Message}");
            Console.Error.WriteLine("按当前账户重建所有者与密钥。");
            return CreateKeyFor(store, owner, ownerName);
        }
    }

    private static bool CreateKeyFor(
        OwnerKeyStore store, System.Security.Principal.SecurityIdentifier owner,
        string ownerName)
    {
        try
        {
            using var key = store.Create(owner, ownerName);
            Console.WriteLine(
                $"受保护模式：已生成密钥（指纹 {key.Fingerprint[..16]}…）。");
            return true;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"受保护模式密钥创建失败：{ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// 正常 UAC 时提权账户 == 登录账户；over-the-shoulder 时不同。
    /// 3.1 默认拒绝后者，必须显式 --allow-owner-mismatch。
    /// </summary>
    private static bool CheckOwnerMatchesInteractiveSession(bool allowMismatch)
    {
        var current = OwnerAccount.GetCurrentSid();
        var interactive = OwnerAccount.TryGetInteractiveSid(out var interactiveName);

        if (interactive is null)
        {
            Console.WriteLine("提示：无法检测交互登录账户，跳过跨账户检查。");
            return true;
        }

        if (interactive.Equals(current))
        {
            return true;
        }

        Console.Error.WriteLine("检测到提权账户与当前登录账户不同：");
        Console.Error.WriteLine($"  登录账户：{interactiveName ?? interactive.Value}");
        Console.Error.WriteLine($"  所有者（提权账户）：{OwnerAccount.GetCurrentName()}");

        if (allowMismatch)
        {
            Console.WriteLine(
                "已按 --allow-owner-mismatch 继续；之后只有提权账户能使用界面/服务。");
            return true;
        }

        Console.Error.WriteLine(
            "默认取消。确认要让提权账户成为唯一所有者，请加 --allow-owner-mismatch。");
        return false;
    }

    /// <summary>同一所有者换新密钥；旧密钥被覆盖。</summary>
    private static int RotateKey()
    {
        if (!ServiceControl.IsInstalled(ServiceProtocol.ServiceName))
        {
            Console.Error.WriteLine("防护服务尚未安装。请先运行 --install 或 --repair。");
            return 2;
        }

        var store = CreateOwnerKeyStore();
        var owner = OwnerAccount.GetCurrentSid();
        var ownerName = OwnerAccount.GetCurrentName();
        ProtectedModeConfig config;

        try
        {
            config = store.ReadConfig();
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"读取受保护模式配置失败：{ex.Message}");
            return 6;
        }

        if (!string.Equals(
                config.OwnerSid, owner.Value, StringComparison.OrdinalIgnoreCase))
        {
            Console.Error.WriteLine(
                $"当前账户不是所有者（所有者：{config.OwnerName}）。");
            Console.Error.WriteLine("要更换所有者，请运行 --reset-owner。");
            return 7;
        }

        if (!StopServiceForMaintenance())
        {
            return 4;
        }

        try
        {
            using var key = store.Create(owner, ownerName);
            Console.WriteLine(
                $"密钥已轮换：{config.Fingerprint[..16]}… → {key.Fingerprint[..16]}…");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"密钥轮换失败：{ex.Message}");
            return 6;
        }

        if (!ApplyServiceDacl())
        {
            return 6;
        }

        if (!ConfigureSignerForIpc())
        {
            return 6;
        }

        if (!StartServiceAfterKeyChange())
        {
            return 4;
        }

        return VerifyServiceAuth() ? 0 : 6;
    }

    /// <summary>把当前提权账户设为新所有者；旧密钥删除，生成全新密钥。</summary>
    private static int ResetOwner()
    {
        if (!ServiceControl.IsInstalled(ServiceProtocol.ServiceName))
        {
            Console.Error.WriteLine("防护服务尚未安装。请先运行 --install 或 --repair。");
            return 2;
        }

        if (!StopServiceForMaintenance())
        {
            return 4;
        }

        var owner = OwnerAccount.GetCurrentSid();
        var ownerName = OwnerAccount.GetCurrentName();
        var store = CreateOwnerKeyStore();

        if (!store.TryDeleteAll(owner, out var error, out var deleteScheduled))
        {
            Console.Error.WriteLine($"删除旧密钥失败：{error ?? "未知原因"}");

            if (deleteScheduled)
            {
                Console.Error.WriteLine("已登记重启后删除；请重启 Windows 后再运行 --reset-owner。");
            }

            return 6;
        }

        if (!CreateKeyFor(store, owner, ownerName))
        {
            return 6;
        }

        Console.WriteLine($"所有者已切换为：{ownerName}");

        if (!ApplyServiceDacl())
        {
            return 6;
        }

        if (!ConfigureSignerForIpc())
        {
            return 6;
        }

        if (!StartServiceAfterKeyChange())
        {
            return 4;
        }

        return VerifyServiceAuth() ? 0 : 6;
    }

    private static bool StopServiceForMaintenance()
    {
        TryStopUiProcesses();

        try
        {
            if (ServiceControl.IsRunning(ServiceProtocol.ServiceName))
            {
                Console.WriteLine("停止服务…");
                ServiceControl.Stop(ServiceProtocol.ServiceName);
            }

            if (ServiceControl.IsRunning(ServiceProtocol.ServiceName))
            {
                Console.Error.WriteLine("服务仍在运行，无法安全更换密钥。");
                return false;
            }

            return true;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"停止服务失败：{ex.Message}");
            return false;
        }
    }

    private static bool StartServiceAfterKeyChange()
    {
        try
        {
            ServiceControl.EnsureAutoStartNoDelay(ServiceProtocol.ServiceName);
            ServiceControl.Start(ServiceProtocol.ServiceName);

            var deadline = DateTime.UtcNow.AddSeconds(10);

            while (DateTime.UtcNow < deadline
                   && !ServiceControl.IsRunning(ServiceProtocol.ServiceName))
            {
                Thread.Sleep(300);
            }

            if (ServiceControl.IsRunning(ServiceProtocol.ServiceName))
            {
                Console.WriteLine("服务已启动。");
                return true;
            }

            Console.Error.WriteLine(
                "服务没有在 10 秒内进入运行状态。请查看 %ProgramData%\\WinAppGuard\\logs。");
            return false;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"启动服务失败：{ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// 把 2.x 的用户级数据交给服务（3.0-c：界面以普通权限运行，启动时不再做迁移）：
    ///   - 规则分组：导入后删除旧文件；
    ///   - 审计设置：仅在服务的机器级设置文件不存在时迁移一次。
    /// </summary>
    private static void TryMigrateUserDataToService()
    {
        try
        {
            if (!ServiceClient.HasSigner)
            {
                Console.WriteLine("没有签名密钥，跳过旧数据迁移。");
                return;
            }

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
        Console.WriteLine("停止界面进程…");
        TryStopUiProcesses();

        Console.WriteLine("删除开机自启任务…");
        try
        {
            _ = AutoStartManager.Disable();
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"删除开机自启任务失败（可手动在 taskschd.msc 删除）：{ex.Message}");
        }

        ShellShortcut.DeleteDesktopShortcut();

        var serviceRemoved = true;

        if (ServiceControl.IsInstalled(ServiceProtocol.ServiceName))
        {
            Console.WriteLine("停止服务…");

            try
            {
                ServiceControl.Stop(ServiceProtocol.ServiceName);
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"停止服务失败（继续删除）：{ex.Message}");
            }

            Console.WriteLine("删除服务…");
            ServiceControl.Uninstall(ServiceProtocol.ServiceName);
            serviceRemoved = !ServiceControl.IsInstalled(ServiceProtocol.ServiceName);

            if (!serviceRemoved)
            {
                Console.Error.WriteLine(
                    "服务仍然存在（可能是服务 DACL 只允许所有者删除；"
                    + "请由所有者运行卸载，或先由管理员接管服务权限）。");
            }
        }

        // 完整删除本程序在 WFP 里留下的对象（过滤器 + 子层）。
        // 放在删服务之后：服务停止后文件句柄释放，子层也能删干净。
        var rulesRecovered = false;

        try
        {
            var report = WfpRecovery.Recover();
            rulesRecovered = true;
            Console.WriteLine($"WFP 清理：{report.Describe()}");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"删除 WFP 对象失败：{ex.Message}");
            Console.Error.WriteLine("规则可能仍存在。请稍后重新运行卸载程序。");
        }

        // 密钥始终删除，包括 --keep-data。卸载后应用不再持有任何可用副本。
        var keyDeleted = DeleteProtectedMode();

        if (!keepData)
        {
            DeleteDirectoryIfExists(DataDirectory, "数据目录（记录 / 快照 / 设置）");

            var localData = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                AppConstants.AppDataFolderName);

            DeleteDirectoryIfExists(localData, "用户目录（界面设置 / 日志）");
        }

        // 数据目录统删可能已经把密钥目录一起删掉；以实际结果为准。
        keyDeleted |= !ProtectedModeFilesExist();

        var installDeleted = DeleteInstallDirectory();

        Console.WriteLine();
        Console.WriteLine(rulesRecovered && installDeleted && keyDeleted && serviceRemoved
            ? "卸载完成。"
            : "卸载完成，但有部分内容未能删除（见上）。");

        if (keepData)
        {
            Console.WriteLine(
                $"已保留数据目录：{DataDirectory}（受保护模式密钥已删除，重装会生成新密钥）");
        }

        return rulesRecovered && installDeleted && keyDeleted && serviceRemoved ? 0 : 3;
    }

    /// <summary>卸载时删除密钥目录并校验；删不掉要如实报告。</summary>
    private static bool DeleteProtectedMode()
    {
        var store = CreateOwnerKeyStore();

        if (!ProtectedModeFilesExist())
        {
            Console.WriteLine("受保护模式密钥：不存在（无需删除）。");
            return true;
        }

        var owner = OwnerAccount.GetCurrentSid();

        if (store.TryDeleteAll(owner, out var error, out var deleteScheduled))
        {
            Console.WriteLine("受保护模式密钥：已删除并校验不存在。");
            return true;
        }

        Console.Error.WriteLine($"受保护模式密钥删除失败：{error ?? "未知原因"}");

        if (deleteScheduled)
        {
            Console.Error.WriteLine(
                "已登记重启后删除；请在重启后确认 protected-mode 目录已消失。");
        }

        return false;
    }

    private static bool ProtectedModeFilesExist()
    {
        var store = CreateOwnerKeyStore();

        if (store.HasFiles)
        {
            return true;
        }

        if (!Directory.Exists(store.DirectoryPath))
        {
            return false;
        }

        // 能列目录就看是否为空；列不了（不是所有者）按“仍存在”处理，
        // 不能因为读不到就报告删除成功。
        return !TryInspectProtectedModeDirectory(out var hasEntries) || hasEntries;
    }

    /// <summary>双击安装器（无参数）：未安装就装，已安装就修复。</summary>
    private static int RunSetupDefault(bool allowOwnerMismatch)
    {
        Console.WriteLine("WinAppGuard 安装工具（双击模式）");
        Console.WriteLine();

        var code = ServiceControl.IsInstalled(ServiceProtocol.ServiceName)
            ? RepairWithBanner(allowOwnerMismatch)
            : InstallWithBanner(allowOwnerMismatch);

        PauseIfInteractive();
        return code;
    }

    private static int InstallWithBanner(bool allowOwnerMismatch)
    {
        Console.WriteLine("执行安装…");
        Console.WriteLine();
        return Install(allowOwnerMismatch);
    }

    private static int RepairWithBanner(bool allowOwnerMismatch)
    {
        Console.WriteLine("检测到已安装：执行修复（保留密钥、规则与数据）…");
        Console.WriteLine();
        return Repair(allowOwnerMismatch);
    }

    /// <summary>双击卸载器（WinAppGuardUninstall.exe）：确认后完整卸载。</summary>
    private static int RunUninstallerInteractive()
    {
        Console.WriteLine("WinAppGuard 卸载程序");
        Console.WriteLine();
        Console.WriteLine("将删除：");
        Console.WriteLine("  - 防护服务 WinAppGuardSvc");
        Console.WriteLine("  - 本程序创建的全部 WFP 规则与子层");
        Console.WriteLine("  - 桌面快捷方式、开机自启任务");
        Console.WriteLine("  - 受保护模式密钥（protected-mode，始终删除）");
        Console.WriteLine("  - 记录 / 规则快照 / 设置（%ProgramData%\\WinAppGuard）");
        Console.WriteLine("  - 界面设置与日志（%LOCALAPPDATA%\\WinAppGuard）");
        Console.WriteLine("  - 安装目录（C:\\Program Files\\WinAppGuard）");
        Console.WriteLine();
        Console.Write("确定要完全卸载吗？[y/N] ");

        if (Console.IsInputRedirected)
        {
            Console.WriteLine();
            Console.Error.WriteLine("非交互模式请使用：WinAppGuardUninstall.exe --uninstall");
            return 1;
        }

        var answer = Console.ReadLine()?.Trim();

        if (!string.Equals(answer, "y", StringComparison.OrdinalIgnoreCase)
            && !string.Equals(answer, "yes", StringComparison.OrdinalIgnoreCase))
        {
            Console.WriteLine("已取消，未做任何修改。");
            PauseIfInteractive();
            return 0;
        }

        Console.WriteLine();
        var code = Uninstall(keepData: false);
        PauseIfInteractive();
        return code;
    }

    private static bool IsUninstallerInvocation()
    {
        var name = Path.GetFileNameWithoutExtension(Environment.ProcessPath) ?? string.Empty;
        return name.Contains("Uninstall", StringComparison.OrdinalIgnoreCase);
    }

    private static void TryStopUiProcesses()
    {
        foreach (var process in Process.GetProcessesByName("WinAppGuard"))
        {
            try
            {
                process.Kill();
                process.WaitForExit(5000);
                Console.WriteLine($"已结束界面进程（PID {process.Id}）。");
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"结束界面进程失败（PID {process.Id}）：{ex.Message}");
            }
        }
    }

    private static void DeleteDirectoryIfExists(string path, string description)
    {
        if (!Directory.Exists(path))
        {
            return;
        }

        try
        {
            Directory.Delete(path, recursive: true);
            Console.WriteLine($"已删除{description}：{path}");
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"删除{description}失败：{ex.Message}");
        }
    }

    /// <summary>
    /// 删除安装目录。若当前 exe 就在目录里（安装器/卸载器本身），
    /// 先删其它文件，再让 cmd 在本进程退出后删除剩下的目录。
    /// </summary>
    private static bool DeleteInstallDirectory()
    {
        if (!Directory.Exists(InstallDirectory))
        {
            return true;
        }

        var current = Environment.ProcessPath;
        var inside = current is not null
                     && current.StartsWith(
                         InstallDirectory + Path.DirectorySeparatorChar,
                         StringComparison.OrdinalIgnoreCase);

        try
        {
            if (!inside)
            {
                Directory.Delete(InstallDirectory, recursive: true);
                Console.WriteLine($"已删除安装目录：{InstallDirectory}");
                return true;
            }

            foreach (var file in Directory.GetFiles(InstallDirectory))
            {
                if (!string.Equals(file, current, StringComparison.OrdinalIgnoreCase))
                {
                    File.Delete(file);
                }
            }

            foreach (var directory in Directory.GetDirectories(InstallDirectory))
            {
                Directory.Delete(directory, recursive: true);
            }

            var command = $"/c ping -n 3 127.0.0.1 >nul & rmdir /s /q \"{InstallDirectory}\"";
            Process.Start(new ProcessStartInfo("cmd.exe", command)
            {
                CreateNoWindow = true,
                UseShellExecute = false,
                WindowStyle = ProcessWindowStyle.Hidden,
            });

            Console.WriteLine("安装目录将在程序退出后删除。");
            return true;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"删除安装目录失败（可能有文件仍被占用）：{ex.Message}");
            Console.Error.WriteLine("请关闭相关程序后重试，或手动删除该目录。");
            return false;
        }
    }

    private static void PauseIfInteractive()
    {
        if (Console.IsInputRedirected)
        {
            return;
        }

        Console.WriteLine();
        Console.WriteLine("按任意键退出…");

        try
        {
            Console.ReadKey(intercept: true);
        }
        catch (Exception)
        {
            // 没有控制台时忽略。
        }
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

    /// <summary>
    /// 解析安装载荷：
    ///   1. 优先读 Setup 末尾追加的内置 ZIP（发布版：用户只需下载 Setup + Uninstall）；
    ///   2. 没有内置载荷时回退到"读安装器同目录的文件"（开发期/手动解压场景）。
    /// 返回的临时目录由 <see cref="Payload.Dispose"/> 清理。
    /// </summary>
    private static Payload LocatePayload()
    {
        var extracted = EmbeddedPayload.TryExtract();

        if (extracted is not null)
        {
            return new Payload(extracted, temporary: true);
        }

        var source = AppContext.BaseDirectory;
        var ui = Path.Combine(source, UiExeName);
        var service = Path.Combine(source, ServiceExeName);

        if (!File.Exists(ui) || !File.Exists(service))
        {
            throw new FileNotFoundException(
                $"安装器没有内置载荷，同目录也缺少 {UiExeName} / {ServiceExeName}（当前目录：{source}）。");
        }

        return new Payload(source, temporary: false);
    }

    private static void CopyPayload(Payload payload)
    {
        File.Copy(payload.Ui, Path.Combine(InstallDirectory, UiExeName), overwrite: true);
        File.Copy(payload.Service, Path.Combine(InstallDirectory, ServiceExeName), overwrite: true);

        // 安装器本体（base）装进 Program Files：
        //   - 作为 WinAppGuardSetup.exe → 界面「启动服务 / 修复」用；
        //   - 作为 WinAppGuardUninstall.exe → 用户随时完整卸载（同一份二进制，文件名决定行为）。
        var setupTarget = Path.Combine(InstallDirectory, "WinAppGuardSetup.exe");
        var uninstallTarget = Path.Combine(InstallDirectory, UninstallerExeName);

        CopyIfDifferent(payload.SetupInstaller, setupTarget);
        CopyIfDifferent(payload.SetupInstaller, uninstallTarget);
    }

    private static void CopyIfDifferent(string source, string target)
    {
        if (!File.Exists(source))
        {
            return;
        }

        if (string.Equals(
                Path.GetFullPath(source), Path.GetFullPath(target),
                StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        File.Copy(source, target, overwrite: true);
    }

    /// <summary>一次安装用到的载荷文件（可能来自临时解压目录）。</summary>
    private sealed class Payload : IDisposable
    {
        internal Payload(string directory, bool temporary)
        {
            DirectoryPath = directory;
            IsTemporary = temporary;
        }

        internal string DirectoryPath { get; }

        private bool IsTemporary { get; }

        internal string Ui => Path.Combine(DirectoryPath, UiExeName);

        internal string Service => Path.Combine(DirectoryPath, ServiceExeName);

        internal string SetupInstaller => Path.Combine(DirectoryPath, "WinAppGuardSetup.exe");

        public void Dispose()
        {
            if (!IsTemporary)
            {
                return;
            }

            try
            {
                Directory.Delete(DirectoryPath, recursive: true);
            }
            catch (Exception)
            {
                // 临时目录删不掉不影响安装。
            }
        }
    }
}
