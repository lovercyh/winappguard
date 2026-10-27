using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using WinAppGuard.Contracts;
using WinAppGuard.Core;
using WinAppGuard.Core.Audit;
using WinAppGuard.Core.Diagnostics.AntiScan;
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

    private static bool _withNpcap;
    private static bool _withoutNpcap;

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
            _withNpcap = args.Contains("--with-npcap", StringComparer.OrdinalIgnoreCase);
            _withoutNpcap = args.Contains("--without-npcap", StringComparer.OrdinalIgnoreCase);

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
                    Bilingual.Fail("这个 exe 没有内置载荷（开发期直接运行 bin 里的 Setup 属于正常）。", "This exe has no embedded payload (running Setup from bin during development is normal).");
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
            Bilingual.Fail($"失败：{ex.Message}", $"Failed: {ex.Message}");
            return 1;
        }
    }

    private static void PrintUsage()
    {
        // 帮助文本按语言分段：两种语言各自完整，用户不用在两种语言之间来回找。
        Console.WriteLine("WinAppGuard 安装工具 | WinAppGuard Setup");
        Console.WriteLine();

        Console.WriteLine("  双击 WinAppGuardSetup.exe            安装（未装）或修复（已装），并创建桌面快捷方式");
        Console.WriteLine("  双击 WinAppGuardUninstall.exe        完整卸载（服务 / 规则 / 快捷方式 / 记录 / 设置 / 目录）");
        Console.WriteLine();
        Console.WriteLine("  WinAppGuardSetup.exe --install     安装（复制文件 + 创建服务 + 启动）");
        Console.WriteLine("                       --with-npcap    同时安装 Npcap（会打开官方 GUI）");
        Console.WriteLine("                       --without-npcap 跳过 Npcap（反扫描不可用）");
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
        Console.WriteLine();

        Console.WriteLine("  Double-click WinAppGuardSetup.exe      install (if missing) or repair, and create a desktop shortcut");
        Console.WriteLine("  Double-click WinAppGuardUninstall.exe  full uninstall (service / rules / shortcut / records / settings / folder)");
        Console.WriteLine();
        Console.WriteLine("  WinAppGuardSetup.exe --install     install (copy files + create service + start)");
        Console.WriteLine("                       --with-npcap    also install Npcap (opens the official GUI)");
        Console.WriteLine("                       --without-npcap skip Npcap (anti-scan unavailable)");
        Console.WriteLine("                       --allow-owner-mismatch  continue when the elevated account differs (owner = elevated account)");
        Console.WriteLine("  WinAppGuardSetup.exe --repair      repair (overwrite files + restart service; keep key/rules/data)");
        Console.WriteLine("  WinAppGuardSetup.exe --rotate-key  issue a new key for the same owner (old key deleted)");
        Console.WriteLine("  WinAppGuardSetup.exe --reset-owner make the current elevated account the new owner (new key)");
        Console.WriteLine("  WinAppGuardSetup.exe --start-service start the service only (also fixes Automatic (Delayed Start))");
        Console.WriteLine("  WinAppGuardSetup.exe --uninstall   full uninstall (stop/delete service + delete all rules and data)");
        Console.WriteLine("                       --keep-data  keep %ProgramData%\\WinAppGuard (the key is always deleted)");
        Console.WriteLine();
        Console.WriteLine("WinAppGuard.exe and WinAppGuardSvc.exe must be next to the installer.");
        Console.WriteLine("Since 3.1 only the elevated install account (owner) can use the UI/service; other accounts are rejected.");
    }

    private static int Install(bool allowOwnerMismatch)
    {
        if (ServiceControl.IsInstalled(ServiceProtocol.ServiceName))
        {
            Bilingual.Say("检测到已安装：按修复处理（保留现有密钥与所有者）。", "Already installed: repairing (existing key and owner are kept).");
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
        Bilingual.Say($"已复制到：{InstallDirectory}", $"Copied to: {InstallDirectory}");

        // 快捷方式尽早创建：即使服务启动失败，用户也找得到界面。
        ShellShortcut.CreateDesktopShortcut(Path.Combine(InstallDirectory, UiExeName));

        MaybeInstallNpcap(payload);

        if (!ServiceControl.IsInstalled(ServiceProtocol.ServiceName))
        {
            ServiceControl.Install(
                ServiceProtocol.ServiceName,
                ServiceProtocol.ServiceDisplayName,
                Path.Combine(InstallDirectory, ServiceExeName),
                ServiceProtocol.ServiceDescription);

            Bilingual.Say("已创建服务（自动启动、崩溃后自动重启）。", "Service created (automatic start, restart on crash).");
        }

        // 老版本装的是「自动（延迟启动）」：VM 实测经常起不来，这里统一修正。
        ServiceControl.EnsureAutoStartNoDelay(ServiceProtocol.ServiceName);

        // 2.x 的审计记录在用户目录；服务读不到，装/修时顺手迁到 ProgramData。
        TryMigrateAuditRecords();

        // 3.1：首次安装必须生成全新密钥；旧残留一律先删，绝不复用。
        if (!CreateFreshProtectedModeKey())
        {
            Bilingual.Fail("受保护模式密钥创建失败，安装中止（服务未启动）。", "Failed to create the protected-mode key; installation aborted (service not started).");
            return 6;
        }

        if (!ApplyServiceDacl())
        {
            Bilingual.Fail("服务 DACL 设置失败，安装中止（服务未启动）。", "Failed to set the service DACL; installation aborted (service not started).");
            return 6;
        }

        if (!ConfigureSignerForIpc())
        {
            Bilingual.Fail("受保护模式签名密钥加载失败，安装中止（服务未启动）。", "Failed to load the protected-mode signing key; installation aborted (service not started).");
            return 6;
        }

        ServiceControl.Start(ServiceProtocol.ServiceName);
        Thread.Sleep(1200);

        if (!ServiceControl.IsRunning(ServiceProtocol.ServiceName))
        {
            Bilingual.Fail("服务没有进入运行状态。请查看 %ProgramData%\\WinAppGuard\\logs。", "The service did not reach the running state. See %ProgramData%\\WinAppGuard\\logs.");
            return 4;
        }

        if (!VerifyServiceAuth())
        {
            Bilingual.Fail("受保护模式签名自检失败，安装中止。请查看服务日志。", "Protected-mode signing self-check failed; installation aborted. See the service log.");
            return 6;
        }

        TryMigrateUserDataToService();
        TryRecoverLegacyStrictMode();

        Bilingual.Say("服务已启动。", "Service started.");
        Console.WriteLine();
        Bilingual.Say($"完成。界面程序：{Path.Combine(InstallDirectory, UiExeName)}", $"Done. UI: {Path.Combine(InstallDirectory, UiExeName)}");
        Bilingual.Say($"桌面快捷方式：{ShellShortcut.DesktopShortcutPath}", $"Desktop shortcut: {ShellShortcut.DesktopShortcutPath}");
        Bilingual.Say($"卸载程序：{Path.Combine(InstallDirectory, UninstallerExeName)}", $"Uninstaller: {Path.Combine(InstallDirectory, UninstallerExeName)}");
        Bilingual.Say("卸载：WinAppGuardSetup.exe --uninstall", "Uninstall: WinAppGuardSetup.exe --uninstall");
        return 0;
    }

    /// <summary>
    /// 4.0：按用户选择安装 Npcap。
    ///
    /// A1 方案：随包放官方安装包，但**不静默安装**（免费版不支持 /S），
    /// 只启动官方 GUI，并锁定推荐选项。用户可以在 Npcap 窗口里点安装/取消。
    /// </summary>
    private static void MaybeInstallNpcap(Payload payload)
    {
        if (_withoutNpcap)
        {
            Bilingual.Say("已按参数跳过 Npcap（反扫描不可用）。", "Npcap skipped by argument (anti-scan unavailable).");
            return;
        }

        if (NpcapLocator.IsAvailable)
        {
            Bilingual.Say(
                $"检测到 Npcap {NpcapLocator.GetVersion()}，跳过安装。",
                $"Npcap {NpcapLocator.GetVersion()} is already installed; skipping.");
            return;
        }

        if (!File.Exists(payload.NpcapInstaller))
        {
            Bilingual.Say(
                "安装包未包含 Npcap，反扫描功能将不可用。",
                "This package does not contain Npcap; anti-scan will be unavailable.");
            return;
        }

        var install = _withNpcap;

        if (!install)
        {
            if (Console.IsInputRedirected)
            {
                Bilingual.Say(
                    "非交互安装：未指定 --with-npcap，跳过 Npcap（反扫描不可用）。",
                    "Non-interactive install: Npcap was not requested; anti-scan will be unavailable.");
                return;
            }

            Console.WriteLine();
            Console.WriteLine("反端口扫描需要 Npcap（Windows 数据包捕获驱动）。");
            Console.WriteLine("本安装包附带 Npcap 官方安装程序，未做任何修改。");
            Console.WriteLine();
            Console.WriteLine("安装 Npcap 时会打开官方安装窗口，请保持以下选项：");
            Console.WriteLine("  [ ] Install Npcap in WinPcap API-compatible Mode");
            Console.WriteLine("  [ ] Support loopback traffic");
            Console.WriteLine("  [ ] Support raw 802.11 traffic");
            Console.WriteLine("  [x] Restrict Npcap driver's access to Administrators only");
            Console.WriteLine();
            Console.WriteLine("是否现在安装 Npcap？[Y/n]");
            Console.WriteLine("Install Npcap now? [Y/n]");
            Console.Write("> ");

            var answer = Console.ReadLine()?.Trim();
            install = answer is null
                      || answer.Length == 0
                      || answer.Equals("y", StringComparison.OrdinalIgnoreCase)
                      || answer.Equals("yes", StringComparison.OrdinalIgnoreCase);
        }

        if (!install)
        {
            Bilingual.Say(
                "已跳过 Npcap；防火墙主功能继续安装，反扫描不可用。",
                "Npcap skipped; the firewall installs normally and anti-scan is unavailable.");
            return;
        }

        if (!VerifyNpcapInstaller(payload.NpcapInstaller))
        {
            Bilingual.Fail(
                "Npcap 安装包校验失败，已停止安装 Npcap。",
                "The bundled Npcap installer failed verification; Npcap was not installed.");
            return;
        }

        Bilingual.Say(
            "正在打开 Npcap 官方安装程序…",
            "Opening the official Npcap installer…");
        Bilingual.Say(
            "请在 Npcap 窗口里完成安装，然后回到本窗口。",
            "Complete the Npcap setup, then return to this window.");

        try
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = payload.NpcapInstaller,
                Arguments = "/winpcap_mode=disabled /loopback_support=disabled " +
                            "/dot11_support=disabled /admin_only=enforced",
                UseShellExecute = false,
                CreateNoWindow = false,
                WorkingDirectory = payload.DirectoryPath,
            };

            using var process = Process.Start(startInfo);

            if (process is null)
            {
                Bilingual.Fail(
                    "无法启动 Npcap 安装程序。",
                    "Could not start the Npcap installer.");
                return;
            }

            process.WaitForExit();
            var code = process.ExitCode;

            if (code is 0 or 3010)
            {
                var reboot = code == 3010
                    ? "Npcap 安装成功，但需要重启后才会完全生效。"
                    : "Npcap 安装完成。";

                Bilingual.Say(reboot, code == 3010
                    ? "Npcap installed; a reboot is required before it is fully active."
                    : "Npcap installation completed.");
            }
            else if (code == 1)
            {
                Bilingual.Say(
                    "Npcap 安装被取消；反扫描不可用。",
                    "Npcap installation was cancelled; anti-scan is unavailable.");
            }
            else
            {
                Bilingual.Say(
                    $"Npcap 安装未完成（退出码 {code}）；反扫描不可用。",
                    $"Npcap installation did not complete (exit code {code}); anti-scan is unavailable.");
            }
        }
        catch (Exception ex)
        {
            Bilingual.Fail(
                $"启动 Npcap 安装程序失败：{ex.Message}",
                $"Failed to start the Npcap installer: {ex.Message}");
        }

        if (!NpcapLocator.IsAvailable)
        {
            Bilingual.Say(
                "当前仍未检测到 Npcap；可以稍后重装 WinAppGuard 或手动安装 Npcap。",
                "Npcap is still not detected; reinstall WinAppGuard later or install Npcap manually.");
        }
    }

    private static bool VerifyNpcapInstaller(string path)
    {
        const string expectedHash =
            "682B57E1C05EF375931975C9D6DED40888F4BFDF9F4B11571E654F962F1199B6";

        try
        {
            var actual = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)));

            if (!string.Equals(actual, expectedHash, StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }

            // Authenticode 的 PE 签名提取目前没有 X509CertificateLoader 等价 API；
            // 这里只读取签名者 Subject，真正的完整性由上面的固定 SHA-256 保证。
#pragma warning disable SYSLIB0057
            var cert = System.Security.Cryptography.X509Certificates.X509Certificate
                .CreateFromSignedFile(path);
#pragma warning restore SYSLIB0057

            var subject = cert.Subject ?? string.Empty;
            return subject.Contains("Nmap Software LLC", StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception)
        {
            return false;
        }
    }

    private static int Repair(bool allowOwnerMismatch)
    {
        using var payload = LocatePayload();
        TryStopUiProcesses();

        if (ServiceControl.IsInstalled(ServiceProtocol.ServiceName))
        {
            Bilingual.Say("停止服务…", "Stopping the service…");
            ServiceControl.Stop(ServiceProtocol.ServiceName);
        }

        Directory.CreateDirectory(InstallDirectory);
        CopyPayload(payload);
        ShellShortcut.CreateDesktopShortcut(Path.Combine(InstallDirectory, UiExeName));

        MaybeInstallNpcap(payload);

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
            Bilingual.Fail("受保护模式准备失败，修复中止（服务未启动）。", "Protected-mode preparation failed; repair aborted (service not started).");
            return 6;
        }

        var daclApplied = ApplyServiceDacl();

        if (!daclApplied && IsCurrentUserOwner())
        {
            Bilingual.Fail(
                "受保护模式：当前账户是所有者，但服务 DACL 设置失败；修复中止。",
                "Protected mode: this account is the owner, but setting the service DACL failed; repair aborted.");
            return 6;
        }

        var signerReady = ConfigureSignerForIpc();

        if (!signerReady && IsCurrentUserOwner())
        {
            Bilingual.Fail(
                "受保护模式：当前账户是所有者，但签名密钥加载失败；修复中止。",
                "Protected mode: this account is the owner, but loading the signing key failed; repair aborted.");
            return 6;
        }

        ServiceControl.Start(ServiceProtocol.ServiceName);
        Thread.Sleep(1200);

        if (ServiceControl.IsRunning(ServiceProtocol.ServiceName))
        {
            if (signerReady && !VerifyServiceAuth())
            {
                Bilingual.Fail("受保护模式签名自检失败，修复中止。请查看服务日志。", "Protected-mode signing self-check failed; repair aborted. See the service log.");
                return 6;
            }

            TryMigrateUserDataToService();
            TryRecoverLegacyStrictMode();
        }

        Console.WriteLine(ServiceControl.IsRunning(ServiceProtocol.ServiceName)
            ? Bilingual.One("修复完成，服务正在运行。", "Repair completed; the service is running.")
            : Bilingual.One("修复后服务仍未运行，请查看日志。", "The service is still not running after repair; see the logs."));

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
                Bilingual.Fail($"设置服务 DACL 失败：{error}", $"Failed to set the service DACL: {error}");
                return false;
            }

            Bilingual.Say(
                $"服务 DACL：SYSTEM + {config.OwnerName} 完全控制；Administrators 仅查询/启动。",
                $"Service DACL: SYSTEM + {config.OwnerName} full control; Administrators query/start only.");
            return true;
        }
        catch (Exception ex)
        {
            Bilingual.Fail($"设置服务 DACL 失败：{ex.Message}", $"Failed to set the service DACL: {ex.Message}");
            return false;
        }
    }

    /// <summary>把已安装密钥加载成 ServiceClient 的签名器。</summary>
    private static bool ConfigureSignerForIpc()
    {
        if (ProtectedModeClient.TryConfigureSigner(out var fingerprint, out var error))
        {
            Bilingual.Say(
                $"受保护模式：签名密钥已加载（指纹 {fingerprint?[..16]}…）。",
                $"Protected mode: signing key loaded (fingerprint {fingerprint?[..16]}…).");
            return true;
        }

        Bilingual.Say(
            $"受保护模式：当前账户无法加载签名密钥（{error}）；签名自检与旧数据迁移将跳过。",
            $"Protected mode: this account cannot load the signing key ({error}); signing self-check and legacy data migration will be skipped.");
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
            Bilingual.Say("受保护模式：没有签名能力，跳过安装后签名自检。", "Protected mode: no signing capability; skipping the post-install signing self-check.");
            return true;
        }

        string expectedFingerprint;

        try
        {
            expectedFingerprint = CreateOwnerKeyStore().ReadConfig().Fingerprint;
        }
        catch (Exception ex)
        {
            Bilingual.Fail($"读取受保护模式配置失败：{ex.Message}", $"Failed to read the protected-mode config: {ex.Message}");
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
            Bilingual.Fail(
                $"签名 status 自检失败：{lastError ?? "服务没有返回状态"}",
                $"Signed status self-check failed: {lastError ?? "the service returned no status"}");
            return false;
        }

        if (status.ProtocolVersion != ServiceProtocol.Version || !status.ProtectedMode)
        {
            Bilingual.Fail(
                $"签名自检失败：协议 {status.ProtocolVersion}，受保护模式={status.ProtectedMode}。",
                $"Signing self-check failed: protocol {status.ProtocolVersion}, protected mode={status.ProtectedMode}.");
            return false;
        }

        if (!string.Equals(
                status.ProtectedModeFingerprint, expectedFingerprint,
                StringComparison.OrdinalIgnoreCase))
        {
            Bilingual.Fail(
                "签名自检失败：服务使用的公钥指纹与本地配置不一致。",
                "Signing self-check failed: the service's public-key fingerprint does not match the local config.");
            return false;
        }

        Bilingual.Say(
            $"受保护模式：签名自检通过（所有者 {status.ProtectedModeOwner}，指纹 {status.ProtectedModeFingerprint![..16]}…）。",
            $"Protected mode: signing self-check passed (owner {status.ProtectedModeOwner}, fingerprint {status.ProtectedModeFingerprint![..16]}…).");
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
                Bilingual.Fail($"清理旧密钥失败：{error ?? "未知原因"}", $"Failed to clean up the old key: {error ?? "unknown reason"}");

                if (deleteScheduled)
                {
                    Bilingual.Fail("已登记重启后删除；请重启 Windows 后再安装。", "Deletion is scheduled for the next restart; restart Windows and run the installer again.");
                }

                return false;
            }

            using var key = store.Create(owner, ownerName);
            Bilingual.Say(
                $"受保护模式：已为 {ownerName} 生成新密钥（指纹 {key.Fingerprint[..16]}…）。",
                $"Protected mode: new key generated for {ownerName} (fingerprint {key.Fingerprint[..16]}…).");
            return true;
        }
        catch (Exception ex)
        {
            Bilingual.Fail($"受保护模式密钥创建失败：{ex.Message}", $"Failed to create the protected-mode key: {ex.Message}");
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
                Bilingual.Say(
                    "受保护模式目录存在但无法读取（当前账户不是所有者）；保留原配置。",
                    "The protected-mode folder exists but cannot be read (this account is not the owner); the existing config is kept.");
                return true;
            }

            if (hasEntries)
            {
                Bilingual.Say(
                    "受保护模式目录存在但没有可读配置；为安全起见保留，请由所有者运行 --repair，或用 --reset-owner 重建。",
                    "The protected-mode folder exists but has no readable config; it was kept for safety. Run --repair as the owner, or rebuild it with --reset-owner.");
                return true;
            }

            if (!CheckOwnerMatchesInteractiveSession(allowOwnerMismatch))
            {
                return false;
            }

            Bilingual.Say("受保护模式：未发现密钥（首次升级/配置缺失），按当前账户生成。", "Protected mode: no key found (first upgrade or missing config); generating one for the current account.");
            return CreateKeyFor(store, owner, ownerName);
        }

        try
        {
            var config = store.ReadConfig();

            if (!string.Equals(
                    config.OwnerSid, owner.Value, StringComparison.OrdinalIgnoreCase))
            {
                Bilingual.Say(
                    $"受保护模式：现有所有者是 {config.OwnerName}（{config.OwnerSid}）。",
                    $"Protected mode: the current owner is {config.OwnerName} ({config.OwnerSid}).");
                Bilingual.Say(
                    "当前账户不是所有者：密钥保留，当前账户仍无法使用界面/服务。",
                    "This account is not the owner: the key is kept, and this account still cannot use the UI/service.");
                return true;
            }

            try
            {
                using var key = store.LoadForOwner(owner);
                Bilingual.Say(
                    $"受保护模式：保留现有密钥（指纹 {key.Fingerprint[..16]}…）。",
                    $"Protected mode: existing key kept (fingerprint {key.Fingerprint[..16]}…).");
                return true;
            }
            catch (Exception ex)
            {
                Bilingual.Fail($"现有密钥不可用：{ex.Message}", $"The existing key is unusable: {ex.Message}");
                Bilingual.Fail("按同一所有者重建密钥（旧密钥将被替换）。", "Rebuilding the key for the same owner (the old key will be replaced).");
                return CreateKeyFor(store, owner, ownerName);
            }
        }
        catch (UnauthorizedAccessException ex)
        {
            Bilingual.Say($"受保护模式：无法读取配置（当前账户不是所有者？）：{ex.Message}", $"Protected mode: cannot read the config (is this account not the owner?): {ex.Message}");
            Bilingual.Say("保留原配置与密钥；当前账户仍无法使用界面/服务。", "The existing config and key are kept; this account still cannot use the UI/service.");
            return true;
        }
        catch (Exception ex) when (ex is InvalidDataException or FileNotFoundException)
        {
            Bilingual.Fail($"受保护模式配置缺失/损坏：{ex.Message}", $"Protected-mode config missing or corrupted: {ex.Message}");
            Bilingual.Fail("按当前账户重建所有者与密钥。", "Rebuilding the owner and key for the current account.");
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
            Bilingual.Say(
                $"受保护模式：已生成密钥（指纹 {key.Fingerprint[..16]}…）。",
                $"Protected mode: key generated (fingerprint {key.Fingerprint[..16]}…).");
            return true;
        }
        catch (Exception ex)
        {
            Bilingual.Fail($"受保护模式密钥创建失败：{ex.Message}", $"Failed to create the protected-mode key: {ex.Message}");
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
            Bilingual.Say("提示：无法检测交互登录账户，跳过跨账户检查。", "Note: the interactive logon account could not be detected; the cross-account check is skipped.");
            return true;
        }

        if (interactive.Equals(current))
        {
            return true;
        }

        Bilingual.Fail("检测到提权账户与当前登录账户不同：", "The elevated account differs from the signed-in account:");
        Bilingual.Fail($"  登录账户：{interactiveName ?? interactive.Value}", $"  Signed-in account: {interactiveName ?? interactive.Value}");
        Bilingual.Fail($"  所有者（提权账户）：{OwnerAccount.GetCurrentName()}", $"  Owner (elevated account): {OwnerAccount.GetCurrentName()}");

        if (allowMismatch)
        {
            Bilingual.Say(
                "已按 --allow-owner-mismatch 继续；之后只有提权账户能使用界面/服务。",
                "Continuing because of --allow-owner-mismatch; afterwards only the elevated account can use the UI/service.");
            return true;
        }

        Bilingual.Fail(
            "默认取消。确认要让提权账户成为唯一所有者，请加 --allow-owner-mismatch。",
            "Cancelled by default. To make the elevated account the sole owner, add --allow-owner-mismatch.");
        return false;
    }

    /// <summary>同一所有者换新密钥；旧密钥被覆盖。</summary>
    private static int RotateKey()
    {
        if (!ServiceControl.IsInstalled(ServiceProtocol.ServiceName))
        {
            Bilingual.Fail("防护服务尚未安装。请先运行 --install 或 --repair。", "The guard service is not installed. Run --install or --repair first.");
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
            Bilingual.Fail($"读取受保护模式配置失败：{ex.Message}", $"Failed to read the protected-mode config: {ex.Message}");
            return 6;
        }

        if (!string.Equals(
                config.OwnerSid, owner.Value, StringComparison.OrdinalIgnoreCase))
        {
            Bilingual.Fail(
                $"当前账户不是所有者（所有者：{config.OwnerName}）。",
                $"This account is not the owner (owner: {config.OwnerName}).");
            Bilingual.Fail("要更换所有者，请运行 --reset-owner。", "To change the owner, run --reset-owner.");
            return 7;
        }

        if (!StopServiceForMaintenance())
        {
            return 4;
        }

        try
        {
            using var key = store.Create(owner, ownerName);
            Bilingual.Say(
                $"密钥已轮换：{config.Fingerprint[..16]}… → {key.Fingerprint[..16]}…",
                $"Key rotated: {config.Fingerprint[..16]}… → {key.Fingerprint[..16]}…");
        }
        catch (Exception ex)
        {
            Bilingual.Fail($"密钥轮换失败：{ex.Message}", $"Key rotation failed: {ex.Message}");
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
            Bilingual.Fail("防护服务尚未安装。请先运行 --install 或 --repair。", "The guard service is not installed. Run --install or --repair first.");
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
            Bilingual.Fail($"删除旧密钥失败：{error ?? "未知原因"}", $"Failed to delete the old key: {error ?? "unknown reason"}");

            if (deleteScheduled)
            {
                Bilingual.Fail("已登记重启后删除；请重启 Windows 后再运行 --reset-owner。", "Deletion is scheduled for the next restart; restart Windows and run --reset-owner again.");
            }

            return 6;
        }

        if (!CreateKeyFor(store, owner, ownerName))
        {
            return 6;
        }

        Bilingual.Say($"所有者已切换为：{ownerName}", $"Owner changed to: {ownerName}");

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
                Bilingual.Say("停止服务…", "Stopping the service…");
                ServiceControl.Stop(ServiceProtocol.ServiceName);
            }

            if (ServiceControl.IsRunning(ServiceProtocol.ServiceName))
            {
                Bilingual.Fail("服务仍在运行，无法安全更换密钥。", "The service is still running; the key cannot be replaced safely.");
                return false;
            }

            return true;
        }
        catch (Exception ex)
        {
            Bilingual.Fail($"停止服务失败：{ex.Message}", $"Failed to stop the service: {ex.Message}");
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
                Bilingual.Say("服务已启动。", "Service started.");
                return true;
            }

            Bilingual.Fail(
                "服务没有在 10 秒内进入运行状态。请查看 %ProgramData%\\WinAppGuard\\logs。",
                "The service did not reach the running state within 10 seconds. See %ProgramData%\\WinAppGuard\\logs.");
            return false;
        }
        catch (Exception ex)
        {
            Bilingual.Fail($"启动服务失败：{ex.Message}", $"Failed to start the service: {ex.Message}");
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
                Bilingual.Say("没有签名密钥，跳过旧数据迁移。", "No signing key; skipping legacy data migration.");
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
                Bilingual.Fail("服务未就绪，跳过旧数据迁移（下次 --repair 会再试）。", "The service is not ready; skipping legacy data migration (the next --repair will retry).");
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
                    Bilingual.Say($"分组迁移：{response.Affected} 条。", $"Rule groups migrated: {response.Affected}.");
                }
                else
                {
                    Bilingual.Fail($"分组迁移失败（旧文件保留）：{response?.Error ?? error}", $"Rule-group migration failed (the old file is kept): {response?.Error ?? error}");
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
                    Bilingual.Say("记录设置：已迁移到服务。", "Audit settings migrated to the service.");
                }
                else
                {
                    Bilingual.Fail($"记录设置迁移失败：{response?.Error ?? error}", $"Audit settings migration failed: {response?.Error ?? error}");
                }
            }
        }
        catch (Exception ex)
        {
            Bilingual.Fail($"旧数据迁移失败（不影响安装）：{ex.Message}", $"Legacy data migration failed (installation is not affected): {ex.Message}");
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
                Console.WriteLine(Bilingual.One(
                    result.Message,
                    $"Audit records migration: {result.Migrated} migrated, {result.Failed} failed."));
            }
        }
        catch (Exception ex)
        {
            Bilingual.Fail($"记录迁移失败（不影响安装，源文件保留）：{ex.Message}", $"Audit record migration failed (installation is not affected; source files are kept): {ex.Message}");
        }
    }

    private static int StartServiceOnly()
    {
        if (!ServiceControl.IsInstalled(ServiceProtocol.ServiceName))
        {
            Bilingual.Fail("防护服务尚未安装。请先运行 --install 或 --repair。", "The guard service is not installed. Run --install or --repair first.");
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
            Bilingual.Fail("服务没有在 10 秒内进入运行状态。请查看 %ProgramData%\\WinAppGuard\\logs。", "The service did not reach the running state within 10 seconds. See %ProgramData%\\WinAppGuard\\logs.");
            return 4;
        }

        Bilingual.Say("服务已启动（自动启动、不延迟）。", "Service started (automatic, no delay).");
        return 0;
    }

    private static int Uninstall(bool keepData)
    {
        // 3.4：收紧后的 WFP DACL 只允许所有者删除对象。
        // 有对象且当前账户不是所有者时先拒绝，避免“服务删了、规则还在”的半卸载。
        if (WfpRecovery.HasOurObjects() && !ProtectedModeClient.IsCurrentUserOwner())
        {
            Bilingual.Fail(
                "还有本工具的 WFP 规则，但当前账户不是所有者。3.4 起这些规则只允许所有者删除；请用安装时的所有者账户运行卸载。",
                "This app still has WFP rules, but the current account is not the owner. Since 3.4 only the owner can delete them; run the uninstaller as the install account.");
            return 7;
        }

        Bilingual.Say("停止界面进程…", "Stopping UI processes…");
        TryStopUiProcesses();

        Bilingual.Say("删除开机自启任务…", "Deleting the logon auto-start task…");
        try
        {
            _ = AutoStartManager.Disable();
        }
        catch (Exception ex)
        {
            Bilingual.Fail($"删除开机自启任务失败（可手动在 taskschd.msc 删除）：{ex.Message}", $"Failed to delete the logon auto-start task (you can delete it manually in taskschd.msc): {ex.Message}");
        }

        ShellShortcut.DeleteDesktopShortcut();

        var serviceRemoved = true;

        if (ServiceControl.IsInstalled(ServiceProtocol.ServiceName))
        {
            Bilingual.Say("停止服务…", "Stopping the service…");

            try
            {
                ServiceControl.Stop(ServiceProtocol.ServiceName);
            }
            catch (Exception ex)
            {
                Bilingual.Fail($"停止服务失败（继续删除）：{ex.Message}", $"Failed to stop the service (deletion continues): {ex.Message}");
            }

            Bilingual.Say("删除服务…", "Deleting the service…");
            ServiceControl.Uninstall(ServiceProtocol.ServiceName);
            serviceRemoved = !ServiceControl.IsInstalled(ServiceProtocol.ServiceName);

            if (!serviceRemoved)
            {
                Bilingual.Fail(
                    "服务仍然存在（可能是服务 DACL 只允许所有者删除；请由所有者运行卸载，或先由管理员接管服务权限）。",
                    "The service still exists (its DACL may allow only the owner to delete it). Run the uninstaller as the owner, or take over the service permissions as an administrator first.");
            }
        }

        // 完整删除本程序在 WFP 里留下的对象（过滤器 + 子层）。
        // 放在删服务之后：服务停止后文件句柄释放，子层也能删干净。
        var rulesRecovered = false;

        try
        {
            var report = WfpRecovery.Recover();
            rulesRecovered = true;
            Console.WriteLine(Bilingual.One(
                $"WFP 清理：{report.Describe()}",
                report.WasAlreadyClean
                    ? "WFP cleanup: nothing left by this app; the system was already clean."
                    : $"WFP cleanup: {report.FiltersDeleted} filters deleted and this app's sublayer removed."));
        }
        catch (Exception ex)
        {
            Bilingual.Fail($"删除 WFP 对象失败：{ex.Message}", $"Failed to delete WFP objects: {ex.Message}");
            Bilingual.Fail("规则可能仍存在。请稍后重新运行卸载程序。", "Rules may still exist. Run the uninstaller again later.");
        }

        // 密钥始终删除，包括 --keep-data。卸载后应用不再持有任何可用副本。
        var keyDeleted = DeleteProtectedMode();

        if (!keepData)
        {
            DeleteDirectoryIfExists(DataDirectory, "数据目录（记录 / 快照 / 设置）", "data folder (records / snapshots / settings)");

            var localData = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                AppConstants.AppDataFolderName);

            DeleteDirectoryIfExists(localData, "用户目录（界面设置 / 日志）", "user folder (UI settings / logs)");
        }

        // 数据目录统删可能已经把密钥目录一起删掉；以实际结果为准。
        keyDeleted |= !ProtectedModeFilesExist();

        var installDeleted = DeleteInstallDirectory();

        Console.WriteLine();
        Console.WriteLine(rulesRecovered && installDeleted && keyDeleted && serviceRemoved
            ? Bilingual.One("卸载完成。", "Uninstall completed.")
            : Bilingual.One("卸载完成，但有部分内容未能删除（见上）。", "Uninstall completed, but some items could not be deleted (see above)."));

        if (keepData)
        {
            Bilingual.Say(
                $"已保留数据目录：{DataDirectory}（受保护模式密钥已删除，重装会生成新密钥）",
                $"Data folder kept: {DataDirectory} (the protected-mode key was deleted; reinstalling generates a new key).");
        }

        return rulesRecovered && installDeleted && keyDeleted && serviceRemoved ? 0 : 3;
    }

    /// <summary>卸载时删除密钥目录并校验；删不掉要如实报告。</summary>
    private static bool DeleteProtectedMode()
    {
        var store = CreateOwnerKeyStore();

        if (!ProtectedModeFilesExist())
        {
            Bilingual.Say("受保护模式密钥：不存在（无需删除）。", "Protected-mode key: not present (nothing to delete).");
            return true;
        }

        var owner = OwnerAccount.GetCurrentSid();

        if (store.TryDeleteAll(owner, out var error, out var deleteScheduled))
        {
            Bilingual.Say("受保护模式密钥：已删除并校验不存在。", "Protected-mode key: deleted and verified absent.");
            return true;
        }

        Bilingual.Fail($"受保护模式密钥删除失败：{error ?? "未知原因"}", $"Failed to delete the protected-mode key: {error ?? "unknown reason"}");

        if (deleteScheduled)
        {
            Bilingual.Fail(
                "已登记重启后删除；请在重启后确认 protected-mode 目录已消失。",
                "Deletion is scheduled for the next restart; after restarting, confirm that the protected-mode folder is gone.");
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
        Bilingual.Say("WinAppGuard 安装工具（双击模式）", "WinAppGuard Setup (double-click mode)");
        Console.WriteLine();

        var code = ServiceControl.IsInstalled(ServiceProtocol.ServiceName)
            ? RepairWithBanner(allowOwnerMismatch)
            : InstallWithBanner(allowOwnerMismatch);

        PauseIfInteractive();
        return code;
    }

    private static int InstallWithBanner(bool allowOwnerMismatch)
    {
        Bilingual.Say("执行安装…", "Installing…");
        Console.WriteLine();
        return Install(allowOwnerMismatch);
    }

    private static int RepairWithBanner(bool allowOwnerMismatch)
    {
        Bilingual.Say("检测到已安装：执行修复（保留密钥、规则与数据）…", "Already installed: repairing (key, rules and data are kept)…");
        Console.WriteLine();
        return Repair(allowOwnerMismatch);
    }

    /// <summary>双击卸载器（WinAppGuardUninstall.exe）：确认后完整卸载。</summary>
    private static int RunUninstallerInteractive()
    {
        Console.WriteLine("WinAppGuard 卸载程序 | WinAppGuard Uninstaller");
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
        Console.WriteLine("This will delete:");
        Console.WriteLine("  - the guard service WinAppGuardSvc");
        Console.WriteLine("  - all WFP rules and the sublayer created by this app");
        Console.WriteLine("  - the desktop shortcut and the logon auto-start task");
        Console.WriteLine("  - the protected-mode key (always deleted)");
        Console.WriteLine("  - records / rule snapshots / settings (%ProgramData%\\WinAppGuard)");
        Console.WriteLine("  - UI settings and logs (%LOCALAPPDATA%\\WinAppGuard)");
        Console.WriteLine("  - the install folder (C:\\Program Files\\WinAppGuard)");
        Console.WriteLine();
        Console.Write("确定要完全卸载吗？[y/N]  Completely uninstall? [y/N] ");

        if (Console.IsInputRedirected)
        {
            Console.WriteLine();
            Bilingual.Fail("非交互模式请使用：WinAppGuardUninstall.exe --uninstall", "For non-interactive use: WinAppGuardUninstall.exe --uninstall");
            return 1;
        }

        var answer = Console.ReadLine()?.Trim();

        if (!string.Equals(answer, "y", StringComparison.OrdinalIgnoreCase)
            && !string.Equals(answer, "yes", StringComparison.OrdinalIgnoreCase))
        {
            Bilingual.Say("已取消，未做任何修改。", "Cancelled; nothing was changed.");
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
                Bilingual.Say($"已结束界面进程（PID {process.Id}）。", $"Stopped UI process (PID {process.Id}).");
            }
            catch (Exception ex)
            {
                Bilingual.Fail($"结束界面进程失败（PID {process.Id}）：{ex.Message}", $"Failed to stop UI process (PID {process.Id}): {ex.Message}");
            }
        }
    }

    private static void DeleteDirectoryIfExists(
        string path, string descriptionZh, string descriptionEn)
    {
        if (!Directory.Exists(path))
        {
            return;
        }

        try
        {
            Directory.Delete(path, recursive: true);
            Console.WriteLine(Bilingual.One(
                $"已删除{descriptionZh}：{path}", $"Deleted {descriptionEn}: {path}"));
        }
        catch (Exception ex)
        {
            Bilingual.Fail(
                $"删除{descriptionZh}失败：{ex.Message}", $"Failed to delete {descriptionEn}: {ex.Message}");
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
                Bilingual.Say($"已删除安装目录：{InstallDirectory}", $"Deleted the install folder: {InstallDirectory}");
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

            Bilingual.Say("安装目录将在程序退出后删除。", "The install folder will be deleted after this program exits.");
            return true;
        }
        catch (Exception ex)
        {
            Bilingual.Fail($"删除安装目录失败（可能有文件仍被占用）：{ex.Message}", $"Failed to delete the install folder (some files may still be in use): {ex.Message}");
            Bilingual.Fail("请关闭相关程序后重试，或手动删除该目录。", "Close the programs involved and retry, or delete the folder manually.");
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
        Bilingual.Say("按任意键退出…", "Press any key to exit…");

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
            Console.WriteLine(Bilingual.One(
                result.Message,
                result.Restored
                    ? "Legacy strict mode restored: outbound is Allow for all three profiles."
                    : "Legacy strict mode was left on but could not be fully restored."));

            if (!result.Restored)
            {
                Bilingual.Fail("⚠ 自动还原没有完全成功：请手工把 wf.msc 三套配置文件的「出站连接」都改成「允许」。", "WARNING: automatic restore did not fully succeed. In wf.msc, set Outbound connections to Allow for all three profiles.");
            }
        }
        catch (Exception ex)
        {
            Bilingual.Fail($"1.x 严格模式兜底失败（不影响安装）：{ex.Message}", $"1.x strict-mode recovery failed (installation is not affected): {ex.Message}");
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
                $"安装器没有内置载荷，同目录也缺少 {UiExeName} / {ServiceExeName}（当前目录：{source}）。"
                + Environment.NewLine
                + $"The installer has no embedded payload and the folder does not contain {UiExeName} / {ServiceExeName} (current folder: {source}).");
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

        if (File.Exists(payload.NpcapLicense))
        {
            CopyIfDifferent(
                payload.NpcapLicense,
                Path.Combine(InstallDirectory, "Npcap-LICENSE.txt"));
        }
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

        internal string NpcapInstaller => Path.Combine(DirectoryPath, EmbeddedPayload.NpcapInstallerName);

        internal string NpcapLicense => Path.Combine(DirectoryPath, EmbeddedPayload.NpcapLicenseName);

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
