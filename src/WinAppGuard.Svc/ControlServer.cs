using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using WinAppGuard.Contracts;
using WinAppGuard.Contracts.Protocol;
using WinAppGuard.Core;
using WinAppGuard.Core.ProtectedMode;
using WinAppGuard.Core.Wfp;
using WinAppGuard.Models;

namespace WinAppGuard.Service;

/// <summary>
/// 命名管道服务端（3.1 协议 v2）。
///
/// 认证顺序：
///   1. 管道 ACL（3.1 仍是 SYSTEM + Administrators + Interactive）；
///   2. 客户端令牌检查（拿 PID / 是否提权）；
///   3. **挑战-签名**：服务发 32 字节 nonce，客户端用所有者 ECDSA 私钥
///      对 <c>nonce || 请求原始字节</c> 签名；验签失败一律拒绝。
///
/// 写命令仍然要求客户端令牌已提权（M1.5 的 UAC 模型）；
/// 查看/记录只要求签名，不要求提权。
/// </summary>
internal sealed class ControlServer : IDisposable
{
    private static readonly RuleHandlers Rules = new();

    private PipeHost? _pipeHost;
    // 5.9：命令路由在 Start 里创建并校验；校验失败时不创建控制管道（失败关闭）。
    private static CommandRouter? _router;
    private static ModuleHost? _modules;
    // 服务进程里只有一个 ControlServer；BuildStatus 被 RuleHandlers 静态调用，
    // 所以这两项用 static，保证状态命令和规则命令看到同一份配置。
    private static ProtectedModeConfig? _protectedMode;
    private static int _authRejectedCount;
    private System.Threading.Timer? _expiryTimer;
    private System.Threading.Timer? _tamperTimer;
    private System.Threading.Timer? _lockdownTimer;

    internal void Start()
    {
        // 5.9：先校验命令目录。每条命令必须恰好一个 Handler、策略显式；
        // 失败时不创建控制管道，避免线上出现“有的命令没人处理”。
        try
        {
            _router = ServiceCatalog.CreateRouter();
            ServiceLog.Info(
                "WAG-IPC-013",
                $"Command catalog validated: {_router.Handlers.Count} commands, "
                + $"{_router.Handlers.Select(handler => handler.Module).Distinct(StringComparer.Ordinal).Count()} modules.");
        }
        catch (Exception ex)
        {
            _router = null;
            ServiceLog.Error(
                "WAG-IPC-014",
                "Command catalog validation failed; the control pipe will not be created.", ex);
        }

        // 3.1：启动时加载受保护模式配置。缺失/损坏就**不创建控制管道**（失败关闭），
        // 但 WFP / 审计仍然工作；由 Setup --repair 重建配置。
        try
        {
            _protectedMode = ProtectedModeConfig.Load(
                ServicePaths.ProtectedModeConfigFile);

            ServiceLog.Info(
                "WAG-AUTH-001",
                $"Protected mode: owner {_protectedMode.OwnerName}, fingerprint {_protectedMode.Fingerprint[..16]}...");
        }
        catch (Exception ex)
        {
            _protectedMode = null;
            ServiceLog.Error(
                "WAG-AUTH-002",
                "Protected-mode config is unavailable; the control pipe will not be created (fail closed). "
                + "Run WinAppGuardSetup.exe --repair as the owner.", ex);
        }

        // 3.0-c：界面以普通权限运行，需要读取快照与审计记录。
        ServiceDataPermissions.EnsureReadableByUsers();

        // 1.x → 2.0 的规则迁移（从 1.x 直接升到 3.0 的机器需要）。
        // 界面不再做这件事（它已经没有 WFP 访问能力）。
        try
        {
            var migration = StartupMigration.RunIfNeeded(out var migrationError);

            if (migrationError is not null)
            {
                ServiceLog.Warning("WAG-DATA-010", "Startup migration reported an error; legacy rules are kept and the next start will retry.");
            }

            if (migration is not null)
            {
                ServiceLog.Info(
                    "WAG-DATA-011",
                    $"Startup migration: migrated {migration.Migrated}, skipped {migration.Skipped}, "
                    + $"failed {migration.Failed}, legacy firewall rules deleted {migration.FirewallRulesDeleted}.");
            }
        }
        catch (Exception ex)
        {
            ServiceLog.Warning("WAG-DATA-012", "Startup migration failed (service startup is not affected).", ex);
        }

        // 3.4：启动时只在快照不存在时写一份，绝不用“实际过滤器”覆盖权威副本。
        // 这样“服务停止期间过滤器被外部删除”仍然能被篡改防护按快照补回。
        ServiceLog.Info("WAG-DATA-013", "Startup: ensuring the rule snapshot.");
        Rules.SaveSnapshotIfMissing();

        // 3.4：把 3.1–3.3 创建的 WFP 对象迁移到 owner-only DACL。
        // 迁移会删除并重建过滤器，所以放在管道启动之前，避免客户端并发写入。
        Rules.MigrateDaclIfNeeded(_protectedMode?.OwnerSid);

        // 迁移失败或过滤器在停机期间被删除时，启动阶段就按快照补回，
        // 不等 15 秒后的定时器。
        Rules.CheckTamper();

        // 5.9：按模块启动。rules 先启动定时清理，检测 Host 按依赖顺序启动，
        // 控制管道最后启动；单个模块失败不阻止其它模块。
        _modules = new ModuleHost(ServiceModules.Create(this));
        _modules.StartAll();
    }

    /// <summary>5.9：规则相关定时器（到期清理、篡改检测、临时锁网）。</summary>
    internal void StartRuleServices()
    {
        // 到期清理归服务：界面关掉、没人点刷新时也要准时解除临时阻断。
        _expiryTimer = new System.Threading.Timer(
            _ => Rules.PurgeExpiredQuietly(),
            state: null,
            dueTime: TimeSpan.FromSeconds(3),
            period: TimeSpan.FromSeconds(30));

        // 篡改检测：每 10 秒拿权威副本和实际过滤器比对（删了立即重建）。
        _tamperTimer = new System.Threading.Timer(
            _ => Rules.CheckTamper(),
            state: null,
            dueTime: TimeSpan.FromSeconds(15),
            period: TimeSpan.FromSeconds(10));

        // 3.5：临时锁网到期检查。每秒一次，锁内只比较一个 DateTime；
        // 到期撤销在 RuleHandlers 的串行锁里做，避免与规则写入同时碰 WFP。
        _lockdownTimer = new System.Threading.Timer(
            _ => Rules.ExpireLockdownIfDue(),
            state: null,
            dueTime: TimeSpan.FromSeconds(1),
            period: TimeSpan.FromSeconds(1));
    }

    internal void StopRuleServices()
    {
        _expiryTimer?.Dispose();
        _expiryTimer = null;
        _tamperTimer?.Dispose();
        _tamperTimer = null;
        _lockdownTimer?.Dispose();
        _lockdownTimer = null;
    }

    /// <summary>5.9：控制管道是最后一个模块，确保依赖模块先就绪。</summary>
    internal void StartControlPlane()
    {
        if (_protectedMode is null || _router is null)
        {
            throw new InvalidOperationException(
                "受保护模式或命令目录不可用，控制管道已禁用。");
        }

        _pipeHost = new PipeHost();
        _pipeHost.Start();

        ServiceLog.Info(
            "WAG-IPC-001",
            $"IPC started: {ServiceProtocol.PipeName} (v4 signed session).");
    }

    internal void StopControlPlane()
    {
        var host = _pipeHost;
        _pipeHost = null;
        host?.Dispose();
    }

    internal static string RulesHealth()
        => $"tamperRebuilt={Rules.TamperRebuiltCount}, expiredPurged={Rules.ExpiredPurgedCount}";

    internal string ControlPlaneHealth()
        => _pipeHost is { IsListening: true } ? "listening" : "not listening";

    internal void Stop()
    {
        StopControlPlane();

        // 严格模式会话随服务一起撤销：停服务 = 立即恢复联网。
        // 放在模块停止之前，避免等检测模块收尾后才恢复。
        LockdownHost.Shutdown();
        StrictModeHost.Shutdown();

        var modules = _modules;
        _modules = null;
        modules?.Dispose();
    }

    public void Dispose()
    {
        Stop();
    }

    /// </summary>
    internal static ProcessPathsView ResolveProcessPaths(ServiceRequest request)
    {
        var paths = new List<ProcessPathDto>();
        var pids = (request.Pids ?? new List<int>())
            .Distinct()
            .Take(64);

        foreach (var pid in pids)
        {
            if (pid <= 0)
            {
                paths.Add(new ProcessPathDto { Pid = pid, Error = "invalid_pid" });
                continue;
            }

            try
            {
                var path = ProcessResolver.TryGetImagePath(pid);

                paths.Add(new ProcessPathDto
                {
                    Pid = pid,
                    Path = path,
                    Error = string.IsNullOrEmpty(path) ? "unavailable" : null,
                });
            }
            catch (Exception)
            {
                paths.Add(new ProcessPathDto { Pid = pid, Error = "unavailable" });
            }
        }

        return new ProcessPathsView
        {
            Ok = true,
            Paths = paths,
        };
    }
    internal static ResponsePayload DispatchRequest(
        ServiceRequest request, bool elevated, uint clientPid)
        => Dispatch(request, elevated, clientPid);

    private static ResponsePayload Dispatch(ServiceRequest request, bool elevated, uint clientPid)
    {
        if (request.ProtocolVersion != ServiceProtocol.Version)
        {
            return new ErrorView
            {
                Ok = false,
                Error = $"协议版本不匹配（服务 {ServiceProtocol.Version}，客户端 {request.ProtocolVersion}）。",
            };
        }

        // 3.0-b 起写命令会用 "write." 前缀，必须提权；v1 的只读命令允许任何交互用户。
        // 5.9：统一由 CommandPolicyTable 判定，不再在这里散落三套规则。
        // 鉴权探针也走同一张策略表（Read），由 Handler 返回当前提权状态。
        var denied = CommandPolicyGuard.Check(request, elevated, clientPid);

        if (denied is not null)
        {
            return denied;
        }

        var router = _router;

        if (router is null)
        {
            return new ErrorView
            {
                Ok = false,
                Error = "服务命令目录未通过启动校验，控制管道不可用。",
            };
        }

        try
        {
            return router.Dispatch(new CommandContext(request, elevated, clientPid));
        }
        catch (Exception ex)
        {
            // 单条命令抛异常不能把整条 IPC 会话打断，否则界面会误判成“服务未运行”。
            ServiceLog.Warning(
                "WAG-IPC-016",
                $"Command {request.Command} threw while dispatching.", ex);

            return new ErrorView
            {
                Ok = false,
                ErrorCode = nameof(ProtocolErrorCode.Internal),
                Error = $"{ex.GetType().Name}: {ex.Message}",
            };
        }
    }

    /// <summary>5.9：规则命令统一交给 RuleHandlers（与启动迁移、定时任务共用同一实例）。</summary>
    internal static ResponsePayload HandleRuleCommand(ServiceRequest request) => Rules.Handle(request);

    internal static ServiceStatus BuildStatus()
    {
        // 与规则写入串行：WFP 的读和写不要同时发生（status 命令不走 RuleHandlers）。
        lock (RuleHandlers.Gate)
        {
            return StatusBuilder.Build();
        }
    }

    private static string BuildVersion()
    {
        var informational = Assembly.GetExecutingAssembly()
            .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?
            .InformationalVersion;

        if (string.IsNullOrEmpty(informational))
        {
            return Assembly.GetExecutingAssembly().GetName().Version?.ToString(3) ?? "0.0.0";
        }

        var plus = informational.IndexOf('+');
        return plus > 0 ? informational[..plus] : informational;
    }

    internal static ProtectedModeConfig? CurrentProtectedMode => _protectedMode;

    internal static bool HasRouter => _router is not null;

    internal static string VersionText => BuildVersion();

    internal static string RuntimeVersion => BuildVersion();

    internal static long RuleRevision => Rules.RuleRevision;

    internal static string RuleRevisionEpoch => Rules.RuleRevisionEpoch;

    internal static RuleHandlers RuleHandler => Rules;

    internal static ModuleHost? CurrentModules => _modules;

    internal static int AuthRejectedCount => Volatile.Read(ref _authRejectedCount);

    internal static int RecordAuthRejection()
        => Interlocked.Increment(ref _authRejectedCount);
}
