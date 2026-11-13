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

    private readonly CancellationTokenSource _cancellation = new();
    private Thread? _thread;
    private bool _loggedReady;
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

        _thread = new Thread(Loop)
        {
            IsBackground = true,
            Name = "ipc-server",
        };

        _thread.Start();

        ServiceLog.Info(
            "WAG-IPC-001",
            $"IPC started: {ServiceProtocol.PipeName} (v3 signed session).");
    }

    internal void StopControlPlane()
    {
        _thread?.Join(3000);
        _thread = null;
    }

    internal static string RulesHealth()
        => $"tamperRebuilt={Rules.TamperRebuiltCount}, expiredPurged={Rules.ExpiredPurgedCount}";

    internal string ControlPlaneHealth()
        => _thread is { IsAlive: true } ? "listening" : "not listening";

    internal void Stop()
    {
        try
        {
            _cancellation.Cancel();
        }
        catch (ObjectDisposedException)
        {
            return;
        }

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
        _cancellation.Dispose();
    }

    private void Loop()
    {
        while (!_cancellation.IsCancellationRequested)
        {
            try
            {
                // 用 NamedPipeServerStreamAcl.Create：安全描述符在**创建时**就生效，
                // 不存在"先建默认管道再收紧"的竞态；也不需要手工 SetSecurityInfo
                // （后者在非管理员下会直接 ACCESS_DENIED，实测）。
                using var pipe = CreateOwnerOnlyPipe();

                if (!_loggedReady)
                {
                    _loggedReady = true;
                    ServiceLog.Info("WAG-IPC-002", "Named pipe created (ACL: SYSTEM + owner only).");
                }

                pipe.WaitForConnectionAsync(_cancellation.Token).GetAwaiter().GetResult();

                if (_cancellation.IsCancellationRequested)
                {
                    break;
                }

                HandleClient(pipe, _cancellation.Token);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (ObjectDisposedException)
            {
                break;
            }
            catch (Exception ex)
            {
                ServiceLog.Error("WAG-IPC-003", "IPC connection handling failed.", ex);
                Thread.Sleep(200);
            }
        }
    }

    private void HandleClient(NamedPipeServerStream pipe, CancellationToken serverToken)
    {
        if (_protectedMode is null)
        {
            return;
        }

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(serverToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(5));

        if (!ClientAuth.TryGetElevation(
                pipe, out var elevated, out var clientPid,
                out var clientSid, out var clientPath, out var reason))
        {
            ServiceLog.Warning("WAG-IPC-004", $"Rejected IPC connection (pid={clientPid}); client identity could not be verified.");
            TryWrite(pipe, new ProtocolMessage
            {
                Type = "error",
                V = ServiceProtocol.Version,
                Ok = false,
                ErrorCode = nameof(ProtocolErrorCode.NotOwner),
                Message = reason,
            }, timeout.Token);
            return;
        }

        ProtocolMessage? hello;

        try
        {
            hello = PipeCodec.ReadAsync<ProtocolMessage>(pipe, timeout.Token)
                .GetAwaiter().GetResult();
        }
        catch (OperationCanceledException)
        {
            ServiceLog.Warning("WAG-IPC-005", "IPC v3 hello timed out.");
            return;
        }
        catch (Exception ex)
        {
            ServiceLog.Warning("WAG-IPC-006", "IPC v3 hello was malformed.", ex);
            return;
        }

        if (hello is null
            || !string.Equals(hello.Type, "hello", StringComparison.Ordinal)
            || string.IsNullOrWhiteSpace(hello.ClientNonce))
        {
            RejectProtocol(pipe, timeout.Token, ProtocolErrorCode.VersionMismatch, "协议握手无效。");
            return;
        }

        if (hello.V != ServiceProtocol.Version)
        {
            RejectProtocol(pipe, timeout.Token, ProtocolErrorCode.VersionMismatch, "协议版本不匹配。");
            return;
        }

        var serverNonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        var sessionId = Guid.NewGuid().ToString("N");
        var capacities = new[] { "v3", "modules", "revision" };

        TryWrite(pipe, new ProtocolMessage
        {
            Type = "challenge",
            V = ServiceProtocol.Version,
            SessionId = sessionId,
            ServerNonce = serverNonce,
            ServerTimeUtc = DateTime.UtcNow,
            ToolVersion = BuildVersion(),
            Protocol = ServiceProtocol.Version,
            Capabilities = capacities,
            MaxFrameBytes = ServiceProtocol.MaxMessageBytes,
        }, timeout.Token);

        ProtocolMessage? auth;

        try
        {
            auth = PipeCodec.ReadAsync<ProtocolMessage>(pipe, timeout.Token)
                .GetAwaiter().GetResult();
        }
        catch (OperationCanceledException)
        {
            ServiceLog.Warning("WAG-IPC-008", "IPC v3 auth timed out.");
            return;
        }
        catch (Exception ex)
        {
            ServiceLog.Warning("WAG-IPC-009", "IPC v3 auth was malformed.", ex);
            return;
        }

        if (auth is null
            || !string.Equals(auth.Type, "auth", StringComparison.Ordinal)
            || !string.Equals(auth.SessionId, sessionId, StringComparison.Ordinal)
            || string.IsNullOrWhiteSpace(auth.Signature))
        {
            RejectProtocol(pipe, timeout.Token, ProtocolErrorCode.NotOwner, "认证失败。");
            return;
        }

        var authBytes = Encoding.UTF8.GetBytes(
            $"{serverNonce}|{hello.ClientNonce}|{sessionId}");

        byte[] authSignature;

        try
        {
            authSignature = Convert.FromBase64String(auth.Signature);
        }
        catch (FormatException)
        {
            RejectProtocol(pipe, timeout.Token, ProtocolErrorCode.NotOwner, "认证失败。");
            return;
        }

        if (!OwnerKey.Verify(
                _protectedMode.GetPublicKeyBytes(), authBytes, authSignature))
        {
            var rejected = Interlocked.Increment(ref _authRejectedCount);
            ServiceLog.Warning(
                "WAG-AUTH-003",
                $"Rejected IPC v3 auth: invalid signature (pid={clientPid}, sid={clientSid ?? "?"}, path={clientPath ?? "?"}, total rejected={rejected}).");
            RejectProtocol(pipe, timeout.Token, ProtocolErrorCode.NotOwner, "认证失败。");
            return;
        }

        TryWrite(pipe, new ProtocolMessage
        {
            Type = "welcome",
            V = ServiceProtocol.Version,
            SessionId = sessionId,
            ExpiresUtc = DateTime.UtcNow.AddMinutes(5),
            Protocol = ServiceProtocol.Version,
        }, timeout.Token);

        var expectedSeq = 1L;
        var sessionExpiresUtc = DateTime.UtcNow.AddMinutes(5);
        var nonceBytes = Encoding.UTF8.GetBytes(serverNonce);
        var rateWindowStartUtc = DateTime.UtcNow;
        var requestCountInWindow = 0;

        while (!serverToken.IsCancellationRequested)
        {
            var now = DateTime.UtcNow;

            if (now - rateWindowStartUtc >= TimeSpan.FromSeconds(1))
            {
                rateWindowStartUtc = now;
                requestCountInWindow = 0;
            }

            if (++requestCountInWindow > 50)
            {
                RejectProtocol(pipe, timeout.Token, ProtocolErrorCode.RateLimited, "请求过于频繁。");
                break;
            }

            ProtocolMessage? frame;

            try
            {
                frame = PipeCodec.ReadAsync<ProtocolMessage>(pipe, timeout.Token)
                    .GetAwaiter().GetResult();
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                ServiceLog.Warning("WAG-IPC-010", "IPC v3 request was malformed.", ex);
                break;
            }

            if (frame is null)
            {
                break;
            }

            if (!string.Equals(frame.Type, "request", StringComparison.Ordinal)
                || frame.Seq != expectedSeq
                || string.IsNullOrWhiteSpace(frame.Command)
                || frame.Payload is null)
            {
                RejectProtocol(pipe, timeout.Token, ProtocolErrorCode.InvalidArgument, "请求帧无效。");
                break;
            }

            if (DateTime.UtcNow > sessionExpiresUtc)
            {
                RejectProtocol(pipe, timeout.Token, ProtocolErrorCode.Timeout, "会话已过期。");
                break;
            }

            if (string.IsNullOrWhiteSpace(frame.Signature))
            {
                RejectProtocol(pipe, timeout.Token, ProtocolErrorCode.NotOwner, "请求缺少签名。");
                break;
            }

            var canonical = ProtocolSigning.CanonicalBytes(frame);
            var signed = new byte[nonceBytes.Length + canonical.Length];
            Buffer.BlockCopy(nonceBytes, 0, signed, 0, nonceBytes.Length);
            Buffer.BlockCopy(canonical, 0, signed, nonceBytes.Length, canonical.Length);

            byte[] requestSignature;

            try
            {
                requestSignature = Convert.FromBase64String(frame.Signature);
            }
            catch (FormatException)
            {
                RejectProtocol(pipe, timeout.Token, ProtocolErrorCode.NotOwner, "请求签名无效。");
                break;
            }

            if (!OwnerKey.Verify(
                    _protectedMode.GetPublicKeyBytes(), signed, requestSignature))
            {
                RejectProtocol(pipe, timeout.Token, ProtocolErrorCode.NotOwner, "请求签名无效。");
                break;
            }

            ServiceRequest request;

            try
            {
                request = frame.Payload.Value
                    .Deserialize<ServiceRequest>(ServiceProtocol.JsonOptions)
                    ?? new ServiceRequest();
            }
            catch (Exception ex)
            {
                ServiceLog.Warning("WAG-IPC-011", "IPC v3 request payload was invalid.", ex);
                RejectProtocol(pipe, timeout.Token, ProtocolErrorCode.InvalidArgument, "请求载荷无效。");
                break;
            }

            request.Id = frame.Id ?? request.Id;
            request.Command = frame.Command;
            request.ProtocolVersion = ServiceProtocol.Version;

            if (request.Command.StartsWith("write.", StringComparison.OrdinalIgnoreCase))
            {
                ServiceLog.Operation(
                    "WAG-IPC-012",
                    $"IPC v3 write operation: pid={clientPid}, sid={clientSid ?? "?"}, path={clientPath ?? "?"}, command={request.Command}.");
            }

            var response = Dispatch(request, elevated, clientPid);

            TryWrite(pipe, new ProtocolMessage
            {
                Type = "response",
                V = ServiceProtocol.Version,
                Id = request.Id,
                Seq = frame.Seq,
                Ok = response.Ok,
                ErrorCode = response.ErrorCode
                    ?? (response.Ok ? nameof(ProtocolErrorCode.None) : nameof(ProtocolErrorCode.Internal)),
                Message = response.Error,
                Revision = Rules.RuleRevision,
                Data = JsonSerializer.SerializeToElement(response, ServiceProtocol.JsonOptions),
            }, timeout.Token);

            expectedSeq++;
        }
    }

    private static void RejectProtocol(
        NamedPipeServerStream pipe,
        CancellationToken token,
        ProtocolErrorCode code,
        string message)
    {
        TryWrite(pipe, new ProtocolMessage
        {
            Type = "error",
            V = ServiceProtocol.Version,
            Ok = false,
            ErrorCode = code.ToString(),
            Message = message,
        }, token);
    }

    /// <summary>
    /// 3.5：批量 PID → 路径。只返回当前仍存在且服务能打开的进程。
    /// </summary>
    internal static ServiceResponse ResolveProcessPaths(ServiceRequest request)
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

        return new ServiceResponse
        {
            Id = request.Id,
            Ok = true,
            ProcessPaths = paths,
        };
    }
    private static void TryWrite<T>(
        NamedPipeServerStream pipe, T response, CancellationToken token)
    {
        try
        {
            PipeCodec.WriteAsync(pipe, response, token).GetAwaiter().GetResult();
        }
        catch (Exception ex)
        {
            ServiceLog.Warning("WAG-IPC-015", "Failed to write the IPC response.", ex);
        }
    }

    private ServiceResponse Dispatch(ServiceRequest request, bool elevated, uint clientPid)
    {
        if (request.ProtocolVersion != ServiceProtocol.Version)
        {
            return new ServiceResponse
            {
                Id = request.Id,
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
            return new ServiceResponse
            {
                Id = request.Id,
                Ok = false,
                Error = "服务命令目录未通过启动校验，控制管道不可用。",
            };
        }

        return router.Dispatch(new CommandContext(request, elevated, clientPid));
    }

    /// <summary>5.9：规则命令统一交给 RuleHandlers（与启动迁移、定时任务共用同一实例）。</summary>
    internal static ServiceResponse HandleRuleCommand(ServiceRequest request) => Rules.Handle(request);

    internal static ServiceStatus BuildStatus()
    {
        // 与规则写入串行：WFP 的读和写不要同时发生（status 命令不走 RuleHandlers）。
        lock (RuleHandlers.Gate)
        {
            return BuildStatusCore();
        }
    }

    private static ServiceStatus BuildStatusCore()
    {
        var status = new ServiceStatus
        {
            ServiceVersion = BuildVersion(),
            ProtocolVersion = ServiceProtocol.Version,
            ProtectedMode = _protectedMode is not null,
            ProtectedModeOwner = _protectedMode?.OwnerName,
            ProtectedModeOwnerSid = _protectedMode?.OwnerSid,
            ProtectedModeFingerprint = _protectedMode?.Fingerprint,
            AuthRejectedCount = Volatile.Read(ref _authRejectedCount),
            Revision = Rules.RuleRevision,
            RevisionEpoch = Rules.RuleRevisionEpoch,
            Modules = _modules?.Snapshot()
                .Select(item => new ModuleStatusDto
                {
                    Name = item.Name,
                    Order = item.Order,
                    State = item.State.ToString(),
                    Detail = item.Detail,
                    LastError = item.LastError,
                    Restarts = item.RestartCount,
                })
                .ToList(),
        };

        try
        {
            using var engine = WfpEngine.Open();

            try
            {
                _ = engine.ReadSublayer();
                status.SublayerPresent = true;
            }
            catch (WfpException)
            {
                status.SublayerPresent = false;
            }

            var rules = Rules.GetRuleSnapshot();
            status.BlockRuleCount = rules.Count(rule => rule.Action == FirewallAction.Block);
            status.AllowRuleCount = rules.Count(rule => rule.Action == FirewallAction.Allow);
            status.IpRuleCount = rules.Count(rule => !string.IsNullOrEmpty(rule.IpAddress));
        }
        catch (Exception ex)
        {
            ServiceLog.Warning("WAG-SVC-010", "Failed to read service status.", ex);
        }

        status.StrictModeActive = StrictModeHost.IsEnabled;
        status.StrictModePermittedCount = StrictModeHost.PermittedCount;
        status.StrictModeLockdownActive = LockdownHost.IsActive;
        status.StrictModeLockdownExpiresUtc = LockdownHost.ExpiresUtc;
        status.StrictModeLockdownRemainingSeconds = LockdownHost.RemainingSeconds;

        var audit = AuditHost.Snapshot();
        status.AuditEnabled = audit.Enabled;
        status.AuditDomainLookup = audit.DomainLookup;
        status.AuditRetentionDays = audit.RetentionDays;
        status.AuditCollecting = AuditHost.Collecting;
        status.AuditEventsWritten = AuditHost.EventsWritten;
        var traffic = TrafficCaptureHost.GetStatus();
        status.TrafficCollecting = traffic.Collecting;
        status.TrafficEventsSeen = TrafficHost.EventsSeen;
        status.TrafficPps = traffic.Pps;
        status.TrafficDropped = traffic.Dropped;
        status.TrafficSampled = traffic.Sampled;
        status.DnsCollecting = DnsHost.Collecting;

        var ids = IdsHost.GetStatus();
        status.IdsEnabled = ids.Enabled;
        status.IdsCollecting = ids.Collecting;
        status.IdsAlertsNew = ids.AlertsNew;
        status.IdsFlowCount = ids.FlowCount;
        status.IdsEventsSeen = ids.EventsSeen;

        var antiScan = AntiScanHost.GetStatus();
        status.AntiScanEnabled = antiScan.Enabled;
        status.AntiScanCollecting = antiScan.Collecting;
        status.AntiScanNpcapAvailable = antiScan.NpcapAvailable;
        status.AntiScanBlockedCount = antiScan.BlockedCount;

        var lan = LanHost.GetStatus();
        status.LanCollecting = lan.Collecting;
        status.LanEventCount = lan.EventCount;
        status.LanBlockedCount = lan.BlockedCount;
        status.LanBaselineReady = lan.BaselineReady;

        // 4.3：DNS 安全。
        status.DnsSecurityCollecting = lan.DnsSecurityCollecting;
        status.DnsSecurityEventCount = lan.DnsSecurityEventCount;

        // 4.4：IPv6 邻接安全。
        status.Ipv6SecurityCollecting = lan.Ipv6SecurityCollecting;
        status.Ipv6SecurityEventCount = lan.Ipv6SecurityEventCount;

        status.TamperRebuiltCount = Rules.TamperRebuiltCount;
        status.LastTamperUtc = Rules.LastTamperUtc;
        status.ExpiredPurgedCount = Rules.ExpiredPurgedCount;
        status.LastPurgedPrograms = Rules.LastPurgedPrograms;

        return status;
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

    /// <summary>
    /// 创建一条只有 SYSTEM 与**所有者 SID** 能连接的命名管道。
    /// 安全描述符在建管道时生效，避免"先建后收紧"的窗口。
    /// 其他账户（包括其他管理员）连不上；这是 3.1 第 4 步的边界。
    /// </summary>
    private static NamedPipeServerStream CreateOwnerOnlyPipe()
    {
        var security = new PipeSecurity();

        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            PipeAccessRights.FullControl,
            AccessControlType.Allow));

        security.AddAccessRule(new PipeAccessRule(
            _protectedMode!.GetOwnerSid(),
            PipeAccessRights.FullControl,
            AccessControlType.Allow));

        return NamedPipeServerStreamAcl.Create(
            ServiceProtocol.PipeName,
            PipeDirection.InOut,
            maxNumberOfServerInstances: 4,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous,
            inBufferSize: 0,
            outBufferSize: 0,
            pipeSecurity: security);
    }
}