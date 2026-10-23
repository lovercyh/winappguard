using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text.Json;
using WinAppGuard.Contracts;
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
    // 服务进程里只有一个 ControlServer；BuildStatus 被 RuleHandlers 静态调用，
    // 所以这两项用 static，保证状态命令和规则命令看到同一份配置。
    private static ProtectedModeConfig? _protectedMode;
    private static int _authRejectedCount;
    private System.Threading.Timer? _expiryTimer;
    private System.Threading.Timer? _tamperTimer;

    internal void Start()
    {
        // 3.1：启动时加载受保护模式配置。缺失/损坏就**不创建控制管道**（失败关闭），
        // 但 WFP / 审计仍然工作；由 Setup --repair 重建配置。
        try
        {
            _protectedMode = ProtectedModeConfig.Load(
                ServicePaths.ProtectedModeConfigFile);

            ServiceLog.Info(
                $"受保护模式：所有者 {_protectedMode.OwnerName}，"
                + $"指纹 {_protectedMode.Fingerprint[..16]}…");
        }
        catch (Exception ex)
        {
            _protectedMode = null;
            ServiceLog.Error(
                "受保护模式配置不可用，控制管道不会创建（失败关闭）。"
                + "请以所有者身份运行 WinAppGuardSetup.exe --repair。", ex);
        }

        if (_protectedMode is not null)
        {
            _thread = new Thread(Loop)
            {
                IsBackground = true,
                Name = "ipc-server",
            };

            _thread.Start();
        }

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

        // 3.0-c：界面以普通权限运行，需要读取快照与审计记录。
        ServiceDataPermissions.EnsureReadableByUsers();

        // 1.x → 2.0 的规则迁移（从 1.x 直接升到 3.0 的机器需要）。
        // 界面不再做这件事（它已经没有 WFP 访问能力）。
        try
        {
            var migration = StartupMigration.RunIfNeeded(out var migrationError);

            if (migrationError is not null)
            {
                ServiceLog.Warning($"启动迁移：{migrationError}");
            }

            if (migration is not null)
            {
                ServiceLog.Info(
                    $"启动迁移：迁移 {migration.Migrated} 条、跳过 {migration.Skipped} 条、" +
                    $"失败 {migration.Failed} 条、删除旧规则 {migration.FirewallRulesDeleted} 条。");
            }
        }
        catch (Exception ex)
        {
            ServiceLog.Warning($"启动迁移失败（不影响服务启动）：{ex.Message}");
        }

        // 启动时先写一份权威副本：即使从没改过规则，离线界面也有东西可看。
        ServiceLog.Info("启动：写入规则快照…");
        Rules.SaveSnapshotNow();

        // 篡改防护：新建的子层/过滤器在创建时就带上保护性 DACL
        // （见 WfpEngine.TryBuildProtectiveSd）。已有对象保持原有安全描述符，
        // 不再做"先创建再改安全信息"——VM 实测那样会把服务启动卡死。

        // 审计采集随服务启动（设置里关着就不开）。
        ServiceLog.Info("启动：启动审计采集…");
        AuditHost.StartIfEnabled();

        if (_protectedMode is not null)
        {
            ServiceLog.Info($"IPC 已启动：{ServiceProtocol.PipeName}（v2 签名鉴权）");
        }
    }

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

        _expiryTimer?.Dispose();
        _expiryTimer = null;
        _tamperTimer?.Dispose();
        _tamperTimer = null;

        // 严格模式会话随服务一起撤销：停服务 = 立即恢复联网。
        StrictModeHost.Shutdown();

        // 审计采集也停掉（记录文件先刷盘再关闭）。
        AuditHost.Stop();

        _thread?.Join(3000);
        _thread = null;
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
                    ServiceLog.Info("命名管道已创建（ACL：仅 SYSTEM + 所有者）。");
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
                ServiceLog.Error("IPC 连接处理失败。", ex);
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
            ServiceLog.Warning($"拒绝 IPC 连接：{reason}");
            TryWrite(pipe, new ServiceResponse { Ok = false, Error = reason }, timeout.Token);
            return;
        }

        ServiceRequest? challenge;

        try
        {
            challenge = PipeCodec.ReadAsync<ServiceRequest>(pipe, timeout.Token)
                .GetAwaiter().GetResult();
        }
        catch (OperationCanceledException)
        {
            ServiceLog.Warning("IPC 认证挑战超时。");
            return;
        }
        catch (Exception ex)
        {
            ServiceLog.Warning($"IPC 认证挑战不合法：{ex.Message}");
            return;
        }

        if (challenge is null)
        {
            return;
        }

        if (challenge.ProtocolVersion != ServiceProtocol.Version
            || !string.Equals(
                challenge.Command, ServiceProtocol.Commands.AuthChallenge,
                StringComparison.Ordinal))
        {
            ServiceLog.Warning(
                $"拒绝 IPC：第一条命令必须是 auth.challenge（PID {clientPid}，"
                + $"命令 {challenge.Command}）。");
            TryWrite(pipe, new ServiceResponse
            {
                Id = challenge.Id,
                Ok = false,
                Error = "认证失败",
            }, timeout.Token);
            return;
        }

        var nonce = RandomNumberGenerator.GetBytes(32);

        TryWrite(pipe, new ServiceResponse
        {
            Id = challenge.Id,
            Ok = true,
            Nonce = Convert.ToBase64String(nonce),
        }, timeout.Token);

        SignedEnvelope envelope;

        try
        {
            envelope = PipeCodec.ReadSignedAsync(pipe, timeout.Token)
                .GetAwaiter().GetResult();
        }
        catch (OperationCanceledException)
        {
            ServiceLog.Warning("IPC 签名封套超时。");
            return;
        }
        catch (Exception ex)
        {
            ServiceLog.Warning($"IPC 签名封套不合法：{ex.Message}");
            return;
        }

        var signedData = new byte[nonce.Length + envelope.Payload.Length];
        Buffer.BlockCopy(nonce, 0, signedData, 0, nonce.Length);
        Buffer.BlockCopy(envelope.Payload, 0, signedData, nonce.Length, envelope.Payload.Length);

        if (!OwnerKey.Verify(
                _protectedMode.GetPublicKeyBytes(), signedData, envelope.Signature))
        {
            var rejected = Interlocked.Increment(ref _authRejectedCount);
            ServiceLog.Warning(
                $"拒绝 IPC：签名无效（PID {clientPid}，SID {clientSid ?? "?"}，路径 {clientPath ?? "?"}，累计 {rejected} 次）。");
            TryWrite(pipe, new ServiceResponse
            {
                Id = challenge.Id,
                Ok = false,
                Error = "认证失败",
            }, timeout.Token);
            return;
        }

        ServiceRequest? request;

        try
        {
            request = JsonSerializer.Deserialize<ServiceRequest>(
                envelope.Payload, ServiceProtocol.JsonOptions);
        }
        catch (Exception ex)
        {
            ServiceLog.Warning($"IPC 请求 JSON 不合法：{ex.Message}");
            return;
        }

        if (request is null)
        {
            return;
        }

        if (request.Command.StartsWith("write.", StringComparison.OrdinalIgnoreCase))
        {
            ServiceLog.Info(
                $"IPC 写操作：PID {clientPid}，SID {clientSid ?? "?"}，路径 {clientPath ?? "?"}，命令 {request.Command}。");
        }

        TryWrite(pipe, Dispatch(request, elevated, clientPid), timeout.Token);
    }

    private static void TryWrite(NamedPipeServerStream pipe, ServiceResponse response, CancellationToken token)
    {
        try
        {
            PipeCodec.WriteAsync(pipe, response, token).GetAwaiter().GetResult();
        }
        catch (Exception ex)
        {
            ServiceLog.Warning($"写回 IPC 响应失败：{ex.Message}");
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

        // 规则命令统一交给 RuleHandlers；写命令的提权检查在下面先做。
        var isRuleCommand = request.Command == ServiceProtocol.Commands.ListRules
            || request.Command == ServiceProtocol.Commands.FilterMap
            || request.Command == ServiceProtocol.Commands.AllowTargets
            || request.Command == ServiceProtocol.Commands.ImportGroups
            || request.Command.StartsWith("write.rules.", StringComparison.OrdinalIgnoreCase)
            || request.Command.StartsWith("write.strict.", StringComparison.OrdinalIgnoreCase)
            || request.Command.StartsWith("write.audit.", StringComparison.OrdinalIgnoreCase);

        // 鉴权探针：不做任何事，只回答"当前客户端有没有提权"。
        if (string.Equals(request.Command, ServiceProtocol.Commands.AuthCheck, StringComparison.Ordinal))
        {
            ServiceLog.Info($"鉴权探针：PID {clientPid}，提权={elevated}");

            return new ServiceResponse
            {
                Id = request.Id,
                Ok = elevated,
                Error = elevated ? null : "当前客户端未提权。",
            };
        }

        // 3.0-b 起写命令会用 "write." 前缀，必须提权；v1 的只读命令允许任何交互用户。
        if (request.Command.StartsWith("write.", StringComparison.OrdinalIgnoreCase) && !elevated)
        {
            ServiceLog.Warning($"拒绝写操作：PID {clientPid} 未提权。");

            return new ServiceResponse
            {
                Id = request.Id,
                Ok = false,
                Error = "修改规则需要管理员权限（请从界面操作，会弹出 UAC）。",
            };
        }

        return request.Command switch
        {
            ServiceProtocol.Commands.Ping => new ServiceResponse
            {
                Id = request.Id,
                Ok = true,
                Status = BuildStatus(),
            },

            ServiceProtocol.Commands.Status => new ServiceResponse
            {
                Id = request.Id,
                Ok = true,
                Status = BuildStatus(),
            },

            _ when isRuleCommand => Rules.Handle(request),

            _ => new ServiceResponse
            {
                Id = request.Id,
                Ok = false,
                Error = $"未知命令：{request.Command}",
            },
        };
    }

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

            var rules = RuleEngine.GetRules();
            status.BlockRuleCount = rules.Count(rule => rule.Action == FirewallAction.Block);
            status.AllowRuleCount = rules.Count(rule => rule.Action == FirewallAction.Allow);
            status.IpRuleCount = rules.Count(rule => !string.IsNullOrEmpty(rule.IpAddress));
        }
        catch (Exception ex)
        {
            ServiceLog.Warning($"读取服务状态失败：{ex.Message}");
        }

        status.StrictModeActive = StrictModeHost.IsEnabled;
        status.StrictModePermittedCount = StrictModeHost.PermittedCount;

        var audit = AuditHost.Snapshot();
        status.AuditEnabled = audit.Enabled;
        status.AuditDomainLookup = audit.DomainLookup;
        status.AuditRetentionDays = audit.RetentionDays;
        status.AuditCollecting = AuditHost.Collecting;
        status.AuditEventsWritten = AuditHost.EventsWritten;

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