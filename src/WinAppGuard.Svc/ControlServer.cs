using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Reflection;
using System.Runtime.InteropServices;
using WinAppGuard.Contracts;
using WinAppGuard.Core;
using WinAppGuard.Core.Wfp;
using WinAppGuard.Models;

namespace WinAppGuard.Service;

/// <summary>
/// 命名管道服务端（v1 只读命令）。
///
/// 两道门：
///   1. **管道 ACL**：只允许 SYSTEM 与 Administrators 连接（非管理员连不上）；
///   2. **令牌校验**：连上之后还要确认客户端令牌**已提权**（M1.5）。
/// 第二道是真正的边界：ACL 只是提前把大多数无关进程挡在外面。
/// </summary>
internal sealed class ControlServer : IDisposable
{
    private readonly CancellationTokenSource _cancellation = new();
    private Thread? _thread;
    private bool _loggedReady;

    internal void Start()
    {
        _thread = new Thread(Loop)
        {
            IsBackground = true,
            Name = "ipc-server",
        };

        _thread.Start();
        ServiceLog.Info($"IPC 已启动：{ServiceProtocol.PipeName}");
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
                using var pipe = CreateAdminOnlyPipe();

                if (!_loggedReady)
                {
                    _loggedReady = true;
                    ServiceLog.Info("命名管道已创建（ACL：仅 SYSTEM + Administrators）。");
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

    private static void HandleClient(NamedPipeServerStream pipe, CancellationToken serverToken)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(serverToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(3));

        if (!ClientAuth.TryGetElevation(pipe, out var elevated, out var clientPid, out var reason))
        {
            ServiceLog.Warning($"拒绝 IPC 连接：{reason}");
            TryWrite(pipe, new ServiceResponse { Ok = false, Error = reason }, timeout.Token);
            return;
        }

        ServiceRequest? request;

        try
        {
            request = PipeCodec.ReadAsync<ServiceRequest>(pipe, timeout.Token)
                .GetAwaiter().GetResult();
        }
        catch (OperationCanceledException)
        {
            ServiceLog.Warning("IPC 请求超时。");
            return;
        }
        catch (Exception ex)
        {
            ServiceLog.Warning($"IPC 请求不合法：{ex.Message}");
            return;
        }

        if (request is null)
        {
            return;
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

    private static ServiceResponse Dispatch(ServiceRequest request, bool elevated, uint clientPid)
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
        var status = new ServiceStatus
        {
            ServiceVersion = BuildVersion(),
            ProtocolVersion = ServiceProtocol.Version,
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
    /// 创建一条只有 SYSTEM 与 Administrators 能连接的命名管道。
    /// 安全描述符在建管道时生效，避免"先建后收紧"的窗口。
    /// </summary>
    private static NamedPipeServerStream CreateAdminOnlyPipe()
    {
        var security = new PipeSecurity();

        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            PipeAccessRights.FullControl,
            AccessControlType.Allow));

        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
            PipeAccessRights.FullControl,
            AccessControlType.Allow));

        // M1.5：查看 / 记录不需要管理员，所以**交互登录用户**必须能连上。
        // 写命令由服务端逐条校验"令牌是否提权"，而不是靠管道 ACL 一刀切。
        // 用 Interactive 而不是 Authenticated Users：排除网络登录（远程管道访问）。
        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.InteractiveSid, null),
            PipeAccessRights.ReadWrite,
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