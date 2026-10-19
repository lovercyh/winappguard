using System.ComponentModel;
using System.IO.Pipes;
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
                using var pipe = new NamedPipeServerStream(
                    ServiceProtocol.PipeName,
                    PipeDirection.InOut,
                    maxNumberOfServerInstances: 4,
                    PipeTransmissionMode.Byte,
                    PipeOptions.Asynchronous);

                ApplyAdminOnlyAcl(pipe);

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

        if (!ClientAuth.IsElevated(pipe, out var reason))
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

        TryWrite(pipe, Dispatch(request), timeout.Token);
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

    private static ServiceResponse Dispatch(ServiceRequest request)
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

    // ---------------- 管道 ACL：只允许 SYSTEM + Administrators ----------------

    private const uint SeKernelObject = 6;
    private const uint DaclSecurityInformation = 4;
    private const uint SddlRevision1 = 1;

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptorW(
        string stringSecurityDescriptor, uint stringSdRevision, out IntPtr securityDescriptor, out uint size);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetSecurityDescriptorDacl(
        IntPtr securityDescriptor, out bool daclPresent, out IntPtr dacl, out bool daclDefaulted);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern uint SetSecurityInfo(
        IntPtr handle, uint objectType, uint securityInformation,
        IntPtr owner, IntPtr group, IntPtr dacl, IntPtr sacl);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr handle);

    private static void ApplyAdminOnlyAcl(NamedPipeServerStream pipe)
    {
        // D: DACL；(A;;GA;;;SY) SYSTEM 完全控制；(A;;GA;;;BA) Administrators 完全控制。
        const string sddl = "D:(A;;GA;;;SY)(A;;GA;;;BA)";

        if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl, SddlRevision1, out var descriptor, out _))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(), "构造管道安全描述符失败");
        }

        try
        {
            if (!GetSecurityDescriptorDacl(descriptor, out var present, out var dacl, out _) || !present)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "安全描述符里没有 DACL");
            }

            var rc = SetSecurityInfo(
                pipe.SafePipeHandle.DangerousGetHandle(),
                SeKernelObject,
                DaclSecurityInformation,
                IntPtr.Zero,
                IntPtr.Zero,
                dacl,
                IntPtr.Zero);

            if (rc != 0)
            {
                throw new Win32Exception((int)rc, "设置管道 ACL 失败");
            }
        }
        finally
        {
            _ = LocalFree(descriptor);
        }
    }
}
