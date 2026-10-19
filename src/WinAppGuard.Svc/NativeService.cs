using System.Runtime.InteropServices;
using WinAppGuard.Contracts;

namespace WinAppGuard.Service;

/// <summary>
/// 以 Windows 服务方式运行的入口。
///
/// 为什么用 P/Invoke 而不是 ServiceBase：
///   本项目不引入第三方/额外 NuGet 包；service host 需要的四个 API 都很小，
///   自己声明一遍反而更可审计（出厂审计能逐项核对）。
/// </summary>
internal static class NativeService
{
    internal const int ErrorFailedServiceControllerConnect = 1063;

    private const uint ServiceWin32OwnProcess = 0x10;
    private const uint ServiceAcceptStop = 0x1;
    private const uint ServiceAcceptShutdown = 0x4;

    private const uint ServiceControlStop = 1;
    private const uint ServiceControlShutdown = 5;

    private const uint StateStopped = 1;
    private const uint StateStartPending = 2;
    private const uint StateStopPending = 3;
    private const uint StateRunning = 4;

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatus
    {
        public uint ServiceType;
        public uint CurrentState;
        public uint ControlsAccepted;
        public uint Win32ExitCode;
        public uint ServiceSpecificExitCode;
        public uint CheckPoint;
        public uint WaitHint;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ServiceTableEntry
    {
        [MarshalAs(UnmanagedType.LPWStr)]
        public string? ServiceName;

        [MarshalAs(UnmanagedType.FunctionPtr)]
        public ServiceMainFunction? ServiceProc;
    }

    private delegate void ServiceMainFunction(int argc, IntPtr argv);

    private delegate int HandlerEx(int control, int eventType, IntPtr eventData, IntPtr context);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool StartServiceCtrlDispatcherW(ServiceTableEntry[] table);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr RegisterServiceCtrlHandlerExW(
        string serviceName, HandlerEx handler, IntPtr context);

    [DllImport("advapi32.dll")]
    private static extern bool SetServiceStatus(IntPtr statusHandle, ref ServiceStatus status);

    private static ServiceMainFunction? _serviceMain;
    private static HandlerEx? _handler;
    private static IntPtr _statusHandle = IntPtr.Zero;
    private static ManualResetEventSlim? _stopEvent;
    private static ControlServer? _server;

    /// <summary>交给 SCM；返回 false 时通过 <paramref name="error"/> 给出 Win32 错误码。</summary>
    internal static bool TryRun(out int error)
    {
        _serviceMain = ServiceMain;
        _handler = OnControl;

        var table = new[]
        {
            new ServiceTableEntry
            {
                ServiceName = ServiceProtocol.ServiceName,
                ServiceProc = _serviceMain,
            },
            new ServiceTableEntry { ServiceName = null, ServiceProc = null },
        };

        if (StartServiceCtrlDispatcherW(table))
        {
            error = 0;
            return true;
        }

        error = Marshal.GetLastWin32Error();
        return false;
    }

    private static void ServiceMain(int argc, IntPtr argv)
    {
        _stopEvent = new ManualResetEventSlim(false);

        _statusHandle = RegisterServiceCtrlHandlerExW(
            ServiceProtocol.ServiceName, _handler!, IntPtr.Zero);

        if (_statusHandle == IntPtr.Zero)
        {
            return;
        }

        ReportStatus(StateStartPending, waitHint: 10_000);
        ServiceLog.Info("服务正在启动。");

        try
        {
            _server = new ControlServer();
            _server.Start();

            ReportStatus(StateRunning, waitHint: 0);
            ServiceLog.Info("服务已启动。");

            _stopEvent.Wait();

            ReportStatus(StateStopPending, waitHint: 10_000);
            _server.Stop();
            _server = null;

            ReportStatus(StateStopped, waitHint: 0);
            ServiceLog.Info("服务已停止。");
        }
        catch (Exception ex)
        {
            ServiceLog.Error("服务运行失败。", ex);
            ReportStatus(StateStopped, waitHint: 0);
        }
        finally
        {
            _stopEvent.Dispose();
            _stopEvent = null;
        }
    }

    private static int OnControl(int control, int eventType, IntPtr eventData, IntPtr context)
    {
        if (control is (int)ServiceControlStop or (int)ServiceControlShutdown)
        {
            try
            {
                ReportStatus(StateStopPending, waitHint: 10_000);
            }
            catch (Exception)
            {
                // 停止过程中报告状态失败不应阻止退出。
            }

            _stopEvent?.Set();
        }

        return 0;
    }

    private static void ReportStatus(uint state, uint waitHint)
    {
        if (_statusHandle == IntPtr.Zero)
        {
            return;
        }

        var status = new ServiceStatus
        {
            ServiceType = ServiceWin32OwnProcess,
            CurrentState = state,
            ControlsAccepted = state == StateRunning
                ? ServiceAcceptStop | ServiceAcceptShutdown
                : 0,
            Win32ExitCode = 0,
            CheckPoint = 0,
            WaitHint = waitHint,
        };

        _ = SetServiceStatus(_statusHandle, ref status);
    }
}
