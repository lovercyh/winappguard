using System.ComponentModel;
using System.Runtime.InteropServices;

namespace WinAppGuard.Setup;

/// <summary>
/// 服务控制（SCM）的最小封装。
///
/// 用 P/Invoke 而不是 `sc.exe`：不依赖外部命令、能拿到真实错误码，
/// 也便于出厂审计逐项核对（项目一贯做法）。
/// </summary>
internal static class ServiceControl
{
    private const uint ScManagerConnect = 0x0001;
    private const uint ScManagerCreateService = 0x0002;

    private const uint ServiceWin32OwnProcess = 0x00000010;
    private const uint ServiceAutoStart = 0x00000002;
    private const uint ServiceErrorNormal = 0x00000001;

    private const uint ServiceQueryStatus = 0x0004;
    private const uint ServiceStart = 0x0010;
    private const uint ServiceStop = 0x0020;
    private const uint ServiceChangeConfig = 0x0002;
    private const uint Delete = 0x00010000;

    private const uint ServiceControlStop = 1;
    private const uint ServiceStopped = 1;
    private const uint ServiceStartPending = 2;
    private const uint ServiceStopPending = 3;
    private const uint ServiceRunning = 4;

    private const uint ServiceConfigDescription = 1;
    private const uint ServiceConfigFailureActions = 2;
    private const uint ServiceConfigDelayedAutoStart = 3;

    private const uint ScActionRestart = 1;

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
    private struct ServiceDescription
    {
        public string Description;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct ServiceFailureActions
    {
        public uint ResetPeriod;
        public string? RebootMessage;
        public string? RestartCommand;
        public uint ActionCount;
        public IntPtr Actions;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ScAction
    {
        public uint Type;
        public uint Delay;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceDelayedAutoStartInfo
    {
        public int DelayedAutostart;
    }

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr OpenSCManagerW(string? machineName, string? databaseName, uint desiredAccess);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr CreateServiceW(
        IntPtr scm, string serviceName, string? displayName, uint desiredAccess,
        uint serviceType, uint startType, uint errorControl, string binaryPathName,
        string? loadOrderGroup, IntPtr tagId, string? dependencies,
        string? serviceStartName, string? password);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr OpenServiceW(IntPtr scm, string serviceName, uint desiredAccess);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool StartServiceW(IntPtr service, int argumentCount, IntPtr arguments);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool ControlService(IntPtr service, uint control, ref ServiceStatus status);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool QueryServiceStatus(IntPtr service, ref ServiceStatus status);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool DeleteService(IntPtr service);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool ChangeServiceConfig2W(IntPtr service, uint infoLevel, IntPtr info);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool CloseServiceHandle(IntPtr handle);

    internal static bool IsInstalled(string serviceName)
    {
        var scm = OpenScm();
        try
        {
            var service = OpenServiceW(scm, serviceName, ServiceQueryStatus);
            if (service == IntPtr.Zero)
            {
                return false;
            }

            _ = CloseServiceHandle(service);
            return true;
        }
        finally
        {
            _ = CloseServiceHandle(scm);
        }
    }

    internal static bool IsRunning(string serviceName)
    {
        var scm = OpenScm();
        try
        {
            var service = OpenServiceW(scm, serviceName, ServiceQueryStatus);
            if (service == IntPtr.Zero)
            {
                return false;
            }

            try
            {
                var status = new ServiceStatus();
                return QueryServiceStatus(service, ref status) && status.CurrentState == ServiceRunning;
            }
            finally
            {
                _ = CloseServiceHandle(service);
            }
        }
        finally
        {
            _ = CloseServiceHandle(scm);
        }
    }

    /// <summary>创建服务（已存在则抛错，由调用方决定是否先删除）。</summary>
    internal static void Install(string serviceName, string displayName, string binaryPath, string description)
    {
        var scm = OpenScm(ScManagerConnect | ScManagerCreateService);

        try
        {
            var service = CreateServiceW(
                scm, serviceName, displayName,
                ServiceQueryStatus | ServiceStart | ServiceStop | ServiceChangeConfig | Delete,
                ServiceWin32OwnProcess, ServiceAutoStart, ServiceErrorNormal,
                $"\"{binaryPath}\"", null, IntPtr.Zero, null, null, null);

            if (service == IntPtr.Zero)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "创建服务失败");
            }

            try
            {
                SetDescription(service, description);
                SetFailureActions(service);
                SetDelayedAutoStart(service);
            }
            finally
            {
                _ = CloseServiceHandle(service);
            }
        }
        finally
        {
            _ = CloseServiceHandle(scm);
        }
    }

    internal static void Start(string serviceName)
    {
        var scm = OpenScm();

        try
        {
            var service = OpenServiceW(scm, serviceName, ServiceStart | ServiceQueryStatus);

            if (service == IntPtr.Zero)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "打开服务失败");
            }

            try
            {
                if (!StartServiceW(service, 0, IntPtr.Zero))
                {
                    var error = Marshal.GetLastWin32Error();

                    // 1056 = 服务已经在运行，不算失败。
                    if (error != 1056)
                    {
                        throw new Win32Exception(error, "启动服务失败");
                    }
                }
            }
            finally
            {
                _ = CloseServiceHandle(service);
            }
        }
        finally
        {
            _ = CloseServiceHandle(scm);
        }
    }

    /// <summary>停止服务并等待（最多 15 秒）。</summary>
    internal static void Stop(string serviceName)
    {
        var scm = OpenScm();

        try
        {
            var service = OpenServiceW(scm, serviceName, ServiceStop | ServiceQueryStatus);

            if (service == IntPtr.Zero)
            {
                return;
            }

            try
            {
                var status = new ServiceStatus();
                _ = ControlService(service, ServiceControlStop, ref status);

                var deadline = DateTime.UtcNow.AddSeconds(15);

                while (DateTime.UtcNow < deadline)
                {
                    if (!QueryServiceStatus(service, ref status)
                        || status.CurrentState == ServiceStopped)
                    {
                        return;
                    }

                    Thread.Sleep(200);
                }

                throw new TimeoutException("服务没有在 15 秒内停止。");
            }
            finally
            {
                _ = CloseServiceHandle(service);
            }
        }
        finally
        {
            _ = CloseServiceHandle(scm);
        }
    }

    internal static void Uninstall(string serviceName)
    {
        var scm = OpenScm();

        try
        {
            var service = OpenServiceW(scm, serviceName, Delete | ServiceQueryStatus);

            if (service == IntPtr.Zero)
            {
                return;
            }

            try
            {
                if (!DeleteService(service))
                {
                    var error = Marshal.GetLastWin32Error();

                    // 1060 = 服务不存在。
                    if (error != 1060)
                    {
                        throw new Win32Exception(error, "删除服务失败");
                    }
                }
            }
            finally
            {
                _ = CloseServiceHandle(service);
            }
        }
        finally
        {
            _ = CloseServiceHandle(scm);
        }
    }

    private static IntPtr OpenScm(uint access = ScManagerConnect)
    {
        var scm = OpenSCManagerW(null, null, access);

        if (scm == IntPtr.Zero)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error(), "打开服务控制管理器失败（需要管理员）");
        }

        return scm;
    }

    private static void SetDescription(IntPtr service, string description)
    {
        var info = new ServiceDescription { Description = description };
        var pointer = Marshal.AllocHGlobal(Marshal.SizeOf<ServiceDescription>());

        try
        {
            Marshal.StructureToPtr(info, pointer, false);

            if (!ChangeServiceConfig2W(service, ServiceConfigDescription, pointer))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "设置服务描述失败");
            }
        }
        finally
        {
            Marshal.FreeHGlobal(pointer);
        }
    }

    private static void SetFailureActions(IntPtr service)
    {
        // 崩溃后 5s / 15s / 60s 重启；1 小时后重置计数。
        var delays = new uint[] { 5_000, 15_000, 60_000 };
        var actionSize = Marshal.SizeOf<ScAction>();
        var actionsPointer = Marshal.AllocHGlobal(actionSize * delays.Length);
        var infoPointer = Marshal.AllocHGlobal(Marshal.SizeOf<ServiceFailureActions>());

        try
        {
            for (var i = 0; i < delays.Length; i++)
            {
                var action = new ScAction { Type = ScActionRestart, Delay = delays[i] };
                Marshal.StructureToPtr(action, IntPtr.Add(actionsPointer, i * actionSize), false);
            }

            var info = new ServiceFailureActions
            {
                ResetPeriod = 3600,
                ActionCount = (uint)delays.Length,
                Actions = actionsPointer,
            };

            Marshal.StructureToPtr(info, infoPointer, false);

            if (!ChangeServiceConfig2W(service, ServiceConfigFailureActions, infoPointer))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "设置失败重启策略失败");
            }
        }
        finally
        {
            Marshal.FreeHGlobal(infoPointer);
            Marshal.FreeHGlobal(actionsPointer);
        }
    }

    private static void SetDelayedAutoStart(IntPtr service)
    {
        var info = new ServiceDelayedAutoStartInfo { DelayedAutostart = 1 };
        var pointer = Marshal.AllocHGlobal(Marshal.SizeOf<ServiceDelayedAutoStartInfo>());

        try
        {
            Marshal.StructureToPtr(info, pointer, false);

            if (!ChangeServiceConfig2W(service, ServiceConfigDelayedAutoStart, pointer))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error(), "设置延迟启动失败");
            }
        }
        finally
        {
            Marshal.FreeHGlobal(pointer);
        }
    }
}
