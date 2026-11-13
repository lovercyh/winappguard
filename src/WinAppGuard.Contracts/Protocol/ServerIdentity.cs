using System.Runtime.InteropServices;

namespace WinAppGuard.Contracts.Protocol;

/// <summary>
/// 5.10：客户端校验管道对端确实是已安装的 WinAppGuard 服务进程。
///
/// 为什么不用“打开服务端令牌 + 镜像路径”：
///   服务以 SYSTEM 运行，普通权限界面没有权限打开 SYSTEM 进程令牌，
///   会把正常服务误判成假服务端。
///
/// 现在直接比较：
///   - 管道服务端 PID（GetNamedPipeServerProcessId）；
///   - SCM 里 WinAppGuardSvc 的 PID（QueryServiceStatusEx）。
/// 两者一致才放行。非管理员无法伪造这个 PID。
/// </summary>
public static class ServerIdentity
{
    private const uint ScManagerConnect = 0x0001;
    private const uint ServiceQueryStatus = 0x0004;
    private const int ScStatusProcessInfo = 0;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetNamedPipeServerProcessId(IntPtr pipe, out uint serverProcessId);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr OpenSCManagerW(
        string? machineName, string? databaseName, uint desiredAccess);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern IntPtr OpenServiceW(
        IntPtr scManager, string serviceName, uint desiredAccess);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool QueryServiceStatusEx(
        IntPtr service,
        int infoLevel,
        IntPtr buffer,
        uint bufferSize,
        out uint bytesNeeded);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool CloseServiceHandle(IntPtr handle);

    [StructLayout(LayoutKind.Sequential)]
    private struct ServiceStatusProcess
    {
        public uint ServiceType;
        public uint CurrentState;
        public uint ControlsAccepted;
        public uint Win32ExitCode;
        public uint ServiceSpecificExitCode;
        public uint CheckPoint;
        public uint WaitHint;
        public uint ProcessId;
        public uint ServiceFlags;
    }

    public static bool IsExpectedServer(IntPtr pipeHandle, out string? error)
    {
        error = null;

        try
        {
            if (!GetNamedPipeServerProcessId(pipeHandle, out var serverPid))
            {
                error = $"无法读取管道服务端进程：Win32 {Marshal.GetLastWin32Error()}";
                return false;
            }

            if (!TryGetServiceProcessId(out var servicePid, out var serviceError))
            {
                error = serviceError;
                return false;
            }

            if (serverPid != servicePid)
            {
                error = $"管道服务端 PID {serverPid} 与已安装服务 PID {servicePid} 不一致。";
                return false;
            }

            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    private static bool TryGetServiceProcessId(out uint processId, out string? error)
    {
        processId = 0;
        error = null;

        var scManager = OpenSCManagerW(null, null, ScManagerConnect);

        if (scManager == IntPtr.Zero)
        {
            error = $"无法连接服务管理器：Win32 {Marshal.GetLastWin32Error()}";
            return false;
        }

        var service = IntPtr.Zero;

        try
        {
            service = OpenServiceW(scManager, ServiceProtocol.ServiceName, ServiceQueryStatus);

            if (service == IntPtr.Zero)
            {
                error = $"无法打开服务 {ServiceProtocol.ServiceName}：Win32 {Marshal.GetLastWin32Error()}";
                return false;
            }

            var size = Marshal.SizeOf<ServiceStatusProcess>();
            var buffer = Marshal.AllocHGlobal(size);

            try
            {
                if (!QueryServiceStatusEx(
                        service, ScStatusProcessInfo, buffer, (uint)size, out _))
                {
                    error = $"无法查询服务状态：Win32 {Marshal.GetLastWin32Error()}";
                    return false;
                }

                var status = Marshal.PtrToStructure<ServiceStatusProcess>(buffer);

                if (status.ProcessId == 0)
                {
                    error = "服务没有运行中的进程。";
                    return false;
                }

                processId = status.ProcessId;
                return true;
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        finally
        {
            if (service != IntPtr.Zero)
            {
                _ = CloseServiceHandle(service);
            }

            _ = CloseServiceHandle(scManager);
        }
    }
}
