using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace WinAppGuard.Contracts.Protocol;

/// <summary>
/// 5.10：客户端校验管道对端确实是本安装目录里的 SYSTEM 服务。
/// 防的是“非管理员先抢占同名管道，再返回假数据”。
/// </summary>
public static class ServerIdentity
{
    private const uint ProcessQueryLimitedInformation = 0x1000;
    private const uint TokenQuery = 0x0008;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetNamedPipeServerProcessId(IntPtr pipe, out uint serverProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint desiredAccess, bool inheritHandle, uint processId);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    private static extern bool QueryFullProcessImageNameW(
        IntPtr process, uint flags, StringBuilder exeName, ref int size);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(IntPtr process, uint desiredAccess, out IntPtr token);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    public static bool IsExpectedServer(IntPtr pipeHandle, out string? error)
    {
        error = null;

        try
        {
            if (!GetNamedPipeServerProcessId(pipeHandle, out var pid))
            {
                error = $"无法读取管道服务端进程：Win32 {Marshal.GetLastWin32Error()}";
                return false;
            }

            var process = OpenProcess(ProcessQueryLimitedInformation, false, pid);

            if (process == IntPtr.Zero)
            {
                error = $"无法打开服务端进程 {pid}：Win32 {Marshal.GetLastWin32Error()}";
                return false;
            }

            var token = IntPtr.Zero;

            try
            {
                var pathBuffer = new StringBuilder(1024);
                var pathLength = pathBuffer.Capacity;

                if (!QueryFullProcessImageNameW(process, 0, pathBuffer, ref pathLength))
                {
                    error = $"无法读取服务端镜像路径：Win32 {Marshal.GetLastWin32Error()}";
                    return false;
                }

                var serverPath = pathBuffer.ToString();
                var expectedDirectory = Path.GetFullPath(AppContext.BaseDirectory)
                    .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                var actualDirectory = Path.GetFullPath(Path.GetDirectoryName(serverPath) ?? string.Empty)
                    .TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);

                if (!string.Equals(expectedDirectory, actualDirectory, StringComparison.OrdinalIgnoreCase))
                {
                    error = $"服务端镜像不在安装目录：{serverPath}";
                    return false;
                }

                if (!OpenProcessToken(process, TokenQuery, out token))
                {
                    error = $"无法读取服务端令牌：Win32 {Marshal.GetLastWin32Error()}";
                    return false;
                }

                using var identity = new WindowsIdentity(token);
                var systemSid = new SecurityIdentifier(
                    WellKnownSidType.LocalSystemSid, null);

                if (identity.User is null || !identity.User.Equals(systemSid))
                {
                    error = "服务端不是 SYSTEM。";
                    return false;
                }

                return true;
            }
            finally
            {
                if (token != IntPtr.Zero)
                {
                    _ = CloseHandle(token);
                }

                _ = CloseHandle(process);
            }
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }
}
