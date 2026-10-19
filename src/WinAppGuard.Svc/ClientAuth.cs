using System.IO.Pipes;
using System.Runtime.InteropServices;
using WinAppGuard.Core;

namespace WinAppGuard.Service;

/// <summary>
/// 客户端令牌校验：只接受**已提权**的客户端（M1.5）。
///
/// 为什么不是"校验密钥"：同一用户下的恶意进程能读到任何内置/落盘的密钥，
/// 只有"提权"这件事是操作系统替我们保证的边界（见 docs/服务化设计.md §14.2.1）。
/// </summary>
internal static class ClientAuth
{
    private const uint ProcessQueryLimitedInformation = 0x1000;

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetNamedPipeClientProcessId(IntPtr pipe, out uint clientProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint desiredAccess, bool inheritHandle, uint processId);

    internal static bool IsElevated(NamedPipeServerStream pipe, out string reason)
    {
        reason = string.Empty;

        if (!GetNamedPipeClientProcessId(pipe.SafePipeHandle.DangerousGetHandle(), out var processId))
        {
            reason = $"拿不到客户端进程号（Win32 {Marshal.GetLastWin32Error()}）。";
            return false;
        }

        var process = OpenProcess(ProcessQueryLimitedInformation, false, processId);

        if (process == IntPtr.Zero)
        {
            reason = $"打不开客户端进程 {processId}（Win32 {Marshal.GetLastWin32Error()}）。";
            return false;
        }

        var token = IntPtr.Zero;

        try
        {
            token = TokenInspector.OpenProcessToken(process);

            if (token == IntPtr.Zero)
            {
                reason = $"拿不到客户端令牌（Win32 {Marshal.GetLastWin32Error()}）。";
                return false;
            }

            if (!TokenInspector.IsElevated(token))
            {
                reason = $"客户端进程 {processId} 没有提权，拒绝操作。";
                return false;
            }

            return true;
        }
        finally
        {
            if (token != IntPtr.Zero)
            {
                _ = TokenInspector.CloseHandle(token);
            }

            _ = TokenInspector.CloseHandle(process);
        }
    }
}
