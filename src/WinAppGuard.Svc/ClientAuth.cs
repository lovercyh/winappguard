using System.IO.Pipes;
using System.Runtime.InteropServices;
using WinAppGuard.Core;

namespace WinAppGuard.Service;

/// <summary>
/// 客户端身份检查（M1.5）。
///
/// 注意：这里**不再直接拒绝未提权客户端** —— 查看/记录本来就该免管理员。
/// 它只负责回答"这个客户端有没有提权"，由具体命令决定是否放行
/// （写规则需要提权，读状态不需要）。
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

    /// <summary>
    /// 读取客户端进程的提权状态。
    /// </summary>
    /// <returns>能确定身份返回 true；连进程/令牌都打不开返回 false（此时应拒绝连接）。</returns>
    internal static bool TryGetElevation(
        NamedPipeServerStream pipe, out bool elevated, out uint processId, out string? error)
    {
        elevated = false;
        processId = 0;
        error = null;

        if (!GetNamedPipeClientProcessId(pipe.SafePipeHandle.DangerousGetHandle(), out processId))
        {
            error = $"拿不到客户端进程号（Win32 {Marshal.GetLastWin32Error()}）。";
            return false;
        }

        var process = OpenProcess(ProcessQueryLimitedInformation, false, processId);

        if (process == IntPtr.Zero)
        {
            error = $"打不开客户端进程 {processId}（Win32 {Marshal.GetLastWin32Error()}）。";
            return false;
        }

        var token = IntPtr.Zero;

        try
        {
            token = TokenInspector.OpenProcessToken(process);

            if (token == IntPtr.Zero)
            {
                error = $"拿不到客户端令牌（Win32 {Marshal.GetLastWin32Error()}）。";
                return false;
            }

            elevated = TokenInspector.IsElevated(token);
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
