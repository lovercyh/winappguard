using System.Runtime.InteropServices;

namespace WinAppGuard.Core;

/// <summary>
/// 判断一个访问令牌是否**已提权**（UAC 提升后的管理员令牌）。
///
/// 为什么单独抽出来：服务用它做 IPC 鉴权，自检用它验证"未提权会被拒绝"。
/// 两处必须是**同一份判断** —— 各写一遍迟早会分叉。
/// </summary>
internal static class TokenInspector
{
    private const uint TokenQuery = 0x8;

    /// <summary>TOKEN_INFORMATION_CLASS.TokenElevation。</summary>
    private const int TokenElevation = 20;

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool GetTokenInformation(
        IntPtr tokenHandle, int tokenInformationClass,
        IntPtr tokenInformation, uint tokenInformationLength, out uint returnLength);

    /// <summary>令牌是否已提权。</summary>
    internal static bool IsElevated(IntPtr token)
    {
        if (token == IntPtr.Zero)
        {
            return false;
        }

        var buffer = Marshal.AllocHGlobal(sizeof(uint));

        try
        {
            if (!GetTokenInformation(token, TokenElevation, buffer, sizeof(uint), out _))
            {
                return false;
            }

            return Marshal.ReadInt32(buffer) != 0;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    /// <summary>打开一个进程的令牌（调用方负责 CloseHandle）。</summary>
    internal static IntPtr OpenProcessToken(IntPtr processHandle)
    {
        return OpenProcessTokenCore(processHandle, TokenQuery, out var token)
            ? token
            : IntPtr.Zero;
    }

    [DllImport("advapi32.dll", SetLastError = true, EntryPoint = "OpenProcessToken")]
    private static extern bool OpenProcessTokenCore(
        IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern bool CloseHandle(IntPtr handle);
}
