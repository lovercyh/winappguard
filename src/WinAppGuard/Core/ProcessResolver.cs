using System.Text;
using WinAppGuard.Interop;

namespace WinAppGuard.Core;

/// <summary>
/// 进程的身份信息。
/// </summary>
/// <param name="Name">显示用名称，例如 chrome.exe。</param>
/// <param name="Path">可执行文件完整路径；拿不到时为空字符串。</param>
public readonly record struct ProcessIdentity(string Name, string Path);

/// <summary>
/// 根据 PID 查出进程的名称和可执行文件路径。
///
/// 设计要点：
///   1. 只用 Win32 API，不创建 System.Diagnostics.Process 对象。
///      Process 对象会占用系统句柄，如果每 3 秒全量刷新一次而不释放，
///      句柄数会持续增长，长时间挂机就会出问题。
///   2. 查不到路径不算错误，返回占位结果即可。
///      连接表里总会有拿不到路径的条目（System 内核进程、刚退出的进程、受保护进程），
///      这是正常现象，不应该让整个扫描失败。
/// </summary>
public static class ProcessResolver
{
    /// <summary>存放路径的缓冲区长度（字符数）。1024 个字符足够容纳超长路径。</summary>
    private const int PathBufferLength = 1024;

    /// <summary>
    /// 解析进程身份。任何情况下都不会抛异常。
    /// </summary>
    /// <param name="pid">进程 PID。</param>
    public static ProcessIdentity Resolve(int pid)
    {
        // PID 0 是「系统空闲进程」，理论上不会拥有网络连接，这里只做兜底。
        if (pid <= 0)
        {
            return new ProcessIdentity("系统空闲进程", string.Empty);
        }

        // PID 4 是 Windows 内核的 System 进程，它没有对应的可执行文件。
        if (pid == 4)
        {
            return new ProcessIdentity("System（内核）", string.Empty);
        }

        var path = TryGetImagePath(pid);
        if (string.IsNullOrEmpty(path))
        {
            return new ProcessIdentity($"PID {pid}", string.Empty);
        }

        return new ProcessIdentity(Path.GetFileName(path), path);
    }

    /// <summary>
    /// 查询指定进程可执行文件的完整路径，失败返回 null。
    /// </summary>
    public static string? TryGetImagePath(int pid)
    {
        // 使用 PROCESS_QUERY_LIMITED_INFORMATION：权限要求最低，
        // 能读取绝大多数进程，包括 64 位系统上运行的 32 位进程（WOW64）。
        var handle = NativeMethods.OpenProcess(NativeMethods.PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        if (handle == IntPtr.Zero)
        {
            return null;
        }

        try
        {
            var buffer = new StringBuilder(PathBufferLength);
            var size = buffer.Capacity;

            if (!NativeMethods.QueryFullProcessImageNameW(handle, 0, buffer, ref size))
            {
                return null;
            }

            // size 是实际写入的字符数，不是缓冲区长度，必须按它截取。
            return buffer.ToString(0, size);
        }
        finally
        {
            // 无论成功失败都要关句柄，否则会持续泄漏。
            NativeMethods.CloseHandle(handle);
        }
    }
}
