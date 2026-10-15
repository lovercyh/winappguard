using System.ComponentModel;
using System.Net;
using System.Runtime.InteropServices;
using WinAppGuard.Interop;
using WinAppGuard.Models;

namespace WinAppGuard.Core;

/// <summary>
/// TCP 连接扫描的过滤选项。
///
/// 之所以做成一个显式选项对象，而不是一堆 bool 参数，
/// 是为了让调用处一眼就能看清「这次扫描过滤掉了什么」，
/// 避免出现 Scan(false, false, true) 这种谁也看不懂的调用。
///
/// 默认值对应「正在联网的程序」这一使用场景：
/// 只看有归属进程、还活着的连接。
/// </summary>
public sealed class ConnectionScanOptions
{
    /// <summary>
    /// 是否包含处于「监听中」（LISTEN）状态的连接。默认不包含。
    /// 监听只是开着端口等别人来连，不代表正在联网。
    /// </summary>
    public bool IncludeListening { get; init; }

    /// <summary>
    /// 是否包含已经结束、正在等系统回收的连接（TIME_WAIT、CLOSED、DELETE_TCB）。默认不包含。
    ///
    /// 这类连接的归属进程通常已经退出，PID 会是 0，既看不出是哪个程序，也没法据此创建防火墙规则。
    /// 在实测中它们数量极大（动辄上百条），默认显示会把列表完全淹没。
    /// </summary>
    public bool IncludeClosed { get; init; }

    /// <summary>
    /// 是否包含没有归属进程的连接（PID 为 0）。默认不包含。
    ///
    /// 没有归属进程就意味着：显示不出程序名、也无法为它创建防火墙规则。
    /// 这是「默认隐藏」里唯一一个可能让用户觉得意外的，所以单独做成开关。
    /// </summary>
    public bool IncludeOwnerless { get; init; }

    /// <summary>
    /// 是否隐藏本机回环连接（127.0.0.1 / ::1）。默认隐藏。
    ///
    /// 回环连接是同一台机器上的进程互相通信（各类后台服务、浏览器内部进程等），
    /// 数据并没有真的走到网络上去。
    /// 实测中这类连接的占比极高（本机 319 条里有近一半），默认隐藏之后，
    /// 「到底哪个程序在联网」才能一目了然。
    /// </summary>
    public bool HideLoopback { get; init; } = true;
}

/// <summary>
/// TCP 连接扫描器。
///
/// 通过 iphlpapi 的 GetExtendedTcpTable 一次性取回整张连接表，
/// 这张表的特点是每一行都带「拥有该连接的进程 PID」，这是按 PID 反查程序的前提。
///
/// 注意：本类只做「读」，不修改任何系统状态。
/// </summary>
public static class ConnectionScanner
{
    /// <summary>
    /// 按指定过滤条件扫描当前的所有 TCP 连接。
    /// </summary>
    /// <param name="options">过滤条件。传 null 表示使用全部关闭的默认条件。</param>
    /// <returns>连接列表。扫描失败时抛出 <see cref="Win32Exception"/>。</returns>
    public static List<TcpConnectionItem> Scan(ConnectionScanOptions? options = null)
    {
        options ??= new ConnectionScanOptions();

        var result = new List<TcpConnectionItem>(256);

        // 一个进程通常有多条连接，它的路径只需要查一次，用缓存避免重复调用系统 API。
        var processCache = new Dictionary<int, ProcessIdentity>();

        ScanIPv4(result, options, processCache);
        ScanIPv6(result, options, processCache);

        return result;
    }

    /// <summary>
    /// 判断一条连接是否应该出现在结果里。
    /// IPv4 / IPv6 共用这一份判断逻辑，避免两边规则写歪。
    /// </summary>
    private static bool ShouldInclude(TcpState state, int pid, ConnectionScanOptions options)
    {
        // 1) 监听状态
        if (state == TcpState.Listen)
        {
            return options.IncludeListening;
        }

        // 2) 已经结束、等系统回收的状态
        if (state is TcpState.TimeWait or TcpState.Closed or TcpState.DeleteTcb)
        {
            return options.IncludeClosed;
        }

        // 3) 没有归属进程
        if (pid <= 0)
        {
            return options.IncludeOwnerless;
        }

        // 其余（已建立、同步中、正在关闭等）都是「有意义且可操作」的连接。
        return true;
    }

    /// <summary>扫描 IPv4 连接表。</summary>
    private static void ScanIPv4(
        List<TcpConnectionItem> result,
        ConnectionScanOptions options,
        Dictionary<int, ProcessIdentity> processCache)
    {
        var buffer = IntPtr.Zero;

        try
        {
            var size = 0;
            var ret = NativeMethods.GetExtendedTcpTable(
                IntPtr.Zero, ref size, false,
                NativeMethods.AF_INET, NativeMethods.TCP_TABLE_OWNER_PID_ALL, 0);

            // 第一次调用只为了问「需要多大缓冲区」，正常应返回 ERROR_INSUFFICIENT_BUFFER。
            if (ret == NativeMethods.NO_ERROR)
            {
                // 表里一条连接都没有。
                return;
            }

            if (ret != NativeMethods.ERROR_INSUFFICIENT_BUFFER || size <= 0)
            {
                throw new Win32Exception((int)ret, "获取 IPv4 TCP 连接表失败");
            }

            buffer = Marshal.AllocHGlobal(size);

            ret = NativeMethods.GetExtendedTcpTable(
                buffer, ref size, false,
                NativeMethods.AF_INET, NativeMethods.TCP_TABLE_OWNER_PID_ALL, 0);

            if (ret != NativeMethods.NO_ERROR)
            {
                throw new Win32Exception((int)ret, "获取 IPv4 TCP 连接表失败");
            }

            // 缓冲区开头是一个 DWORD，表示行数；之后紧跟连续的行数据。
            var rowCount = Marshal.ReadInt32(buffer);
            var rowSize = Marshal.SizeOf<MibTcpRowOwnerPid>();
            var rowPointer = IntPtr.Add(buffer, sizeof(int));

            for (var i = 0; i < rowCount; i++)
            {
                var row = Marshal.PtrToStructure<MibTcpRowOwnerPid>(rowPointer);
                rowPointer = IntPtr.Add(rowPointer, rowSize);

                var state = (TcpState)row.State;
                var pid = (int)row.OwningPid;
                var remoteAddress = ToIPv4Address(row.RemoteAddr);

                if (!ShouldInclude(state, pid, options))
                {
                    continue;
                }

                if (options.HideLoopback && IPAddress.IsLoopback(remoteAddress))
                {
                    continue;
                }

                var identity = GetIdentity(pid, processCache);

                result.Add(new TcpConnectionItem
                {
                    Pid = pid,
                    ProcessName = identity.Name,
                    ProcessPath = identity.Path,
                    Protocol = "IPv4",
                    LocalPort = NetworkToHostPort(row.LocalPort),
                    RemoteAddress = remoteAddress,
                    RemotePort = NetworkToHostPort(row.RemotePort),
                    State = state,
                });
            }
        }
        finally
        {
            // 非托管内存必须手动释放。
            if (buffer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
    }

    /// <summary>扫描 IPv6 连接表。逻辑与 IPv4 一致，只是结构体和地址长度不同。</summary>
    private static void ScanIPv6(
        List<TcpConnectionItem> result,
        ConnectionScanOptions options,
        Dictionary<int, ProcessIdentity> processCache)
    {
        var buffer = IntPtr.Zero;

        try
        {
            var size = 0;
            var ret = NativeMethods.GetExtendedTcpTable(
                IntPtr.Zero, ref size, false,
                NativeMethods.AF_INET6, NativeMethods.TCP_TABLE_OWNER_PID_ALL, 0);

            if (ret == NativeMethods.NO_ERROR)
            {
                // 本机没有 IPv6 TCP 连接，属于正常情况。
                return;
            }

            if (ret != NativeMethods.ERROR_INSUFFICIENT_BUFFER || size <= 0)
            {
                throw new Win32Exception((int)ret, "获取 IPv6 TCP 连接表失败");
            }

            buffer = Marshal.AllocHGlobal(size);

            ret = NativeMethods.GetExtendedTcpTable(
                buffer, ref size, false,
                NativeMethods.AF_INET6, NativeMethods.TCP_TABLE_OWNER_PID_ALL, 0);

            if (ret != NativeMethods.NO_ERROR)
            {
                throw new Win32Exception((int)ret, "获取 IPv6 TCP 连接表失败");
            }

            var rowCount = Marshal.ReadInt32(buffer);
            var rowSize = Marshal.SizeOf<MibTcp6RowOwnerPid>();
            var rowPointer = IntPtr.Add(buffer, sizeof(int));

            for (var i = 0; i < rowCount; i++)
            {
                var row = Marshal.PtrToStructure<MibTcp6RowOwnerPid>(rowPointer);
                rowPointer = IntPtr.Add(rowPointer, rowSize);

                var state = (TcpState)row.State;
                var pid = (int)row.OwningPid;
                var remoteAddress = new IPAddress(row.RemoteAddr, row.RemoteScopeId);

                if (!ShouldInclude(state, pid, options))
                {
                    continue;
                }

                if (options.HideLoopback && IPAddress.IsLoopback(remoteAddress))
                {
                    continue;
                }

                var identity = GetIdentity(pid, processCache);

                result.Add(new TcpConnectionItem
                {
                    Pid = pid,
                    ProcessName = identity.Name,
                    ProcessPath = identity.Path,
                    Protocol = "IPv6",
                    LocalPort = NetworkToHostPort(row.LocalPort),
                    RemoteAddress = remoteAddress,
                    RemotePort = NetworkToHostPort(row.RemotePort),
                    State = state,
                });
            }
        }
        finally
        {
            if (buffer != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
    }

    /// <summary>取进程身份，带一次扫描内的缓存。</summary>
    private static ProcessIdentity GetIdentity(int pid, Dictionary<int, ProcessIdentity> cache)
    {
        if (cache.TryGetValue(pid, out var cached))
        {
            return cached;
        }

        var identity = ProcessResolver.Resolve(pid);
        cache[pid] = identity;
        return identity;
    }

    /// <summary>
    /// 把表中「网络字节序」的端口号还原成正常数值。
    ///
    /// 端口以网络字节序存放在 DWORD 的低 16 位里，例如 8080（0x1F90）
    /// 读出来是 0x901F，所以需要交换高低字节。
    /// </summary>
    private static ushort NetworkToHostPort(uint networkOrderPort)
    {
        var value = (ushort)(networkOrderPort & 0xFFFF);
        return (ushort)((value >> 8) | ((value & 0xFF) << 8));
    }

    /// <summary>
    /// 把表中「网络字节序」的 IPv4 地址还原成 IPAddress。
    ///
    /// 地址在内存中就是 a.b.c.d 四个字节，BitConverter 在 x64 上（小端）
    /// 取出的字节顺序恰好一致，直接交给 IPAddress 即可。
    /// 本项目仅发布 win-x64，不涉及大端平台。
    /// </summary>
    private static IPAddress ToIPv4Address(uint networkOrderAddress)
        => new(BitConverter.GetBytes(networkOrderAddress));
}
