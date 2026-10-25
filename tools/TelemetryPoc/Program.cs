using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace WinAppGuard.TelemetryPoc;

/// <summary>
/// 3.5 POC：TCP 扩展统计。
///
/// 只用于测量，不进产品。运行方式（管理员 PowerShell，VM 里）：
///   WinAppGuard.TelemetryPoc.exe --tcp 10
///
/// 它会：
///   1. 枚举当前 TCP 连接（IPv4/IPv6）；
///   2. 对每条连接启用 TCP_ESTATS_DATA；
///   3. 等待 N 秒；
///   4. 读回每条连接的 DataBytesOut / DataBytesIn，按 PID 汇总。
///
/// 限制：只能统计 TCP；短连接可能在等待期间关闭，读不到。
/// </summary>
internal static class Program
{
    private const int AfInet = 2;
    private const int AfInet6 = 23;
    private const int TcpTableOwnerPidAll = 5;
    private const int TcpConnectionEstatsData = 1;
    private const uint TcpStateEstablished = 5;

    private static int Main(string[] args)
    {
        Console.OutputEncoding = System.Text.Encoding.UTF8;

        if (args.Length == 0 || args[0] is "--help" or "-h")
        {
            Console.WriteLine("WinAppGuard 3.5 POC — TCP 扩展统计");
            Console.WriteLine();
            Console.WriteLine("  WinAppGuard.TelemetryPoc.exe --tcp [秒数]");
            Console.WriteLine();
            Console.WriteLine("需要管理员权限。只读，不修改防火墙规则。");
            return 0;
        }

        if (!string.Equals(args[0], "--tcp", StringComparison.OrdinalIgnoreCase))
        {
            Console.Error.WriteLine("未知参数。用 --help 查看用法。");
            return 1;
        }

        var seconds = 10;

        if (args.Length > 1 && int.TryParse(args[1], out var parsed) && parsed is > 0 and <= 300)
        {
            seconds = parsed;
        }

        var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        var elevated = principal.IsInRole(WindowsBuiltInRole.Administrator);

        Console.WriteLine($"管理员 = {elevated}");

        if (!elevated)
        {
            Console.WriteLine("警告：非管理员可能无法启用/读取 TCP 统计。");
        }

        try
        {
            Run(seconds);
            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"POC 失败：{ex.GetType().Name}: {ex.Message}");
            return 2;
        }
    }

    private static void Run(int seconds)
    {
        var connections = new List<Connection>();

        connections.AddRange(EnumerateV4());
        connections.AddRange(EnumerateV6());

        Console.WriteLine($"TCP 连接数（含所有状态）= {connections.Count}");

        var established = connections
            .Where(connection => connection.State == TcpStateEstablished)
            .ToList();

        Console.WriteLine($"其中 ESTABLISHED = {established.Count}");

        var enabled = 0;

        foreach (var connection in established)
        {
            if (connection.EnableStats())
            {
                enabled++;
            }
        }

        Console.WriteLine($"已启用统计 = {enabled}");
        Console.WriteLine($"等待 {seconds} 秒…");

        Thread.Sleep(TimeSpan.FromSeconds(seconds));

        var byPid = new Dictionary<int, (ulong Out, ulong In)>();
        var readable = 0;
        var failed = 0;

        foreach (var connection in established)
        {
            if (!connection.TryRead(out var sent, out var received))
            {
                failed++;
                continue;
            }

            readable++;

            byPid.TryGetValue(connection.Pid, out var current);
            byPid[connection.Pid] = (current.Out + sent, current.In + received);
        }

        Console.WriteLine($"可读连接 = {readable}，读取失败 = {failed}");
        Console.WriteLine();

        ulong totalOut = 0;
        ulong totalIn = 0;

        foreach (var item in byPid.OrderByDescending(pair => pair.Value.Out + pair.Value.In).Take(20))
        {
            var name = GetProcessName(item.Key);
            totalOut += item.Value.Out;
            totalIn += item.Value.In;

            Console.WriteLine(
                $"PID {item.Key,6}  {name,-28}  上传 {FormatBytes(item.Value.Out),12}  下载 {FormatBytes(item.Value.In),12}");
        }

        Console.WriteLine();
        Console.WriteLine($"合计：上传 {FormatBytes(totalOut)}，下载 {FormatBytes(totalIn)}");

        if (readable == 0)
        {
            Console.WriteLine();
            Console.WriteLine("没有读到任何统计。可能原因：非管理员、连接已关闭、系统不支持/未启用 TCP 扩展统计。");
        }
    }

    private static string GetProcessName(int pid)
    {
        try
        {
            using var process = Process.GetProcessById(pid);
            return process.ProcessName + ".exe";
        }
        catch (Exception)
        {
            return $"<PID {pid}>";
        }
    }

    private static string FormatBytes(ulong bytes)
    {
        string[] units = { "B", "KB", "MB", "GB", "TB" };
        var value = (double)bytes;
        var unit = 0;

        while (value >= 1024 && unit < units.Length - 1)
        {
            value /= 1024;
            unit++;
        }

        return $"{value:0.##} {units[unit]}";
    }

    private abstract class Connection
    {
        internal required int Pid { get; init; }

        internal required uint State { get; init; }

        internal abstract bool EnableStats();

        internal abstract bool TryRead(out ulong sent, out ulong received);
    }

    private sealed class ConnectionV4 : Connection
    {
        internal required MibTcpRow Row { get; init; }

        internal override bool EnableStats()
        {
            var row = Row;
            byte enable = 1;
            var rc = SetPerTcpConnectionEStats(
                ref row, TcpConnectionEstatsData, ref enable, 0, 1,
                IntPtr.Zero, 0, 0);

            return rc == 0;
        }

        internal override bool TryRead(out ulong sent, out ulong received)
        {
            sent = 0;
            received = 0;

            var row = Row;
            var rod = default(TcpEstatsDataRod);

            var rc = GetPerTcpConnectionEStats(
                ref row, TcpConnectionEstatsData,
                IntPtr.Zero, 0, 0,
                IntPtr.Zero, 0, 0,
                ref rod, 0, (uint)Marshal.SizeOf<TcpEstatsDataRod>());

            if (rc != 0)
            {
                return false;
            }

            sent = rod.DataBytesOut;
            received = rod.DataBytesIn;
            return true;
        }
    }

    private sealed class ConnectionV6 : Connection
    {
        internal required MibTcp6Row Row { get; init; }

        internal override bool EnableStats()
        {
            var row = Row;
            byte enable = 1;
            var rc = SetPerTcp6ConnectionEStats(
                ref row, TcpConnectionEstatsData, ref enable, 0, 1,
                IntPtr.Zero, 0, 0);

            return rc == 0;
        }

        internal override bool TryRead(out ulong sent, out ulong received)
        {
            sent = 0;
            received = 0;

            var row = Row;
            var rod = default(TcpEstatsDataRod);

            var rc = GetPerTcp6ConnectionEStats(
                ref row, TcpConnectionEstatsData,
                IntPtr.Zero, 0, 0,
                IntPtr.Zero, 0, 0,
                ref rod, 0, (uint)Marshal.SizeOf<TcpEstatsDataRod>());

            if (rc != 0)
            {
                return false;
            }

            sent = rod.DataBytesOut;
            received = rod.DataBytesIn;
            return true;
        }
    }

    // ---------------- 枚举 ----------------

    private static IEnumerable<Connection> EnumerateV4()
    {
        var buffer = GetTable(AfInet, TcpTableOwnerPidAll);
        if (buffer == IntPtr.Zero)
        {
            yield break;
        }

        try
        {
            var count = Marshal.ReadInt32(buffer);
            var rowSize = Marshal.SizeOf<MibTcpRowOwnerPid>();
            var rowPtr = IntPtr.Add(buffer, 4);

            for (var i = 0; i < count; i++)
            {
                var owner = Marshal.PtrToStructure<MibTcpRowOwnerPid>(
                    IntPtr.Add(rowPtr, i * rowSize));

                yield return new ConnectionV4
                {
                    Pid = (int)owner.OwningPid,
                    State = owner.State,
                    Row = new MibTcpRow
                    {
                        State = owner.State,
                        LocalAddr = owner.LocalAddr,
                        LocalPort = owner.LocalPort,
                        RemoteAddr = owner.RemoteAddr,
                        RemotePort = owner.RemotePort,
                    },
                };
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static IEnumerable<Connection> EnumerateV6()
    {
        var buffer = GetTable(AfInet6, TcpTableOwnerPidAll);
        if (buffer == IntPtr.Zero)
        {
            yield break;
        }

        try
        {
            var count = Marshal.ReadInt32(buffer);
            var rowSize = Marshal.SizeOf<MibTcp6RowOwnerPid>();
            var rowPtr = IntPtr.Add(buffer, 4);

            for (var i = 0; i < count; i++)
            {
                var owner = Marshal.PtrToStructure<MibTcp6RowOwnerPid>(
                    IntPtr.Add(rowPtr, i * rowSize));

                yield return new ConnectionV6
                {
                    Pid = (int)owner.OwningPid,
                    State = owner.State,
                    Row = new MibTcp6Row
                    {
                        LocalAddr = owner.LocalAddr,
                        LocalScopeId = owner.LocalScopeId,
                        LocalPort = owner.LocalPort,
                        RemoteAddr = owner.RemoteAddr,
                        RemoteScopeId = owner.RemoteScopeId,
                        RemotePort = owner.RemotePort,
                        State = owner.State,
                    },
                };
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static IntPtr GetTable(int family, int tableClass)
    {
        var size = 0;
        var rc = GetExtendedTcpTable(
            IntPtr.Zero, ref size, false, family, tableClass, 0);

        if (rc != 122 && size <= 0) // ERROR_INSUFFICIENT_BUFFER
        {
            Console.Error.WriteLine($"GetExtendedTcpTable 取大小失败：{rc}");
            return IntPtr.Zero;
        }

        var buffer = Marshal.AllocHGlobal(size);
        rc = GetExtendedTcpTable(buffer, ref size, false, family, tableClass, 0);

        if (rc != 0)
        {
            Marshal.FreeHGlobal(buffer);
            Console.Error.WriteLine($"GetExtendedTcpTable 失败：{rc}");
            return IntPtr.Zero;
        }

        return buffer;
    }

    // ---------------- 结构 ----------------

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcpRow
    {
        public uint State;
        public uint LocalAddr;
        public uint LocalPort;
        public uint RemoteAddr;
        public uint RemotePort;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcp6Row
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] LocalAddr;

        public uint LocalScopeId;
        public uint LocalPort;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] RemoteAddr;

        public uint RemoteScopeId;
        public uint RemotePort;
        public uint State;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcpRowOwnerPid
    {
        public uint State;
        public uint LocalAddr;
        public uint LocalPort;
        public uint RemoteAddr;
        public uint RemotePort;
        public uint OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcp6RowOwnerPid
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] LocalAddr;

        public uint LocalScopeId;
        public uint LocalPort;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] RemoteAddr;

        public uint RemoteScopeId;
        public uint RemotePort;
        public uint State;
        public uint OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TcpEstatsDataRod
    {
        public ulong DataBytesOut;
        public ulong DataBytesIn;
        public ulong DataSegsOut;
        public ulong DataSegsIn;
        public ulong SegsOut;
        public ulong SegsIn;
        public uint SoftErrors;
        public uint SoftErrorReason;
        public uint SndUna;
        public uint SndNxt;
        public uint SndMax;
        public ulong ThruBytesAcked;
        public uint RcvNxt;
        public ulong ThruBytesReceived;
    }

    // ---------------- P/Invoke ----------------

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr tcpTable, ref int size, bool order, int family, int tableClass, uint reserved);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint SetPerTcpConnectionEStats(
        ref MibTcpRow row, int estatsType, ref byte rw, uint rwVersion, uint rwSize,
        IntPtr ros, uint rosVersion, uint rosSize);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetPerTcpConnectionEStats(
        ref MibTcpRow row, int estatsType,
        IntPtr rw, uint rwVersion, uint rwSize,
        IntPtr ros, uint rosVersion, uint rosSize,
        ref TcpEstatsDataRod rod, uint rodVersion, uint rodSize);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint SetPerTcp6ConnectionEStats(
        ref MibTcp6Row row, int estatsType, ref byte rw, uint rwVersion, uint rwSize,
        IntPtr ros, uint rosVersion, uint rosSize);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetPerTcp6ConnectionEStats(
        ref MibTcp6Row row, int estatsType,
        IntPtr rw, uint rwVersion, uint rwSize,
        IntPtr ros, uint rosVersion, uint rosSize,
        ref TcpEstatsDataRod rod, uint rodVersion, uint rodSize);
}
