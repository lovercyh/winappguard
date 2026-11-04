using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace WinAppGuard.Core.Diagnostics.NetworkDetection;

/// <summary>
/// 5.0：把 Suricata 告警里的五元组反查为本机 PID/进程。
///
/// Suricata 只认识包，不认识进程；这里用 Windows 的 TCP/UDP 所有者表补上。
/// 反查失败时返回 PID 0，界面显示“未知进程”，不影响告警本身。
/// </summary>
internal static class FlowProcessResolver
{
    private const int AfInet = 2;
    private const int AfInet6 = 23;
    private const int ErrorInsufficientBuffer = 122;
    private const int TcpTableOwnerPidAll = 5;
    private const int UdpTableOwnerPid = 1;

    private static readonly object Gate = new();
    private static readonly TimeSpan CacheLifetime = TimeSpan.FromSeconds(1);

    private static DateTime _tcpLoadedUtc;
    private static DateTime _udpLoadedUtc;
    private static List<TcpRow> _tcpRows = new();
    private static List<UdpRow> _udpRows = new();

    internal static (int Pid, string Name, string Path) Resolve(
        string protocol,
        string localAddress,
        int localPort,
        string remoteAddress,
        int remotePort)
    {
        try
        {
            var isUdp = string.Equals(protocol, "UDP", StringComparison.OrdinalIgnoreCase);
            var pid = isUdp
                ? FindUdp(localAddress, localPort)
                : FindTcp(localAddress, localPort, remoteAddress, remotePort);

            if (pid <= 0)
            {
                return (0, string.Empty, string.Empty);
            }

            var identity = ProcessResolver.Resolve(pid);
            return (pid, identity.Name, identity.Path);
        }
        catch (Exception)
        {
            return (0, string.Empty, string.Empty);
        }
    }

    private static int FindTcp(
        string localAddress, int localPort, string remoteAddress, int remotePort)
    {
        RefreshTcp();

        var local = ParseAddress(localAddress);
        var remote = ParseAddress(remoteAddress);

        // 先做完整五元组匹配，失败再退化为本机端口匹配。
        foreach (var row in _tcpRows)
        {
            if (row.LocalPort != localPort || row.Pid <= 0)
            {
                continue;
            }

            if (remotePort > 0 && row.RemotePort != remotePort)
            {
                continue;
            }

            if (local is not null && !AddressEquals(row.LocalAddress, local))
            {
                continue;
            }

            if (remote is not null && !AddressEquals(row.RemoteAddress, remote))
            {
                continue;
            }

            return row.Pid;
        }

        return 0;
    }

    private static int FindUdp(string localAddress, int localPort)
    {
        RefreshUdp();

        var local = ParseAddress(localAddress);

        foreach (var row in _udpRows)
        {
            if (row.LocalPort == localPort
                && row.Pid > 0
                && (local is null || AddressEquals(row.LocalAddress, local)))
            {
                return row.Pid;
            }
        }

        return 0;
    }

    private static IPAddress? ParseAddress(string text)
        => IPAddress.TryParse(text, out var address) ? address : null;

    private static bool AddressEquals(IPAddress left, IPAddress right)
        => left.AddressFamily == right.AddressFamily
            && left.Equals(right);

    private static void RefreshTcp()
    {
        lock (Gate)
        {
            if (DateTime.UtcNow - _tcpLoadedUtc < CacheLifetime)
            {
                return;
            }

            _tcpRows = ReadTcpRows();
            _tcpLoadedUtc = DateTime.UtcNow;
        }
    }

    private static void RefreshUdp()
    {
        lock (Gate)
        {
            if (DateTime.UtcNow - _udpLoadedUtc < CacheLifetime)
            {
                return;
            }

            _udpRows = ReadUdpRows();
            _udpLoadedUtc = DateTime.UtcNow;
        }
    }

    private static List<TcpRow> ReadTcpRows()
    {
        var rows = new List<TcpRow>();

        foreach (var family in new[] { AfInet, AfInet6 })
        {
            var buffer = ReadTable(
                (ptr, ref size) => GetExtendedTcpTable(
                    ptr, ref size, false, family, TcpTableOwnerPidAll, 0));

            if (buffer == IntPtr.Zero)
            {
                continue;
            }

            try
            {
                var count = Marshal.ReadInt32(buffer);

                if (family == AfInet)
                {
                    var size = Marshal.SizeOf<MibTcpRowOwnerPid>();
                    var offset = 4;

                    for (var i = 0; i < count; i++)
                    {
                        var row = Marshal.PtrToStructure<MibTcpRowOwnerPid>(
                            IntPtr.Add(buffer, offset + i * size));

                        rows.Add(new TcpRow(
                            new IPAddress(BitConverter.GetBytes(row.LocalAddress)),
                            NetworkPort(row.LocalPort),
                            new IPAddress(BitConverter.GetBytes(row.RemoteAddress)),
                            NetworkPort(row.RemotePort),
                            (int)row.OwningPid));
                    }
                }
                else
                {
                    var size = Marshal.SizeOf<MibTcp6RowOwnerPid>();
                    var offset = 4;

                    for (var i = 0; i < count; i++)
                    {
                        var row = Marshal.PtrToStructure<MibTcp6RowOwnerPid>(
                            IntPtr.Add(buffer, offset + i * size));

                        rows.Add(new TcpRow(
                            new IPAddress(row.LocalAddress),
                            NetworkPort(row.LocalPort),
                            new IPAddress(row.RemoteAddress),
                            NetworkPort(row.RemotePort),
                            (int)row.OwningPid));
                    }
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        return rows;
    }

    private static List<UdpRow> ReadUdpRows()
    {
        var rows = new List<UdpRow>();

        foreach (var family in new[] { AfInet, AfInet6 })
        {
            var buffer = ReadTable(
                (ptr, ref size) => GetExtendedUdpTable(
                    ptr, ref size, false, family, UdpTableOwnerPid, 0));

            if (buffer == IntPtr.Zero)
            {
                continue;
            }

            try
            {
                var count = Marshal.ReadInt32(buffer);

                if (family == AfInet)
                {
                    var size = Marshal.SizeOf<MibUdpRowOwnerPid>();
                    var offset = 4;

                    for (var i = 0; i < count; i++)
                    {
                        var row = Marshal.PtrToStructure<MibUdpRowOwnerPid>(
                            IntPtr.Add(buffer, offset + i * size));

                        rows.Add(new UdpRow(
                            new IPAddress(BitConverter.GetBytes(row.LocalAddress)),
                            NetworkPort(row.LocalPort),
                            (int)row.OwningPid));
                    }
                }
                else
                {
                    var size = Marshal.SizeOf<MibUdp6RowOwnerPid>();
                    var offset = 4;

                    for (var i = 0; i < count; i++)
                    {
                        var row = Marshal.PtrToStructure<MibUdp6RowOwnerPid>(
                            IntPtr.Add(buffer, offset + i * size));

                        rows.Add(new UdpRow(
                            new IPAddress(row.LocalAddress),
                            NetworkPort(row.LocalPort),
                            (int)row.OwningPid));
                    }
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        return rows;
    }

    private delegate int TableReader(IntPtr buffer, ref int size);

    private static IntPtr ReadTable(TableReader reader)
    {
        var size = 0;
        var rc = reader(IntPtr.Zero, ref size);

        if (rc != ErrorInsufficientBuffer || size <= 0)
        {
            return IntPtr.Zero;
        }

        var buffer = Marshal.AllocHGlobal(size);
        rc = reader(buffer, ref size);

        if (rc != 0)
        {
            Marshal.FreeHGlobal(buffer);
            return IntPtr.Zero;
        }

        return buffer;
    }

    private static int NetworkPort(uint value)
        => (ushort)IPAddress.NetworkToHostOrder((short)(value & 0xFFFF));

    private readonly record struct TcpRow(
        IPAddress LocalAddress,
        int LocalPort,
        IPAddress RemoteAddress,
        int RemotePort,
        int Pid);

    private readonly record struct UdpRow(IPAddress LocalAddress, int LocalPort, int Pid);

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcpRowOwnerPid
    {
        public uint State;
        public uint LocalAddress;
        public uint LocalPort;
        public uint RemoteAddress;
        public uint RemotePort;
        public uint OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcp6RowOwnerPid
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] LocalAddress;

        public uint LocalScopeId;
        public uint LocalPort;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] RemoteAddress;

        public uint RemoteScopeId;
        public uint RemotePort;
        public uint State;
        public uint OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibUdpRowOwnerPid
    {
        public uint LocalAddress;
        public uint LocalPort;
        public uint OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibUdp6RowOwnerPid
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] LocalAddress;

        public uint LocalScopeId;
        public uint LocalPort;
        public uint OwningPid;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern int GetExtendedTcpTable(
        IntPtr pTcpTable,
        ref int pdwSize,
        bool bOrder,
        int ulAf,
        int tableClass,
        uint reserved);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern int GetExtendedUdpTable(
        IntPtr pUdpTable,
        ref int pdwSize,
        bool bOrder,
        int ulAf,
        int tableClass,
        uint reserved);
}
