using System.Buffers.Binary;
using System.Runtime.InteropServices;
using WinAppGuard.Interop;

namespace WinAppGuard.Core.Diagnostics.Traffic;

/// <summary>
/// 4.1：从 iphlpapi 的 TCP/UDP 端点表里读出「本机端点 → PID」。
///
/// 为什么要快照而不是每包查表：<c>GetExtendedTcpTable</c> 每次返回整张表（几千行），
/// 每包调用会把 CPU 打满。这里每秒构建一次不可变字典，采集线程只做只读查询。
///
/// 监听套接字在表里是 <c>0.0.0.0:port</c> / <c>[::]:port</c>，而抓到的入站包目的地址是
/// 具体 IP，所以查询要支持「精确匹配失败 → 通配匹配」。
///
/// 只读取本机端点表，不发起任何网络请求。
/// </summary>
internal sealed class EndpointOwnerTable : IEndpointOwnerLookup
{
    private readonly Dictionary<TrafficEndpoint, int> _owners;

    private EndpointOwnerTable(Dictionary<TrafficEndpoint, int> owners)
    {
        _owners = owners;
    }

    public int Lookup(in TrafficEndpoint endpoint)
    {
        if (_owners.TryGetValue(endpoint, out var pid))
        {
            return pid;
        }

        return _owners.TryGetValue(endpoint.AsWildcard(), out pid) ? pid : 0;
    }

    public int Count => _owners.Count;

    /// <summary>构建一次快照。任何一张表读失败都不影响其它表。</summary>
    public static EndpointOwnerTable Capture()
    {
        var owners = new Dictionary<TrafficEndpoint, int>(capacity: 1024);

        ReadTcpV4(owners);
        ReadTcpV6(owners);
        ReadUdpV4(owners);
        ReadUdpV6(owners);

        return new EndpointOwnerTable(owners);
    }

    private static void ReadTcpV4(Dictionary<TrafficEndpoint, int> owners)
    {
        var buffer = ReadTable(isUdp: false, NativeMethods.AF_INET, out var rowCount);
        if (buffer == IntPtr.Zero)
        {
            return;
        }

        try
        {
            var size = Marshal.SizeOf<MibTcpRowOwnerPid>();
            var pointer = IntPtr.Add(buffer, sizeof(int));

            for (var i = 0; i < rowCount; i++)
            {
                var row = Marshal.PtrToStructure<MibTcpRowOwnerPid>(pointer);
                pointer = IntPtr.Add(pointer, size);

                var pid = (int)row.OwningPid;
                if (pid <= 0)
                {
                    continue;
                }

                owners[new TrafficEndpoint(
                    4,
                    row.LocalAddr,
                    0,
                    NetworkToHostPort(row.LocalPort),
                    TrafficProtocol.Tcp)] = pid;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static void ReadTcpV6(Dictionary<TrafficEndpoint, int> owners)
    {
        var buffer = ReadTable(isUdp: false, NativeMethods.AF_INET6, out var rowCount);
        if (buffer == IntPtr.Zero)
        {
            return;
        }

        try
        {
            var size = Marshal.SizeOf<MibTcp6RowOwnerPid>();
            var pointer = IntPtr.Add(buffer, sizeof(int));

            for (var i = 0; i < rowCount; i++)
            {
                var row = Marshal.PtrToStructure<MibTcp6RowOwnerPid>(pointer);
                pointer = IntPtr.Add(pointer, size);

                var pid = (int)row.OwningPid;
                if (pid <= 0 || row.LocalAddr is null || row.LocalAddr.Length < 16)
                {
                    continue;
                }

                owners[new TrafficEndpoint(
                    6,
                    BinaryPrimitives.ReadUInt64LittleEndian(row.LocalAddr),
                    BinaryPrimitives.ReadUInt64LittleEndian(row.LocalAddr.AsSpan(8)),
                    NetworkToHostPort(row.LocalPort),
                    TrafficProtocol.Tcp)] = pid;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static void ReadUdpV4(Dictionary<TrafficEndpoint, int> owners)
    {
        var buffer = ReadTable(isUdp: true, NativeMethods.AF_INET, out var rowCount);
        if (buffer == IntPtr.Zero)
        {
            return;
        }

        try
        {
            var size = Marshal.SizeOf<MibUdpRowOwnerPid>();
            var pointer = IntPtr.Add(buffer, sizeof(int));

            for (var i = 0; i < rowCount; i++)
            {
                var row = Marshal.PtrToStructure<MibUdpRowOwnerPid>(pointer);
                pointer = IntPtr.Add(pointer, size);

                var pid = (int)row.OwningPid;
                if (pid <= 0)
                {
                    continue;
                }

                owners[new TrafficEndpoint(
                    4,
                    row.LocalAddr,
                    0,
                    NetworkToHostPort(row.LocalPort),
                    TrafficProtocol.Udp)] = pid;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static void ReadUdpV6(Dictionary<TrafficEndpoint, int> owners)
    {
        var buffer = ReadTable(isUdp: true, NativeMethods.AF_INET6, out var rowCount);
        if (buffer == IntPtr.Zero)
        {
            return;
        }

        try
        {
            var size = Marshal.SizeOf<MibUdp6RowOwnerPid>();
            var pointer = IntPtr.Add(buffer, sizeof(int));

            for (var i = 0; i < rowCount; i++)
            {
                var row = Marshal.PtrToStructure<MibUdp6RowOwnerPid>(pointer);
                pointer = IntPtr.Add(pointer, size);

                var pid = (int)row.OwningPid;
                if (pid <= 0 || row.LocalAddr is null || row.LocalAddr.Length < 16)
                {
                    continue;
                }

                owners[new TrafficEndpoint(
                    6,
                    BinaryPrimitives.ReadUInt64LittleEndian(row.LocalAddr),
                    BinaryPrimitives.ReadUInt64LittleEndian(row.LocalAddr.AsSpan(8)),
                    NetworkToHostPort(row.LocalPort),
                    TrafficProtocol.Udp)] = pid;
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    /// <summary>读一张表：先问大小，再分配，再读。失败返回 IntPtr.Zero。</summary>
    private static IntPtr ReadTable(bool isUdp, int family, out int rowCount)
    {
        rowCount = 0;
        var size = 0;
        var tableClass = isUdp ? NativeMethods.UDP_TABLE_OWNER_PID : NativeMethods.TCP_TABLE_OWNER_PID_ALL;

        var first = isUdp
            ? NativeMethods.GetExtendedUdpTable(IntPtr.Zero, ref size, false, family, tableClass, 0)
            : NativeMethods.GetExtendedTcpTable(IntPtr.Zero, ref size, false, family, tableClass, 0);

        if (first != NativeMethods.ERROR_INSUFFICIENT_BUFFER || size <= 0)
        {
            return IntPtr.Zero;
        }

        var buffer = Marshal.AllocHGlobal(size);

        try
        {
            var second = isUdp
                ? NativeMethods.GetExtendedUdpTable(buffer, ref size, false, family, tableClass, 0)
                : NativeMethods.GetExtendedTcpTable(buffer, ref size, false, family, tableClass, 0);

            if (second != NativeMethods.NO_ERROR)
            {
                Marshal.FreeHGlobal(buffer);
                return IntPtr.Zero;
            }

            rowCount = Marshal.ReadInt32(buffer);

            if (rowCount <= 0)
            {
                Marshal.FreeHGlobal(buffer);
                return IntPtr.Zero;
            }

            return buffer;
        }
        catch (Exception)
        {
            Marshal.FreeHGlobal(buffer);
            return IntPtr.Zero;
        }
    }

    private static ushort NetworkToHostPort(uint networkOrderPort)
    {
        var value = (ushort)(networkOrderPort & 0xFFFF);
        return (ushort)((value >> 8) | ((value & 0xFF) << 8));
    }
}
