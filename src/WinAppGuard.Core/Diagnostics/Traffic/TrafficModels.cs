using System.Buffers.Binary;

namespace WinAppGuard.Core.Diagnostics.Traffic;

/// <summary>4.1：精确流量只区分 TCP 与 UDP（ICMP/ARP 不计）。</summary>
public enum TrafficProtocol : byte
{
    Tcp = 6,
    Udp = 17,
}

/// <summary>4.1：相对本机的方向。</summary>
public enum TrafficDirection : byte
{
    Inbound = 0,
    Outbound = 1,
}

/// <summary>
/// 4.1：一个「本机端点」的紧凑表示（协议 + 地址 + 端口）。
///
/// 用定长结构而不是字符串，避免每包 ToString() 分配：
///   - IPv4 放到 <see cref="AddressHigh"/> 的低 32 位；
///   - IPv6 拆成高/低两个 64 位。
/// 地址都按 **小端读取的原始字节** 归一化，和 iphlpapi 表里的字段一一对应。
/// </summary>
public readonly record struct TrafficEndpoint(
    byte Family,
    ulong AddressHigh,
    ulong AddressLow,
    ushort Port,
    TrafficProtocol Protocol)
{
    public static TrafficEndpoint FromIPv4(
        ReadOnlySpan<byte> address, ushort port, TrafficProtocol protocol)
        => new(4, BinaryPrimitives.ReadUInt32LittleEndian(address), 0, port, protocol);

    public static TrafficEndpoint FromIPv6(
        ReadOnlySpan<byte> address, ushort port, TrafficProtocol protocol)
        => new(
            6,
            BinaryPrimitives.ReadUInt64LittleEndian(address),
            BinaryPrimitives.ReadUInt64LittleEndian(address[8..]),
            port,
            protocol);

    /// <summary>通配地址（0.0.0.0 / ::）——监听套接字在端点表里就是这种形式。</summary>
    public TrafficEndpoint AsWildcard() => this with { AddressHigh = 0, AddressLow = 0 };

    public bool IsWildcard => AddressHigh == 0 && AddressLow == 0;
}

/// <summary>4.1：一个包的统计事实（不包含载荷，只有长度和端点）。</summary>
public readonly record struct TrafficPacket(
    TrafficEndpoint Local,
    TrafficDirection Direction,
    TrafficProtocol Protocol,
    int Bytes);

/// <summary>4.1：端点 → PID 的查询接口（生产实现读 iphlpapi，测试用假实现）。</summary>
public interface IEndpointOwnerLookup
{
    /// <summary>返回 0 表示查不到。</summary>
    int Lookup(in TrafficEndpoint endpoint);
}

/// <summary>4.1：单个程序的流量快照。</summary>
public sealed class TrafficProgramSnapshot
{
    public string Key { get; init; } = string.Empty;

    public string? Path { get; init; }

    public string Name { get; init; } = string.Empty;

    public bool IsPathKnown { get; init; }

    public int Pid { get; init; }

    public long TcpBytesIn { get; init; }

    public long TcpBytesOut { get; init; }

    public long UdpBytesIn { get; init; }

    public long UdpBytesOut { get; init; }

    /// <summary>4.1：无法判断协议的分片字节（只会计入总数）。</summary>
    public long OtherBytesIn { get; init; }

    public long OtherBytesOut { get; init; }

    public long PacketsIn { get; init; }

    public long PacketsOut { get; init; }

    public long RateIn { get; init; }

    public long RateOut { get; init; }

    public DateTime LastSeenUtc { get; init; }
}

/// <summary>4.1：一次快照（程序列表 + 全局速率序列）。</summary>
public sealed class TrafficSnapshot
{
    public List<TrafficProgramSnapshot> Programs { get; init; } = new();

    /// <summary>最近 5 分钟，每秒一个点，旧的在前。</summary>
    public List<long> BytesIn { get; init; } = new();

    public List<long> BytesOut { get; init; } = new();

    public DateTime SeriesStartUtc { get; init; }

    public int IntervalMs { get; init; } = 1000;
}
