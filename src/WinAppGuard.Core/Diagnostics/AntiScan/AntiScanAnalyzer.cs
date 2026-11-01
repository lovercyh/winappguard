using System.Net;
using System.Net.Sockets;

namespace WinAppGuard.Core.Diagnostics.AntiScan;

/// <summary>4.0 / 4.5：一次入站探测（只含头部元数据）。</summary>
/// <param name="Protocol">6=TCP、17=UDP、1=ICMP、58=ICMPv6。</param>
public readonly record struct InboundProbe(
    DateTime TimeUtc,
    byte Protocol,
    IPAddress SourceAddress,
    ushort SourcePort,
    IPAddress LocalAddress,
    ushort LocalPort);

/// <summary>4.5：协议号常量（与 IP 头一致）。</summary>
public static class ProbeProtocol
{
    public const byte Icmp = 1;
    public const byte Tcp = 6;
    public const byte Udp = 17;
    public const byte Icmpv6 = 58;

    public static bool IsKnown(byte protocol)
        => protocol is Tcp or Udp or Icmp or Icmpv6;

    public static string ToText(byte protocol) => protocol switch
    {
        Udp => "udp",
        Icmp or Icmpv6 => "icmp",
        _ => "tcp",
    };
}

/// <summary>4.0 / 4.5：反扫描设置。</summary>
public sealed class AntiScanSettings
{
    /// <summary>
    /// 配置版本。4.5 之前的文件没有这个字段（反序列化为 0），
    /// 加载时据此把新协议开关补成默认开启；用户改过之后不会再被覆盖。
    /// </summary>
    public int Version { get; set; } = AntiScanSettingsVersion.Current;

    public bool Enabled { get; set; } = true;

    /// <summary>standard / conservative。</summary>
    public string Sensitivity { get; set; } = "standard";

    /// <summary>4.5：检测 UDP 扫描（目标端口无人监听）。默认开启。</summary>
    public bool DetectUdp { get; set; } = true;

    /// <summary>4.5：检测 ICMP / ICMPv6 Echo 扫描。默认开启。</summary>
    public bool DetectIcmp { get; set; } = true;

    /// <summary>是否自动临时封禁高危扫描来源；默认关闭。</summary>
    public bool AutoBlock { get; set; }

    /// <summary>临时封禁分钟数；5–60。</summary>
    public int BlockMinutes { get; set; } = 10;

    /// <summary>永不自动封禁的地址。</summary>
    public List<string> Allowlist { get; set; } = new();
}

/// <summary>4.5：设置版本。</summary>
public static class AntiScanSettingsVersion
{
    public const int Current = 1;
}

/// <summary>4.0 / 4.5：一条扫描发现。</summary>
public sealed class AntiScanFinding
{
    public string Id { get; } = Guid.NewGuid().ToString("N");

    public DateTime TimeUtc { get; init; }

    public string SourceAddress { get; init; } = string.Empty;

    /// <summary>触发本次告警的协议（TCP/UDP/ICMP）。</summary>
    public byte Protocol { get; init; } = ProbeProtocol.Tcp;

    public string ProtocolText => ProbeProtocol.ToText(Protocol);

    public int DistinctPorts { get; init; }

    public int DistinctHosts { get; init; }

    /// <summary>窗口内的探测包数（TCP SYN / UDP 包 / ICMP Echo）。</summary>
    public int ProbeCount { get; init; }

    public int WindowSeconds { get; init; }

    /// <summary>medium / high。</summary>
    public string Severity { get; init; } = AntiScanSeverity.Medium;
}

/// <summary>4.0：反扫描级别。</summary>
public static class AntiScanSeverity
{
    public const string Medium = "medium";
    public const string High = "high";
}

/// <summary>
/// 4.0 / 4.5：入站扫描分析器（纯内存、可离线测试）。
///
/// 按来源 IP 维护 60 秒滑动窗口：
///   - TCP SYN：垂直（多端口）/ 水平（多本地地址）扫描；
///   - UDP：目标端口无人监听的不同端口数（监听端口由宿主过滤）；
///   - ICMP / ICMPv6 Echo：单位时间请求数（ping 扫描）。
///
/// 这不是内核级检测：它依赖采集层能看到包。Npcap 能看到打到关闭端口的探测。
/// </summary>
public sealed class AntiScanAnalyzer
{
    private static readonly TimeSpan Window = TimeSpan.FromSeconds(60);
    private static readonly TimeSpan FastWindow = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan AlertCooldown = TimeSpan.FromMinutes(10);

    private const int MaxSources = 8192;
    private const int MaxHitsPerSource = 4096;

    private readonly object _gate = new();
    private readonly Func<ushort, bool>? _isLocalUdpPortListening;
    private readonly Dictionary<string, SourceState> _sources = new(StringComparer.Ordinal);
    private readonly Dictionary<string, (DateTime TimeUtc, string Severity)> _lastAlert =
        new(StringComparer.Ordinal);

    private long _eventsSeen;

    /// <param name="isLocalUdpPortListening">
    /// 4.5：判断某个本地 UDP 端口是否有人监听。响应用户自己请求的 UDP 会打到监听端口，
    /// 只有“没人监听”的目标端口才可能是扫描。null = 不做过滤（离线测试用）。
    /// </param>
    public AntiScanAnalyzer(Func<ushort, bool>? isLocalUdpPortListening = null)
    {
        _isLocalUdpPortListening = isLocalUdpPortListening;
    }

    public long EventsSeen
    {
        get { lock (_gate) { return _eventsSeen; } }
    }

    public int SourceCount
    {
        get { lock (_gate) { return _sources.Count; } }
    }

    public AntiScanFinding? Observe(InboundProbe probe, DateTime now, AntiScanSettings settings)
    {
        if (!settings.Enabled || !ProbeProtocol.IsKnown(probe.Protocol))
        {
            return null;
        }

        if (probe.Protocol == ProbeProtocol.Tcp
            && (probe.SourcePort == 0 || probe.LocalPort == 0))
        {
            return null;
        }

        if (probe.Protocol == ProbeProtocol.Udp)
        {
            if (!settings.DetectUdp || probe.SourcePort == 0 || probe.LocalPort == 0)
            {
                return null;
            }

            // 有人监听的端口收到的是“响应”或正常业务，不是扫描。
            if (_isLocalUdpPortListening?.Invoke(probe.LocalPort) == true)
            {
                return null;
            }
        }

        if (probe.Protocol is ProbeProtocol.Icmp or ProbeProtocol.Icmpv6
            && !settings.DetectIcmp)
        {
            return null;
        }

        if (!IsUsableSource(probe.SourceAddress))
        {
            return null;
        }

        var key = probe.SourceAddress.ToString();
        AntiScanFinding? finding = null;

        lock (_gate)
        {
            _eventsSeen++;

            if (!_sources.TryGetValue(key, out var state))
            {
                if (_sources.Count >= MaxSources)
                {
                    RemoveOldestSourceLocked();
                }

                state = new SourceState { Address = probe.SourceAddress };
                _sources[key] = state;
            }

            state.LastSeenUtc = probe.TimeUtc;
            state.Hits.Add(new Hit(probe.TimeUtc, probe.LocalAddress, probe.LocalPort, probe.Protocol));

            if (state.Hits.Count > MaxHitsPerSource)
            {
                state.Hits.RemoveRange(0, state.Hits.Count - MaxHitsPerSource);
            }

            if (state.Hits.Count % 64 == 0
                || now - state.LastPruneUtc >= TimeSpan.FromSeconds(1))
            {
                PruneStateLocked(state, now);
            }

            var conservative = string.Equals(
                settings.Sensitivity, "conservative", StringComparison.OrdinalIgnoreCase);

            var tcpPorts = new HashSet<ushort>();
            var tcpPortsFast = new HashSet<ushort>();
            var tcpHosts = new HashSet<string>(StringComparer.Ordinal);
            var tcpCount = 0;
            var udpPorts = new HashSet<ushort>();
            var udpPortsFast = new HashSet<ushort>();
            var udpCount = 0;
            var icmpCount = 0;

            // 单次遍历同时算三种协议，避免每个包都做多次 LINQ 扫描。
            foreach (var hit in state.Hits)
            {
                var age = now - hit.TimeUtc;

                if (age > Window)
                {
                    continue;
                }

                switch (hit.Protocol)
                {
                    case ProbeProtocol.Tcp:
                        tcpCount++;
                        tcpPorts.Add(hit.LocalPort);
                        tcpHosts.Add(hit.LocalAddress.ToString());

                        if (age <= FastWindow)
                        {
                            tcpPortsFast.Add(hit.LocalPort);
                        }

                        break;

                    case ProbeProtocol.Udp:
                        udpCount++;
                        udpPorts.Add(hit.LocalPort);

                        if (age <= FastWindow)
                        {
                            udpPortsFast.Add(hit.LocalPort);
                        }

                        break;

                    default:
                        icmpCount++;
                        break;
                }
            }

            var mediumPorts = conservative ? 40 : 20;
            var highPorts = conservative ? 100 : 50;
            var highFastPorts = conservative ? 40 : 20;
            var mediumHosts = conservative ? 20 : 10;
            var highHosts = conservative ? 60 : 30;

            var mediumUdpPorts = conservative ? 30 : 15;
            var highUdpPorts = conservative ? 60 : 30;

            // 快速阈值必须低于“中危阈值”，否则 1 秒一个端口时会先被快速规则判高危，
            // 45 个端口的慢速扫描永远走不到中危分支（离线测试会直接暴露这个问题）。
            var highUdpFastPorts = conservative ? 24 : 12;

            var mediumIcmp = conservative ? 40 : 20;
            var highIcmp = conservative ? 80 : 40;

            var severity = (string?)null;
            byte protocol = ProbeProtocol.Tcp;

            if (tcpPortsFast.Count >= highFastPorts
                || tcpPorts.Count >= highPorts
                || tcpHosts.Count >= highHosts)
            {
                severity = AntiScanSeverity.High;
                protocol = ProbeProtocol.Tcp;
            }
            else if (tcpPorts.Count >= mediumPorts || tcpHosts.Count >= mediumHosts)
            {
                severity = AntiScanSeverity.Medium;
                protocol = ProbeProtocol.Tcp;
            }

            if (udpPortsFast.Count >= highUdpFastPorts || udpPorts.Count >= highUdpPorts)
            {
                severity = AntiScanSeverity.High;
                protocol = ProbeProtocol.Udp;
            }
            else if (severity is null && udpPorts.Count >= mediumUdpPorts)
            {
                severity = AntiScanSeverity.Medium;
                protocol = ProbeProtocol.Udp;
            }

            if (icmpCount >= highIcmp)
            {
                severity = AntiScanSeverity.High;
                protocol = ProbeProtocol.Icmp;
            }
            else if (severity is null && icmpCount >= mediumIcmp)
            {
                severity = AntiScanSeverity.Medium;
                protocol = ProbeProtocol.Icmp;
            }

            if (severity is null)
            {
                return null;
            }

            if (_lastAlert.TryGetValue(key, out var last)
                && now - last.TimeUtc < AlertCooldown
                && SeverityRank(severity) <= SeverityRank(last.Severity))
            {
                return null;
            }

            _lastAlert[key] = (now, severity);

            finding = new AntiScanFinding
            {
                TimeUtc = now,
                SourceAddress = key,
                Protocol = protocol,
                DistinctPorts = protocol == ProbeProtocol.Udp
                    ? udpPorts.Count
                    : tcpPorts.Count,
                DistinctHosts = tcpHosts.Count,
                ProbeCount = protocol switch
                {
                    ProbeProtocol.Udp => udpCount,
                    ProbeProtocol.Icmp => icmpCount,
                    _ => tcpCount,
                },
                WindowSeconds = (int)Window.TotalSeconds,
                Severity = severity,
            };
        }

        return finding;
    }

    /// <summary>解除封禁后清掉冷却，让同一来源可以重新触发。</summary>
    public void ResetSource(string address)
    {
        lock (_gate)
        {
            _lastAlert.Remove(address);
        }
    }

    public void Clear()
    {
        lock (_gate)
        {
            _sources.Clear();
            _lastAlert.Clear();
            _eventsSeen = 0;
        }
    }

    private void PruneStateLocked(SourceState state, DateTime now)
    {
        state.Hits.RemoveAll(hit => now - hit.TimeUtc > Window);
        state.LastPruneUtc = now;
    }

    private void RemoveOldestSourceLocked()
    {
        var oldestKey = default(string);
        var oldest = DateTime.MaxValue;

        foreach (var pair in _sources)
        {
            if (pair.Value.LastSeenUtc < oldest)
            {
                oldest = pair.Value.LastSeenUtc;
                oldestKey = pair.Key;
            }
        }

        if (oldestKey is not null)
        {
            _sources.Remove(oldestKey);
        }
    }

    private static int SeverityRank(string severity)
        => severity == AntiScanSeverity.High ? 2 : 1;

    private static bool IsUsableSource(IPAddress address)
    {
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            var bytes = address.GetAddressBytes();

            if (IPAddress.IsLoopback(address))
            {
                return false;
            }

            // 组播 / 广播 / 0.0.0.0
            if (bytes[0] is >= 224 and <= 239 || address.Equals(IPAddress.Any))
            {
                return false;
            }

            return true;
        }

        if (address.AddressFamily != AddressFamily.InterNetworkV6)
        {
            return false;
        }

        return !IPAddress.IsLoopback(address)
               && !address.Equals(IPAddress.IPv6Any)
               && !address.IsIPv6Multicast;
    }

    private sealed class SourceState
    {
        public IPAddress Address = IPAddress.None;
        public DateTime LastSeenUtc;
        public DateTime LastPruneUtc;
        public List<Hit> Hits = new();
    }

    private readonly record struct Hit(
        DateTime TimeUtc,
        IPAddress LocalAddress,
        ushort LocalPort,
        byte Protocol);
}
