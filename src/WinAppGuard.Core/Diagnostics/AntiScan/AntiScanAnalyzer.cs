using System.Net;
using System.Net.Sockets;

namespace WinAppGuard.Core.Diagnostics.AntiScan;

/// <summary>4.0：一次入站 TCP SYN 观察（只含头部元数据）。</summary>
public readonly record struct InboundSyn(
    DateTime TimeUtc,
    IPAddress SourceAddress,
    ushort SourcePort,
    IPAddress LocalAddress,
    ushort LocalPort);

/// <summary>4.0：反扫描设置。</summary>
public sealed class AntiScanSettings
{
    public bool Enabled { get; set; } = true;

    /// <summary>standard / conservative。</summary>
    public string Sensitivity { get; set; } = "standard";

    /// <summary>是否自动临时封禁高危扫描来源；默认关闭。</summary>
    public bool AutoBlock { get; set; }

    /// <summary>临时封禁分钟数；5–60。</summary>
    public int BlockMinutes { get; set; } = 10;

    /// <summary>永不自动封禁的地址。</summary>
    public List<string> Allowlist { get; set; } = new();
}

/// <summary>4.0：一条扫描发现。</summary>
public sealed class AntiScanFinding
{
    public string Id { get; } = Guid.NewGuid().ToString("N");

    public DateTime TimeUtc { get; init; }

    public string SourceAddress { get; init; } = string.Empty;

    public int DistinctPorts { get; init; }

    public int DistinctHosts { get; init; }

    public int SynCount { get; init; }

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
/// 4.0：入站端口扫描分析器（纯内存、可离线测试）。
///
/// 只看 TCP SYN，按来源 IP 维护 60 秒滑动窗口：
///   - 垂直扫描：同一来源访问本机多个不同端口；
///   - 水平扫描：同一来源访问本机多个不同地址（多网卡/多地址）。
///
/// 这不是内核级检测：它依赖采集层能看到 SYN。Npcap / Pktmon 能看到打关闭端口的 SYN，
/// ETW accept 只能看到已建立连接。
/// </summary>
public sealed class AntiScanAnalyzer
{
    private static readonly TimeSpan Window = TimeSpan.FromSeconds(60);
    private static readonly TimeSpan FastWindow = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan AlertCooldown = TimeSpan.FromMinutes(10);

    private const int MaxSources = 8192;
    private const int MaxHitsPerSource = 4096;

    private readonly object _gate = new();
    private readonly Dictionary<string, SourceState> _sources = new(StringComparer.Ordinal);
    private readonly Dictionary<string, (DateTime TimeUtc, string Severity)> _lastAlert =
        new(StringComparer.Ordinal);

    private long _eventsSeen;

    public long EventsSeen
    {
        get { lock (_gate) { return _eventsSeen; } }
    }

    public int SourceCount
    {
        get { lock (_gate) { return _sources.Count; } }
    }

    public AntiScanFinding? Observe(InboundSyn syn, DateTime now, AntiScanSettings settings)
    {
        if (!settings.Enabled || syn.SourcePort == 0 || syn.LocalPort == 0)
        {
            return null;
        }

        if (!IsUsableSource(syn.SourceAddress))
        {
            return null;
        }

        var key = syn.SourceAddress.ToString();
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

                state = new SourceState { Address = syn.SourceAddress };
                _sources[key] = state;
            }

            state.LastSeenUtc = syn.TimeUtc;
            state.Hits.Add(new Hit(syn.TimeUtc, syn.LocalAddress, syn.LocalPort));

            if (state.Hits.Count > MaxHitsPerSource)
            {
                state.Hits.RemoveRange(0, state.Hits.Count - MaxHitsPerSource);
            }

            if (state.Hits.Count % 64 == 0
                || now - state.LastPruneUtc >= TimeSpan.FromSeconds(1))
            {
                PruneStateLocked(state, now);
            }

            var ports = state.Hits
                .Where(hit => now - hit.TimeUtc <= Window)
                .Select(hit => hit.LocalPort)
                .Distinct()
                .Count();

            var hosts = state.Hits
                .Where(hit => now - hit.TimeUtc <= Window)
                .Select(hit => hit.LocalAddress)
                .Distinct()
                .Count();

            var synCount = state.Hits.Count(hit => now - hit.TimeUtc <= Window);

            var fastPorts = state.Hits
                .Where(hit => now - hit.TimeUtc <= FastWindow)
                .Select(hit => hit.LocalPort)
                .Distinct()
                .Count();

            var conservative = string.Equals(
                settings.Sensitivity, "conservative", StringComparison.OrdinalIgnoreCase);

            var mediumPorts = conservative ? 40 : 20;
            var highPorts = conservative ? 100 : 50;
            var highFastPorts = conservative ? 40 : 20;
            var mediumHosts = conservative ? 20 : 10;
            var highHosts = conservative ? 60 : 30;

            string? severity = null;

            if (fastPorts >= highFastPorts || ports >= highPorts || hosts >= highHosts)
            {
                severity = AntiScanSeverity.High;
            }
            else if (ports >= mediumPorts || hosts >= mediumHosts)
            {
                severity = AntiScanSeverity.Medium;
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
                DistinctPorts = ports,
                DistinctHosts = hosts,
                SynCount = synCount,
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

    private readonly record struct Hit(DateTime TimeUtc, IPAddress LocalAddress, ushort LocalPort);
}
