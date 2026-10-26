using System.Net;
using System.Net.Sockets;

namespace WinAppGuard.Core.Diagnostics.Ids;

/// <summary>3.7：告警级别（存储/协议里用稳定字符串）。</summary>
public static class IdsSeverity
{
    public const string Low = "low";
    public const string Medium = "medium";
    public const string High = "high";
}

/// <summary>3.7：IDS 设置（机器级，服务持久化）。</summary>
public sealed class IdsSettings
{
    public bool Enabled { get; set; } = true;

    /// <summary>standard / conservative。</summary>
    public string Sensitivity { get; set; } = "standard";

    /// <summary>告警本地保留天数。</summary>
    public int RetentionDays { get; set; } = 30;

    public bool BeaconingRule { get; set; } = true;

    public bool ScanRule { get; set; } = true;

    public bool LateralRule { get; set; } = true;

    public bool DnsRule { get; set; } = true;
}

/// <summary>3.7：抑制一条规则/程序/目标的告警。</summary>
public sealed class IdsSuppression
{
    /// <summary>稳定 id（界面取消抑制时用）。</summary>
    public string Id { get; set; } = Guid.NewGuid().ToString("N");

    /// <summary>规则 id，或 * 表示全部规则。</summary>
    public string RuleId { get; set; } = "*";

    /// <summary>程序完整路径；空表示不按程序限制。</summary>
    public string? ProcessPath { get; set; }

    /// <summary>程序名（路径拿不到时兜底）。</summary>
    public string? ProcessName { get; set; }

    /// <summary>目标（远端 IP:端口 / 父域）；空表示不按目标限制。</summary>
    public string? Target { get; set; }

    /// <summary>到期时间（UTC）；null = 永久。</summary>
    public DateTime? UntilUtc { get; set; }
}

/// <summary>3.7：一条 IDS 告警。</summary>
public sealed class IdsAlert
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");

    public DateTime TimeUtc { get; set; }

    public string Severity { get; set; } = IdsSeverity.Medium;

    public string RuleId { get; set; } = string.Empty;

    public string RuleName { get; set; } = string.Empty;

    public int Pid { get; set; }

    public string ProcessName { get; set; } = string.Empty;

    public string? ProcessPath { get; set; }

    public string Target { get; set; } = string.Empty;

    /// <summary>英文的数值型证据，界面负责显示；不写中文，避免英文界面混入中文。</summary>
    public string Evidence { get; set; } = string.Empty;

    public string Status { get; set; } = "new";

    public string DedupKey { get; set; } = string.Empty;
}

/// <summary>3.7：网络 ETW 事件里的连接观察（只含元数据）。</summary>
public readonly record struct NetworkFlowObservation(
    DateTime TimeUtc,
    int Pid,
    string Protocol,
    string RemoteAddress,
    ushort RemotePort,
    bool IsOutbound,
    bool IsConnection,
    uint Size);

/// <summary>3.7：DNS 查询观察（进程身份在事件发生时解析，避免 PID 复用误归属）。</summary>
public readonly record struct NetworkDnsObservation(
    DateTime TimeUtc,
    int Pid,
    string QueryName,
    string Status,
    string? ProcessName = null,
    string? ProcessPath = null);

/// <summary>
/// 3.7：IDS 规则分析器（纯内存、无 ETW/无 IO）。
///
/// 输入是连接/PID/字节/DNS 观察，输出是告警；服务负责采集、持久化和界面。
/// 规则阈值来自 3.7 POC：正常使用 10 分钟 0 告警，合成场景全部命中。
/// </summary>
public sealed class IdsAnalyzer
{
    private static readonly TimeSpan FlowRetention = TimeSpan.FromMinutes(30);
    private static readonly TimeSpan ScanWindow = TimeSpan.FromSeconds(60);
    private static readonly TimeSpan LateralWindow = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan DnsWindow = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan BeaconWindow = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan AlertCooldown = TimeSpan.FromMinutes(30);

    /// <summary>flow 表上限；超过后淘汰最久没活动的。</summary>
    private const int MaxFlows = 20_000;

    /// <summary>DNS 观察上限；超过后丢掉最旧的 2000 条。</summary>
    private const int MaxDnsObservations = 20_000;

    private readonly object _gate = new();
    private readonly Dictionary<string, FlowState> _flows = new(StringComparer.Ordinal);
    private readonly List<EndpointHit> _endpoints = new();
    private readonly List<DnsObservation> _dns = new();
    private readonly Dictionary<string, DateTime> _lastAlertUtc = new(StringComparer.Ordinal);
    private long _eventsSeen;
    private long _eventsLost;

    public int FlowCount
    {
        get { lock (_gate) { return _flows.Count; } }
    }

    /// <summary>交给规则引擎的网络事件数（flow 观察）。</summary>
    public long EventsSeen
    {
        get { lock (_gate) { return _eventsSeen; } }
    }

    /// <summary>没进 flow 表的事件数（flow 上限淘汰 + 解析失败由调用方另计）。</summary>
    public long EventsLost
    {
        get { lock (_gate) { return _eventsLost; } }
    }

    public void ObserveFlow(NetworkFlowObservation observation)
    {
        if (observation.Pid <= 0 || observation.RemotePort == 0)
        {
            return;
        }

        var key = $"{observation.Pid}|{observation.Protocol}|{observation.RemoteAddress}|{observation.RemotePort}";
        var now = observation.TimeUtc;

        lock (_gate)
        {
            _eventsSeen++;

            if (!_flows.TryGetValue(key, out var flow))
            {
                if (_flows.Count >= MaxFlows)
                {
                    EvictOldestFlowsLocked();
                }

                flow = new FlowState
                {
                    Pid = observation.Pid,
                    Protocol = observation.Protocol,
                    Remote = observation.RemoteAddress,
                    RemotePort = observation.RemotePort,
                    FirstSeenUtc = now,
                };

                _flows[key] = flow;
            }

            flow.LastSeenUtc = now;

            if (observation.IsConnection)
            {
                // 只把**出站**连接计入规则：监听端接受的入站连接不是这台机器的外联行为，
                // 否则正常服务器（游戏 / Web / 文件共享）会被误判成扫描或 beacon。
                if (observation.IsOutbound)
                {
                    flow.Connections.Add(now);

                    if (flow.Connections.Count > 64)
                    {
                        flow.Connections.RemoveAt(0);
                    }

                    if (string.Equals(observation.Protocol, "TCP", StringComparison.Ordinal)
                        && !IsNoisyEndpoint(observation.RemoteAddress, observation.RemotePort))
                    {
                        _endpoints.Add(new EndpointHit(
                            now, observation.Pid, observation.RemoteAddress, observation.RemotePort));

                        if (_endpoints.Count > 50_000)
                        {
                            _endpoints.RemoveRange(0, 10_000);
                            _eventsLost += 10_000;
                        }
                    }
                }
            }
            else if (observation.IsOutbound)
            {
                flow.BytesOut += observation.Size;
            }
            else
            {
                flow.BytesIn += observation.Size;
            }
        }
    }

    public void ObserveDns(NetworkDnsObservation observation)
    {
        if (observation.Pid <= 0 || string.IsNullOrWhiteSpace(observation.QueryName))
        {
            return;
        }

        lock (_gate)
        {
            _dns.Add(new DnsObservation(
                observation.TimeUtc,
                observation.Pid,
                observation.QueryName.Trim(),
                observation.Status,
                observation.ProcessName ?? string.Empty,
                observation.ProcessPath ?? string.Empty));

            if (_dns.Count > MaxDnsObservations)
            {
                var remove = _dns.Count - MaxDnsObservations;
                _dns.RemoveRange(0, remove);
                _eventsLost += remove;
            }
        }
    }

    /// <summary>清空 flow/DNS/冷却状态（不碰告警存储）。</summary>
    public void Clear()
    {
        lock (_gate)
        {
            _flows.Clear();
            _endpoints.Clear();
            _dns.Clear();
            _lastAlertUtc.Clear();
            _eventsSeen = 0;
            _eventsLost = 0;
        }
    }

    /// <summary>
    /// flow 到上限时一次淘汰最久没活动的一批（10%），而不是每个新 flow 都做一次 O(n) 扫描。
    /// 突发大量短连接时这能把 CPU 从「每个事件扫 2 万条」降到摊销常数级。
    /// </summary>
    private void EvictOldestFlowsLocked()
    {
        var removeCount = Math.Max(1, MaxFlows / 10);

        var oldest = _flows
            .OrderBy(pair => pair.Value.LastSeenUtc)
            .Take(removeCount)
            .Select(pair => pair.Key)
            .ToList();

        foreach (var key in oldest)
        {
            _flows.Remove(key);
        }

        _eventsLost += oldest.Count;
    }

    /// <summary>按当前设置评估一次，返回新告警。</summary>
    public List<IdsAlert> Evaluate(
        DateTime now,
        IdsSettings settings,
        IReadOnlyList<IdsSuppression> suppressions)
    {
        var alerts = new List<IdsAlert>();

        lock (_gate)
        {
            Prune(now);

            var factor = string.Equals(
                settings.Sensitivity, "conservative", StringComparison.OrdinalIgnoreCase)
                ? 2
                : 1;

            if (settings.BeaconingRule)
            {
                EvaluateBeaconing(now, factor, suppressions, alerts);
            }

            if (settings.ScanRule)
            {
                EvaluateScanning(now, factor, suppressions, alerts);
            }

            if (settings.LateralRule)
            {
                EvaluateLateral(now, factor, suppressions, alerts);
            }

            if (settings.DnsRule)
            {
                EvaluateDns(now, factor, suppressions, alerts);
            }
        }

        return alerts;
    }

    private void Prune(DateTime now)
    {
        _endpoints.RemoveAll(hit => now - hit.TimeUtc > LateralWindow);
        _dns.RemoveAll(item => now - item.TimeUtc > DnsWindow);

        foreach (var key in _flows
                     .Where(pair => now - pair.Value.LastSeenUtc > FlowRetention)
                     .Select(pair => pair.Key)
                     .ToList())
        {
            _flows.Remove(key);
        }

        foreach (var key in _lastAlertUtc
                     .Where(pair => now - pair.Value > TimeSpan.FromDays(1))
                     .Select(pair => pair.Key)
                     .ToList())
        {
            _lastAlertUtc.Remove(key);
        }
    }

    private void EvaluateBeaconing(
        DateTime now, int factor, IReadOnlyList<IdsSuppression> suppressions, List<IdsAlert> alerts)
    {
        var minimumConnections = 6 * factor;

        foreach (var flow in _flows.Values)
        {
            if (!string.Equals(flow.Protocol, "TCP", StringComparison.Ordinal)
                || IsNoisyEndpoint(flow.Remote, flow.RemotePort))
            {
                continue;
            }

            var times = flow.Connections
                .Where(time => now - time <= BeaconWindow)
                .ToList();

            if (times.Count < minimumConnections)
            {
                continue;
            }

            // 系统进程（svchost / services / lsass 等）不参与 beaconing，
            // 否则 Windows 自身的定时任务会被当成 C2。可以在设计上后续做成设置项。
            var identity = ProcessResolver.Resolve(flow.Pid);

            if (IsSystemProcess(identity.Name))
            {
                continue;
            }

            var intervals = new List<double>();

            for (var i = 1; i < times.Count; i++)
            {
                intervals.Add((times[i] - times[i - 1]).TotalSeconds);
            }

            if (intervals.Any(value => value < 4.0 || value > 300))
            {
                continue;
            }

            var mean = intervals.Average();
            var variance = intervals.Sum(value => (value - mean) * (value - mean)) / intervals.Count;
            var cv = mean > 0 ? Math.Sqrt(variance) / mean : double.MaxValue;
            var averageBytes = (flow.BytesOut + flow.BytesIn) / Math.Max(1, times.Count);

            if (averageBytes > 256 * 1024)
            {
                continue;
            }

            if (mean is < 4.0 or > 300 || cv > 0.35)
            {
                continue;
            }

            var target = $"{flow.Remote}:{flow.RemotePort}";
            var key = AlertKey("beaconing", flow.Pid, target);

            if (!ShouldAlert(
                    key, now, suppressions, flow.Pid, null, target,
                    identity.Name, identity.Path))
            {
                continue;
            }

            alerts.Add(CreateAlert(
                IdsSeverity.Medium,
                "beaconing",
                flow.Pid,
                target,
                $"connections={times.Count}; mean={mean:0.0}s; jitter={cv:0.00}; avg={averageBytes}B",
                key,
                identity.Name,
                identity.Path));
        }
    }

    private void EvaluateScanning(
        DateTime now, int factor, IReadOnlyList<IdsSuppression> suppressions, List<IdsAlert> alerts)
    {
        var threshold = 15 * factor;

        var recent = _endpoints
            .Where(hit => now - hit.TimeUtc <= ScanWindow)
            .GroupBy(hit => hit.Pid);

        foreach (var group in recent)
        {
            var hits = group.ToList();

            var vertical = hits
                .GroupBy(hit => hit.Remote)
                .Select(host => new
                {
                    Host = host.Key,
                    Ports = host.Select(hit => hit.RemotePort).Distinct().Count(),
                })
                .FirstOrDefault(item => item.Ports >= threshold);

            var horizontal = hits
                .GroupBy(hit => hit.RemotePort)
                .Where(port => port.Key is not 80 and not 443)
                .Select(port => new
                {
                    Port = port.Key,
                    Hosts = port.Select(hit => hit.Remote).Distinct().Count(),
                })
                .FirstOrDefault(item => item.Hosts >= threshold);

            if (vertical is null && horizontal is null)
            {
                continue;
            }

            var count = Math.Max(vertical?.Ports ?? 0, horizontal?.Hosts ?? 0);
            var target = vertical is not null
                ? $"host:{vertical.Host}"
                : $"port:{horizontal!.Port}";
            var key = AlertKey("scan", group.Key, target);

            if (!ShouldAlert(key, now, suppressions, group.Key, null, target))
            {
                continue;
            }

            var evidence = vertical is not null
                ? $"sameHost={vertical.Host}; ports={vertical.Ports}; window=60s"
                : $"samePort={horizontal!.Port}; hosts={horizontal.Hosts}; window=60s";

            alerts.Add(CreateAlert(
                count >= threshold * 2 ? IdsSeverity.High : IdsSeverity.Medium,
                "scan",
                group.Key,
                target,
                evidence,
                key));
        }
    }

    private void EvaluateLateral(
        DateTime now, int factor, IReadOnlyList<IdsSuppression> suppressions, List<IdsAlert> alerts)
    {
        var threshold = 3 * factor;

        var recent = _endpoints
            .Where(hit => now - hit.TimeUtc <= LateralWindow
                          && hit.RemotePort is 445 or 3389 or 5985 or 135 or 139
                          && IsPrivate(hit.Remote))
            .GroupBy(hit => hit.Pid);

        foreach (var group in recent)
        {
            var hosts = group
                .Select(hit => hit.Remote)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Count();

            if (hosts < threshold)
            {
                continue;
            }

            var key = AlertKey("lateral", group.Key, "private-admin-ports");

            if (!ShouldAlert(key, now, suppressions, group.Key, null, "private-admin-ports"))
            {
                continue;
            }

            alerts.Add(CreateAlert(
                IdsSeverity.High,
                "lateral",
                group.Key,
                "private-admin-ports",
                $"privateHosts={hosts}; ports=445,3389,5985,135,139; window=600s",
                key));
        }
    }

    private void EvaluateDns(
        DateTime now, int factor, IReadOnlyList<IdsSuppression> suppressions, List<IdsAlert> alerts)
    {
        var uniqueThreshold = 20 * factor;
        var longThreshold = 10 * factor;

        var recent = _dns
            .Where(item => now - item.TimeUtc <= DnsWindow)
            .GroupBy(item => (item.Pid, Parent: ParentDomain(item.QueryName)));

        foreach (var group in recent)
        {
            var parent = group.Key.Parent;

            if (parent.Length == 0)
            {
                continue;
            }

            var observedName = group
                .Select(item => item.ProcessName)
                .FirstOrDefault(name => name.Length > 0);

            var observedPath = group
                .Select(item => item.ProcessPath)
                .FirstOrDefault(path => path.Length > 0);

            var identity = string.IsNullOrEmpty(observedName)
                ? ProcessResolver.Resolve(group.Key.Pid)
                : new ProcessIdentity(observedName!, observedPath ?? string.Empty);

            if (IsSystemProcess(identity.Name))
            {
                continue;
            }

            // 同一域名可能先有「发起」再有「完成」两条事件；按域名取最后一条，
            // 避免 NXDOMAIN 比例被重复事件稀释。
            var latest = group
                .GroupBy(item => item.QueryName, StringComparer.OrdinalIgnoreCase)
                .Select(items => items.OrderByDescending(item => item.TimeUtc).First())
                .ToList();

            var names = latest
                .Select(item => item.QueryName)
                .ToList();

            var longNames = names.Count(name => name.Length >= 40);
            var nxdomain = latest.Count(item => item.Status is "NXDOMAIN" or "NO_RECORDS");
            var total = latest.Count;

            if (names.Count < uniqueThreshold
                && longNames < longThreshold
                && !(total >= uniqueThreshold && nxdomain * 100 / total >= 70))
            {
                continue;
            }

            var key = AlertKey("dns", group.Key.Pid, parent);

            if (!ShouldAlert(
                    key, now, suppressions, group.Key.Pid, identity.Path, parent,
                    identity.Name, identity.Path))
            {
                continue;
            }

            alerts.Add(CreateAlert(
                IdsSeverity.Medium,
                "dns",
                group.Key.Pid,
                parent,
                $"parent={parent}; unique={names.Count}; long={longNames}; nxdomain={nxdomain}/{total}",
                key,
                identity.Name,
                identity.Path));
        }
    }

    private bool ShouldAlert(
        string key,
        DateTime now,
        IReadOnlyList<IdsSuppression> suppressions,
        int pid,
        string? processPath,
        string target,
        string? identityName = null,
        string? identityPath = null)
    {
        if (_lastAlertUtc.TryGetValue(key, out var last) && now - last < AlertCooldown)
        {
            return false;
        }

        var identity = string.IsNullOrEmpty(identityName)
            ? ProcessResolver.Resolve(pid)
            : new ProcessIdentity(identityName!, identityPath ?? string.Empty);

        if (IsSuppressed(
                key.Split('|')[0],
                identity.Path,
                identity.Name,
                target,
                suppressions,
                now))
        {
            return false;
        }

        _lastAlertUtc[key] = now;
        return true;
    }

    private static bool IsSuppressed(
        string ruleId,
        string? processPath,
        string processName,
        string target,
        IReadOnlyList<IdsSuppression> suppressions,
        DateTime now)
    {
        foreach (var suppression in suppressions)
        {
            if (suppression.UntilUtc is { } until && until <= now)
            {
                continue;
            }

            if (!string.Equals(suppression.RuleId, "*", StringComparison.OrdinalIgnoreCase)
                && !string.Equals(suppression.RuleId, ruleId, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (!string.IsNullOrEmpty(suppression.ProcessPath)
                && !string.Equals(suppression.ProcessPath, processPath, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (!string.IsNullOrEmpty(suppression.ProcessName)
                && !string.Equals(suppression.ProcessName, processName, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            if (!string.IsNullOrEmpty(suppression.Target)
                && !string.Equals(suppression.Target, target, StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            return true;
        }

        return false;
    }

    private static IdsAlert CreateAlert(
        string severity, string ruleId, int pid, string target, string evidence, string key,
        string? processName = null, string? processPath = null)
    {
        var identity = string.IsNullOrEmpty(processName)
            ? ProcessResolver.Resolve(pid)
            : new ProcessIdentity(processName!, processPath ?? string.Empty);

        return new IdsAlert
        {
            TimeUtc = DateTime.UtcNow,
            Severity = severity,
            RuleId = ruleId,
            RuleName = ruleId,
            Pid = pid,
            ProcessName = identity.Name,
            ProcessPath = string.IsNullOrEmpty(identity.Path) ? null : identity.Path,
            Target = target,
            Evidence = evidence,
            DedupKey = key,
        };
    }

    private static string AlertKey(string ruleId, int pid, string target)
        => $"{ruleId}|{pid}|{target}";

    private static readonly HashSet<string> TwoLevelSuffixes = new(StringComparer.OrdinalIgnoreCase)
    {
        "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn",
        "co.uk", "org.uk", "ac.uk", "gov.uk",
        "co.jp", "ne.jp", "or.jp",
        "com.au", "net.au", "org.au",
        "com.br", "com.tw", "com.hk", "com.sg",
    };

    private static string ParentDomain(string name)
    {
        var trimmed = name.Trim().TrimEnd('.');

        if (trimmed.Length == 0)
        {
            return string.Empty;
        }

        var parts = trimmed.Split('.');

        if (parts.Length >= 3)
        {
            var lastTwo = $"{parts[^2]}.{parts[^1]}";

            if (TwoLevelSuffixes.Contains(lastTwo))
            {
                return $"{parts[^3]}.{lastTwo}".ToLowerInvariant();
            }
        }

        return parts.Length >= 2
            ? $"{parts[^2]}.{parts[^1]}".ToLowerInvariant()
            : trimmed.ToLowerInvariant();
    }

    private static bool IsSystemProcess(string name)
        => name.Equals("svchost.exe", StringComparison.OrdinalIgnoreCase)
           || name.Equals("WinAppGuardSvc.exe", StringComparison.OrdinalIgnoreCase)
           || name.Equals("System", StringComparison.OrdinalIgnoreCase)
           || name.Equals("System（内核）", StringComparison.OrdinalIgnoreCase)
           || name.Equals("services.exe", StringComparison.OrdinalIgnoreCase)
           || name.Equals("lsass.exe", StringComparison.OrdinalIgnoreCase)
           || name.Equals("dns.exe", StringComparison.OrdinalIgnoreCase);

    private static bool IsPrivate(string address)
    {
        if (!IPAddress.TryParse(address, out var ip)
            || ip.AddressFamily != AddressFamily.InterNetwork)
        {
            return false;
        }

        var bytes = ip.GetAddressBytes();

        return bytes[0] == 10
               || (bytes[0] == 172 && bytes[1] is >= 16 and <= 31)
               || (bytes[0] == 192 && bytes[1] == 168);
    }

    private static bool IsNoisyEndpoint(string address, ushort port)
    {
        if (port is 53 or 5353 or 5355 or 1900 or 3702 or 137 or 138)
        {
            return true;
        }

        if (!IPAddress.TryParse(address, out var ip))
        {
            return false;
        }

        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            var bytes = ip.GetAddressBytes();
            return bytes[0] is >= 224 and <= 239
                   || (bytes[0] == 255 && bytes[1] == 255 && bytes[2] == 255 && bytes[3] == 255)
                   || (bytes[0] == 169 && bytes[1] == 254);
        }

        var v6 = ip.GetAddressBytes();
        return v6[0] == 0xff || (v6[0] == 0xfe && (v6[1] & 0xc0) == 0x80);
    }

    private sealed class FlowState
    {
        public int Pid;
        public string Protocol = string.Empty;
        public string Remote = string.Empty;
        public ushort RemotePort;
        public DateTime FirstSeenUtc;
        public DateTime LastSeenUtc;
        public long BytesIn;
        public long BytesOut;
        public List<DateTime> Connections = new();
    }

    private readonly record struct EndpointHit(
        DateTime TimeUtc, int Pid, string Remote, ushort RemotePort);

    private readonly record struct DnsObservation(
        DateTime TimeUtc,
        int Pid,
        string QueryName,
        string Status,
        string ProcessName,
        string ProcessPath);
}
