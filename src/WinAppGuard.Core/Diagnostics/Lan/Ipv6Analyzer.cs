using System.Net;

namespace WinAppGuard.Core.Diagnostics.Lan;

/// <summary>
/// 4.4：IPv6 邻接安全分析（RA / DHCPv6 / NDP）。
///
/// 只做主机侧检测：不主动投毒、不保存报文、默认不阻断。
/// 基线学习 5 分钟，或直到看到带前缀的路由器。
/// </summary>
public sealed class Ipv6Analyzer
{
    public const int MaxEvents = 500;

    private static readonly TimeSpan LearningPeriod = TimeSpan.FromMinutes(5);
    private static readonly TimeSpan Cooldown = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan RateWindow = TimeSpan.FromSeconds(10);
    private const int RateThreshold = 20;
    private const int MacAddressThreshold = 8;
    private const int MaxRateKeys = 1024;
    private const int MaxCooldowns = 4096;

    private readonly object _gate = new();
    private readonly Ipv6State _state;
    private readonly List<LanEvent> _events = new();
    private readonly Dictionary<string, DateTime> _cooldown = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, Queue<DateTime>> _raRate = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, Queue<DateTime>> _naRate = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, HashSet<string>> _macAddresses = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, List<(string Mac, DateTime At)>> _addressMacs =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _localAddresses = new(StringComparer.OrdinalIgnoreCase);

    private DateTime _learningStartedUtc;

    public Ipv6Analyzer(Ipv6State state, DateTime now)
    {
        _state = state;
        _learningStartedUtc = now;
    }

    public Action<LanEvent>? EventObserved { get; set; }

    public Action? StateChanged { get; set; }

    public bool BaselineReady
    {
        get { lock (_gate) { return _state.BaselineReadyUtc is not null; } }
    }

    public DateTime? BaselineUtc
    {
        get { lock (_gate) { return _state.BaselineReadyUtc; } }
    }

    public int EventCount
    {
        get { lock (_gate) { return _events.Count; } }
    }

    public List<string> TrustedRouters
    {
        get { lock (_gate) { return _state.TrustedRouters.ToList(); } }
    }

    public List<string> TrustedDhcpServers
    {
        get { lock (_gate) { return _state.TrustedDhcpServers.ToList(); } }
    }

    public void UpdateLocalAddresses(IEnumerable<string> addresses)
    {
        lock (_gate)
        {
            _localAddresses.Clear();

            foreach (var address in addresses)
            {
                var normalized = NormalizeAddress(address);

                if (normalized is not null)
                {
                    _localAddresses.Add(normalized);
                }
            }
        }
    }

    /// <summary>由宿主周期性调用：即使没有 IPv6 流量，5 分钟后也要结束基线学习。</summary>
    public void Tick(DateTime now)
    {
        lock (_gate)
        {
            UpdateBaselineReadyLocked(now);
        }
    }

    public void SeedEvents(IEnumerable<LanEvent> events)
    {
        lock (_gate)
        {
            foreach (var item in events)
            {
                if (_events.Count >= 200)
                {
                    break;
                }

                if (!_events.Any(existing => existing.Id == item.Id))
                {
                    _events.Add(item);
                }
            }

            _events.Sort((left, right) => right.TimeUtc.CompareTo(left.TimeUtc));
        }
    }

    public void ObserveRa(Ipv6RaMessage message, DateTime now)
    {
        if (string.IsNullOrWhiteSpace(message.SourceAddress)
            || string.IsNullOrWhiteSpace(message.SourceMac))
        {
            return;
        }

        lock (_gate)
        {
            PruneLocked(now);

            var source = NormalizeAddress(message.SourceAddress) ?? message.SourceAddress;
            var mac = NormalizeMac(message.SourceMac);
            var trusted = IsTrustedRouterLocked(source, mac);
            var router = _state.Routers.FirstOrDefault(item =>
                string.Equals(item.LinkLocal, source, StringComparison.OrdinalIgnoreCase));

            if (router is null)
            {
                var baseline = _state.BaselineReadyUtc is null;

                router = new Ipv6Router
                {
                    LinkLocal = source,
                    Mac = mac,
                    Prefixes = ClonePrefixes(message.Prefixes),
                    Managed = message.Managed,
                    Other = message.Other,
                    HomeAgent = message.HomeAgent,
                    RouterLifetime = message.RouterLifetime,
                    FirstSeenUtc = now,
                    LastSeenUtc = now,
                    Baseline = baseline,
                };

                _state.Routers.Add(router);

                if (!baseline && !trusted)
                {
                    RaiseLocked(
                        Ipv6EventKinds.RaUnexpectedRouter,
                        LanSeverity.High,
                        message.Adapter,
                        $"出现基线外的 IPv6 路由器 {source}（MAC {mac}）。",
                        source,
                        mac,
                        source,
                        null,
                        now);
                }
                else
                {
                    StateChanged?.Invoke();
                }
            }
            else
            {
                var macChanged = router.Baseline
                                 && !string.Equals(router.Mac, mac, StringComparison.OrdinalIgnoreCase);

                if (macChanged)
                {
                    RaiseLocked(
                        Ipv6EventKinds.RaUnexpectedRouter,
                        LanSeverity.High,
                        message.Adapter,
                        $"基线路由器 {source} 的 MAC 从 {router.Mac} 变为 {mac}。",
                        source,
                        mac,
                        source,
                        router.Mac,
                        now);
                    router.LastSeenUtc = now;
                }
                else
                {
                    if (router.Baseline)
                    {
                        if (!PrefixesEqual(router.Prefixes, message.Prefixes))
                        {
                            RaiseLocked(
                                Ipv6EventKinds.RaPrefixChanged,
                                LanSeverity.High,
                                message.Adapter,
                                $"路由器 {source} 的 on-link 前缀发生变化。",
                                source,
                                mac,
                                source,
                                null,
                                now);
                        }

                        if (router.Managed != message.Managed
                            || router.Other != message.Other
                            || router.HomeAgent != message.HomeAgent
                            || router.RouterLifetime != message.RouterLifetime
                            || !PrefixLifetimesEqual(router.Prefixes, message.Prefixes))
                        {
                            RaiseLocked(
                                Ipv6EventKinds.RaFlagsOrLifetimeChanged,
                                LanSeverity.Medium,
                                message.Adapter,
                                $"路由器 {source} 的 RA 标志或生命周期发生变化。",
                                source,
                                mac,
                                source,
                                null,
                                now);
                        }
                    }
                    else if (!trusted)
                    {
                        RaiseLocked(
                            Ipv6EventKinds.RaUnexpectedRouter,
                            LanSeverity.High,
                            message.Adapter,
                            $"出现基线外的 IPv6 路由器 {source}（MAC {mac}）。",
                            source,
                            mac,
                            source,
                            null,
                            now);
                    }

                    router.Mac = mac;
                    router.Prefixes = ClonePrefixes(message.Prefixes);
                    router.Managed = message.Managed;
                    router.Other = message.Other;
                    router.HomeAgent = message.HomeAgent;
                    router.RouterLifetime = message.RouterLifetime;
                    router.LastSeenUtc = now;
                }
            }

            if (_state.BaselineReadyUtc is not null
                && _state.Routers.Count > 1
                && !trusted)
            {
                RaiseLocked(
                    Ipv6EventKinds.RaMultipleRouters,
                    LanSeverity.Medium,
                    message.Adapter,
                    $"同时存在多个 IPv6 路由器（当前 {_state.Routers.Count} 个）。",
                    "multiple",
                    mac,
                    source,
                    null,
                    now);
            }

            if (TrackRateLocked(_raRate, source, now))
            {
                RaiseLocked(
                    Ipv6EventKinds.RaFlood,
                    LanSeverity.Low,
                    message.Adapter,
                    $"路由器 {source} 在 10 秒内发送了过多 RA。",
                    source,
                    mac,
                    source,
                    null,
                    now);
            }

            UpdateBaselineReadyLocked(now);
            StateChanged?.Invoke();
        }
    }

    public void ObserveDhcp(Ipv6DhcpMessage message, DateTime now)
    {
        if (!message.ServerToClient
            || message.MessageType is not (2 or 7 or 10)
            || string.IsNullOrWhiteSpace(message.SourceAddress))
        {
            return;
        }

        lock (_gate)
        {
            PruneLocked(now);

            var address = NormalizeAddress(message.SourceAddress) ?? message.SourceAddress;
            var mac = NormalizeMac(message.SourceMac);
            var serverId = string.IsNullOrWhiteSpace(message.ServerId)
                ? address
                : message.ServerId!;
            var trusted = IsTrustedDhcpLocked(serverId, mac);
            var server = _state.DhcpServers.FirstOrDefault(item =>
                string.Equals(item.ServerId, serverId, StringComparison.OrdinalIgnoreCase));

            if (server is null)
            {
                var baseline = _state.BaselineReadyUtc is null;

                server = new Ipv6DhcpServer
                {
                    ServerId = serverId,
                    Address = address,
                    Mac = mac,
                    DnsServers = message.DnsServers.ToList(),
                    Domains = message.Domains.ToList(),
                    IaAddresses = CloneIa(message.IaAddresses),
                    MinPreferredLifetime = message.MinPreferredLifetime,
                    MinValidLifetime = message.MinValidLifetime,
                    FirstSeenUtc = now,
                    LastSeenUtc = now,
                    Baseline = baseline,
                };

                _state.DhcpServers.Add(server);

                if (!baseline && !trusted)
                {
                    RaiseLocked(
                        Ipv6EventKinds.DhcpUnexpectedServer,
                        LanSeverity.High,
                        message.Adapter,
                        $"出现基线外的 DHCPv6 服务器 {address}（Server ID {ShortId(serverId)}）。",
                        serverId,
                        mac,
                        address,
                        null,
                        now);
                }
                else
                {
                    StateChanged?.Invoke();
                }
            }
            else
            {
                var macChanged = server.Baseline
                                 && !string.IsNullOrWhiteSpace(mac)
                                 && !string.IsNullOrWhiteSpace(server.Mac)
                                 && !string.Equals(server.Mac, mac, StringComparison.OrdinalIgnoreCase);

                if (macChanged)
                {
                    RaiseLocked(
                        Ipv6EventKinds.DhcpUnexpectedServer,
                        LanSeverity.High,
                        message.Adapter,
                        $"基线 DHCPv6 服务器 {address} 的 MAC 从 {server.Mac} 变为 {mac}。",
                        serverId,
                        mac,
                        address,
                        server.Mac,
                        now);
                    server.LastSeenUtc = now;
                }
                else
                {
                    if (!server.Baseline && !trusted)
                    {
                        RaiseLocked(
                            Ipv6EventKinds.DhcpUnexpectedServer,
                            LanSeverity.High,
                            message.Adapter,
                            $"出现基线外的 DHCPv6 服务器 {address}（Server ID {ShortId(serverId)}）。",
                            serverId,
                            mac,
                            address,
                            null,
                            now);
                    }

                    if (server.Baseline
                        && (!SetEqual(server.DnsServers, message.DnsServers)
                            || !SetEqual(server.Domains, message.Domains)
                            || !IaEqual(server.IaAddresses, message.IaAddresses)
                            || server.MinPreferredLifetime != message.MinPreferredLifetime
                            || server.MinValidLifetime != message.MinValidLifetime))
                    {
                        RaiseLocked(
                            Ipv6EventKinds.DhcpOptionMismatch,
                            LanSeverity.Medium,
                            message.Adapter,
                            $"DHCPv6 服务器 {address} 下发的 DNS / 前缀 / 生命周期发生变化。",
                            serverId,
                            mac,
                            address,
                            null,
                            now);
                    }

                    server.Address = address;
                    server.Mac = mac;
                    server.DnsServers = message.DnsServers.ToList();
                    server.Domains = message.Domains.ToList();
                    server.IaAddresses = CloneIa(message.IaAddresses);
                    server.MinPreferredLifetime = message.MinPreferredLifetime;
                    server.MinValidLifetime = message.MinValidLifetime;
                    server.LastSeenUtc = now;
                }
            }

            if (message.IaAddresses.Count > 0
                && (message.MinPreferredLifetime < 60 || message.MinValidLifetime < 60))
            {
                RaiseLocked(
                    Ipv6EventKinds.DhcpShortLease,
                    LanSeverity.Low,
                    message.Adapter,
                    $"DHCPv6 服务器 {address} 下发的租期异常短（{message.MinValidLifetime} 秒）。",
                    serverId,
                    mac,
                    address,
                    null,
                    now);
            }

            if (_state.BaselineReadyUtc is not null
                && _state.DhcpServers.Count > 1
                && !trusted)
            {
                RaiseLocked(
                    Ipv6EventKinds.DhcpMultipleServers,
                    LanSeverity.Medium,
                    message.Adapter,
                    $"同时存在多个 DHCPv6 服务器（当前 {_state.DhcpServers.Count} 个）。",
                    "multiple",
                    mac,
                    address,
                    null,
                    now);
            }

            UpdateBaselineReadyLocked(now);
            StateChanged?.Invoke();
        }
    }

    public void ObserveNd(Ipv6NdMessage message, DateTime now)
    {
        if (string.IsNullOrWhiteSpace(message.TargetAddress))
        {
            return;
        }

        lock (_gate)
        {
            PruneLocked(now);

            var source = NormalizeAddress(message.SourceAddress) ?? message.SourceAddress;
            var target = NormalizeAddress(message.TargetAddress) ?? message.TargetAddress;
            var sourceMac = NormalizeMac(message.SourceMac);
            var targetMac = NormalizeMac(message.TargetMac);

            if (message.Type == 137)
            {
                if (!_state.Routers.Any(item =>
                        string.Equals(item.LinkLocal, source, StringComparison.OrdinalIgnoreCase)))
                {
                    RaiseLocked(
                        Ipv6EventKinds.RedirectUnexpected,
                        LanSeverity.Medium,
                        message.Adapter,
                        $"非基线路由器 {source} 发送了 IPv6 Redirect。",
                        source,
                        sourceMac,
                        target,
                        null,
                        now);
                }

                UpdateBaselineReadyLocked(now);
                return;
            }

            if (targetMac is not null
                && sourceMac is not null
                && !string.Equals(targetMac, sourceMac, StringComparison.OrdinalIgnoreCase))
            {
                RaiseLocked(
                    Ipv6EventKinds.NdSenderMismatch,
                    LanSeverity.Medium,
                    message.Adapter,
                    $"NDP 选项里的 MAC {targetMac} 与以太网源 MAC {sourceMac} 不一致。",
                    target,
                    sourceMac,
                    target,
                    targetMac,
                    now);
            }

            if (message.Type == 135)
            {
                if (source == "::"
                    && _localAddresses.Contains(target))
                {
                    RaiseLocked(
                        Ipv6EventKinds.DadConflict,
                        LanSeverity.Medium,
                        message.Adapter,
                        $"本机地址 {target} 正在被其他设备做 DAD 探测。",
                        target,
                        sourceMac,
                        target,
                        null,
                        now);
                }

                UpdateBaselineReadyLocked(now);
                return;
            }

            if (message.Type != 136)
            {
                return;
            }

            var router = _state.Routers.FirstOrDefault(item =>
                string.Equals(item.LinkLocal, target, StringComparison.OrdinalIgnoreCase));

            if (router is not null && targetMac is not null)
            {
                if (_state.BaselineReadyUtc is not null
                    && !string.Equals(router.Mac, targetMac, StringComparison.OrdinalIgnoreCase)
                    && !IsTrustedRouterLocked(target, targetMac))
                {
                    RaiseLocked(
                        Ipv6EventKinds.NaRouterMacChanged,
                        LanSeverity.High,
                        message.Adapter,
                        $"路由器 {target} 的 NA 声明的 MAC 从 {router.Mac} 变为 {targetMac}。",
                        target,
                        targetMac,
                        target,
                        router.Mac,
                        now);
                }

                UpdateBaselineReadyLocked(now);
                return;
            }

            var neighbor = _state.Neighbors.FirstOrDefault(item =>
                string.Equals(item.Address, target, StringComparison.OrdinalIgnoreCase));

            if (neighbor is null)
            {
                _state.Neighbors.Add(new Ipv6Neighbor
                {
                    Address = target,
                    Mac = targetMac ?? string.Empty,
                    IsRouter = message.Router,
                    FirstSeenUtc = now,
                    LastSeenUtc = now,
                });

                if (!string.IsNullOrWhiteSpace(targetMac))
                {
                    TrackMacLocked(targetMac, target, now);
                }

                StateChanged?.Invoke();
            }
            else
            {
                if (_state.BaselineReadyUtc is not null
                    && targetMac is not null
                    && !string.Equals(neighbor.Mac, targetMac, StringComparison.OrdinalIgnoreCase))
                {
                    RaiseLocked(
                        Ipv6EventKinds.NaCacheMismatch,
                        LanSeverity.Medium,
                        message.Adapter,
                        $"邻居 {target} 的 MAC 从 {neighbor.Mac} 变为 {targetMac}。",
                        target,
                        targetMac,
                        target,
                        neighbor.Mac,
                        now);
                }

                neighbor.Mac = targetMac ?? neighbor.Mac;
                neighbor.IsRouter = message.Router || neighbor.IsRouter;
                neighbor.LastSeenUtc = now;

                if (!string.IsNullOrWhiteSpace(targetMac))
                {
                    TrackMacLocked(targetMac, target, now);
                }
            }

            if (targetMac is not null
                && _macAddresses.TryGetValue(targetMac, out var addresses)
                && addresses.Count >= MacAddressThreshold)
            {
                RaiseLocked(
                    Ipv6EventKinds.NaMacBehavior,
                    LanSeverity.Medium,
                    message.Adapter,
                    $"MAC {targetMac} 声称了 {addresses.Count} 个 IPv6 地址。",
                    targetMac,
                    targetMac,
                    target,
                    null,
                    now);
            }

            if (targetMac is not null
                && _addressMacs.TryGetValue(target, out var history))
            {
                var recent = history.Where(item => now - item.At <= TimeSpan.FromMinutes(1)).ToList();

                if (recent.Select(item => item.Mac).Distinct(StringComparer.OrdinalIgnoreCase).Count() >= 3)
                {
                    RaiseLocked(
                        Ipv6EventKinds.NaMacBehavior,
                        LanSeverity.Medium,
                        message.Adapter,
                        $"邻居 {target} 在 1 分钟内频繁更换 MAC。",
                        target,
                        targetMac,
                        target,
                        null,
                        now);
                }
            }

            if (!message.Solicited && targetMac is not null && TrackRateLocked(_naRate, targetMac, now))
            {
                RaiseLocked(
                    Ipv6EventKinds.NaUnsolicitedBurst,
                    LanSeverity.Low,
                    message.Adapter,
                    $"MAC {targetMac} 在 10 秒内发送了过多免费 NA。",
                    targetMac,
                    targetMac,
                    target,
                    null,
                    now);
            }

            UpdateBaselineReadyLocked(now);
            StateChanged?.Invoke();
        }
    }

    public Ipv6SecuritySnapshot Snapshot()
    {
        lock (_gate)
        {
            return new Ipv6SecuritySnapshot
            {
                Events = _events.ToList(),
                Routers = _state.Routers.ToList(),
                DhcpServers = _state.DhcpServers.ToList(),
                Neighbors = _state.Neighbors.ToList(),
                BaselineReady = _state.BaselineReadyUtc is not null,
                BaselineUtc = _state.BaselineReadyUtc,
            };
        }
    }

    public bool TrustRouter(string linkLocal, string mac, bool enabled, DateTime now)
    {
        var address = NormalizeAddress(linkLocal);

        if (address is null || string.IsNullOrWhiteSpace(mac))
        {
            return false;
        }

        lock (_gate)
        {
            var key = Ipv6TrustKeys.Router(address, NormalizeMac(mac));
            SetTrustLocked(_state.TrustedRouters, key, enabled);
            ClearCooldownLocked(key);
            StateChanged?.Invoke();
            return true;
        }
    }

    public bool TrustDhcp(string serverId, string? mac, bool enabled, DateTime now)
    {
        if (string.IsNullOrWhiteSpace(serverId))
        {
            return false;
        }

        lock (_gate)
        {
            var key = Ipv6TrustKeys.Dhcp(serverId, NormalizeMac(mac));
            SetTrustLocked(_state.TrustedDhcpServers, key, enabled);
            ClearCooldownLocked(key);
            StateChanged?.Invoke();
            return true;
        }
    }

    public void ClearEvents()
    {
        lock (_gate)
        {
            _events.Clear();
        }
    }

    public void ResetBaseline(DateTime now)
    {
        lock (_gate)
        {
            _state.Routers.Clear();
            _state.DhcpServers.Clear();
            _state.Neighbors.Clear();
            _state.BaselineReadyUtc = null;
            _learningStartedUtc = now;
            _raRate.Clear();
            _naRate.Clear();
            _macAddresses.Clear();
            _addressMacs.Clear();
            StateChanged?.Invoke();
        }
    }

    private void UpdateBaselineReadyLocked(DateTime now)
    {
        if (_state.BaselineReadyUtc is not null)
        {
            return;
        }

        var hasRouter = _state.Routers.Any(item => item.Baseline && item.Prefixes.Count > 0);
        var hasDhcp = _state.DhcpServers.Any(item => item.Baseline);

        if ((hasRouter && hasDhcp) || now - _learningStartedUtc >= LearningPeriod)
        {
            _state.BaselineReadyUtc = now;
            StateChanged?.Invoke();
        }
    }

    private void RaiseLocked(
        string kind,
        string severity,
        string adapter,
        string detail,
        string key,
        string? sourceMac,
        string? targetIp,
        string? targetMac,
        DateTime now)
    {
        if (_state.BaselineReadyUtc is null)
        {
            return;
        }

        var cooldownKey = $"{kind}|{key}";

        if (_cooldown.TryGetValue(cooldownKey, out var until) && until > now)
        {
            return;
        }

        _cooldown[cooldownKey] = now + Cooldown;

        var item = new LanEvent
        {
            TimeUtc = now,
            Kind = kind,
            Severity = severity,
            Adapter = adapter,
            Detail = detail,
            SourceMac = sourceMac,
            TargetIp = targetIp,
            TargetMac = targetMac,
        };

        _events.Insert(0, item);

        if (_events.Count > MaxEvents)
        {
            _events.RemoveRange(MaxEvents, _events.Count - MaxEvents);
        }

        EventObserved?.Invoke(item);
    }

    private bool TrackRateLocked(
        Dictionary<string, Queue<DateTime>> table,
        string key,
        DateTime now)
    {
        if (!table.TryGetValue(key, out var queue))
        {
            if (table.Count >= MaxRateKeys)
            {
                table.Clear();
            }

            queue = new Queue<DateTime>();
            table[key] = queue;
        }

        while (queue.Count > 0 && now - queue.Peek() > RateWindow)
        {
            queue.Dequeue();
        }

        queue.Enqueue(now);
        return queue.Count > RateThreshold;
    }

    private void TrackMacLocked(string mac, string address, DateTime now)
    {
        if (!_macAddresses.TryGetValue(mac, out var addresses))
        {
            addresses = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            _macAddresses[mac] = addresses;
        }

        addresses.Add(address);

        if (!_addressMacs.TryGetValue(address, out var history))
        {
            history = new List<(string Mac, DateTime At)>();
            _addressMacs[address] = history;
        }

        history.Add((mac, now));

        if (history.Count > 16)
        {
            history.RemoveRange(0, history.Count - 16);
        }
    }

    private void PruneLocked(DateTime now)
    {
        if (_cooldown.Count > MaxCooldowns)
        {
            foreach (var key in _cooldown
                         .Where(pair => pair.Value <= now)
                         .Select(pair => pair.Key)
                         .ToList())
            {
                _cooldown.Remove(key);
            }
        }

        if (_raRate.Count > MaxRateKeys)
        {
            _raRate.Clear();
        }

        if (_naRate.Count > MaxRateKeys)
        {
            _naRate.Clear();
        }
    }

    private bool IsTrustedRouterLocked(string linkLocal, string mac)
    {
        var key = Ipv6TrustKeys.Router(linkLocal, mac);
        return _state.TrustedRouters.Contains(key, StringComparer.OrdinalIgnoreCase);
    }

    private bool IsTrustedDhcpLocked(string serverId, string? mac)
    {
        var key = Ipv6TrustKeys.Dhcp(serverId, mac);
        return _state.TrustedDhcpServers.Contains(key, StringComparer.OrdinalIgnoreCase);
    }

    private void ClearCooldownLocked(string key)
    {
        foreach (var cooldown in _cooldown.Keys
                     .Where(item => item.EndsWith("|" + key, StringComparison.OrdinalIgnoreCase))
                     .ToList())
        {
            _cooldown.Remove(cooldown);
        }
    }

    private static void SetTrustLocked(List<string> list, string key, bool enabled)
    {
        var index = list.FindIndex(item =>
            string.Equals(item, key, StringComparison.OrdinalIgnoreCase));

        if (enabled && index < 0)
        {
            list.Add(key);
        }
        else if (!enabled && index >= 0)
        {
            list.RemoveAt(index);
        }
    }

    private static List<Ipv6PrefixInfo> ClonePrefixes(IEnumerable<Ipv6PrefixInfo> prefixes)
        => prefixes.Select(item => new Ipv6PrefixInfo
        {
            Prefix = item.Prefix,
            PrefixLength = item.PrefixLength,
            ValidLifetime = item.ValidLifetime,
            PreferredLifetime = item.PreferredLifetime,
            OnLink = item.OnLink,
            Autonomous = item.Autonomous,
        }).ToList();

    private static List<Ipv6IaInfo> CloneIa(IEnumerable<Ipv6IaInfo> addresses)
        => addresses.Select(item => new Ipv6IaInfo
        {
            Address = item.Address,
            PrefixLength = item.PrefixLength,
            PreferredLifetime = item.PreferredLifetime,
            ValidLifetime = item.ValidLifetime,
        }).ToList();

    private static bool PrefixesEqual(
        IReadOnlyList<Ipv6PrefixInfo> left,
        IReadOnlyList<Ipv6PrefixInfo> right)
    {
        var leftSet = left
            .Select(item => $"{item.Prefix}/{item.PrefixLength}")
            .OrderBy(item => item, StringComparer.Ordinal)
            .ToList();
        var rightSet = right
            .Select(item => $"{item.Prefix}/{item.PrefixLength}")
            .OrderBy(item => item, StringComparer.Ordinal)
            .ToList();

        return leftSet.SequenceEqual(rightSet, StringComparer.Ordinal);
    }

    private static bool PrefixLifetimesEqual(
        IReadOnlyList<Ipv6PrefixInfo> left,
        IReadOnlyList<Ipv6PrefixInfo> right)
    {
        if (left.Count != right.Count)
        {
            return false;
        }

        for (var i = 0; i < left.Count; i++)
        {
            if (left[i].ValidLifetime != right[i].ValidLifetime
                || left[i].PreferredLifetime != right[i].PreferredLifetime
                || left[i].OnLink != right[i].OnLink
                || left[i].Autonomous != right[i].Autonomous)
            {
                return false;
            }
        }

        return true;
    }

    private static bool SetEqual(
        IEnumerable<string> left,
        IEnumerable<string> right)
    {
        var leftSet = left.OrderBy(item => item, StringComparer.OrdinalIgnoreCase).ToList();
        var rightSet = right.OrderBy(item => item, StringComparer.OrdinalIgnoreCase).ToList();
        return leftSet.SequenceEqual(rightSet, StringComparer.OrdinalIgnoreCase);
    }

    private static bool IaEqual(
        IReadOnlyList<Ipv6IaInfo> left,
        IReadOnlyList<Ipv6IaInfo> right)
    {
        var leftSet = left
            .Select(item => $"{item.Address}/{item.PrefixLength}")
            .OrderBy(item => item, StringComparer.Ordinal)
            .ToList();
        var rightSet = right
            .Select(item => $"{item.Address}/{item.PrefixLength}")
            .OrderBy(item => item, StringComparer.Ordinal)
            .ToList();
        return leftSet.SequenceEqual(rightSet, StringComparer.Ordinal);
    }

    private static string NormalizeMac(string? mac)
        => string.IsNullOrWhiteSpace(mac) ? string.Empty : mac.Trim().ToLowerInvariant();

    private static string? NormalizeAddress(string? address)
    {
        if (string.IsNullOrWhiteSpace(address))
        {
            return null;
        }

        return IPAddress.TryParse(address.Trim(), out var parsed)
            ? parsed.ToString()
            : address.Trim().ToLowerInvariant();
    }

    private static string ShortId(string value)
        => value.Length <= 16 ? value : value[..16] + "…";
}
