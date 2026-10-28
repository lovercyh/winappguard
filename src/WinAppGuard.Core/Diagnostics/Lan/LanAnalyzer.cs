namespace WinAppGuard.Core.Diagnostics.Lan;

/// <summary>
/// 4.2：ARP / DHCP 检测规则（纯逻辑，可离线测试）。
///
/// 设计原则：
///   - 基线学习期（启动后 10 分钟，或网关 + DHCP 都出现）内只学习、不告警；
///   - 同一（规则 + 关键值）10 分钟内只报一次；
///   - 用户“信任”后写基线，重启仍生效；
///   - 任何情况下都不修改系统（不做静态 ARP、不自动阻断）。
/// </summary>
public sealed class LanAnalyzer
{
    public const int MaxEvents = 1000;

    private static readonly TimeSpan LearningPeriod = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan Cooldown = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan MacClaimWindow = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan FlapWindow = TimeSpan.FromSeconds(60);
    private static readonly TimeSpan GratuitousWindow = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan ServerWindow = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan BlockTtl = TimeSpan.FromMinutes(10);

    private readonly object _gate = new();
    private readonly LanState _state;
    private readonly List<LanEvent> _events = new();
    private readonly Dictionary<string, DateTime> _cooldown = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, IpState> _ips = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, MacState> _macs = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, List<DateTime>> _gratuitous = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, Dictionary<string, DateTime>> _serversByAdapter =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, string> _lastGatewayMac = new(StringComparer.OrdinalIgnoreCase);

    private List<LanGatewayHint> _gatewayHints = new();
    private DateTime _learningStartedUtc;

    public LanAnalyzer(LanState state, DateTime now)
    {
        _state = state;
        _learningStartedUtc = now;
    }

    /// <summary>每条新事件都会回调一次（宿主用它落盘 + 写日志 + 托盘提示）。</summary>
    public Action<LanEvent>? EventObserved { get; set; }

    /// <summary>基线 / 设置 / 阻断发生变化时回调（宿主用它保存 state.json）。</summary>
    public Action? StateChanged { get; set; }

    public bool BaselineReady
    {
        get { lock (_gate) { return _state.BaselineReadyUtc is not null; } }
    }

    public void UpdateGatewayHints(IEnumerable<LanGatewayHint> hints)
    {
        lock (_gate)
        {
            _gatewayHints = hints.ToList();
        }
    }

    public void ObserveArp(ArpFrame frame, DateTime now)
    {
        if (string.IsNullOrWhiteSpace(frame.SenderIp) || string.IsNullOrWhiteSpace(frame.SenderMac))
        {
            return;
        }

        lock (_gate)
        {
            ObserveArpLocked(frame, now);
            UpdateBaselineReadyLocked(now);
        }
    }

    public void ObserveDhcp(DhcpMessage message, DateTime now)
    {
        if (string.IsNullOrWhiteSpace(message.ServerIp))
        {
            return;
        }

        lock (_gate)
        {
            ObserveDhcpLocked(message, now);
            UpdateBaselineReadyLocked(now);
        }
    }

    /// <summary>启动时把落盘的历史事件读回内存（新的在前）。</summary>
    public void SeedEvents(IEnumerable<LanEvent> items)
    {
        lock (_gate)
        {
            _events.Clear();
            _events.AddRange(items.Take(MaxEvents));
        }
    }

    public LanSnapshot Snapshot()    {
        lock (_gate)
        {
            PruneBlocksLocked(DateTime.UtcNow);

            return new LanSnapshot
            {
                Events = _events.Take(200).ToList(),
                Gateways = _state.Gateways.ToList(),
                DhcpServers = _state.DhcpServers.ToList(),
                Blocks = _state.Blocks.ToList(),
                BaselineReady = _state.BaselineReadyUtc is not null,
                BaselineUtc = _state.BaselineReadyUtc,
            };
        }
    }

    public LanSettings Settings
    {
        get { lock (_gate) { return Clone(_state.Settings); } }
    }

    /// <summary>4.3：网关基线副本（DNS 分析用，避免跨线程无锁读取）。</summary>
    public List<LanGateway> Gateways
    {
        get { lock (_gate) { return _state.Gateways.ToList(); } }
    }

    public void ApplySettings(LanSettings settings)
    {
        lock (_gate)
        {
            _state.Settings.RetentionDays = LanStateStore.NormalizeRetention(settings.RetentionDays);
            _state.Settings.DhcpBlockEnabled = settings.DhcpBlockEnabled;
            StateChanged?.Invoke();
        }
    }

    public bool Trust(string kind, string value, DateTime now)
    {
        lock (_gate)
        {
            if (string.Equals(kind, "gateway", StringComparison.OrdinalIgnoreCase))
            {
                var gateway = _state.Gateways.FirstOrDefault(item =>
                    string.Equals(item.Ip, value, StringComparison.OrdinalIgnoreCase));

                if (gateway is null)
                {
                    return false;
                }

                // 用“最后一次观测到的 MAC”更新基线：用户点的就是当前网络的样子。
                if (_lastGatewayMac.TryGetValue($"{gateway.Adapter}|{gateway.Ip}", out var mac))
                {
                    gateway.Mac = mac;
                }

                gateway.LearnedUtc = now;
                gateway.Trusted = true;
                ClearCooldownLocked(LanEventKinds.ArpGatewayMacChanged, $"{gateway.Adapter}|{gateway.Ip}");
                ClearCooldownLocked(LanEventKinds.ArpGatewayCacheMismatch, $"{gateway.Adapter}|{gateway.Ip}");
            }
            else if (string.Equals(kind, "dhcp", StringComparison.OrdinalIgnoreCase))
            {
                var server = _state.DhcpServers.FirstOrDefault(item =>
                    string.Equals(item.ServerIp, value, StringComparison.OrdinalIgnoreCase));

                if (server is null)
                {
                    return false;
                }

                server.Trusted = true;
                ClearCooldownLocked(LanEventKinds.DhcpUnexpectedServer, server.ServerIp);
                ClearCooldownLocked(LanEventKinds.DhcpMultipleServers, server.Adapter);
            }
            else
            {
                return false;
            }

            StateChanged?.Invoke();
            return true;
        }
    }

    public void ResetBaseline(DateTime now)
    {
        lock (_gate)
        {
            _state.Gateways.Clear();
            _state.DhcpServers.Clear();
            _state.BaselineReadyUtc = null;
            _learningStartedUtc = now;
            _cooldown.Clear();
            _ips.Clear();
            _macs.Clear();
            _gratuitous.Clear();
            _serversByAdapter.Clear();
            _lastGatewayMac.Clear();
            StateChanged?.Invoke();
        }
    }

    public void ClearEvents()
    {
        lock (_gate)
        {
            _events.Clear();
        }
    }

    public int PruneBlocks(DateTime now)
    {
        lock (_gate)
        {
            var removed = PruneBlocksLocked(now);

            if (removed > 0)
            {
                StateChanged?.Invoke();
            }

            return removed;
        }
    }

    public bool AddBlock(string serverIp, DateTime now, string reason, string? eventId)
    {
        lock (_gate)
        {
            if (!_state.Settings.DhcpBlockEnabled)
            {
                return false;
            }

            var existing = _state.Blocks.FirstOrDefault(item =>
                string.Equals(item.ServerIp, serverIp, StringComparison.OrdinalIgnoreCase));

            if (existing is null)
            {
                _state.Blocks.Add(new LanBlock
                {
                    ServerIp = serverIp,
                    UntilUtc = now + BlockTtl,
                    Reason = reason,
                    EventId = eventId,
                });
            }
            else
            {
                existing.UntilUtc = now + BlockTtl;
                existing.Reason = reason;
                existing.EventId = eventId;
            }

            StateChanged?.Invoke();
            return true;
        }
    }

    public bool RemoveBlock(string serverIp)
    {
        lock (_gate)
        {
            var removed = _state.Blocks.RemoveAll(item =>
                string.Equals(item.ServerIp, serverIp, StringComparison.OrdinalIgnoreCase));

            if (removed > 0)
            {
                StateChanged?.Invoke();
                return true;
            }

            return false;
        }
    }

    public List<LanBlock> Blocks
    {
        get { lock (_gate) { return _state.Blocks.ToList(); } }
    }

    private void ObserveArpLocked(ArpFrame frame, DateTime now)
    {
        var adapter = frame.Adapter;
        var ipKey = $"{adapter}|{frame.SenderIp}";
        var nowReady = _state.BaselineReadyUtc is not null;

        // 同一 IP 频繁换 MAC。
        if (_ips.TryGetValue(ipKey, out var ipState))
        {
            if (!string.Equals(ipState.LastMac, frame.SenderMac, StringComparison.OrdinalIgnoreCase))
            {
                ipState.Changes.Add(now);
                ipState.LastMac = frame.SenderMac;
            }

            ipState.Changes.RemoveAll(time => now - time > FlapWindow);

            if (nowReady && ipState.Changes.Count >= 2)
            {
                RaiseLocked(
                    LanEventKinds.ArpIpMacFlapping,
                    LanSeverity.Medium,
                    adapter,
                    $"IP {frame.SenderIp} 在 60 秒内换了 {ipState.Changes.Count} 次 MAC（当前 {frame.SenderMac}）。",
                    ipKey,
                    frame.SenderMac,
                    frame.SenderIp,
                    frame.SenderMac,
                    now);
            }
        }
        else
        {
            _ips[ipKey] = new IpState { LastMac = frame.SenderMac };
        }

        // 同一 MAC 声称多个 IP。
        var macKey = $"{adapter}|{frame.SenderMac}";

        if (!_macs.TryGetValue(macKey, out var macState))
        {
            macState = new MacState();
            _macs[macKey] = macState;
        }

        macState.Ips[frame.SenderIp] = now;
        foreach (var stale in macState.Ips.Where(pair => now - pair.Value > MacClaimWindow).Select(pair => pair.Key).ToList())
        {
            macState.Ips.Remove(stale);
        }

        if (nowReady && macState.Ips.Count >= 3)
        {
            RaiseLocked(
                LanEventKinds.ArpMacClaimsManyIps,
                LanSeverity.Medium,
                adapter,
                $"MAC {frame.SenderMac} 在 10 分钟内声称了 {macState.Ips.Count} 个 IP。",
                macKey,
                frame.SenderMac,
                frame.SenderIp,
                frame.SenderMac,
                now);
        }

        // 应答里的 sender MAC 与帧源 MAC 不一致。
        if (frame.IsReply && nowReady
            && !string.Equals(frame.EthernetSourceMac, frame.SenderMac, StringComparison.OrdinalIgnoreCase))
        {
            RaiseLocked(
                LanEventKinds.ArpSenderMismatch,
                LanSeverity.Medium,
                adapter,
                $"ARP 应答的 sender MAC {frame.SenderMac} 与以太网源 {frame.EthernetSourceMac} 不一致。",
                ipKey,
                frame.SenderMac,
                frame.SenderIp,
                frame.SenderMac,
                now);
        }

        // 网关基线。
        var isGateway = _gatewayHints.Any(hint =>
            string.Equals(hint.Ip, frame.SenderIp, StringComparison.OrdinalIgnoreCase)
            && (string.IsNullOrEmpty(hint.Adapter)
                || string.Equals(hint.Adapter, adapter, StringComparison.OrdinalIgnoreCase)));

        if (isGateway)
        {
            _lastGatewayMac[ipKey] = frame.SenderMac;

            var gateway = _state.Gateways.FirstOrDefault(item =>
                string.Equals(item.Adapter, adapter, StringComparison.OrdinalIgnoreCase)
                && string.Equals(item.Ip, frame.SenderIp, StringComparison.OrdinalIgnoreCase));

            if (gateway is null)
            {
                _state.Gateways.Add(new LanGateway
                {
                    Adapter = adapter,
                    Ip = frame.SenderIp,
                    Mac = frame.SenderMac,
                    LearnedUtc = now,
                    Trusted = false,
                });

                StateChanged?.Invoke();
            }
            else if (!string.Equals(gateway.Mac, frame.SenderMac, StringComparison.OrdinalIgnoreCase))
            {
                if (nowReady)
                {
                    RaiseLocked(
                        LanEventKinds.ArpGatewayMacChanged,
                        LanSeverity.High,
                        adapter,
                        $"网关 {frame.SenderIp} 的 MAC 从 {gateway.Mac} 变为 {frame.SenderMac}。",
                        ipKey,
                        frame.SenderMac,
                        frame.SenderIp,
                        gateway.Mac,
                        now);

                    if (LanEnvironment.TryGetArpCacheMac(frame.SenderIp, out var cached)
                        && !string.Equals(cached, gateway.Mac, StringComparison.OrdinalIgnoreCase))
                    {
                        RaiseLocked(
                            LanEventKinds.ArpGatewayCacheMismatch,
                            LanSeverity.High,
                            adapter,
                            $"本机 ARP 缓存里的网关 MAC 是 {cached}，基线是 {gateway.Mac}。",
                            ipKey,
                            frame.SenderMac,
                            frame.SenderIp,
                            cached,
                            now);
                    }
                }
            }
        }

        // 免费 ARP 突发。
        if (frame.IsGratuitous)
        {
            if (!_gratuitous.TryGetValue(macKey, out var times))
            {
                times = new List<DateTime>();
                _gratuitous[macKey] = times;
            }

            times.Add(now);
            times.RemoveAll(time => now - time > GratuitousWindow);

            if (nowReady && times.Count > 20)
            {
                RaiseLocked(
                    LanEventKinds.ArpGratuitousBurst,
                    LanSeverity.Low,
                    adapter,
                    $"MAC {frame.SenderMac} 在 10 秒内发了 {times.Count} 个免费 ARP。",
                    macKey,
                    frame.SenderMac,
                    frame.SenderIp,
                    frame.SenderMac,
                    now);
            }
        }
    }

    private void ObserveDhcpLocked(DhcpMessage message, DateTime now)
    {
        var nowReady = _state.BaselineReadyUtc is not null;

        var server = _state.DhcpServers.FirstOrDefault(item =>
            string.Equals(item.ServerIp, message.ServerIp, StringComparison.OrdinalIgnoreCase));

        if (server is null)
        {
            server = new LanDhcpServer
            {
                ServerIp = message.ServerIp,
                Mac = message.SourceMac,
                Adapter = message.Adapter,
                Gateway = message.Router,
                Dns = message.Dns,
                LeaseSeconds = message.LeaseSeconds,
                FirstSeenUtc = now,
                Trusted = false,
            };

            _state.DhcpServers.Add(server);
            StateChanged?.Invoke();

            if (nowReady)
            {
                RaiseLocked(
                    LanEventKinds.DhcpUnexpectedServer,
                    LanSeverity.High,
                    message.Adapter,
                    $"出现基线外的 DHCP 服务器 {message.ServerIp}（MAC {message.SourceMac}）。",
                    message.ServerIp,
                    message.SourceMac,
                    message.ServerIp,
                    null,
                    now);
            }
        }
        else
        {
            if (nowReady)
            {
                if (!string.IsNullOrEmpty(message.Router)
                    && !string.IsNullOrEmpty(server.Gateway)
                    && !string.Equals(server.Gateway, message.Router, StringComparison.OrdinalIgnoreCase))
                {
                    RaiseLocked(
                        LanEventKinds.DhcpOptionMismatch,
                        LanSeverity.Medium,
                        message.Adapter,
                        $"DHCP 服务器 {server.ServerIp} 下发的网关从 {server.Gateway} 变为 {message.Router}。",
                        server.ServerIp,
                        message.SourceMac,
                        server.ServerIp,
                        null,
                        now);
                }

                if (message.LeaseSeconds is > 0 and < 60)
                {
                    RaiseLocked(
                        LanEventKinds.DhcpShortLease,
                        LanSeverity.Medium,
                        message.Adapter,
                        $"DHCP 服务器 {server.ServerIp} 下发 {message.LeaseSeconds} 秒的租期。",
                        server.ServerIp,
                        message.SourceMac,
                        server.ServerIp,
                        null,
                        now);
                }

                var gateway = _state.Gateways.FirstOrDefault(item =>
                    string.Equals(item.Adapter, message.Adapter, StringComparison.OrdinalIgnoreCase));

                if (gateway is not null
                    && !string.IsNullOrEmpty(server.Mac)
                    && !string.Equals(gateway.Mac, server.Mac, StringComparison.OrdinalIgnoreCase))
                {
                    RaiseLocked(
                        LanEventKinds.DhcpServerNotGateway,
                        LanSeverity.Medium,
                        message.Adapter,
                        $"DHCP 服务器 MAC {server.Mac} 与网关 MAC {gateway.Mac} 不一致。",
                        server.ServerIp,
                        message.SourceMac,
                        server.ServerIp,
                        null,
                        now);
                }
            }

            // 更新“最近一次”看到的参数（基线以第一次为准，但界面要显示最新值）。
            server.Mac = message.SourceMac;
            server.Adapter = message.Adapter;
            server.Gateway = message.Router ?? server.Gateway;
            server.Dns = message.Dns ?? server.Dns;
            server.LeaseSeconds = message.LeaseSeconds > 0 ? message.LeaseSeconds : server.LeaseSeconds;
            StateChanged?.Invoke();
        }

        // 同一网段出现多个 DHCP 服务器。
        if (!_serversByAdapter.TryGetValue(message.Adapter, out var servers))
        {
            servers = new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);
            _serversByAdapter[message.Adapter] = servers;
        }

        servers[message.ServerIp] = now;
        foreach (var stale in servers.Where(pair => now - pair.Value > ServerWindow).Select(pair => pair.Key).ToList())
        {
            servers.Remove(stale);
        }

        if (nowReady && servers.Count >= 2)
        {
            RaiseLocked(
                LanEventKinds.DhcpMultipleServers,
                LanSeverity.High,
                message.Adapter,
                $"同一网段出现 {servers.Count} 个 DHCP 服务器：{string.Join(", ", servers.Keys)}。",
                message.Adapter,
                message.SourceMac,
                message.ServerIp,
                null,
                now);
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

    private void UpdateBaselineReadyLocked(DateTime now)
    {
        if (_state.BaselineReadyUtc is not null)
        {
            return;
        }

        if (now - _learningStartedUtc >= LearningPeriod
            || (_state.Gateways.Count > 0 && _state.DhcpServers.Count > 0))
        {
            _state.BaselineReadyUtc = now;
            StateChanged?.Invoke();
        }
    }

    private void ClearCooldownLocked(string kind, string key)
    {
        _cooldown.Remove($"{kind}|{key}");
    }

    private int PruneBlocksLocked(DateTime now)
    {
        var removed = _state.Blocks.RemoveAll(item => item.UntilUtc <= now);

        if (removed > 0)
        {
            StateChanged?.Invoke();
        }

        return removed;
    }

    private static LanSettings Clone(LanSettings settings) => new()
    {
        RetentionDays = settings.RetentionDays,
        DhcpBlockEnabled = settings.DhcpBlockEnabled,
    };

    private sealed class IpState
    {
        public string LastMac = string.Empty;
        public List<DateTime> Changes = new();
    }

    private sealed class MacState
    {
        public Dictionary<string, DateTime> Ips = new(StringComparer.OrdinalIgnoreCase);
    }
}
