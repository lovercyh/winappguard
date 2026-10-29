using System.Net;

namespace WinAppGuard.Core.Diagnostics.Lan;

/// <summary>
/// 4.3：DNS 应答校验与绕过检测（纯逻辑，可离线测试）。
///
/// 只跟踪“本机发出的查询 → 收到的应答”，不保存报文、不阻断。
/// 规则：应答来源不符、事务 ID 不符、应答域名不符、NXDOMAIN 带答案、
/// 冲突应答、TTL 异常、DNS 服务器非网关、明文 DNS 绕过。
/// </summary>
public sealed class DnsAnalyzer
{
    public const int MaxEvents = 500;

    private static readonly TimeSpan LearningPeriod = TimeSpan.FromMinutes(2);
    private static readonly TimeSpan QueryTimeout = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan AnsweredRetention = TimeSpan.FromSeconds(2);
    private static readonly TimeSpan RecentQueryWindow = TimeSpan.FromSeconds(2);
    private static readonly TimeSpan Cooldown = TimeSpan.FromMinutes(10);
    private const int MaxPending = 4096;
    private const int MaxObservedServers = 256;
    private const int MaxCooldowns = 4096;

    private readonly object _gate = new();
    private readonly LanState _state;
    private readonly List<LanEvent> _events = new();
    private readonly Dictionary<string, DateTime> _cooldown = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, PendingQuery> _pending = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, DateTime> _recent = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, ObservedServer> _observed = new(StringComparer.OrdinalIgnoreCase);

    private List<DnsServerHint> _configured = new();
    private List<LanGateway> _gateways = new();
    private DateTime _learningStartedUtc;

    public DnsAnalyzer(LanState state, DateTime now)
    {
        _state = state;
        _learningStartedUtc = now;
    }

    public Action<LanEvent>? EventObserved { get; set; }

    public Action? StateChanged { get; set; }

    public bool BaselineReady
    {
        get { lock (_gate) { return _state.DnsBaselineReadyUtc is not null; } }
    }

    public void UpdateConfiguredServers(IEnumerable<DnsServerHint> hints)
    {
        lock (_gate)
        {
            _configured = hints.ToList();
            UpdateBaselineReadyLocked(DateTime.UtcNow);
        }
    }

    public void Observe(DnsMessage message, DateTime now)
    {
        if (string.IsNullOrWhiteSpace(message.QuestionName)
            || IsLoopback(message.ClientAddress)
            || IsLoopback(message.ServerAddress))
        {
            return;
        }

        lock (_gate)
        {
            PruneLocked(now);

            if (!_observed.ContainsKey(message.ServerAddress)
                && _observed.Count >= MaxObservedServers)
            {
                var oldest = _observed
                    .OrderBy(pair => pair.Value.LastSeenUtc)
                    .Select(pair => pair.Key)
                    .FirstOrDefault();

                if (oldest is not null)
                {
                    _observed.Remove(oldest);
                }
            }

            // 只有应答的以太网源 MAC 才属于服务器；请求的源 MAC 是客户端，
            // 目的 MAC 可能是路由器，因此查询侧只记录地址与时间。
            if (message.IsResponse)
            {
                _observed[message.ServerAddress] = new ObservedServer
                {
                    Adapter = message.Adapter,
                    Mac = message.SourceMac,
                    LastSeenUtc = now,
                };
            }
            else
            {
                _observed[message.ServerAddress] = new ObservedServer
                {
                    Adapter = message.Adapter,
                    Mac = _observed.TryGetValue(message.ServerAddress, out var existing)
                        ? existing.Mac
                        : null,
                    LastSeenUtc = now,
                };
            }

            if (!message.IsResponse)
            {
                ObserveQueryLocked(message, now);
            }
            else
            {
                ObserveResponseLocked(message, now);
            }

            UpdateBaselineReadyLocked(now);
        }
    }

    public DnsSecuritySnapshot Snapshot()
    {
        lock (_gate)
        {
            var servers = new List<DnsServerView>();
            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var hint in _configured)
            {
                if (!seen.Add(hint.Address))
                {
                    continue;
                }

                servers.Add(new DnsServerView
                {
                    Address = hint.Address,
                    Adapter = hint.Adapter,
                    Source = "configured",
                    Mac = _observed.TryGetValue(hint.Address, out var observed) ? observed.Mac : null,
                    Trusted = IsTrustedLocked(hint.Address),
                });
            }

            foreach (var pair in _observed.OrderByDescending(pair => pair.Value.LastSeenUtc))
            {
                if (!seen.Add(pair.Key))
                {
                    continue;
                }

                servers.Add(new DnsServerView
                {
                    Address = pair.Key,
                    Adapter = pair.Value.Adapter,
                    Source = "observed",
                    Mac = pair.Value.Mac,
                    Trusted = IsTrustedLocked(pair.Key),
                });
            }

            // 已信任但当前既没配置也没观察到的服务器也要列出来，否则用户无法取消信任。
            foreach (var address in _state.TrustedDnsServers)
            {
                if (!seen.Add(address))
                {
                    continue;
                }

                servers.Add(new DnsServerView
                {
                    Address = address,
                    Adapter = string.Empty,
                    Source = "trusted",
                    Mac = null,
                    Trusted = true,
                });
            }

            return new DnsSecuritySnapshot
            {
                Events = _events.ToList(),
                Servers = servers,
                BaselineReady = _state.DnsBaselineReadyUtc is not null,
                BaselineUtc = _state.DnsBaselineReadyUtc,
                ConfiguredCount = _configured.Select(item => item.Address)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .Count(),
            };
        }
    }

    public bool Trust(string address, bool enabled, DateTime now)
    {
        if (!IPAddress.TryParse(address, out var parsed))
        {
            return false;
        }

        var normalized = parsed.ToString();

        lock (_gate)
        {
            var index = _state.TrustedDnsServers.FindIndex(item =>
                string.Equals(item, normalized, StringComparison.OrdinalIgnoreCase));

            if (enabled && index < 0)
            {
                _state.TrustedDnsServers.Add(normalized);
            }
            else if (!enabled && index >= 0)
            {
                _state.TrustedDnsServers.RemoveAt(index);
            }

            ClearCooldownsForServerLocked(normalized);

            StateChanged?.Invoke();
            return true;
        }
    }

    private void ClearCooldownsForServerLocked(string address)
    {
        var suffix = "|" + address;

        foreach (var key in _cooldown.Keys
                     .Where(item => item.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
                     .ToList())
        {
            _cooldown.Remove(key);
        }
    }

    public void ClearEvents()
    {
        lock (_gate)
        {
            _events.Clear();
        }
    }

    public int EventCount
    {
        get { lock (_gate) { return _events.Count; } }
    }

    /// <summary>4.3：用户信任的 DNS 服务器（用于落盘与界面）。</summary>
    public List<string> TrustedServers
    {
        get { lock (_gate) { return _state.TrustedDnsServers.ToList(); } }
    }

    public DateTime? BaselineUtc
    {
        get { lock (_gate) { return _state.DnsBaselineReadyUtc; } }
    }

    public int ConfiguredCount
    {
        get
        {
            lock (_gate)
            {
                return _configured.Select(item => item.Address)
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .Count();
            }
        }
    }

    /// <summary>
    /// 4.3：刷新网关基线副本（由 LanHost 周期调用）。
    ///
    /// DNS 分析与 LAN 分析共享 LanState，但各自有锁；这里复制一份，
    /// 避免在抓包线程上无锁遍历另一个线程正在修改的列表。
    /// </summary>
    public void UpdateGatewayBaselines(IEnumerable<LanGateway> gateways)
    {
        lock (_gate)
        {
            _gateways = gateways
                .Select(item => new LanGateway
                {
                    Adapter = item.Adapter,
                    Ip = item.Ip,
                    Mac = item.Mac,
                    LearnedUtc = item.LearnedUtc,
                    Trusted = item.Trusted,
                })
                .ToList();
        }
    }

    private void ObserveQueryLocked(DnsMessage message, DateTime now)
    {
        var key = PendingKey(message);

        if (_pending.Count >= MaxPending)
        {
            var oldest = _pending.OrderBy(pair => pair.Value.SentUtc).First().Key;
            _pending.Remove(oldest);
        }

        _pending[key] = new PendingQuery
        {
            Name = message.QuestionName,
            Type = message.QuestionType,
            Server = message.ServerAddress,
            SentUtc = now,
        };

        _recent[RecentKey(message)] = now;

        if (IsConfiguredOrTrustedLocked(message.ServerAddress))
        {
            return;
        }

        RaiseLocked(
            LanEventKinds.DnsPlaintextBypass,
            LanSeverity.Medium,
            message.Adapter,
            $"明文 DNS 查询发往非配置服务器 {message.ServerAddress}（域名 {message.QuestionName}）。",
            message.ServerAddress,
            message.SourceMac,
            message.ServerAddress,
            null,
            now);
    }

    private void ObserveResponseLocked(DnsMessage message, DateTime now)
    {
        CheckServerMacLocked(message, now);

        // 用户信任的服务器不再做应答侧告警（避免把合法 CDN / 上游怪癖当成投毒）。
        var trusted = IsTrustedLocked(message.ServerAddress);
        var key = PendingKey(message);

        if (!_pending.TryGetValue(key, out var pending))
        {
            // 事务 ID 对不上任何未完成请求，但域名与最近的查询一致 → 盲投毒嫌疑。
            var recentKey = RecentKey(message);

            if (!trusted
                && _recent.TryGetValue(recentKey, out var seen)
                && now - seen <= RecentQueryWindow)
            {
                RaiseLocked(
                    LanEventKinds.DnsTransactionMismatch,
                    LanSeverity.High,
                    message.Adapter,
                    $"DNS 应答的事务 ID 与请求不一致（域名 {message.QuestionName}，来源 {message.ServerAddress}）。",
                    message.ServerAddress,
                    message.SourceMac,
                    message.ServerAddress,
                    null,
                    now);
            }

            return;
        }

        if (!trusted
            && !string.Equals(pending.Server, message.ServerAddress, StringComparison.OrdinalIgnoreCase))
        {
            RaiseLocked(
                LanEventKinds.DnsResponseUnexpectedServer,
                LanSeverity.High,
                message.Adapter,
                $"查询 {pending.Name} 发往 {pending.Server}，应答却来自 {message.ServerAddress}。",
                $"{pending.Name}|{message.ServerAddress}",
                message.SourceMac,
                message.ServerAddress,
                null,
                now);
        }

        if (!trusted
            && (!string.Equals(pending.Name, message.QuestionName, StringComparison.OrdinalIgnoreCase)
                || pending.Type != message.QuestionType))
        {
            RaiseLocked(
                LanEventKinds.DnsAnswerNameMismatch,
                LanSeverity.High,
                message.Adapter,
                $"请求 {pending.Name}，应答里的域名却是 {message.QuestionName}。",
                pending.Name,
                message.SourceMac,
                message.ServerAddress,
                null,
                now);
        }

        if (!trusted && !message.Truncated && message.ResponseCode == 3 && message.Answers.Count > 0)
        {
            RaiseLocked(
                LanEventKinds.DnsNxdomainWithAnswer,
                LanSeverity.High,
                message.Adapter,
                $"NXDOMAIN 应答却带了 {message.Answers.Count} 条答案（域名 {pending.Name}）。",
                pending.Name,
                message.SourceMac,
                message.ServerAddress,
                null,
                now);
        }

        if (!trusted
            && !pending.TtlReported
            && !message.Truncated
            && message.Answers.Any(answer => answer.Ttl < 10))
        {
            pending.TtlReported = true;

            RaiseLocked(
                LanEventKinds.DnsTtlSuspicious,
                LanSeverity.Low,
                message.Adapter,
                $"应答 {pending.Name} 的 TTL 异常短（{message.Answers.Min(answer => answer.Ttl)} 秒）。",
                pending.Name,
                message.SourceMac,
                message.ServerAddress,
                null,
                now);
        }

        var set = string.Join(
            ",",
            message.Answers
                .Where(answer => answer.Type is 1 or 28 && answer.Value is not null)
                .Select(answer => $"{answer.Type}:{answer.Value}")
                .OrderBy(value => value, StringComparer.Ordinal));

        if (!message.Truncated && !trusted && set.Length > 0)
        {
            if (pending.AnswerSets.Count > 0
                && !pending.AnswerSets.Contains(set, StringComparer.Ordinal))
            {
                RaiseLocked(
                    LanEventKinds.DnsConflictingAnswers,
                    LanSeverity.Medium,
                    message.Adapter,
                    $"同一请求 {pending.Name} 在 2 秒内收到不同应答。",
                    pending.Name,
                    message.SourceMac,
                    message.ServerAddress,
                    null,
                    now);
            }

            if (pending.AnswerSets.Count < 4)
            {
                pending.AnswerSets.Add(set);
            }
        }

        pending.AnsweredUtc = now;
    }

    private void CheckServerMacLocked(DnsMessage message, DateTime now)
    {
        if (string.IsNullOrWhiteSpace(message.SourceMac)
            || IsTrustedLocked(message.ServerAddress))
        {
            return;
        }

        var gateway = _gateways.FirstOrDefault(item =>
            string.Equals(item.Adapter, message.Adapter, StringComparison.OrdinalIgnoreCase));

        if (gateway is null
            || string.Equals(gateway.Mac, message.SourceMac, StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        RaiseLocked(
            LanEventKinds.DnsServerNotGateway,
            LanSeverity.Medium,
            message.Adapter,
            $"DNS 服务器 {message.ServerAddress} 的 MAC {message.SourceMac} 与网关 MAC {gateway.Mac} 不一致。",
            message.ServerAddress,
            message.SourceMac,
            message.ServerAddress,
            null,
            now);
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
        if (_state.DnsBaselineReadyUtc is null)
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
        if (_state.DnsBaselineReadyUtc is not null)
        {
            return;
        }

        if (_configured.Count > 0 || now - _learningStartedUtc >= LearningPeriod)
        {
            _state.DnsBaselineReadyUtc = now;
            StateChanged?.Invoke();
        }
    }

    private bool IsConfiguredOrTrustedLocked(string address)
    {
        if (IsTrustedLocked(address))
        {
            return true;
        }

        return _configured.Any(item =>
            string.Equals(item.Address, address, StringComparison.OrdinalIgnoreCase));
    }

    private bool IsTrustedLocked(string address)
        => _state.TrustedDnsServers.Any(item =>
            string.Equals(item, address, StringComparison.OrdinalIgnoreCase));

    private void PruneLocked(DateTime now)
    {
        foreach (var pair in _pending.ToList())
        {
            var age = now - pair.Value.SentUtc;

            if (pair.Value.AnsweredUtc is { } answered)
            {
                if (now - answered > AnsweredRetention)
                {
                    _pending.Remove(pair.Key);
                }

                continue;
            }

            if (age > QueryTimeout)
            {
                _pending.Remove(pair.Key);
            }
        }

        if (_recent.Count > 8192)
        {
            foreach (var pair in _recent.Where(pair => now - pair.Value > RecentQueryWindow).Select(pair => pair.Key).ToList())
            {
                _recent.Remove(pair);
            }
        }

        // 冷却表按（规则 + 关键值）累积；过期的清掉，避免长跑后无限增长。
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
    }

    private static string PendingKey(DnsMessage message)
        => $"{message.Adapter}|{message.ClientAddress}|{message.ClientPort}|{message.TransactionId}";

    private static string RecentKey(DnsMessage message)
        => $"{message.Adapter}|{message.ClientAddress}|{message.ClientPort}|{message.QuestionName}|{message.QuestionType}";

    private static bool IsLoopback(string address)
        => IPAddress.TryParse(address, out var parsed) && IPAddress.IsLoopback(parsed);

    private sealed class PendingQuery
    {
        public string Name = string.Empty;
        public ushort Type;
        public string Server = string.Empty;
        public DateTime SentUtc;
        public DateTime? AnsweredUtc;
        public bool TtlReported;
        public List<string> AnswerSets = new();
    }

    private sealed class ObservedServer
    {
        public string Adapter = string.Empty;
        public string? Mac;
        public DateTime LastSeenUtc;
    }
}
