using System.Net;
using System.Net.Sockets;

namespace WinAppGuard.Core.Diagnostics.Lan;

/// <summary>
/// 4.5：LLMNR / NBNS / mDNS 投毒分析器（纯内存、可离线测试）。
///
/// 规则：
///   - 地址冲突：同一名称 60 秒内被不同来源解析到不同地址；
///   - 非请求应答：LLMNR/NBNS 应答没有 10 秒内对应的查询（按协议 + 名称 + TXID 匹配）；
///   - 一个来源应答多个名称：60 秒内 ≥5 个不同名称（Responder 特征，mDNS 不做）；
///   - WPAD：`wpad` / `wpad.*` 的应答来源不是网关/DNS；
///   - mDNS 冲突：只报地址冲突，不做“多名称”（Bonjour 设备天然如此）。
///
/// 冷却：10 分钟（mDNS 30 分钟），键 = 规则 + 名称/来源，避免刷屏。
/// </summary>
public sealed class NameResolutionAnalyzer
{
    private static readonly TimeSpan QueryWindow = TimeSpan.FromSeconds(10);
    private static readonly TimeSpan AnswerWindow = TimeSpan.FromSeconds(60);
    private static readonly TimeSpan Cooldown = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan MdnsCooldown = TimeSpan.FromMinutes(30);

    private const int MaxSources = 1024;
    private const int MaxNamesPerSource = 64;
    private const int MaxAnswersPerName = 8;
    private const int ManyNamesThreshold = 5;

    private readonly object _gate = new();
    private readonly Dictionary<string, DateTime> _queries = new(StringComparer.Ordinal);
    private readonly Dictionary<string, List<AnswerRecord>> _answers = new(StringComparer.Ordinal);
    private readonly Dictionary<string, SourceRecord> _sources = new(StringComparer.Ordinal);
    private readonly Dictionary<string, DateTime> _lastAlert = new(StringComparer.Ordinal);
    private HashSet<string> _knownServers = new(StringComparer.OrdinalIgnoreCase);

    private DateTime _nextPruneUtc = DateTime.MinValue;

    /// <summary>网关 / DNS 服务器：这些来源应答 WPAD 不算投毒。</summary>
    public void SetKnownServers(IEnumerable<string> servers)
    {
        lock (_gate)
        {
            _knownServers = servers
                .Where(item => !string.IsNullOrWhiteSpace(item))
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
        }
    }

    public List<NameAlert> Observe(NameMessage message, DateTime now)
    {
        var alerts = new List<NameAlert>();

        lock (_gate)
        {
            PruneLocked(now);

            var source = UpsertSourceLocked(message, now);

            if (!message.IsResponse)
            {
                _queries[$"{message.Protocol}|{message.Name}|{message.TransactionId}"] = now;
                return alerts;
            }

            source.Responses++;
            source.Names[message.Name] = now;
            TrimNamesLocked(source);

            var addressText = message.Addresses.Count == 0
                ? "（无地址）"
                : string.Join(", ", message.Addresses);
            source.LastAnswer = $"{message.Name} → {addressText}";

            var isMdns = message.Protocol == NameProtocols.Mdns;

            // 1) WPAD：wpad / wpad.* 的应答来自非网关、非 DNS。
            if (IsWpad(message.Name) && !_knownServers.Contains(message.SourceAddress))
            {
                alerts.Add(new NameAlert
                {
                    TimeUtc = now,
                    Kind = NameEventKinds.Wpad,
                    Severity = LanSeverity.High,
                    Protocol = message.Protocol,
                    Name = message.Name,
                    SourceAddress = message.SourceAddress,
                    SourceMac = message.SourceMac,
                    Detail = $"收到针对 {message.Name} 的 {NameProtocols.ToText(message.Protocol)} 应答" +
                             $"（来源 {message.SourceAddress}，地址 {addressText}），" +
                             "来源不是网关/DNS，疑似 WPAD 劫持。",
                });
            }

            // 2) 一个来源短时间应答多个名称：Responder 的典型行为（mDNS 不做）。
            if (!isMdns)
            {
                var distinctNames = source.Names.Count(pair => now - pair.Value <= AnswerWindow);

                if (distinctNames >= ManyNamesThreshold)
                {
                    alerts.Add(new NameAlert
                    {
                        TimeUtc = now,
                        Kind = NameEventKinds.ManyNames,
                        Severity = LanSeverity.High,
                        Protocol = message.Protocol,
                        Name = message.Name,
                        SourceAddress = message.SourceAddress,
                        SourceMac = message.SourceMac,
                        Detail = $"来源 {message.SourceAddress}" +
                                 (string.IsNullOrWhiteSpace(message.SourceMac) ? string.Empty : $"（{message.SourceMac}）") +
                                 $"在 60 秒内应答了 {distinctNames} 个不同名称，" +
                                 "符合 Responder 一类名称投毒工具的特征。",
                    });
                }
            }

            // 3) 同一名称被不同来源解析到不同地址。
            if (message.Addresses.Count > 0
                && _answers.TryGetValue(message.Name, out var history))
            {
                var conflict = history.FirstOrDefault(item =>
                    now - item.TimeUtc <= AnswerWindow
                    && !string.Equals(item.SourceAddress, message.SourceAddress, StringComparison.OrdinalIgnoreCase)
                    && !SameMac(item.SourceMac, message.SourceMac)
                    && item.Addresses.Count > 0
                    && AddressesConflict(item.Addresses, message.Addresses));

                if (conflict is not null)
                {
                    var otherText = string.Join(", ", conflict.Addresses);

                    alerts.Add(new NameAlert
                    {
                        TimeUtc = now,
                        Kind = isMdns ? NameEventKinds.MdnsConflict : NameEventKinds.Conflict,
                        Severity = isMdns ? LanSeverity.Medium : LanSeverity.High,
                        Protocol = message.Protocol,
                        Name = message.Name,
                        SourceAddress = message.SourceAddress,
                        SourceMac = message.SourceMac,
                        Detail = $"名称 {message.Name} 在 60 秒内被 {conflict.SourceAddress} 和 " +
                                 $"{message.SourceAddress} 解析到不同地址（{otherText} / {addressText}），" +
                                 "疑似名称解析投毒。",
                    });
                }
            }

            // 4) 非请求应答（LLMNR / NBNS）。
            if (!isMdns)
            {
                var queryKey = $"{message.Protocol}|{message.Name}|{message.TransactionId}";

                if (!_queries.TryGetValue(queryKey, out var queriedAt)
                    || now - queriedAt > QueryWindow)
                {
                    alerts.Add(new NameAlert
                    {
                        TimeUtc = now,
                        Kind = NameEventKinds.Unsolicited,
                        Severity = LanSeverity.Medium,
                        Protocol = message.Protocol,
                        Name = message.Name,
                        SourceAddress = message.SourceAddress,
                        SourceMac = message.SourceMac,
                        Detail = $"收到 {NameProtocols.ToText(message.Protocol)} 对 {message.Name} 的应答" +
                                 $"（来源 {message.SourceAddress}，地址 {addressText}），" +
                                 "但 10 秒内没有对应的查询。",
                    });
                }
            }

            if (message.Addresses.Count > 0)
            {
                if (!_answers.TryGetValue(message.Name, out var records))
                {
                    records = new List<AnswerRecord>();
                    _answers[message.Name] = records;
                }

                records.Add(new AnswerRecord(
                    now,
                    message.SourceAddress,
                    message.SourceMac,
                    message.Addresses.ToHashSet(StringComparer.OrdinalIgnoreCase)));

                if (records.Count > MaxAnswersPerName)
                {
                    records.RemoveRange(0, records.Count - MaxAnswersPerName);
                }
            }

            return FilterCooldownLocked(alerts, now);
        }
    }

    public List<NameSource> SnapshotSources()
    {
        lock (_gate)
        {
            return _sources.Values
                .OrderByDescending(item => item.LastSeenUtc)
                .Select(item => new NameSource
                {
                    Address = item.Address,
                    Mac = item.Mac,
                    Protocols = string.Join("/", item.Protocols.OrderBy(text => text, StringComparer.Ordinal)),
                    AnswerSummary = item.LastAnswer,
                    ResponseCount = item.Responses,
                    LastSeenUtc = item.LastSeenUtc,
                })
                .ToList();
        }
    }

    public void Clear()
    {
        lock (_gate)
        {
            _queries.Clear();
            _answers.Clear();
            _sources.Clear();
            _lastAlert.Clear();
            _nextPruneUtc = DateTime.MinValue;
        }
    }

    private List<NameAlert> FilterCooldownLocked(List<NameAlert> alerts, DateTime now)
    {
        var result = new List<NameAlert>();

        foreach (var alert in alerts)
        {
            var key = alert.Kind switch
            {
                NameEventKinds.ManyNames or NameEventKinds.Unsolicited =>
                    $"{alert.Kind}|{alert.SourceAddress}",
                NameEventKinds.Conflict or NameEventKinds.MdnsConflict => $"{alert.Kind}|{alert.Name}",
                _ => $"{alert.Kind}|{alert.Name}|{alert.SourceAddress}",
            };

            var cooldown = alert.Kind == NameEventKinds.MdnsConflict ? MdnsCooldown : Cooldown;

            if (_lastAlert.TryGetValue(key, out var last) && now - last < cooldown)
            {
                continue;
            }

            _lastAlert[key] = now;
            result.Add(alert);
        }

        return result;
    }

    private SourceRecord UpsertSourceLocked(NameMessage message, DateTime now)
    {
        if (!_sources.TryGetValue(message.SourceAddress, out var source))
        {
            if (_sources.Count >= MaxSources)
            {
                var oldest = _sources.OrderBy(pair => pair.Value.LastSeenUtc).First().Key;
                _sources.Remove(oldest);
            }

            source = new SourceRecord { Address = message.SourceAddress };
            _sources[message.SourceAddress] = source;
        }

        source.LastSeenUtc = now;

        if (!string.IsNullOrWhiteSpace(message.SourceMac))
        {
            source.Mac = message.SourceMac!;
        }

        source.Protocols.Add(NameProtocols.ToText(message.Protocol));
        return source;
    }

    private void TrimNamesLocked(SourceRecord source)
    {
        if (source.Names.Count <= MaxNamesPerSource)
        {
            return;
        }

        foreach (var key in source.Names
                     .OrderBy(pair => pair.Value)
                     .Take(source.Names.Count - MaxNamesPerSource)
                     .Select(pair => pair.Key)
                     .ToList())
        {
            source.Names.Remove(key);
        }
    }

    private void PruneLocked(DateTime now)
    {
        if (now < _nextPruneUtc)
        {
            return;
        }

        _nextPruneUtc = now.AddSeconds(10);

        foreach (var key in _queries
                     .Where(pair => now - pair.Value > QueryWindow)
                     .Select(pair => pair.Key)
                     .ToList())
        {
            _queries.Remove(key);
        }

        foreach (var name in _answers.Keys.ToList())
        {
            var list = _answers[name];
            list.RemoveAll(item => now - item.TimeUtc > AnswerWindow);

            if (list.Count == 0)
            {
                _answers.Remove(name);
            }
        }

        foreach (var key in _lastAlert
                     .Where(pair => now - pair.Value > MdnsCooldown)
                     .Select(pair => pair.Key)
                     .ToList())
        {
            _lastAlert.Remove(key);
        }
    }

    private static bool IsWpad(string name)
        => string.Equals(name, "wpad", StringComparison.OrdinalIgnoreCase)
           || name.StartsWith("wpad.", StringComparison.OrdinalIgnoreCase);

    private static bool SameMac(string? left, string? right)
        => !string.IsNullOrWhiteSpace(left)
           && !string.IsNullOrWhiteSpace(right)
           && string.Equals(left, right, StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// 只比较“两边都有”的地址族：同一个主机用 IPv4 和 IPv6 分别应答是正常现象，
    /// 不能因此报地址冲突。只有同族地址不一致才算冲突。
    /// </summary>
    private static bool AddressesConflict(
        IReadOnlyCollection<string> left,
        IReadOnlyCollection<string> right)
    {
        var leftV4 = left.Where(IsV4).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var rightV4 = right.Where(IsV4).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var leftV6 = left.Where(address => !IsV4(address)).ToHashSet(StringComparer.OrdinalIgnoreCase);
        var rightV6 = right.Where(address => !IsV4(address)).ToHashSet(StringComparer.OrdinalIgnoreCase);

        if (leftV4.Count > 0 && rightV4.Count > 0 && !leftV4.SetEquals(rightV4))
        {
            return true;
        }

        return leftV6.Count > 0
               && rightV6.Count > 0
               && !leftV6.SetEquals(rightV6);
    }

    private static bool IsV4(string address)
        => IPAddress.TryParse(address, out var parsed)
           && parsed.AddressFamily == AddressFamily.InterNetwork;

    private sealed class SourceRecord
    {
        public string Address = string.Empty;
        public string Mac = string.Empty;
        public HashSet<string> Protocols = new(StringComparer.Ordinal);
        public Dictionary<string, DateTime> Names = new(StringComparer.Ordinal);
        public int Responses;
        public string LastAnswer = string.Empty;
        public DateTime LastSeenUtc;
    }

    private sealed class AnswerRecord
    {
        public AnswerRecord(
            DateTime timeUtc,
            string sourceAddress,
            string? sourceMac,
            HashSet<string> addresses)
        {
            TimeUtc = timeUtc;
            SourceAddress = sourceAddress;
            SourceMac = sourceMac;
            Addresses = addresses;
        }

        public DateTime TimeUtc { get; }

        public string SourceAddress { get; }

        public string? SourceMac { get; }

        public HashSet<string> Addresses { get; }
    }
}
