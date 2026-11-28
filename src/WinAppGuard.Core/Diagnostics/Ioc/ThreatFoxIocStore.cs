using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using WinAppGuard.Core.Diagnostics.Ids;

namespace WinAppGuard.Core.Diagnostics.Ioc;

/// <summary>
/// 6.0：ThreatFox 本地 IOC 库。
///
/// 数据来自构建期快照（<c>threatfox/full.csv</c>），运行时只读、不联网。
/// 仅保存匹配所需的最小元数据：值、置信度、恶意家族、威胁类型、ioc_id。
///
/// 匹配范围：
///   - ip:port      → 出站 IPv4 精确匹配
///   - domain       → DNS 查询精确匹配（含一级父域）
///   - url          → 取主机名后按 domain 匹配
///   - md5/sha1/sha256 → 供文件扫描调用（当前仅提供 API）
///
/// 只产生告警，不做阻断；命中受冷却时间约束，避免同一目标刷屏。
/// </summary>
public static class ThreatFoxIocStore
{
    private const int KindIp = 0;
    private const int KindDomain = 1;
    private const int KindUrl = 2;
    private const int KindMd5 = 3;
    private const int KindSha1 = 4;
    private const int KindSha256 = 5;

    private const int ThreatUnknown = 0;
    private const int ThreatBotnetC2 = 1;
    private const int ThreatMalwareDownload = 2;
    private const int ThreatPayloadDelivery = 3;
    private const int ThreatPayload = 4;
    private const int ThreatOther = 5;

    private static readonly string[] ThreatNames =
    {
        "unknown",
        "botnet_cc",
        "malware_download",
        "payload_delivery",
        "payload",
        "other",
    };

    private static readonly TimeSpan HitCooldown = TimeSpan.FromMinutes(10);

    private static readonly object Gate = new();

    private static Dictionary<uint, Entry> _ip = new();
    private static Dictionary<string, Entry> _domain = new(StringComparer.OrdinalIgnoreCase);
    private static Dictionary<string, Entry> _hash = new(StringComparer.Ordinal);
    private static List<string> _malware = new() { "Unknown" };
    private static Dictionary<string, ushort> _malwareIndex = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Unknown"] = 0,
    };

    private static readonly Queue<IocHit> Pending = new();
    private static readonly Dictionary<string, DateTime> Cooldown = new(StringComparer.OrdinalIgnoreCase);

    private static bool _loaded;
    private static bool _active;
    private static int _minConfidence = 75;
    private static DateTime? _sourceUtc;
    private static string? _lastError;
    private static long _matchCount;
    private static DateTime? _lastMatchUtc;

    /// <summary>支持的置信度档位。</summary>
    public static int NormalizeConfidence(int value) => value switch
    {
        <= 50 => 50,
        <= 75 => 75,
        <= 90 => 90,
        _ => 100,
    };

    /// <summary>加载 CSV 快照；失败时保留上一次成功的数据。</summary>
    public static bool Load(string path, int minConfidence)
    {
        minConfidence = NormalizeConfidence(minConfidence);

        try
        {
            if (!File.Exists(path))
            {
                lock (Gate)
                {
                    _active = false;
                    _lastError = $"未找到 IOC 数据文件：{path}";
                }

                return false;
            }

            var ip = new Dictionary<uint, Entry>(45_000);
            var domain = new Dictionary<string, Entry>(45_000, StringComparer.OrdinalIgnoreCase);
            var hash = new Dictionary<string, Entry>(75_000, StringComparer.Ordinal);
            var malware = new List<string> { "Unknown" };
            var malwareIndex = new Dictionary<string, ushort>(StringComparer.OrdinalIgnoreCase)
            {
                ["Unknown"] = 0,
            };
            DateTime? sourceUtc = null;

            foreach (var line in File.ReadLines(path, Encoding.UTF8))
            {
                if (line.Length == 0)
                {
                    continue;
                }

                if (line[0] == '#')
                {
                    sourceUtc ??= TryParseSourceTime(line);
                    continue;
                }

                var fields = ParseCsvLine(line);

                if (fields.Count < 10)
                {
                    continue;
                }

                var type = fields[3];

                if (type.Length == 0 || type == "ioc_type")
                {
                    continue;
                }

                if (!int.TryParse(fields[9], NumberStyles.Integer, CultureInfo.InvariantCulture, out var confidence)
                    || confidence < minConfidence)
                {
                    continue;
                }

                var payload = Pack(
                    confidence,
                    InternMalware(fields[7], malware, malwareIndex),
                    KindOf(type),
                    ThreatOf(fields[4]));

                var iocId = uint.TryParse(fields[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out var id)
                    ? id
                    : 0u;

                var entry = new Entry(payload, iocId);
                var value = fields[2];

                switch (type)
                {
                    case "ip:port":
                        if (TryParseIp(value, out var address))
                        {
                            Upsert(ip, address, entry);
                        }

                        break;

                    case "domain":
                    {
                        var name = NormalizeDomain(value);
                        if (name.Length > 0 && !IsAllowlisted(name))
                        {
                            Upsert(domain, name, entry);
                        }

                        break;
                    }

                    case "url":
                    {
                        if (Uri.TryCreate(value, UriKind.Absolute, out var uri))
                        {
                            if (IPAddress.TryParse(uri.Host, out var hostIp)
                                && hostIp.AddressFamily == AddressFamily.InterNetwork)
                            {
                                Upsert(ip, ToUInt(hostIp), entry);
                            }
                            else
                            {
                                var name = NormalizeDomain(uri.Host);
                                if (name.Length > 0 && !IsAllowlisted(name))
                                {
                                    Upsert(domain, name, entry);
                                }
                            }
                        }

                        break;
                    }

                    case "md5_hash":
                    case "sha1_hash":
                    case "sha256_hash":
                    {
                        var digest = value.Trim().ToLowerInvariant();
                        if (IsHex(digest))
                        {
                            Upsert(hash, digest, entry);
                        }

                        break;
                    }
                }
            }

            lock (Gate)
            {
                _ip = ip;
                _domain = domain;
                _hash = hash;
                _malware = malware;
                _malwareIndex = malwareIndex;
                _minConfidence = minConfidence;
                _sourceUtc = sourceUtc;
                _loaded = ip.Count + domain.Count + hash.Count > 0;
                _active = _loaded;
                _lastError = _loaded ? null : "IOC 文件没有可用条目。";
                Pending.Clear();
                Cooldown.Clear();
                _matchCount = 0;
                _lastMatchUtc = null;
            }

            return _loaded;
        }
        catch (Exception ex)
        {
            lock (Gate)
            {
                _active = false;
                _lastError = $"加载 IOC 失败：{ex.Message}";
            }

            return false;
        }
    }

    /// <summary>关闭 IOC 匹配并释放索引。</summary>
    public static void Unload()
    {
        lock (Gate)
        {
            _ip = new Dictionary<uint, Entry>();
            _domain = new Dictionary<string, Entry>(StringComparer.OrdinalIgnoreCase);
            _hash = new Dictionary<string, Entry>(StringComparer.Ordinal);
            _loaded = false;
            _active = false;
            _lastError = null;
            Pending.Clear();
            Cooldown.Clear();
        }
    }

    public static void ObserveFlow(NetworkFlowObservation flow)
    {
        if (!flow.IsOutbound || flow.Pid <= 0)
        {
            return;
        }

        if (!IPAddress.TryParse(flow.RemoteAddress, out var address)
            || address.AddressFamily != AddressFamily.InterNetwork)
        {
            return;
        }

        var key = ToUInt(address);

        lock (Gate)
        {
            if (!_active || !_ip.TryGetValue(key, out var entry))
            {
                return;
            }

            RecordLocked(
                KindIp,
                $"{flow.RemoteAddress}:{flow.RemotePort}",
                flow.Pid,
                flow.TimeUtc,
                entry);
        }
    }

    public static void ObserveDns(NetworkDnsObservation dns)
    {
        if (dns.Pid <= 0)
        {
            return;
        }

        var name = NormalizeDomain(dns.QueryName);

        if (name.Length == 0)
        {
            return;
        }

        lock (Gate)
        {
            if (!_active)
            {
                return;
            }

            if (TryMatchDomainLocked(name, out var entry))
            {
                RecordLocked(KindDomain, name, dns.Pid, dns.TimeUtc, entry);
                return;
            }

            // 一级父域：IOC 是 evil.com，查询 a.evil.com 也算命中。
            var dot = name.IndexOf('.');

            if (dot > 0 && dot < name.Length - 1)
            {
                var parent = name[(dot + 1)..];

                if (parent.IndexOf('.') > 0 && TryMatchDomainLocked(parent, out entry))
                {
                    RecordLocked(KindDomain, name, dns.Pid, dns.TimeUtc, entry);
                }
            }
        }
    }

    /// <summary>文件哈希查询（供后续文件扫描接入）。</summary>
    public static bool ContainsHash(string hash)
    {
        var digest = hash.Trim().ToLowerInvariant();

        if (!IsHex(digest))
        {
            return false;
        }

        lock (Gate)
        {
            return _active && _hash.ContainsKey(digest);
        }
    }

    /// <summary>取出待上报的命中（由 IDS 主循环调用）。</summary>
    public static List<IocHit> Drain()
    {
        lock (Gate)
        {
            if (Pending.Count == 0)
            {
                return new List<IocHit>();
            }

            var hits = Pending.ToList();
            Pending.Clear();
            return hits;
        }
    }

    public static IocSnapshot Snapshot()
    {
        lock (Gate)
        {
            return new IocSnapshot(
                _loaded,
                _lastError,
                _sourceUtc,
                _minConfidence,
                _ip.Count,
                _domain.Count,
                _hash.Count,
                _matchCount,
                _lastMatchUtc);
        }
    }

    // ---------------- 内部 ----------------

    private static bool TryMatchDomainLocked(string name, out Entry entry)
    {
        if (_domain.TryGetValue(name, out entry))
        {
            return true;
        }

        if (IsAllowlisted(name))
        {
            entry = default;
            return false;
        }

        return false;
    }

    private static void RecordLocked(
        int kind,
        string target,
        int pid,
        DateTime timeUtc,
        Entry entry)
    {
        var dedup = $"{kind}|{target}|{pid}";

        if (Cooldown.TryGetValue(dedup, out var until) && until > timeUtc)
        {
            return;
        }

        if (Cooldown.Count > 4096)
        {
            PruneCooldownLocked(timeUtc);
        }

        Cooldown[dedup] = timeUtc.Add(HitCooldown);

        if (Pending.Count >= 512)
        {
            Pending.Dequeue();
        }

        var confidence = (int)(entry.Payload & 0x7F);
        var malwareIndex = (int)((entry.Payload >> 7) & 0xFFFF);
        var threat = (int)((entry.Payload >> 26) & 0x07);
        var malware = malwareIndex < _malware.Count ? _malware[malwareIndex] : "Unknown";

        Pending.Enqueue(new IocHit(
            timeUtc,
            pid,
            kind == KindIp ? "ip" : "domain",
            target,
            confidence,
            malware,
            threat < ThreatNames.Length ? ThreatNames[threat] : "unknown",
            entry.IocId == 0
                ? "https://threatfox.abuse.ch/"
                : $"https://threatfox.abuse.ch/ioc/{entry.IocId}/"));

        _matchCount++;
        _lastMatchUtc = timeUtc;
    }

    private static void PruneCooldownLocked(DateTime nowUtc)
    {
        var expired = Cooldown
            .Where(pair => pair.Value <= nowUtc)
            .Select(pair => pair.Key)
            .ToList();

        foreach (var key in expired)
        {
            Cooldown.Remove(key);
        }
    }

    private static uint Pack(int confidence, ushort malware, int kind, int threat)
        => (uint)((confidence & 0x7F)
                  | ((malware & 0xFFFF) << 7)
                  | ((kind & 0x07) << 23)
                  | ((threat & 0x07) << 26));

    private static int KindOf(string type) => type switch
    {
        "ip:port" => KindIp,
        "domain" => KindDomain,
        "url" => KindUrl,
        "md5_hash" => KindMd5,
        "sha1_hash" => KindSha1,
        _ => KindSha256,
    };

    private static int ThreatOf(string threat) => threat switch
    {
        "botnet_cc" => ThreatBotnetC2,
        "malware_download" => ThreatMalwareDownload,
        "payload_delivery" => ThreatPayloadDelivery,
        "payload" => ThreatPayload,
        "unknown" => ThreatUnknown,
        _ => ThreatOther,
    };

    private static ushort InternMalware(
        string name,
        List<string> pool,
        Dictionary<string, ushort> index)
    {
        var value = string.IsNullOrWhiteSpace(name) || name == "None" ? "Unknown" : name.Trim();

        if (index.TryGetValue(value, out var existing))
        {
            return existing;
        }

        if (pool.Count >= ushort.MaxValue)
        {
            return 0;
        }

        var id = (ushort)pool.Count;
        pool.Add(value);
        index[value] = id;
        return id;
    }

    private static void Upsert<TKey>(Dictionary<TKey, Entry> map, TKey key, Entry entry)
        where TKey : notnull
    {
        if (map.TryGetValue(key, out var current)
            && (current.Payload & 0x7F) >= (entry.Payload & 0x7F))
        {
            return;
        }

        map[key] = entry;
    }

    private static bool TryParseIp(string value, out uint address)
    {
        address = 0;

        var text = value.Trim();

        if (text.Length == 0)
        {
            return false;
        }

        string host;

        if (text[0] == '[')
        {
            var end = text.IndexOf(']');

            if (end <= 1)
            {
                return false;
            }

            host = text[1..end];
        }
        else
        {
            var colon = text.LastIndexOf(':');

            if (colon > 0 && text.IndexOf(':') == colon)
            {
                host = text[..colon];
            }
            else if (colon < 0)
            {
                host = text;
            }
            else
            {
                // 多个冒号：按不带端口的 IPv6 处理，IPv4 索引不收录。
                return false;
            }
        }

        if (!IPAddress.TryParse(host, out var ip)
            || ip.AddressFamily != AddressFamily.InterNetwork)
        {
            return false;
        }

        var bytes = ip.GetAddressBytes();

        // 私网、环回、链路本地、组播不参与匹配。
        if (bytes[0] is 0 or 10 or 127
            || (bytes[0] == 172 && bytes[1] is >= 16 and <= 31)
            || (bytes[0] == 192 && bytes[1] == 168)
            || (bytes[0] == 169 && bytes[1] == 254)
            || bytes[0] >= 224)
        {
            return false;
        }

        address = ToUInt(ip);
        return true;
    }

    private static uint ToUInt(IPAddress address)
    {
        var bytes = address.GetAddressBytes();
        return ((uint)bytes[0] << 24)
               | ((uint)bytes[1] << 16)
               | ((uint)bytes[2] << 8)
               | bytes[3];
    }

    private static string NormalizeDomain(string value)
    {
        var text = value.Trim();

        if (text.StartsWith("*.", StringComparison.Ordinal))
        {
            text = text[2..];
        }

        text = text.TrimEnd('.').ToLowerInvariant();

        if (text.Length is 0 or > 253)
        {
            return string.Empty;
        }

        if (text.Contains('/') || text.Contains(' ') || text.Contains(':'))
        {
            return string.Empty;
        }

        return text;
    }

    private static bool IsHex(string value)
    {
        if (value.Length is not (32 or 40 or 64))
        {
            return false;
        }

        foreach (var c in value)
        {
            if (!char.IsAsciiHexDigit(c))
            {
                return false;
            }
        }

        return true;
    }

    private static DateTime? TryParseSourceTime(string line)
    {
        var marker = line.IndexOf("Last updated:", StringComparison.OrdinalIgnoreCase);

        if (marker < 0)
        {
            return null;
        }

        var text = line[(marker + "Last updated:".Length)..]
            .Trim()
            .TrimEnd('#')
            .Trim();

        if (text.EndsWith("UTC", StringComparison.OrdinalIgnoreCase))
        {
            text = text[..^3].Trim();
        }

        return DateTime.TryParse(
            text,
            CultureInfo.InvariantCulture,
            DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal,
            out var value)
            ? value
            : null;
    }

    /// <summary>
    /// 解析一行 CSV：支持引号、转义引号和逗号后空格。
    /// 字段数固定为 15，但这里不依赖表头。
    /// </summary>
    private static List<string> ParseCsvLine(string line)
    {
        var fields = new List<string>(16);
        var builder = new StringBuilder(64);
        var quoted = false;

        for (var i = 0; i < line.Length; i++)
        {
            var c = line[i];

            if (quoted)
            {
                if (c == '"')
                {
                    if (i + 1 < line.Length && line[i + 1] == '"')
                    {
                        builder.Append('"');
                        i++;
                    }
                    else
                    {
                        quoted = false;
                    }
                }
                else
                {
                    builder.Append(c);
                }

                continue;
            }

            switch (c)
            {
                case '"':
                    quoted = true;
                    break;
                case ',':
                    fields.Add(builder.ToString().Trim());
                    builder.Clear();
                    break;
                default:
                    builder.Append(c);
                    break;
            }
        }

        fields.Add(builder.ToString().Trim());
        return fields;
    }

    /// <summary>
    /// 硬白名单：操作系统更新、证书吊销、遥测等基础设施。
    /// 命中这些域名时不告警，避免把正常系统行为当成 C2。
    /// </summary>
    private static readonly string[] AllowlistedSuffixes =
    {
        "microsoft.com",
        "windows.com",
        "windowsupdate.com",
        "microsoftonline.com",
        "msedge.net",
        "azureedge.net",
        "live.com",
        "msn.com",
        "bing.com",
        "office.com",
        "office365.com",
        "sharepoint.com",
        "apple.com",
        "icloud.com",
        "mzstatic.com",
        "google.com",
        "gstatic.com",
        "googleapis.com",
        "gvt1.com",
        "gvt2.com",
        "mozilla.org",
        "mozilla.net",
        "digicert.com",
        "letsencrypt.org",
        "globalsign.com",
        "sectigo.com",
        "verisign.com",
        "symantec.com",
        "adobe.com",
        "java.com",
    };

    private static bool IsAllowlisted(string domain)
    {
        foreach (var suffix in AllowlistedSuffixes)
        {
            if (domain.Equals(suffix, StringComparison.OrdinalIgnoreCase)
                || domain.EndsWith("." + suffix, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    private readonly record struct Entry(uint Payload, uint IocId);
}

/// <summary>IOC 库状态快照。</summary>
public sealed record IocSnapshot(
    bool Loaded,
    string? LastError,
    DateTime? SourceUtc,
    int MinConfidence,
    int IpCount,
    int DomainCount,
    int HashCount,
    long MatchCount,
    DateTime? LastMatchUtc)
{
    public int TotalCount => IpCount + DomainCount + HashCount;
}

/// <summary>一条 IOC 命中。</summary>
public sealed record IocHit(
    DateTime TimeUtc,
    int Pid,
    string Kind,
    string Target,
    int Confidence,
    string Malware,
    string ThreatType,
    string Reference);
