namespace WinAppGuard.Core.Audit;

/// <summary>
/// 把「域名 ↔ IP」的快照累积成一张**带时间的历史表**，用来给连接事件"猜"域名。
///
/// ==================== 为什么需要它 ====================
/// Windows 的 DNS 缓存 TTL 很短（实测有 1 秒的条目）。如果只在写审计那一刻读一次，
/// 连接发生前几分钟解析的域名早就没了。所以采集器每 2~5 秒拍一次快照，
/// 这里把结果**累积**下来：IP → {域名, 最后一次看到的时间}。
///
/// ==================== 它给出的是"推测" ====================
///   - 只有一个候选 → 高置信；
///   - 多个候选（CDN 常见）→ 全部列出来，界面标注"不唯一"；
///   - 没有记录 → 返回 null，界面显示"域名未知"。
/// **永远不能拿它作为阻止规则的依据** —— 域名对 IP 不是一对一。
/// </summary>
internal sealed class DomainIndex
{
    private sealed class Entry
    {
        internal required string Name { get; init; }
        internal DateTime LastSeenUtc { get; set; }
        internal uint TtlSeconds { get; set; }
    }

    private readonly object _gate = new();
    private readonly Dictionary<string, List<Entry>> _byAddress = new(StringComparer.OrdinalIgnoreCase);
    private readonly TimeSpan _maxAge;

    /// <param name="maxAge">
    /// 一条解析记录最多"活"多久。默认 30 分钟：
    /// 比绝大多数 TTL 长得多（能覆盖解析后隔一会儿才连接的情况），
    /// 又短到不至于把几小时前的域名硬套在新的连接上。
    /// </param>
    internal DomainIndex(TimeSpan? maxAge = null)
    {
        _maxAge = maxAge ?? TimeSpan.FromMinutes(30);
    }

    /// <summary>当前记住的 IP 数量（自检与界面统计用）。</summary>
    internal int AddressCount
    {
        get
        {
            lock (_gate)
            {
                return _byAddress.Count;
            }
        }
    }

    /// <summary>把一次缓存快照合并进来。</summary>
    internal void Update(IEnumerable<DnsCacheRecord> records, DateTime nowUtc)
    {
        lock (_gate)
        {
            foreach (var record in records)
            {
                if (string.IsNullOrWhiteSpace(record.Address) || string.IsNullOrWhiteSpace(record.Name))
                {
                    continue;
                }

                if (!_byAddress.TryGetValue(record.Address, out var entries))
                {
                    entries = new List<Entry>();
                    _byAddress[record.Address] = entries;
                }

                var existing = entries.FirstOrDefault(
                    entry => string.Equals(entry.Name, record.Name, StringComparison.OrdinalIgnoreCase));

                if (existing is null)
                {
                    entries.Add(new Entry
                    {
                        Name = record.Name,
                        LastSeenUtc = nowUtc,
                        TtlSeconds = record.TtlSeconds,
                    });
                }
                else
                {
                    existing.LastSeenUtc = nowUtc;
                    existing.TtlSeconds = record.TtlSeconds;
                }
            }

            Purge(nowUtc);
        }
    }

    /// <summary>
    /// 猜一个 IP 对应的域名。
    /// </summary>
    /// <returns>
    /// <c>Domain</c>：单个域名，或前三个候选用 <c> / </c> 连接；没有记录时为 null。
    /// <c>CandidateCount</c>：候选数量（用于判断是否"不唯一"）。
    /// </returns>
    internal (string? Domain, int CandidateCount) Resolve(string address, DateTime nowUtc)
    {
        if (string.IsNullOrWhiteSpace(address))
        {
            return (null, 0);
        }

        lock (_gate)
        {
            if (!_byAddress.TryGetValue(address, out var entries))
            {
                return (null, 0);
            }

            var fresh = entries
                .Where(entry => nowUtc - entry.LastSeenUtc <= _maxAge)
                .OrderByDescending(entry => entry.LastSeenUtc)
                .Select(entry => entry.Name)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            if (fresh.Count == 0)
            {
                return (null, 0);
            }

            return fresh.Count == 1
                ? (fresh[0], 1)
                : (string.Join(" / ", fresh.Take(3)), fresh.Count);
        }
    }

    /// <summary>丢掉过期的记录，避免长期运行后字典无限增长。</summary>
    private void Purge(DateTime nowUtc)
    {
        var empty = new List<string>();

        foreach (var pair in _byAddress)
        {
            pair.Value.RemoveAll(entry => nowUtc - entry.LastSeenUtc > _maxAge);

            if (pair.Value.Count == 0)
            {
                empty.Add(pair.Key);
            }
        }

        foreach (var address in empty)
        {
            _byAddress.Remove(address);
        }
    }
}
