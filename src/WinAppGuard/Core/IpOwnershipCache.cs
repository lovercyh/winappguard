using WinAppGuard.Models;

namespace WinAppGuard.Core;

/// <summary>
/// IP 归属结果的进程内缓存。
///
/// 为什么必须有它：
///   连接列表每 3 秒刷新一次，一次可能带出一两百个地址。没有缓存的话，
///   每次刷新都会把同样的地址重新问一遍外部服务 —— 既慢，又等于持续
///   把「用户此刻在跟谁通信」泄露出去。缓存是隐私和性能的双重要求。
///
/// 设计要点：
///   1. **只存在内存里，绝不落盘** —— 落盘就等于把「用户连过哪些 IP」写进磁盘。
///   2. 有**有效期**：AS 归属很少变，但也不能永久信任一个旧结论。
///   3. 有**容量上限**，超出后按写入顺序淘汰最旧的，避免长时间运行无限增长。
///   4. 失败的结果用**更短的有效期**：一次网络抖动不该把「查询失败」
///      这个结论压住 24 小时，否则用户会觉得功能坏了。
///   5. 线程安全：后台线程写，界面线程读。
/// </summary>
public sealed class IpOwnershipCache
{
    /// <summary>所有读写都走这把锁。缓存操作本身很快，不需要更细的粒度。</summary>
    private readonly object _gate = new();

    private readonly Dictionary<string, Entry> _entries = new(StringComparer.Ordinal);

    /// <summary>
    /// 写入顺序表，用于容量淘汰。
    /// 条目里带写入序号，同一个键被覆盖后旧序号在淘汰时会被识别并跳过。
    /// </summary>
    private readonly Queue<(string Key, long Stamp)> _order = new();

    private readonly TimeSpan _successTtl;
    private readonly TimeSpan _failureTtl;
    private readonly int _capacity;

    private long _stamp;

    /// <summary>
    /// 按指定参数构造。有效期与容量做成参数而不是写死，
    /// 是为了让自检工具能用「几百毫秒」的有效期把过期行为快速验证出来。
    /// </summary>
    /// <param name="successTtl">成功结果的有效期。</param>
    /// <param name="failureTtl">失败结果的有效期，应明显短于成功结果。</param>
    /// <param name="capacity">最多保留多少条。</param>
    public IpOwnershipCache(TimeSpan successTtl, TimeSpan failureTtl, int capacity)
    {
        _successTtl = successTtl;
        _failureTtl = failureTtl;
        _capacity = Math.Max(1, capacity);
    }

    /// <summary>用产品默认参数构造（取值见 AppConstants）。</summary>
    public IpOwnershipCache()
        : this(
            TimeSpan.FromHours(AppConstants.OwnershipCacheTtlHours),
            TimeSpan.FromSeconds(AppConstants.OwnershipFailureRetrySeconds),
            AppConstants.OwnershipCacheCapacity)
    {
    }

    /// <summary>当前有效条数（过期的也算在内，仅用于容量观察）。</summary>
    public int Count
    {
        get
        {
            lock (_gate)
            {
                return _entries.Count;
            }
        }
    }

    /// <summary>取一条结果。不存在或已过期都返回 false。</summary>
    public bool TryGet(string key, out IpOwnershipInfo info)
    {
        lock (_gate)
        {
            if (!string.IsNullOrEmpty(key)
                && _entries.TryGetValue(key, out var entry)
                && DateTimeOffset.UtcNow < entry.ExpiresAt)
            {
                info = entry.Info;
                return true;
            }
        }

        info = IpOwnershipInfo.None;
        return false;
    }

    /// <summary>写入一条结果。有效期按结果是否失败自动选择。</summary>
    public void Set(string key, IpOwnershipInfo info)
    {
        if (string.IsNullOrEmpty(key))
        {
            return;
        }

        lock (_gate)
        {
            var stamp = ++_stamp;
            var ttl = info.State == IpOwnershipState.Failed ? _failureTtl : _successTtl;

            _entries[key] = new Entry(info, stamp, DateTimeOffset.UtcNow.Add(ttl));
            _order.Enqueue((key, stamp));

            EvictIfNeeded();
        }
    }

    /// <summary>清空缓存。关闭功能时调用，避免磁盘/内存里留着上次的结论。</summary>
    public void Clear()
    {
        lock (_gate)
        {
            _entries.Clear();
            _order.Clear();
        }
    }

    /// <summary>
    /// 超出容量时从最旧的开始淘汰。
    /// 顺序表里可能有已被覆盖的旧序号，那些直接跳过（它们的有效条目排在更后面）。
    /// </summary>
    private void EvictIfNeeded()
    {
        while (_entries.Count > _capacity && _order.Count > 0)
        {
            var (key, stamp) = _order.Dequeue();

            if (_entries.TryGetValue(key, out var entry) && entry.Stamp == stamp)
            {
                _entries.Remove(key);
            }
        }
    }

    /// <summary>一条缓存记录：结果 + 写入序号 + 到期时刻。</summary>
    private readonly record struct Entry(IpOwnershipInfo Info, long Stamp, DateTimeOffset ExpiresAt);
}
