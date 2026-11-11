using WinAppGuard.Core.Time;

namespace WinAppGuard.Core.Features;

public enum BlockAddStatus
{
    Added = 0,
    Updated = 1,

    /// <summary>达到上限，淘汰了最早到期的一条。</summary>
    EvictedOldest = 2,
}

public readonly record struct BlockAddResult(BlockAddStatus Status, object? EvictedKey);

public sealed record BlockEntry<TKey>(
    TKey Key,
    DateTime CreatedUtc,
    DateTime ExpiresUtc,
    string Reason,
    string? EventId);

/// <summary>
/// 5.9：临时阻断的元数据/时间/上限只有一套。
///
/// 本类不直接操作 WFP：真正创建/删除过滤器由各特性的执行器完成。
/// 这样反扫描、DHCP、IPv6、名称解析、网络检测可以共享同一套 TTL/上限/快照逻辑，
/// 而 WFP 规则权重、DACL、层等安全细节仍留在各自的 WFP 代码里。
///
/// 新程序默认阻止不在本类：它没有固定 TTL，持续到用户选择。
/// </summary>
public sealed class ExpiringBlockRegistry<TKey> where TKey : notnull
{
    private readonly object _gate = new();
    private readonly Dictionary<TKey, BlockEntry<TKey>> _items = new();
    private readonly IClock _clock;

    public ExpiringBlockRegistry(int maxEntries, TimeSpan maxTtl, IClock? clock = null)
    {
        if (maxEntries <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(maxEntries));
        }

        if (maxTtl <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(maxTtl));
        }

        MaxEntries = maxEntries;
        MaxTtl = maxTtl;
        _clock = clock ?? SystemClock.Instance;
    }

    public int MaxEntries { get; }

    public TimeSpan MaxTtl { get; }

    public BlockAddResult TryAdd(TKey key, TimeSpan ttl, string reason, string? eventId = null)
    {
        lock (_gate)
        {
            var now = _clock.UtcNow;
            var effectiveTtl = ttl <= TimeSpan.Zero
                ? MaxTtl
                : ttl > MaxTtl ? MaxTtl : ttl;

            if (_items.TryGetValue(key, out var existing))
            {
                _items[key] = existing with
                {
                    ExpiresUtc = now + effectiveTtl,
                    Reason = reason,
                    EventId = eventId,
                };

                return new BlockAddResult(BlockAddStatus.Updated, null);
            }

            object? evicted = null;

            if (_items.Count >= MaxEntries)
            {
                var oldest = _items.Values
                    .OrderBy(item => item.ExpiresUtc)
                    .FirstOrDefault();

                if (oldest is not null)
                {
                    _items.Remove(oldest.Key);
                    evicted = oldest.Key;
                }
            }

            _items[key] = new BlockEntry<TKey>(
                key,
                now,
                now + effectiveTtl,
                reason,
                eventId);

            return new BlockAddResult(
                evicted is null ? BlockAddStatus.Added : BlockAddStatus.EvictedOldest,
                evicted);
        }
    }

    public bool Release(TKey key)
    {
        lock (_gate)
        {
            return _items.Remove(key);
        }
    }

    public int ReleaseAll()
    {
        lock (_gate)
        {
            var count = _items.Count;
            _items.Clear();
            return count;
        }
    }

    public bool IsBlocked(TKey key)
    {
        lock (_gate)
        {
            return _items.TryGetValue(key, out var item)
                   && item.ExpiresUtc > _clock.UtcNow;
        }
    }

    public IReadOnlyList<BlockEntry<TKey>> Snapshot()
    {
        lock (_gate)
        {
            var now = _clock.UtcNow;

            return _items.Values
                .Where(item => item.ExpiresUtc > now)
                .OrderBy(item => item.ExpiresUtc)
                .ToList();
        }
    }

    public int PurgeExpired()
    {
        lock (_gate)
        {
            var now = _clock.UtcNow;
            var expired = _items
                .Where(pair => pair.Value.ExpiresUtc <= now)
                .Select(pair => pair.Key)
                .ToList();

            foreach (var key in expired)
            {
                _items.Remove(key);
            }

            return expired.Count;
        }
    }
}
