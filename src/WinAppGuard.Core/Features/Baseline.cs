using WinAppGuard.Core.Time;

namespace WinAppGuard.Core.Features;

public sealed record BaselineDiff<T>(
    IReadOnlyList<T> Added,
    IReadOnlyList<T> Removed,
    IReadOnlyList<T> Unchanged);

/// <summary>
/// 5.9：基线学习只有一套。
///
/// 只负责“集合 + 信任 + 比较”；不同特性的采集方式、信任来源和持久化
/// 仍由各自模块决定。LAN / IPv6 / Config 先通过组合使用它，不强行改成同一 DTO。
/// </summary>
public sealed class Baseline<T> where T : notnull
{
    private readonly object _gate = new();
    private readonly HashSet<T> _items;
    private readonly IClock _clock;

    public Baseline(
        IEnumerable<T>? items = null,
        IEqualityComparer<T>? comparer = null,
        IClock? clock = null)
    {
        _items = new HashSet<T>(comparer ?? EqualityComparer<T>.Default);
        _clock = clock ?? SystemClock.Instance;

        if (items is not null)
        {
            _items.UnionWith(items);
        }

        LearnedUtc = _clock.UtcNow;
    }

    public DateTime LearnedUtc { get; private set; }

    public IReadOnlySet<T> Items
    {
        get
        {
            lock (_gate)
            {
                return new HashSet<T>(_items);
            }
        }
    }

    public BaselineDiff<T> Compare(IEnumerable<T> observed)
    {
        lock (_gate)
        {
            var set = new HashSet<T>(observed, _items.Comparer);
            var added = set.Where(item => !_items.Contains(item)).ToList();
            var removed = _items.Where(item => !set.Contains(item)).ToList();
            var unchanged = set.Where(_items.Contains).ToList();

            return new BaselineDiff<T>(added, removed, unchanged);
        }
    }

    public void Reset()
    {
        lock (_gate)
        {
            _items.Clear();
            LearnedUtc = _clock.UtcNow;
        }
    }

    public void Reset(IEnumerable<T> items)
    {
        lock (_gate)
        {
            _items.Clear();
            _items.UnionWith(items);
            LearnedUtc = _clock.UtcNow;
        }
    }

    public bool Trust(T item)
    {
        lock (_gate)
        {
            return _items.Add(item);
        }
    }

    public bool Untrust(T item)
    {
        lock (_gate)
        {
            return _items.Remove(item);
        }
    }

    public bool Contains(T item)
    {
        lock (_gate)
        {
            return _items.Contains(item);
        }
    }
}
