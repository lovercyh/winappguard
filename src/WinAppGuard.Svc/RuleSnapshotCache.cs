using WinAppGuard.Models;

namespace WinAppGuard.Service;

/// <summary>
/// 5.10：规则读缓存。
///
/// 规则列表来自 WFP 枚举，读一次要打开引擎；把结果缓存成不可变快照，
/// 写操作/定时清理/篡改重建后失效并推进 revision。
/// </summary>
internal sealed class RuleSnapshotCache
{
    private readonly object _gate = new();
    private IReadOnlyList<FirewallRuleItem>? _snapshot;
    private long _revision;

    internal string Epoch { get; } = Guid.NewGuid().ToString("N");

    internal long Revision => Interlocked.Read(ref _revision);

    internal IReadOnlyList<FirewallRuleItem> Get(Func<IReadOnlyList<FirewallRuleItem>> loader)
    {
        var snapshot = Volatile.Read(ref _snapshot);

        if (snapshot is not null)
        {
            return snapshot;
        }

        lock (_gate)
        {
            snapshot = _snapshot;

            if (snapshot is not null)
            {
                return snapshot;
            }

            snapshot = loader().ToList();
            Volatile.Write(ref _snapshot, snapshot);
            return snapshot;
        }
    }

    internal void Invalidate(bool bumpRevision = true)
    {
        lock (_gate)
        {
            Volatile.Write(ref _snapshot, null);

            if (bumpRevision)
            {
                Interlocked.Increment(ref _revision);
            }
        }
    }
}
