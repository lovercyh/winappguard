using System.Net;
using WinAppGuard.Models;

namespace WinAppGuard.Core;

/// <summary>
/// IP 归属查询的调度器：把「查询」这件事从界面线程上彻底摘下来。
///
/// 它解决的问题：
///   连接列表每 3 秒刷新一次，一次几百个地址。如果在界面线程上同步查询，
///   界面必然卡死。所以这里把请求丢进待查队列，由后台线程成批处理，
///   结果写进缓存，再通过事件通知界面去刷新。
///
/// 关键行为：
///   1. <see cref="Request"/> 立即返回，绝不在调用方线程上做网络 IO；
///   2. 同一个地址不会重复排队，也不会在「正在查」的时候被再查一次；
///   3. <see cref="IsEnabled"/> 默认 **false**；关闭状态下 Request 直接丢弃，
///      连队列都不进 —— 这是「关闭后零流量」的底层保证，不依赖界面自觉；
///   4. <see cref="ResultsUpdated"/> 在**后台线程**上触发，调用方自己负责切回界面线程；
///   5. <see cref="Dispose"/> 不等待正在进行的网络调用（那会让退出卡住），
///      正在飞的那一批最多再完成一次，之后不再有任何流量。
///
/// 可测试性：查询实现通过构造函数注入（默认是真实的
/// <see cref="IpOwnershipLookup.Query"/>）。自检工具用它替换成不联网的替身，
/// 从而把缓存、淘汰、开关这些逻辑离线验证清楚。
/// </summary>
public sealed class IpOwnershipService : IDisposable
{
    private readonly IpOwnershipCache _cache;
    private readonly Func<IReadOnlyList<IPAddress>, IReadOnlyDictionary<string, IpOwnershipInfo>> _query;

    private readonly object _gate = new();

    /// <summary>等待查询的地址（键是归一化后的 IP 字符串）。</summary>
    private readonly Dictionary<string, IPAddress> _pending = new(StringComparer.Ordinal);

    /// <summary>已经交给后台、但还没回来的地址。避免查询期间被重复排队。</summary>
    private readonly HashSet<string> _inFlight = new(StringComparer.Ordinal);

    private bool _workerRunning;
    private bool _disposed;
    private bool _enabled;

    /// <summary>
    /// 一批结果回来时触发。**在后台线程上**，调用方需自行切回界面线程。
    /// </summary>
    public event Action<IReadOnlyDictionary<string, IpOwnershipInfo>>? ResultsUpdated;

    /// <summary>用产品默认的缓存与真实查询实现构造。</summary>
    public IpOwnershipService()
        : this(new IpOwnershipCache(), IpOwnershipLookup.Query)
    {
    }

    /// <summary>供自检工具注入替身使用。</summary>
    public IpOwnershipService(
        IpOwnershipCache cache,
        Func<IReadOnlyList<IPAddress>, IReadOnlyDictionary<string, IpOwnershipInfo>> query)
    {
        _cache = cache;
        _query = query;
    }

    /// <summary>
    /// 功能是否开启。**默认 false**：没有显式开启之前不会有任何网络流量。
    ///
    /// 关闭时会丢弃尚未发出的待查请求，并清空缓存 ——
    /// 让「关闭」这个动作是干净的，而不是留一堆上次的结论在内存里。
    /// 已经飞出去的那一批无法中断（同步 TCP 调用），它完成后不会再发新的。
    /// </summary>
    public bool IsEnabled
    {
        get
        {
            lock (_gate)
            {
                return _enabled;
            }
        }
        set
        {
            lock (_gate)
            {
                if (_enabled == value)
                {
                    return;
                }

                _enabled = value;

                if (!value)
                {
                    _pending.Clear();
                    _cache.Clear();
                }
            }
        }
    }

    /// <summary>当前缓存条数，仅供观察与自检。</summary>
    public int CachedCount => _cache.Count;

    /// <summary>从缓存取一条结果。功能关闭时也照常返回，由界面决定要不要显示。</summary>
    public bool TryGet(string ipKey, out IpOwnershipInfo info) => _cache.TryGet(ipKey, out info);

    /// <summary>
    /// 请求解析一批地址。**立即返回**，不做任何网络 IO。
    ///
    /// 传入的集合在方法内部就会被读成快照（转成键），
    /// 所以调用方不需要关心线程安全 —— 可以直接传入界面线程上那个列表。
    /// </summary>
    public void Request(IEnumerable<IPAddress>? addresses)
    {
        if (addresses is null)
        {
            return;
        }

        lock (_gate)
        {
            if (_disposed || !_enabled)
            {
                return;
            }

            foreach (var address in addresses)
            {
                if (address is null || !IpOwnershipLookup.IsQueryable(address))
                {
                    // 私有 / 回环地址根本不进队列，更不会发出去。
                    continue;
                }

                var key = IpOwnershipLookup.ToKey(address);

                if (_cache.TryGet(key, out _) || _inFlight.Contains(key))
                {
                    continue;
                }

                _pending[key] = address;
            }

            if (_pending.Count == 0 || _workerRunning)
            {
                return;
            }

            _workerRunning = true;
        }

        ThreadPool.QueueUserWorkItem(_ => RunWorker());
    }

    /// <summary>后台工作循环：一次取一批、查一批、写缓存、通知一批，直到没有待查项。</summary>
    private void RunWorker()
    {
        while (true)
        {
            List<(string Key, IPAddress Address)> batch;

            lock (_gate)
            {
                if (_disposed || !_enabled || _pending.Count == 0)
                {
                    _workerRunning = false;
                    return;
                }

                batch = new List<(string, IPAddress)>(AppConstants.OwnershipMaxIpsPerQuery);
                foreach (var pair in _pending)
                {
                    batch.Add((pair.Key, pair.Value));
                    if (batch.Count >= AppConstants.OwnershipMaxIpsPerQuery)
                    {
                        break;
                    }
                }

                foreach (var item in batch)
                {
                    _pending.Remove(item.Key);
                    _inFlight.Add(item.Key);
                }
            }

            // 网络 IO 一定在锁外做：锁里做慢操作会把调用方（界面线程）一起卡住。
            var results = QuerySafely(batch);

            lock (_gate)
            {
                foreach (var item in batch)
                {
                    _inFlight.Remove(item.Key);

                    if (!_disposed)
                    {
                        _cache.Set(
                            item.Key,
                            results.TryGetValue(item.Key, out var info) ? info : IpOwnershipInfo.NotCovered);
                    }
                }
            }

            if (_disposed)
            {
                // 已经关闭：结果直接丢掉，也不再通知。
                continue;
            }

            ResultsUpdated?.Invoke(results);
        }
    }

    /// <summary>
    /// 调用查询实现，并把任何异常兜住。
    ///
    /// 真实实现（IpOwnershipLookup）内部已经全部兜底，理论上不会抛；
    /// 但注入的替身有可能抛。后台线程上未处理的异常会直接干掉进程，
    /// 所以这里必须再兜一层。
    /// </summary>
    private IReadOnlyDictionary<string, IpOwnershipInfo> QuerySafely(
        List<(string Key, IPAddress Address)> batch)
    {
        try
        {
            var addresses = new List<IPAddress>(batch.Count);
            foreach (var item in batch)
            {
                addresses.Add(item.Address);
            }

            return _query(addresses);
        }
        catch (Exception ex)
        {
            var failed = new Dictionary<string, IpOwnershipInfo>(StringComparer.Ordinal);
            foreach (var item in batch)
            {
                failed[item.Key] = IpOwnershipInfo.Failed(ex.Message);
            }

            return failed;
        }
    }

    /// <summary>
    /// 关闭调度器。**不等待**正在进行的网络调用 —— 等待会让退出卡住，
    /// 而后台线程本身是线程池线程，不会阻止进程退出。
    /// </summary>
    public void Dispose()
    {
        lock (_gate)
        {
            _disposed = true;
            _pending.Clear();
            _cache.Clear();
        }
    }
}
