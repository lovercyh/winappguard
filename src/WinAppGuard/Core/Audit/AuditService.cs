using WinAppGuard.Models;

namespace WinAppGuard.Core.Audit;

/// <summary>
/// 审计服务：把三个数据源串起来，统一写进 <see cref="AuditStore"/>。
///
/// <code>
///   DNS 缓存快照（每 3 秒）──→ DomainIndex ─┐
///   连接表轮询（每 3 秒）──→ 差集 ──────────┼─→ AuditEvent → JSONL
///   WFP 拦截事件（实时）──────────────────┘
/// </code>
///
/// 设计取舍（都写进文档，不藏着）：
///   - **正常连接靠轮询**：WFP 不给"被放行"的事件（实测），所以 3 秒窗口内的短连接会漏；
///   - **拦截事件实时**：轮询根本看不到被拦的连接，这部分反而是最准的；
///   - **域名是推测**：来自本机 DNS 缓存，加密 DNS（DoH）下为空；
///   - **任何一环失败都不影响其它环**：比如订阅失败只影响拦截事件，轮询照常。
/// </summary>
internal sealed class AuditService : IDisposable
{
    private readonly AuditStore _store;
    private readonly DomainIndex _domains = new();
    private readonly ConnectionTracker _connections = new();
    private readonly object _writeGate = new();

    private CancellationTokenSource? _cancellation;
    private Thread? _thread;
    private WfpDropCollector? _drops;
    private DateTime _nextPurge;

    internal AuditService(
        string? directory = null,
        int pollSeconds = 3,
        int retentionDays = AuditStore.DefaultRetentionDays,
        bool allowDomainLookup = true)
    {
        _store = new AuditStore(directory, retentionDays: retentionDays);
        PollSeconds = Math.Max(1, pollSeconds);
        AllowDomainLookup = allowDomainLookup;
        _nextPurge = DateTime.Now.Date.AddDays(1);
    }

    /// <summary>
    /// 是否允许"缓存优先、必要时回源"的 DNS 读取（对应设置里的「域名推测」）。
    /// false 时只用 NO_WIRE_QUERY：绝不发 DNS 包，覆盖率会明显下降。
    /// </summary>
    internal bool AllowDomainLookup { get; }

    /// <summary>连接/DNS 快照的间隔（秒）。</summary>
    internal int PollSeconds { get; }

    /// <summary>是否正在运行。</summary>
    internal bool IsRunning { get; private set; }

    /// <summary>已写入的事件条数。</summary>
    internal int EventsWritten => Volatile.Read(ref _eventsWritten);

    /// <summary>收到的拦截事件条数。</summary>
    internal int DropsSeen => Volatile.Read(ref _dropCounter);

    /// <summary>拦截事件订阅是否成功（失败时仍会继续轮询）。</summary>
    internal bool DropSubscriptionActive => _drops is not null;

    /// <summary>最近一次错误（供界面如实显示，不影响其它功能）。</summary>
    internal string? LastError { get; private set; }

    internal AuditStore Store => _store;

    /// <summary>启动。会尝试订阅 WFP 拦截事件；失败只记错误，不阻止轮询。</summary>
    internal void Start()
    {
        if (IsRunning)
        {
            return;
        }

        try
        {
            _drops = WfpDropCollector.Start();
            _drops.DropDetected += OnDrop;
        }
        catch (Exception ex)
        {
            _drops = null;
            LastError = $"拦截事件订阅失败：{ex.Message}";
            LocalLog.Warning($"审计：{LastError}（连接轮询仍会继续）");
        }

        _cancellation = new CancellationTokenSource();
        _thread = new Thread(() => Loop(_cancellation.Token))
        {
            IsBackground = true,
            Name = "audit",
        };

        IsRunning = true;
        _thread.Start();

        LocalLog.Info($"审计已启动：轮询 {PollSeconds} 秒，拦截事件={(DropSubscriptionActive ? "已订阅" : "未订阅")}");
    }

    public void Dispose()
    {
        if (!IsRunning)
        {
            _store.Dispose();
            return;
        }

        IsRunning = false;

        try
        {
            _cancellation?.Cancel();
            _thread?.Join(5000);
        }
        catch (Exception)
        {
            // 退出阶段忽略。
        }

        if (_drops is not null)
        {
            _drops.DropDetected -= OnDrop;
            _drops.Dispose();
            _drops = null;
        }

        _cancellation?.Dispose();
        _cancellation = null;
        _store.Dispose();

        LocalLog.Info($"审计已停止：共写入 {EventsWritten} 条，其中拦截 {DropsSeen} 条");
    }

    // ==================================================================
    // 后台循环
    // ==================================================================

    private void Loop(CancellationToken token)
    {
        var nextDns = DateTime.MinValue;

        while (!token.IsCancellationRequested)
        {
            try
            {
                var nowUtc = DateTime.UtcNow;

                // ---- DNS 快照（决定"域名"这一列）----
                if (nowUtc >= nextDns)
                {
                    _domains.Update(DnsCacheReader.ReadSnapshot(AllowDomainLookup), nowUtc);
                    nextDns = nowUtc.AddSeconds(PollSeconds);
                }

                // ---- 连接轮询（决定"正常连接"）----
                var snapshot = ConnectionScanner.Scan();
                var added = _connections.Update(ConnectionTracker.FromSnapshot(snapshot));

                foreach (var connection in added)
                {
                    var (domain, _) = _domains.Resolve(connection.Address, nowUtc);

                    Write(new AuditEvent
                    {
                        TimeUtc = nowUtc,
                        Kind = AuditEventKind.Connect,
                        ProcessPath = connection.ProcessPath,
                        ProcessId = connection.ProcessId,
                        RemoteAddress = connection.Address,
                        RemotePort = connection.Port,
                        Protocol = connection.Protocol,
                        Domain = domain,
                    });
                }

                // ---- 每天清理一次过期文件 ----
                if (DateTime.Now >= _nextPurge)
                {
                    var deleted = _store.PurgeExpired(DateTime.Now);
                    if (deleted > 0)
                    {
                        LocalLog.Info($"审计：清理了 {deleted} 个过期文件");
                    }

                    _nextPurge = DateTime.Now.Date.AddDays(1);
                }
            }
            catch (Exception ex)
            {
                LastError = ex.Message;
                LocalLog.Warning($"审计循环出错（已跳过本轮）：{ex.Message}");
            }

            try
            {
                token.WaitHandle.WaitOne(TimeSpan.FromSeconds(PollSeconds));
            }
            catch (ObjectDisposedException)
            {
                return;
            }
        }
    }

    /// <summary>WFP 的线程会调到这里 —— 必须自己保证线程安全。</summary>
    private void OnDrop(WfpDropEvent drop)
    {
        try
        {
            var (domain, _) = _domains.Resolve(drop.RemoteAddress, DateTime.UtcNow);
            Interlocked.Increment(ref _dropCounter);

            Write(new AuditEvent
            {
                TimeUtc = drop.TimeUtc,
                Kind = AuditEventKind.Blocked,

                // 拦截事件里没有 PID（WFP 只给程序身份），这里如实留 0。
                ProcessId = 0,
                ProcessPath = drop.ProcessPath,
                RemoteAddress = drop.RemoteAddress,
                RemotePort = drop.RemotePort,
                Protocol = drop.Protocol,
                FilterId = drop.FilterId,
                Domain = domain,
            });
        }
        catch (Exception ex)
        {
            LastError = ex.Message;
        }
    }

    private void Write(AuditEvent auditEvent)
    {
        lock (_writeGate)
        {
            _store.Append(auditEvent);
            Interlocked.Increment(ref _eventsWritten);
        }
    }

    private int _eventsWritten;
    private int _dropCounter;
}
