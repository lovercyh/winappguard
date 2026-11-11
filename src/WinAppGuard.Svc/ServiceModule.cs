namespace WinAppGuard.Service;

internal enum ModuleState
{
    NotStarted = 0,
    Starting = 1,
    Running = 2,
    Stopped = 3,
    Failed = 4,
}

/// <summary>5.9：一个服务模块的生命周期与健康快照。</summary>
internal sealed class ModuleHealth
{
    internal ModuleHealth(string name, int order, bool restartable)
    {
        Name = name;
        Order = order;
        Restartable = restartable;
    }

    internal string Name { get; }

    internal int Order { get; }

    internal bool Restartable { get; }

    internal ModuleState State { get; set; } = ModuleState.NotStarted;

    internal DateTime? StartedUtc { get; set; }

    internal DateTime? LastAttemptUtc { get; set; }

    internal string? LastError { get; set; }

    internal int RestartCount { get; set; }

    internal string? Detail { get; set; }

    internal ModuleHealth Clone() => new(Name, Order, Restartable)
    {
        State = State,
        StartedUtc = StartedUtc,
        LastAttemptUtc = LastAttemptUtc,
        LastError = LastError,
        RestartCount = RestartCount,
        Detail = Detail,
    };
}

/// <summary>
/// 5.9：一个服务模块。启动顺序由 <see cref="Order"/> 决定，停止按反序执行。
///
/// 模块不直接互相调用；跨模块依赖通过启动顺序保证（例如 IDS 在 Traffic/DNS 之后）。
/// </summary>
internal interface IServiceModule
{
    string Name { get; }

    int Order { get; }

    /// <summary>失败后是否允许监督器自动重启。只给幂等、无共享捕获会话的模块打开。</summary>
    bool Restartable { get; }

    void Start();

    void Stop();

    /// <summary>健康快照里的附加说明；允许返回 null。</summary>
    string? GetDetail();
}

/// <summary>5.9：把现有静态 Host 包装成模块，不复制它们的实现。</summary>
internal sealed class DelegateServiceModule : IServiceModule
{
    private readonly Action _start;
    private readonly Action _stop;
    private readonly Func<string?> _detail;

    internal DelegateServiceModule(
        string name,
        int order,
        bool restartable,
        Action start,
        Action stop,
        Func<string?>? detail = null)
    {
        Name = name;
        Order = order;
        Restartable = restartable;
        _start = start;
        _stop = stop;
        _detail = detail ?? (() => null);
    }

    public string Name { get; }

    public int Order { get; }

    public bool Restartable { get; }

    public void Start() => _start();

    public void Stop() => _stop();

    public string? GetDetail() => _detail();
}

/// <summary>
/// 5.9：模块宿主。
///
///   - 按 Order 正序启动，单个模块失败不阻止其它模块（失败隔离）；
///   - 按反序停止；
///   - 只对声明 Restartable 的模块做有限次自动重启；
///   - 健康快照用于启动日志和后续诊断，不改变协议 v2 的载荷。
/// </summary>
internal sealed class ModuleHost : IDisposable
{
    private const int MaxRestarts = 3;
    private static readonly TimeSpan RestartCooldown = TimeSpan.FromSeconds(30);

    private readonly object _gate = new();
    private readonly List<IServiceModule> _modules;
    private readonly Dictionary<string, ModuleHealth> _health;
    private readonly System.Threading.Timer _supervisor;
    private bool _started;

    internal ModuleHost(IEnumerable<IServiceModule> modules)
    {
        _modules = modules
            .OrderBy(module => module.Order)
            .ThenBy(module => module.Name, StringComparer.Ordinal)
            .ToList();

        if (_modules.Count == 0)
        {
            throw new ArgumentException("至少需要一个服务模块。", nameof(modules));
        }

        var names = new HashSet<string>(StringComparer.Ordinal);

        foreach (var module in _modules)
        {
            if (!names.Add(module.Name))
            {
                throw new InvalidOperationException($"服务模块重名：{module.Name}");
            }

            if (module.Order < 0)
            {
                throw new InvalidOperationException($"服务模块顺序不能为负：{module.Name}");
            }
        }

        _health = _modules.ToDictionary(
            module => module.Name,
            module => new ModuleHealth(module.Name, module.Order, module.Restartable),
            StringComparer.Ordinal);

        _supervisor = new System.Threading.Timer(
            _ => Supervise(),
            state: null,
            Timeout.InfiniteTimeSpan,
            Timeout.InfiniteTimeSpan);
    }

    internal IReadOnlyList<ModuleHealth> Snapshot()
    {
        lock (_gate)
        {
            foreach (var module in _modules)
            {
                var health = _health[module.Name];

                try
                {
                    health.Detail = module.GetDetail();
                }
                catch (Exception)
                {
                    // 健康说明失败不影响快照。
                }
            }

            return _modules
                .Select(module => _health[module.Name].Clone())
                .ToList();
        }
    }

    internal void StartAll()
    {
        lock (_gate)
        {
            if (_started)
            {
                return;
            }

            _started = true;
        }

        foreach (var module in _modules)
        {
            StartModule(module);
        }

        _supervisor.Change(RestartCooldown, RestartCooldown);

        var healthy = Snapshot().Count(item => item.State == ModuleState.Running);

        ServiceLog.Info(
            "WAG-MODULE-001",
            $"Service modules started: {healthy}/{_modules.Count} running ("
            + string.Join(", ", Snapshot().Select(item => $"{item.Name}={item.State}")) + ").");
    }

    internal void StopAll()
    {
        lock (_gate)
        {
            if (!_started)
            {
                return;
            }

            _started = false;
        }

        _supervisor.Change(Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);

        for (var i = _modules.Count - 1; i >= 0; i--)
        {
            StopModule(_modules[i]);
        }

        ServiceLog.Info("WAG-MODULE-002", "Service modules stopped.");
    }

    /// <summary>供测试和监督器使用：尝试重启失败的、允许重启的模块。</summary>
    internal int RestartFailedModules(DateTime nowUtc)
    {
        var restarted = 0;

        foreach (var module in _modules)
        {
            ModuleHealth health;

            lock (_gate)
            {
                health = _health[module.Name];

                if (!_started
                    || health.State != ModuleState.Failed
                    || !module.Restartable
                    || health.RestartCount >= MaxRestarts
                    || (health.LastAttemptUtc is { } last
                        && nowUtc - last < RestartCooldown))
                {
                    continue;
                }

                health.RestartCount++;
            }

            ServiceLog.Warning(
                "WAG-MODULE-003",
                $"Restarting failed service module {module.Name} "
                + $"(attempt {_health[module.Name].RestartCount}/{MaxRestarts}).");

            StartModule(module);
            restarted++;
        }

        return restarted;
    }

    private void Supervise()
    {
        try
        {
            _ = RestartFailedModules(DateTime.UtcNow);
        }
        catch (Exception ex)
        {
            ServiceLog.Warning("WAG-MODULE-004", "Service module supervision failed.", ex);
        }
    }

    private bool StartModule(IServiceModule module)
    {
        lock (_gate)
        {
            var health = _health[module.Name];
            health.State = ModuleState.Starting;
            health.LastAttemptUtc = DateTime.UtcNow;
        }

        try
        {
            module.Start();

            lock (_gate)
            {
                var health = _health[module.Name];
                health.State = ModuleState.Running;
                health.StartedUtc = DateTime.UtcNow;
                health.LastError = null;
            }

            ServiceLog.Info("WAG-MODULE-005", $"Service module started: {module.Name}.");
            return true;
        }
        catch (Exception ex)
        {
            lock (_gate)
            {
                var health = _health[module.Name];
                health.State = ModuleState.Failed;
                health.LastError = ex.Message;
            }

            // 失败隔离：记录后继续启动其它模块。
            ServiceLog.Error(
                "WAG-MODULE-006",
                $"Service module failed to start: {module.Name}. Other modules continue.",
                ex);

            return false;
        }
    }

    private void StopModule(IServiceModule module)
    {
        ModuleState state;

        lock (_gate)
        {
            state = _health[module.Name].State;
        }

        if (state is ModuleState.NotStarted or ModuleState.Stopped)
        {
            return;
        }

        try
        {
            module.Stop();

            lock (_gate)
            {
                var health = _health[module.Name];
                health.State = ModuleState.Stopped;
                health.StartedUtc = null;
            }
        }
        catch (Exception ex)
        {
            lock (_gate)
            {
                var health = _health[module.Name];
                health.State = ModuleState.Failed;
                health.LastError = ex.Message;
            }

            ServiceLog.Warning(
                "WAG-MODULE-007",
                $"Service module failed to stop: {module.Name}.",
                ex);
        }
    }

    public void Dispose()
    {
        StopAll();
        _supervisor.Dispose();
    }
}
