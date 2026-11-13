using WinAppGuard.Core;
using WinAppGuard.Core.Time;

namespace WinAppGuard.Forms;

/// <summary>
/// 5.9：可见页刷新调度器。
///
/// 一个 UI 定时器统一驱动所有页面刷新：
///   - 只在页面可见且自动刷新开启时运行；
///   - 同一个页面的刷新不会重叠；
///   - 自检模式通过 <c>suppressed</c> 整体停掉，避免后台扫描覆盖人造样本。
///
/// 后台通知（新程序、IDS、IPv6、DNS 安全、服务探活）**不在这里**：
/// 它们必须独立于可见页刷新，否则切到别的页后就不再提醒/阻止。
/// </summary>
internal sealed class UiRefreshScheduler : IDisposable
{
    private readonly object _gate = new();
    private readonly System.Windows.Forms.Timer _timer;
    private readonly List<Job> _jobs = new();
    private readonly Func<bool> _suppressed;
    private readonly IClock _clock;
    private bool _disposed;

    internal UiRefreshScheduler(Func<bool> suppressed, IClock? clock = null)
    {
        _suppressed = suppressed;
        _clock = clock ?? SystemClock.Instance;
        _timer = new System.Windows.Forms.Timer { Interval = 1000 };
        _timer.Tick += (_, _) => Tick();
        _timer.Start();
    }

    internal void Register(
        string key,
        int intervalMs,
        Func<bool> isActive,
        Func<Task> refresh)
    {
        if (string.IsNullOrWhiteSpace(key))
        {
            throw new ArgumentException("刷新任务名不能为空。", nameof(key));
        }

        if (isActive is null)
        {
            throw new ArgumentNullException(nameof(isActive));
        }

        if (refresh is null)
        {
            throw new ArgumentNullException(nameof(refresh));
        }

        lock (_gate)
        {
            if (_jobs.Any(job => string.Equals(job.Key, key, StringComparison.Ordinal)))
            {
                throw new InvalidOperationException($"刷新任务重复注册：{key}");
            }

            _jobs.Add(new Job(
                key,
                TimeSpan.FromMilliseconds(Math.Max(500, intervalMs)),
                isActive,
                refresh));
        }
    }

    private void Tick()
    {
        if (_disposed || _suppressed())
        {
            return;
        }

        List<Job> jobs;

        lock (_gate)
        {
            jobs = _jobs.ToList();
        }

        var now = _clock.UtcNow;

        foreach (var job in jobs)
        {
            if (job.Running || now < job.NextDueUtc)
            {
                continue;
            }

            bool active;

            try
            {
                active = job.IsActive();
            }
            catch (Exception ex)
            {
                LocalLog.Warning(
                    LocalLog.Pick(
                        $"页面刷新判断失败：{job.Key}",
                        $"UI refresh activation check failed: {job.Key}"),
                    ex);
                continue;
            }

            if (!active)
            {
                continue;
            }

            job.NextDueUtc = now + job.Interval;
            job.Running = true;
            _ = RunAsync(job);
        }
    }

    private static async Task RunAsync(Job job)
    {
        try
        {
            await job.Refresh().ConfigureAwait(true);
        }
        catch (Exception ex)
        {
            LocalLog.Warning(
                LocalLog.Pick(
                    $"页面刷新失败：{job.Key}",
                    $"UI refresh failed: {job.Key}"),
                ex);
        }
        finally
        {
            job.Running = false;
        }
    }

    public void Dispose()
    {
        if (_disposed)
        {
            return;
        }

        _disposed = true;
        _timer.Stop();
        _timer.Dispose();
    }

    private sealed class Job
    {
        internal Job(
            string key,
            TimeSpan interval,
            Func<bool> isActive,
            Func<Task> refresh)
        {
            Key = key;
            Interval = interval;
            IsActive = isActive;
            Refresh = refresh;
        }

        internal string Key { get; }

        internal TimeSpan Interval { get; }

        internal Func<bool> IsActive { get; }

        internal Func<Task> Refresh { get; }

        internal DateTime NextDueUtc { get; set; } = DateTime.MinValue;

        internal bool Running { get; set; }
    }
}
