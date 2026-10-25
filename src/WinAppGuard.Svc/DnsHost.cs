using WinAppGuard.Contracts;
using WinAppGuard.Core;
using WinAppGuard.Core.Diagnostics;

namespace WinAppGuard.Service;

/// <summary>
/// 3.5：DNS 采集宿主（服务端）。
///
/// 真正抓事件的是 <see cref="DnsEtwMonitor"/>（Core）；这里只负责：
///   - 随服务启动 / 停止；
///   - 会话挂掉后自动重启（30 秒看门狗）；
///   - 给查询结果补上进程路径（服务以 SYSTEM 运行，能读到界面读不到的进程）。
/// </summary>
internal static class DnsHost
{
    private static readonly object Gate = new();

    private static readonly TimeSpan ProcessCacheTtl = TimeSpan.FromSeconds(60);

    private static DnsEtwMonitor? _monitor;
    private static System.Threading.Timer? _watchdog;
    private static readonly Dictionary<int, ProcessCacheEntry> ProcessCache = new();

    internal static bool Collecting
    {
        get { lock (Gate) { return _monitor?.IsRunning == true; } }
    }

    internal static void Start()
    {
        EnsureRunning();

        lock (Gate)
        {
            // 采集挂了要能自己回来；不要因为一次 StartTrace 失败就永久沉默。
            _watchdog ??= new System.Threading.Timer(
                _ => EnsureRunning(),
                state: null,
                dueTime: TimeSpan.FromSeconds(30),
                period: TimeSpan.FromSeconds(30));
        }
    }

    internal static void Stop()
    {
        DnsEtwMonitor? monitor;

        lock (Gate)
        {
            _watchdog?.Dispose();
            _watchdog = null;

            monitor = _monitor;
            _monitor = null;
            ProcessCache.Clear();
        }

        monitor?.Dispose();
        ServiceLog.Info("WAG-DNS-003", "DNS ETW collection stopped.");
    }

    internal static List<DnsDto> Snapshot(int max)
    {
        DnsEtwMonitor? monitor;

        lock (Gate)
        {
            monitor = _monitor;
        }

        if (monitor is null)
        {
            return new List<DnsDto>();
        }

        var records = monitor.Snapshot(max);
        var result = new List<DnsDto>(records.Count);

        lock (Gate)
        {
            foreach (var record in records)
            {
                var (path, name) = ResolveProcessLocked(record.Pid);

                result.Add(new DnsDto
                {
                    TimeUtc = record.TimeUtc,
                    Pid = record.Pid,
                    ProcessPath = path,
                    ProcessName = name,
                    QueryName = record.QueryName,
                    Status = record.Status,
                });
            }
        }

        return result;
    }

    /// <summary>清空内存记录，返回清掉的条数。</summary>
    internal static int Clear()
    {
        DnsEtwMonitor? monitor;

        lock (Gate)
        {
            monitor = _monitor;
        }

        if (monitor is null)
        {
            return 0;
        }

        var count = monitor.Snapshot(10_000).Count;
        monitor.Clear();
        ServiceLog.Operation("WAG-DNS-005", $"DNS records cleared ({count} removed).");
        return count;
    }

    private static void EnsureRunning()
    {
        lock (Gate)
        {
            if (_monitor is { IsRunning: true })
            {
                return;
            }

            if (_monitor is not null)
            {
                var stopped = _monitor;
                _monitor = null;

                try
                {
                    stopped.Dispose();
                }
                catch (Exception ex)
                {
                    ServiceLog.Warning("WAG-DNS-006", "Failed to dispose a stopped DNS ETW session.", ex);
                }

                ServiceLog.Warning("WAG-DNS-004", "DNS ETW session was not running; restarting it.");
            }

            var monitor = new DnsEtwMonitor();

            if (!monitor.Start())
            {
                ServiceLog.Warning(
                    "WAG-DNS-001",
                    $"DNS ETW collection failed to start: {monitor.LastError}.");
                monitor.Dispose();
                return;
            }

            _monitor = monitor;
            ServiceLog.Info(
                "WAG-DNS-002",
                "DNS ETW collection started (Microsoft-Windows-DNS-Client).");
        }
    }

    private static (string? Path, string Name) ResolveProcessLocked(int pid)
    {
        var now = DateTime.UtcNow;

        if (ProcessCache.TryGetValue(pid, out var cached)
            && now - cached.At < ProcessCacheTtl)
        {
            return (cached.Path, Describe(cached.Path, pid));
        }

        if (ProcessCache.Count > 512)
        {
            ProcessCache.Clear();
        }

        string? path;

        try
        {
            path = ProcessResolver.TryGetImagePath(pid);
        }
        catch (Exception)
        {
            path = null;
        }

        ProcessCache[pid] = new ProcessCacheEntry
        {
            Path = path,
            At = now,
        };

        return (path, Describe(path, pid));
    }

    private static string Describe(string? path, int pid)
        => string.IsNullOrEmpty(path) ? $"PID {pid}" : Path.GetFileName(path);

    private sealed class ProcessCacheEntry
    {
        public string? Path;
        public DateTime At;
    }
}
