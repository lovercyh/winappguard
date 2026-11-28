using WinAppGuard.Core;

namespace WinAppGuard.Core.Diagnostics.Processes;

internal sealed record ProcessAttributionResult(
    int Pid,
    string Name,
    string Path,
    string ParentPath,
    string ServiceInstance,
    string? LolbinRule,
    bool Exact,
    string Source);

/// <summary>
/// 6.0：外部模块查询进程归属的唯一入口。
/// ETW 表命中时用 ETW；未命中才回退到当前进程查询，并标记“不确定”。
/// </summary>
internal static class ProcessAttribution
{
    private static ProcessTable? _table;

    internal static void SetTable(ProcessTable table) => _table = table;

    internal static ProcessAttributionResult Resolve(int pid, DateTime? atUtc = null)
    {
        if (pid <= 0)
        {
            return new ProcessAttributionResult(0, string.Empty, string.Empty,
                string.Empty, string.Empty, null, false, "none");
        }

        var table = _table;

        if (table is not null)
        {
            var lookup = atUtc is { } at
                ? table.Resolve(pid, at)
                : table.ResolveCurrent(pid);

            if (lookup.Entry is { } entry)
            {
                var parentPath = string.Empty;

                if (entry.ParentPid > 0)
                {
                    parentPath = table.ResolveCurrent(entry.ParentPid).Entry?.ImagePath
                                 ?? string.Empty;
                }

                return new ProcessAttributionResult(
                    pid,
                    string.IsNullOrEmpty(entry.ImagePath)
                        ? $"PID {pid}"
                        : Path.GetFileName(entry.ImagePath),
                    entry.ImagePath,
                    parentPath,
                    entry.ServiceInstance,
                    entry.LolbinRule,
                    lookup.Exact,
                    "etw");
            }
        }

        var identity = ProcessResolver.Resolve(pid);

        return new ProcessAttributionResult(
            pid,
            identity.Name,
            identity.Path,
            string.Empty,
            string.Empty,
            null,
            false,
            "polling");
    }
}

internal sealed record ProcessEtwStatus(
    bool Enabled,
    bool Running,
    bool Fallback,
    int TableEntries,
    long EventsSeen,
    long ParseFailures,
    long LolbinMatches,
    string? LastError,
    DateTime? LastEventUtc,
    int RestartAttempts,
    DateTime? NextRetryUtc);

/// <summary>6.0：Kernel-Process ETW 的服务级宿主。失败时自动重试。</summary>
internal static class ProcessEtwHost
{
    private static readonly ProcessTable Table = new();
    private static readonly object Gate = new();
    private static ProcessEtwMonitor? _monitor;
    private static Timer? _watchdog;
    private static bool _started;
    private static int _restartAttempts;
    private static string? _lastError;
    private static DateTime? _nextRetryUtc;

    internal static bool Enabled { get; set; } = true;

    internal static void Start()
    {
        lock (Gate)
        {
            if (_started)
            {
                return;
            }

            _started = true;
            ProcessAttribution.SetTable(Table);
            Table.SeedSnapshot();
            TryStartLocked();

            _watchdog ??= new Timer(
                _ => WatchdogTick(), null, TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(10));
        }
    }

    internal static void Stop()
    {
        lock (Gate)
        {
            _started = false;
            _watchdog?.Dispose();
            _watchdog = null;
            _monitor?.Dispose();
            _monitor = null;
            _nextRetryUtc = null;
        }
    }

    internal static ProcessEtwStatus Snapshot()
    {
        lock (Gate)
        {
            var monitor = _monitor;

            return new ProcessEtwStatus(
                Enabled,
                monitor?.IsRunning == true,
                monitor is null || !monitor.IsRunning,
                Table.Count,
                monitor?.EventsSeen ?? 0,
                monitor?.ParseFailures ?? 0,
                monitor?.LolbinMatches ?? 0,
                _lastError ?? monitor?.LastError,
                monitor?.LastEventUtc,
                _restartAttempts,
                _nextRetryUtc);
        }
    }

    private static void WatchdogTick()
    {
        lock (Gate)
        {
            if (!_started)
            {
                return;
            }

            if (_monitor?.IsRunning == true)
            {
                return;
            }

            // ETW 会话可能在服务重启、会话被停或驱动异常后退出。
            // 与旧服务探测一致：自动重建，不要求用户手动点开关。
            TryStartLocked();
        }
    }

    private static void TryStartLocked()
    {
        _monitor?.Dispose();
        _monitor = null;

        var monitor = new ProcessEtwMonitor(Table);

        if (monitor.Start())
        {
            _monitor = monitor;
            _restartAttempts = 0;
            _lastError = null;
            _nextRetryUtc = null;
            return;
        }

        _lastError = monitor.LastError ?? "ETW start failed.";
        monitor.Dispose();
        _restartAttempts++;
        _nextRetryUtc = DateTime.UtcNow.AddSeconds(10);
        LocalLog.Warning($"[WAG-PROC-ETW-001] Kernel-Process ETW start failed (attempt {_restartAttempts}): {_lastError}");
    }
}
