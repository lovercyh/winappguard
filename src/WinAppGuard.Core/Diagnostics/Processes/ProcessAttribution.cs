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
    string? LastError,
    DateTime? LastEventUtc);

/// <summary>6.0：Kernel-Process ETW 的服务级宿主。</summary>
internal static class ProcessEtwHost
{
    private static readonly ProcessTable Table = new();
    private static ProcessEtwMonitor? _monitor;
    private static bool _started;

    internal static bool Enabled { get; set; } = true;

    internal static void Start()
    {
        if (_started || !Enabled)
        {
            return;
        }

        _started = true;
        ProcessAttribution.SetTable(Table);
        Table.SeedSnapshot();

        _monitor = new ProcessEtwMonitor(Table);

        if (!_monitor.Start())
        {
            // ETW 失败不阻止服务：归因自动回退到轮询。
            _monitor.Dispose();
            _monitor = null;
        }
    }

    internal static void Stop()
    {
        _started = false;
        _monitor?.Dispose();
        _monitor = null;
    }

    internal static ProcessEtwStatus Snapshot()
    {
        var monitor = _monitor;

        return new ProcessEtwStatus(
            Enabled,
            monitor?.IsRunning == true,
            monitor is null || !monitor.IsRunning,
            Table.Count,
            monitor?.EventsSeen ?? 0,
            monitor?.ParseFailures ?? 0,
            monitor?.LastError,
            monitor?.LastEventUtc);
    }
}
