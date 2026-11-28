namespace WinAppGuard.Core.Diagnostics.Processes;

/// <summary>6.0：一个进程在 ETW 表中的生命周期记录。</summary>
internal sealed class ProcessTraceEntry
{
    internal int Pid { get; init; }

    internal int ParentPid { get; init; }

    internal string ImagePath { get; init; } = string.Empty;

    /// <summary>只在内存中用于 LOLBin 匹配，不写日志/画像/诊断包。</summary>
    internal string CommandLine { get; init; } = string.Empty;

    internal string ServiceInstance { get; init; } = string.Empty;

    internal string? LolbinRule { get; init; }

    internal DateTime StartUtc { get; init; }

    internal DateTime? StopUtc { get; set; }
}

internal sealed record ProcessLookup(ProcessTraceEntry? Entry, bool Exact);

/// <summary>
/// 6.0：进程生命周期表。ETW 是主来源，启动时用进程快照兜底。
/// </summary>
internal sealed class ProcessTable
{
    private const int MaxEntries = 8192;
    private static readonly TimeSpan RecentWindow = TimeSpan.FromMinutes(10);

    private readonly object _gate = new();
    private readonly Dictionary<int, List<ProcessTraceEntry>> _byPid = new();

    internal int Count
    {
        get { lock (_gate) { return _byPid.Count; } }
    }

    internal void AddStart(ProcessTraceEntry entry)
    {
        lock (_gate)
        {
            if (!_byPid.TryGetValue(entry.Pid, out var list))
            {
                list = new List<ProcessTraceEntry>();
                _byPid[entry.Pid] = list;
            }

            // 同一 PID 的同一开始时间重复上报（Rundown + 实时事件）只保留一条。
            if (list.Any(existing => existing.StartUtc == entry.StartUtc))
            {
                return;
            }

            list.Add(entry);

            if (list.Count > 32)
            {
                list.RemoveRange(0, list.Count - 32);
            }

            PruneLocked();
        }
    }

    internal void AddStop(int pid, DateTime stopUtc)
    {
        lock (_gate)
        {
            if (!_byPid.TryGetValue(pid, out var list))
            {
                return;
            }

            for (var i = list.Count - 1; i >= 0; i--)
            {
                if (list[i].StopUtc is null)
                {
                    list[i].StopUtc = stopUtc;
                    break;
                }
            }
        }
    }

    internal ProcessLookup Resolve(int pid, DateTime atUtc)
    {
        lock (_gate)
        {
            if (!_byPid.TryGetValue(pid, out var list))
            {
                return new ProcessLookup(null, false);
            }

            var matches = list
                .Where(entry => entry.StartUtc <= atUtc
                                && (entry.StopUtc is null || entry.StopUtc >= atUtc))
                .OrderByDescending(entry => entry.StartUtc)
                .ToList();

            if (matches.Count == 1)
            {
                return new ProcessLookup(matches[0], true);
            }

            if (matches.Count > 1)
            {
                // PID 在同一时刻出现重叠：数据不可靠，返回最近一条但标记不确定。
                return new ProcessLookup(matches[0], false);
            }

            // 告警通常比进程退出晚几毫秒：允许最近窗口内的结束进程。
            var recent = list
                .Where(entry => entry.StopUtc is { } stop
                                && stop >= atUtc - RecentWindow)
                .OrderByDescending(entry => entry.StartUtc)
                .FirstOrDefault();

            return new ProcessLookup(recent, false);
        }
    }

    internal ProcessLookup ResolveCurrent(int pid)
    {
        lock (_gate)
        {
            if (!_byPid.TryGetValue(pid, out var list))
            {
                return new ProcessLookup(null, false);
            }

            var active = list
                .Where(entry => entry.StopUtc is null)
                .OrderByDescending(entry => entry.StartUtc)
                .FirstOrDefault();

            if (active is not null)
            {
                return new ProcessLookup(active, true);
            }

            var recent = list
                .OrderByDescending(entry => entry.StartUtc)
                .FirstOrDefault();

            return new ProcessLookup(recent, false);
        }
    }

    internal IReadOnlyList<ProcessTraceEntry> Snapshot()
    {
        lock (_gate)
        {
            return _byPid.Values
                .SelectMany(list => list)
                .OrderByDescending(entry => entry.StartUtc)
                .Take(512)
                .ToList();
        }
    }

    /// <summary>服务启动时补齐已存在的进程；路径拿不到就留空，不猜。</summary>
    internal void SeedSnapshot()
    {
        foreach (var process in System.Diagnostics.Process.GetProcesses())
        {
            try
            {
                var start = process.StartTime.ToUniversalTime();
                var image = string.Empty;

                try
                {
                    image = process.MainModule?.FileName ?? string.Empty;
                }
                catch (Exception)
                {
                    // 系统/其它用户进程可能拒绝访问。
                }

                AddStart(new ProcessTraceEntry
                {
                    Pid = process.Id,
                    ParentPid = 0,
                    ImagePath = image,
                    StartUtc = start,
                });
            }
            catch (Exception)
            {
                // 进程可能已退出。
            }
            finally
            {
                process.Dispose();
            }
        }
    }

    private void PruneLocked()
    {
        if (_byPid.Count <= MaxEntries)
        {
            return;
        }

        var cutoff = DateTime.UtcNow.AddHours(-1);

        foreach (var pid in _byPid.Keys.ToList())
        {
            var list = _byPid[pid];
            list.RemoveAll(entry => entry.StopUtc is { } stop && stop < cutoff);

            if (list.Count == 0)
            {
                _byPid.Remove(pid);
            }

            if (_byPid.Count <= MaxEntries)
            {
                break;
            }
        }
    }
}
