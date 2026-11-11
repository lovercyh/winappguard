using System.Text.Json;
using WinAppGuard.Core.Storage;
using WinAppGuard.Models;

namespace WinAppGuard.Core;

/// <summary>5.9：FirstSeen 记录的新状态外壳；旧文件是顶层数组。</summary>
public sealed class FirstSeenProgramState
{
    public List<FirstSeenProgramRecord> Records { get; set; } = new();
}

/// <summary>
/// 5.8：「新程序联网提醒」的本地记录。
///
/// 文件位置：<c>%LOCALAPPDATA%\WinAppGuard\first-seen-programs.json</c>
///
/// 边界：
///   - 只记录程序路径、进程名和首次 / 最近联网时间；
///   - 不记录 IP、域名、端口或命令行；
///   - 只在本机，不上传；
///   - 模式关闭时由界面决定不调用本类，因此不会继续写入。
/// </summary>
public sealed class FirstSeenProgramStore
{
    private static readonly TimeSpan NotifyCooldown = TimeSpan.FromHours(24);
    private static readonly TimeSpan LastSeenSaveInterval = TimeSpan.FromMinutes(1);

    private readonly object _gate = new();
    private readonly Dictionary<string, FirstSeenProgramRecord> _records =
        new(StringComparer.OrdinalIgnoreCase);

    private DateTime _lastSaveUtc = DateTime.MinValue;

    public FirstSeenProgramStore(string? filePath = null)
    {
        FilePath = filePath ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            AppConstants.AppDataFolderName,
            "first-seen-programs.json");

        Load();
    }

    public string FilePath { get; }

    public string? LastError { get; private set; }

    public int Count
    {
        get
        {
            lock (_gate)
            {
                return _records.Count;
            }
        }
    }

    public int NewCount
    {
        get
        {
            lock (_gate)
            {
                return _records.Values.Count(record => record.IsNew);
            }
        }
    }

    /// <summary>按首次联网时间倒序返回快照。</summary>
    public IReadOnlyList<FirstSeenProgramRecord> Snapshot()
    {
        lock (_gate)
        {
            return _records.Values
                .OrderByDescending(record => record.FirstSeenUtc)
                .ThenBy(record => record.ProcessName, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }
    }

    public FirstSeenProgramRecord? Find(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return null;
        }

        lock (_gate)
        {
            return _records.TryGetValue(path.Trim(), out var record) ? record : null;
        }
    }

    /// <summary>
    /// 模式开启时的静默基线：当前已联网的程序记为“已知 / 启用时已在线”。
    /// 返回新加入的记录数。
    /// </summary>
    public int Baseline(
        IEnumerable<(string Path, string ProcessName)> programs,
        DateTime nowUtc)
    {
        var added = 0;

        lock (_gate)
        {
            foreach (var (path, processName) in Normalize(programs))
            {
                if (_records.TryGetValue(path, out var existing))
                {
                    existing.LastSeenUtc = nowUtc;
                    continue;
                }

                _records[path] = new FirstSeenProgramRecord
                {
                    Path = path,
                    ProcessName = processName,
                    FirstSeenUtc = nowUtc,
                    LastSeenUtc = nowUtc,
                    Acknowledged = true,
                    IsBaseline = true,
                };

                added++;
            }

            SaveLocked();
        }

        return added;
    }

    /// <summary>
    /// 模式开启后的正常观察：
    ///   - 未记录的路径 → 新增为“新”，并返回新增记录；
    ///   - 已记录的路径 → 只更新最近联网时间。
    /// </summary>
    public IReadOnlyList<FirstSeenProgramRecord> Observe(
        IEnumerable<(string Path, string ProcessName)> programs,
        DateTime nowUtc)
    {
        var added = new List<FirstSeenProgramRecord>();

        lock (_gate)
        {
            foreach (var (path, processName) in Normalize(programs))
            {
                if (_records.TryGetValue(path, out var existing))
                {
                    existing.LastSeenUtc = nowUtc;
                    continue;
                }

                var record = new FirstSeenProgramRecord
                {
                    Path = path,
                    ProcessName = processName,
                    FirstSeenUtc = nowUtc,
                    LastSeenUtc = nowUtc,
                    Acknowledged = false,
                    IsBaseline = false,
                };

                _records[path] = record;
                added.Add(record);
            }

            if (added.Count > 0)
            {
                SaveLocked();
            }
            else if (nowUtc - _lastSaveUtc >= LastSeenSaveInterval)
            {
                // 最近联网时间只在内存里更新也没关系，但定期落盘一次，
                // 避免重启后所有“最近联网时间”都停在很久以前。
                SaveLocked();
            }
        }

        return added;
    }

    public bool MarkKnown(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        lock (_gate)
        {
            if (!_records.TryGetValue(path.Trim(), out var record) || record.Acknowledged)
            {
                return false;
            }

            record.Acknowledged = true;
            SaveLocked();
            return true;
        }
    }

    /// <summary>记录用户在默认阻止弹窗里的选择。</summary>
    public bool SetDecision(string? path, FirstSeenDecision decision)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        lock (_gate)
        {
            if (!_records.TryGetValue(path.Trim(), out var record)
                || record.Decision == decision)
            {
                return false;
            }

            record.Decision = decision;
            SaveLocked();
            return true;
        }
    }

    /// <summary>把全部记录标记为已知，返回实际改变的数量。</summary>
    public int MarkAllKnown()
    {
        lock (_gate)
        {
            var changed = 0;

            foreach (var record in _records.Values)
            {
                if (record.Acknowledged)
                {
                    continue;
                }

                record.Acknowledged = true;
                changed++;
            }

            if (changed > 0)
            {
                SaveLocked();
            }

            return changed;
        }
    }

    public bool Delete(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        lock (_gate)
        {
            if (!_records.Remove(path.Trim()))
            {
                return false;
            }

            SaveLocked();
            return true;
        }
    }

    public void Clear()
    {
        lock (_gate)
        {
            _records.Clear();
            SaveLocked();
        }
    }

    /// <summary>同一个程序 24 小时内只提醒一次。</summary>
    public bool ShouldNotify(FirstSeenProgramRecord record, DateTime nowUtc)
        => record.IsNew
           && (record.LastNotifiedUtc is null
               || nowUtc - record.LastNotifiedUtc.Value >= NotifyCooldown);

    public void MarkNotified(IEnumerable<string> paths, DateTime nowUtc)
    {
        lock (_gate)
        {
            var changed = false;

            foreach (var path in paths)
            {
                if (string.IsNullOrWhiteSpace(path)
                    || !_records.TryGetValue(path.Trim(), out var record))
                {
                    continue;
                }

                record.LastNotifiedUtc = nowUtc;
                changed = true;
            }

            if (changed)
            {
                SaveLocked();
            }
        }
    }

    private static IEnumerable<(string Path, string ProcessName)> Normalize(
        IEnumerable<(string Path, string ProcessName)> programs)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var (path, processName) in programs)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                continue;
            }

            var normalized = path.Trim();

            if (!seen.Add(normalized))
            {
                continue;
            }

            yield return (
                normalized,
                string.IsNullOrWhiteSpace(processName)
                    ? Path.GetFileName(normalized)
                    : processName.Trim());
        }
    }

    private void Load()
    {
        var state = CreateFile().Load(out var error, out var migrated);
        LastError = error;

        if (state is null)
        {
            return;
        }

        foreach (var record in state.Records ?? new List<FirstSeenProgramRecord>())
        {
            if (string.IsNullOrWhiteSpace(record.Path))
            {
                continue;
            }

            record.Path = record.Path.Trim();
            _records[record.Path] = record;
        }

        if (migrated)
        {
            SaveLocked();
        }
    }

    private void SaveLocked()
    {
        try
        {
            CreateFile().Save(new FirstSeenProgramState
            {
                Records = _records.Values
                    .OrderBy(record => record.FirstSeenUtc)
                    .ToList(),
            });

            _lastSaveUtc = DateTime.UtcNow;
            LastError = null;
        }
        catch (Exception ex)
        {
            // 写不进去不能让界面崩；下一次有变化再试。
            LastError = ex.Message;
        }
    }

    private JsonStateFile<FirstSeenProgramState> CreateFile()
        => new(FilePath, schemaVersion: 1)
        {
            // 5.8 及更早：顶层是记录数组；5.9：schema/data 外壳。
            Migrate = root => root.ValueKind == JsonValueKind.Array
                ? new FirstSeenProgramState
                {
                    Records = root.Deserialize<List<FirstSeenProgramRecord>>(
                                  JsonStateFile<FirstSeenProgramState>.JsonOptions)
                              ?? new List<FirstSeenProgramRecord>(),
                }
                : JsonStateFile<FirstSeenProgramState>.Deserialize(root),
        };
}
