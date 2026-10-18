using System.Globalization;
using System.Text;
using System.Text.Json;

namespace WinAppGuard.Core.Audit;

/// <summary>用户对一个程序的处置决定。</summary>
internal enum ProgramDecision
{
    /// <summary>还没决定（第一次见到）。</summary>
    Unknown = 0,

    /// <summary>允许联网（不再询问）。</summary>
    Allowed = 1,

    /// <summary>阻止联网（同时会建一条阻止规则）。</summary>
    Blocked = 2,

    /// <summary>以后不再提示，但也不建规则。</summary>
    Ignored = 3,
}

/// <summary>一个见过的程序。</summary>
internal sealed record KnownProgram(
    string Path,
    ProgramDecision Decision,
    DateTime FirstSeenUtc,
    DateTime LastSeenUtc);

/// <summary>
/// 「已知程序」记录：记住每个程序第一次出现的时间，以及用户当时的处置决定。
///
/// 存在的意义：告警只应该在**第一次**见到某个程序时出现一次。
/// 没有这份记录的话，同一个程序每 3 秒就会弹一次 —— 那是骚扰，不是功能。
///
/// 存储：<c>%LOCALAPPDATA%\WinAppGuard\known-programs.json</c>，**只写本机**。
/// 里面只有程序路径和时间/决定，不包含任何网络信息。
/// 文件损坏时回落到空表（不会因此报错，最多重新问一次）。
/// </summary>
internal sealed class KnownProgramStore
{
    private readonly object _gate = new();
    private readonly string _filePath;
    private readonly Dictionary<string, KnownProgram> _programs =
        new(StringComparer.OrdinalIgnoreCase);

    private bool _dirty;

    internal KnownProgramStore(string? filePath = null)
    {
        _filePath = filePath ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            AppConstants.AppDataFolderName,
            "known-programs.json");

        Load();
    }

    /// <summary>文件路径（界面/日志用）。</summary>
    internal string FilePath => _filePath;

    /// <summary>是否成功加载过（损坏时也返回 true，只是表为空）。</summary>
    internal bool Loaded { get; private set; }

    /// <summary>当前记录数。</summary>
    internal int Count
    {
        get
        {
            lock (_gate)
            {
                return _programs.Count;
            }
        }
    }

    /// <summary>
    /// 记录一次"看到这个程序"。
    /// </summary>
    /// <returns>
    /// 如果这是**第一次**见到它，返回 true（调用方据此决定要不要告警）；
    /// 已经见过返回 false。
    /// </returns>
    internal bool Observe(string path, DateTime nowUtc)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        lock (_gate)
        {
            if (_programs.TryGetValue(path, out var existing))
            {
                _programs[path] = existing with { LastSeenUtc = nowUtc };
                _dirty = true;
                return false;
            }

            _programs[path] = new KnownProgram(path, ProgramDecision.Unknown, nowUtc, nowUtc);
            _dirty = true;
            return true;
        }
    }

    /// <summary>取出某个程序的记录；没见过返回 null。</summary>
    internal KnownProgram? Find(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return null;
        }

        lock (_gate)
        {
            return _programs.TryGetValue(path, out var program) ? program : null;
        }
    }

    /// <summary>设置用户决定。程序不在表里时会自动补一条。</summary>
    internal void SetDecision(string path, ProgramDecision decision, DateTime nowUtc)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return;
        }

        lock (_gate)
        {
            if (_programs.TryGetValue(path, out var existing))
            {
                _programs[path] = existing with { Decision = decision, LastSeenUtc = nowUtc };
            }
            else
            {
                _programs[path] = new KnownProgram(path, decision, nowUtc, nowUtc);
            }

            _dirty = true;
        }
    }

    /// <summary>
    /// 忘掉一个程序（用户选了「稍后」）。
    ///
    /// 为什么需要它：告警只在"第一次见到"时触发一次，
    /// 如果「稍后」也把它标成已知，那用户就再也等不到这次询问了 ——
    /// 那不是"稍后"，是"永不"。
    /// </summary>
    internal void Forget(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return;
        }

        lock (_gate)
        {
            if (_programs.Remove(path))
            {
                _dirty = true;
            }
        }
    }

    /// <summary>全部记录（按首次出现时间倒序）。</summary>
    internal IReadOnlyList<KnownProgram> All()
    {
        lock (_gate)
        {
            return _programs.Values
                .OrderByDescending(program => program.FirstSeenUtc)
                .ToList();
        }
    }

    /// <summary>把改动写回磁盘（原子替换，断电不会留下半个文件）。</summary>
    internal void Save()
    {
        lock (_gate)
        {
            if (!_dirty)
            {
                return;
            }

            try
            {
                var directory = Path.GetDirectoryName(_filePath);
                if (!string.IsNullOrEmpty(directory))
                {
                    Directory.CreateDirectory(directory);
                }

                var json = JsonSerializer.Serialize(_programs.Values.ToList(), new JsonSerializerOptions
                {
                    WriteIndented = true,
                });

                var temp = _filePath + ".tmp";
                File.WriteAllText(temp, json, new UTF8Encoding(false));
                File.Move(temp, _filePath, overwrite: true);

                _dirty = false;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                LocalLog.Warning($"保存已知程序列表失败：{ex.Message}");
            }
        }
    }

    private void Load()
    {
        Loaded = true;

        try
        {
            if (!File.Exists(_filePath))
            {
                return;
            }

            var json = File.ReadAllText(_filePath, Encoding.UTF8);
            var items = JsonSerializer.Deserialize<List<KnownProgram>>(json);

            if (items is null)
            {
                return;
            }

            foreach (var item in items)
            {
                if (!string.IsNullOrWhiteSpace(item.Path))
                {
                    _programs[item.Path] = item;
                }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            // 损坏就当作空表：最多重新问用户一次，不会影响其它功能。
            LocalLog.Warning($"读取已知程序列表失败（将按空表处理）：{ex.Message}");
        }
    }
}
