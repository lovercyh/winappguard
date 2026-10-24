using System.Text;
using System.Text.Json;

namespace WinAppGuard.Core;

/// <summary>
/// 「规则分组」的本地存储：规则名 → 分组名。
///
/// 为什么单独一个文件，而不是写进 WFP 规则本身：
///   - 规则的 Description 里已经放了「自动解除」标记，再往里塞分组会让到期解析变脆；
///   - 分组只是**查看方式**，不影响规则是否生效 —— 它丢了最多是"分组回到未分组"，
///     不会让哪条规则失效。把它和规则本体解耦，风险最小。
///
/// 隐私：里面只有规则名（含程序文件名 + 短哈希）和分组名，**没有任何路径、IP 或时间戳**。
/// 规则被删除后，对应条目会在下次刷新时自动清掉（<see cref="Prune"/>）。
/// </summary>
internal sealed class RuleGroupStore
{
    private readonly object _gate = new();
    private readonly Dictionary<string, string> _groups = new(StringComparer.OrdinalIgnoreCase);
    private readonly string _filePath;
    private bool _dirty;

    internal RuleGroupStore(string? filePath = null)
    {
        _filePath = filePath ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            AppConstants.AppDataFolderName,
            "rule-groups.json");

        Load();
    }

    internal string FilePath => _filePath;

    internal string GetGroup(string ruleName)
    {
        if (string.IsNullOrWhiteSpace(ruleName))
        {
            return string.Empty;
        }

        lock (_gate)
        {
            return _groups.TryGetValue(ruleName, out var group) ? group : string.Empty;
        }
    }

    /// <summary>设置分组；传空字符串或 null 表示「未分组」。</summary>
    internal void SetGroup(string ruleName, string? group)
    {
        if (string.IsNullOrWhiteSpace(ruleName))
        {
            return;
        }

        lock (_gate)
        {
            var trimmed = (group ?? string.Empty).Trim();

            if (trimmed.Length == 0)
            {
                if (_groups.Remove(ruleName))
                {
                    _dirty = true;
                }

                return;
            }

            if (_groups.TryGetValue(ruleName, out var existing)
                && string.Equals(existing, trimmed, StringComparison.Ordinal))
            {
                return;
            }

            _groups[ruleName] = trimmed;
            _dirty = true;
        }
    }

    /// <summary>所有分组名（去重、排序；不含「未分组」）。</summary>
    internal IReadOnlyList<string> AllGroups()
    {
        lock (_gate)
        {
            return _groups.Values
                .Where(group => group.Length > 0)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(group => group, StringComparer.CurrentCulture)
                .ToList();
        }
    }

    /// <summary>
    /// 清掉已经不存在的规则留下的分组记录。
    /// 外部（wf.msc 或命令行）删掉规则后，这里不会自动知道 —— 每次刷新规则列表时顺手对齐。
    /// </summary>
    internal int Prune(IEnumerable<string> liveRuleNames)
    {
        var live = new HashSet<string>(liveRuleNames, StringComparer.OrdinalIgnoreCase);
        var removed = 0;

        lock (_gate)
        {
            foreach (var name in _groups.Keys.ToList())
            {
                if (!live.Contains(name))
                {
                    _groups.Remove(name);
                    removed++;
                    _dirty = true;
                }
            }
        }

        return removed;
    }

    /// <summary>整份替换（导入规则时用）。</summary>
    internal void ReplaceAll(IReadOnlyDictionary<string, string> groups)
    {
        lock (_gate)
        {
            _groups.Clear();

            foreach (var pair in groups)
            {
                if (!string.IsNullOrWhiteSpace(pair.Key) && !string.IsNullOrWhiteSpace(pair.Value))
                {
                    _groups[pair.Key] = pair.Value.Trim();
                }
            }

            _dirty = true;
        }
    }

    internal IReadOnlyDictionary<string, string> Snapshot()
    {
        lock (_gate)
        {
            return new Dictionary<string, string>(_groups, StringComparer.OrdinalIgnoreCase);
        }
    }

    /// <summary>
    /// 从旧版本的 groups 文件内容导入（3.0-b 数据迁移用）。
    /// 现有记录优先：同名规则不覆盖。
    /// </summary>
    /// <returns>实际新增的条数。</returns>
    internal int ImportJson(string? json)
    {
        if (string.IsNullOrWhiteSpace(json))
        {
            return 0;
        }

        Document? document;

        try
        {
            document = JsonSerializer.Deserialize<Document>(json);
        }
        catch (JsonException)
        {
            return 0;
        }

        if (document?.Groups is null)
        {
            return 0;
        }

        var added = 0;

        lock (_gate)
        {
            foreach (var pair in document.Groups)
            {
                if (string.IsNullOrWhiteSpace(pair.Key) || string.IsNullOrWhiteSpace(pair.Value))
                {
                    continue;
                }

                if (_groups.ContainsKey(pair.Key))
                {
                    continue;
                }

                _groups[pair.Key] = pair.Value.Trim();
                added++;
            }

            if (added > 0)
            {
                _dirty = true;
            }
        }

        return added;
    }

    /// <summary>保存（原子写；失败不抛出，分组丢了不算故障）。</summary>
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

                var document = new Document
                {
                    Version = 1,
                    Groups = new Dictionary<string, string>(_groups, StringComparer.OrdinalIgnoreCase),
                };

                var json = JsonSerializer.Serialize(document, new JsonSerializerOptions { WriteIndented = true });
                var temporary = _filePath + ".tmp";

                File.WriteAllText(temporary, json, new UTF8Encoding(false));
                File.Move(temporary, _filePath, overwrite: true);

                _dirty = false;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                LocalLog.Warning("[WAG-RULE-040] Failed to save rule groups.", ex);
            }
        }
    }

    private void Load()
    {
        try
        {
            if (!File.Exists(_filePath))
            {
                return;
            }

            var json = File.ReadAllText(_filePath, Encoding.UTF8);
            var document = JsonSerializer.Deserialize<Document>(json);

            if (document?.Groups is null)
            {
                return;
            }

            foreach (var pair in document.Groups)
            {
                if (!string.IsNullOrWhiteSpace(pair.Key) && !string.IsNullOrWhiteSpace(pair.Value))
                {
                    _groups[pair.Key] = pair.Value.Trim();
                }
            }
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or JsonException)
        {
            // 损坏就当空表：最坏情况是分组回到「未分组」，不影响任何规则是否生效。
            LocalLog.Warning("[WAG-RULE-041] Failed to read rule groups (treated as empty).", ex);
        }
    }

    private sealed class Document
    {
        public int Version { get; set; } = 1;

        public Dictionary<string, string> Groups { get; set; } = new();
    }
}
