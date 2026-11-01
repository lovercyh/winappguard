using System.Text;

namespace WinAppGuard.Core.Diagnostics.Config;

/// <summary>
/// 4.5：本机配置完整性分析器（纯内存、可离线测试）。
///
/// 两份快照：
///   - Baseline：用户确认的基线，只用于界面「基线值」与差异展示；
///   - Observed：上一次看到的值，用于判断“这次是不是又变了”，
///     避免同一个未修复的变更每 10 分钟重复告警。
///
/// 只报告「出现变化」的那一刻；已知配置长期偏离基线不会反复刷屏。
/// </summary>
public sealed class ConfigIntegrityAnalyzer
{
    private static readonly TimeSpan AlertCooldown = TimeSpan.FromMinutes(10);

    private readonly object _gate = new();
    private readonly Dictionary<string, ConfigEntry> _baseline = new(StringComparer.Ordinal);
    private readonly Dictionary<string, ConfigEntry> _observed = new(StringComparer.Ordinal);
    private readonly Dictionary<string, DateTime> _lastAlert = new(StringComparer.Ordinal);

    public DateTime? BaselineUtc { get; private set; }

    public int BaselineCount
    {
        get
        {
            lock (_gate)
            {
                return _baseline.Count;
            }
        }
    }

    public bool HasBaseline
    {
        get
        {
            lock (_gate)
            {
                return BaselineUtc is not null && _baseline.Count > 0;
            }
        }
    }

    /// <summary>从状态文件恢复。</summary>
    public void Load(
        DateTime? baselineUtc,
        IEnumerable<ConfigEntry>? baseline,
        IEnumerable<ConfigEntry>? observed)
    {
        lock (_gate)
        {
            _baseline.Clear();
            _observed.Clear();
            _lastAlert.Clear();
            BaselineUtc = baselineUtc;

            foreach (var entry in baseline ?? Array.Empty<ConfigEntry>())
            {
                AddOrReplaceLocked(_baseline, entry);
            }

            foreach (var entry in observed ?? Array.Empty<ConfigEntry>())
            {
                AddOrReplaceLocked(_observed, entry);
            }

            // 老状态文件没有 Observed：用 Baseline 兜底，避免升级后把旧差异全部重报一次。
            if (_observed.Count == 0)
            {
                foreach (var pair in _baseline)
                {
                    _observed[pair.Key] = pair.Value;
                }
            }
        }
    }

    /// <summary>重新采基线：基线 = 观察值 = 当前值，并清掉冷却。</summary>
    public void SetBaseline(IEnumerable<ConfigEntry> entries, DateTime nowUtc)
    {
        lock (_gate)
        {
            SetBaselineLocked(entries, nowUtc);
        }
    }

    /// <summary>比较一次当前快照，返回需要报的事件。</summary>
    public List<ConfigChange> Compare(IEnumerable<ConfigEntry> current, DateTime nowUtc)
    {
        lock (_gate)
        {
            var entries = current
                .GroupBy(KeyOf, StringComparer.Ordinal)
                .Select(group => group.Last())
                .ToList();

            if (BaselineUtc is null || _baseline.Count == 0)
            {
                SetBaselineLocked(entries, nowUtc);
                return new List<ConfigChange>();
            }

            var changes = new List<ConfigChange>();
            var seen = new HashSet<string>(StringComparer.Ordinal);

            foreach (var entry in entries)
            {
                var key = KeyOf(entry);
                seen.Add(key);

                if (!_observed.TryGetValue(key, out var previous))
                {
                    _observed[key] = entry;

                    if (!IsDefault(entry))
                    {
                        changes.Add(BuildNewChange(entry));
                    }

                    continue;
                }

                if (string.Equals(previous.Value, entry.Value, StringComparison.Ordinal))
                {
                    continue;
                }

                _observed[key] = entry;
                changes.Add(BuildChange(previous, entry));
            }

            // 键消失（用户注销、网卡拔掉）不算篡改：直接从观察表移除。
            foreach (var key in _observed.Keys.Where(key => !seen.Contains(key)).ToList())
            {
                _observed.Remove(key);
            }

            var result = new List<ConfigChange>();

            foreach (var change in changes)
            {
                var key = $"{change.Kind}|{change.Scope}";

                if (_lastAlert.TryGetValue(key, out var last)
                    && nowUtc - last < AlertCooldown)
                {
                    continue;
                }

                _lastAlert[key] = nowUtc;
                result.Add(change);
            }

            return result;
        }
    }

    /// <summary>界面用：取某个项的基线值。</summary>
    public bool TryGetBaseline(string kind, string scope, out ConfigEntry entry)
    {
        lock (_gate)
        {
            return _baseline.TryGetValue($"{kind}|{scope}", out entry!);
        }
    }

    /// <summary>导出到状态文件。</summary>
    public ConfigState ExportState()
    {
        lock (_gate)
        {
            return new ConfigState
            {
                BaselineUtc = BaselineUtc,
                Baseline = _baseline.Values
                    .Select(Clone)
                    .OrderBy(entry => entry.Kind, StringComparer.Ordinal)
                    .ThenBy(entry => entry.Scope, StringComparer.Ordinal)
                    .ToList(),
                Observed = _observed.Values
                    .Select(Clone)
                    .OrderBy(entry => entry.Kind, StringComparer.Ordinal)
                    .ThenBy(entry => entry.Scope, StringComparer.Ordinal)
                    .ToList(),
            };
        }
    }

    public static string KeyOf(ConfigEntry entry) => $"{entry.Kind}|{entry.Scope}";

    /// <summary>给事件详情用的中文标签。</summary>
    public static string LabelOf(string kind) => kind switch
    {
        ConfigKinds.Hosts => "hosts 文件",
        ConfigKinds.Proxy => "WinINET 代理",
        ConfigKinds.Pac => "PAC 自动配置",
        ConfigKinds.WinHttp => "WinHTTP 代理",
        ConfigKinds.Policy => "组策略代理",
        ConfigKinds.Dns => "DNS 服务器",
        _ => "本机配置",
    };

    private void SetBaselineLocked(IEnumerable<ConfigEntry> entries, DateTime nowUtc)
    {
        _baseline.Clear();
        _observed.Clear();
        _lastAlert.Clear();
        BaselineUtc = nowUtc;

        foreach (var entry in entries)
        {
            var key = KeyOf(entry);
            _baseline[key] = Clone(entry);
            _observed[key] = Clone(entry);
        }
    }

    private static void AddOrReplaceLocked(
        Dictionary<string, ConfigEntry> target, ConfigEntry entry)
    {
        target[KeyOf(entry)] = Clone(entry);
    }

    private static ConfigChange BuildNewChange(ConfigEntry entry) => new()
    {
        Kind = entry.Kind,
        Scope = entry.Scope,
        Severity = ConfigKinds.SeverityOf(entry.Kind),
        OldSummary = string.Empty,
        NewSummary = entry.Summary,
        Detail = $"{LabelOf(entry.Kind)}新增了配置{ScopeText(entry.Scope)}：{OrEmpty(entry.Summary)}",
    };

    private static ConfigChange BuildChange(ConfigEntry previous, ConfigEntry current) => new()
    {
        Kind = current.Kind,
        Scope = current.Scope,
        Severity = ConfigKinds.SeverityOf(current.Kind),
        OldSummary = previous.Summary,
        NewSummary = current.Summary,
        Detail = current.Kind == ConfigKinds.Hosts
            ? BuildHostsDetail(previous.Value, current.Value)
            : $"{LabelOf(current.Kind)}已变更{ScopeText(current.Scope)}：" +
              $"{OrEmpty(previous.Summary)} → {OrEmpty(current.Summary)}",
    };

    private static string BuildHostsDetail(string oldValue, string newValue)
    {
        var before = SplitLines(oldValue);
        var after = SplitLines(newValue);

        var added = after.Except(before, StringComparer.Ordinal).Take(5).ToList();
        var removed = before.Except(after, StringComparer.Ordinal).Take(5).ToList();
        var addedCount = after.Except(before, StringComparer.Ordinal).Count();
        var removedCount = before.Except(after, StringComparer.Ordinal).Count();

        var text = new StringBuilder();
        text.Append("hosts 文件已变更");
        text.Append($"：新增 {addedCount} 行，删除 {removedCount} 行");

        if (added.Count > 0)
        {
            text.Append("。新增：").Append(string.Join(" | ", added));
        }

        if (removed.Count > 0)
        {
            text.Append("。删除：").Append(string.Join(" | ", removed));
        }

        return Truncate(text.ToString(), 500);
    }

    private static IEnumerable<string> SplitLines(string value)
        => value.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    private static string ScopeText(string scope)
        => string.IsNullOrWhiteSpace(scope) ? string.Empty : $"（{scope}）";

    private static string OrEmpty(string value)
        => string.IsNullOrWhiteSpace(value) ? "（空）" : value;

    private static string Truncate(string value, int max)
        => value.Length <= max ? value : value[..max] + "…";

    private static bool IsDefault(ConfigEntry entry)
    {
        if (entry.Kind == ConfigKinds.Hosts)
        {
            return false;
        }

        return string.IsNullOrWhiteSpace(entry.Value)
               || entry.Value == "enable=0;server=;auto=0"
               || entry.Value == "enable=0;server=;pac=";
    }

    private static ConfigEntry Clone(ConfigEntry entry) => new()
    {
        Kind = entry.Kind,
        Scope = entry.Scope,
        Value = entry.Value,
        Summary = entry.Summary,
    };
}
