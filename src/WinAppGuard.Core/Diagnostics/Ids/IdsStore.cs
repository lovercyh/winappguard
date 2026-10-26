using System.Text;
using System.Text.Json;

namespace WinAppGuard.Core.Diagnostics.Ids;

/// <summary>3.7：IDS 的持久化状态（设置、抑制、告警确认状态）。</summary>
public sealed class IdsState
{
    public IdsSettings Settings { get; set; } = new();

    public List<IdsSuppression> Suppressions { get; set; } = new();

    /// <summary>告警 id → new / ack / ignored。</summary>
    public Dictionary<string, string> AlertStatuses { get; set; } =
        new(StringComparer.Ordinal);
}

/// <summary>3.7：状态文件的原子读写；坏文件按默认值处理，不影响服务启动。</summary>
public static class IdsStateFile
{
    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
    };

    public static IdsState Load(string path)
    {
        try
        {
            if (!File.Exists(path))
            {
                return new IdsState();
            }

            var state = JsonSerializer.Deserialize<IdsState>(
                File.ReadAllText(path, Encoding.UTF8), Options);

            if (state is null)
            {
                return new IdsState();
            }

            state.Settings ??= new IdsSettings();
            state.Suppressions ??= new List<IdsSuppression>();
            state.AlertStatuses ??= new Dictionary<string, string>(StringComparer.Ordinal);

            state.Settings.RetentionDays = Math.Clamp(state.Settings.RetentionDays, 1, 365);

            if (!string.Equals(
                    state.Settings.Sensitivity, "conservative", StringComparison.OrdinalIgnoreCase))
            {
                state.Settings.Sensitivity = "standard";
            }
            else
            {
                state.Settings.Sensitivity = "conservative";
            }

            // 坏 state 文件里可能有 null 项；丢掉，避免之后抑制匹配时 NRE。
            state.Suppressions = state.Suppressions
                .Where(item => item is not null)
                .ToList();

            foreach (var suppression in state.Suppressions)
            {
                if (string.IsNullOrWhiteSpace(suppression.Id))
                {
                    suppression.Id = Guid.NewGuid().ToString("N");
                }

                if (string.IsNullOrWhiteSpace(suppression.RuleId))
                {
                    suppression.RuleId = "*";
                }
            }

            state.AlertStatuses = new Dictionary<string, string>(
                state.AlertStatuses, StringComparer.Ordinal);

            return state;
        }
        catch (Exception)
        {
            return new IdsState();
        }
    }

    public static void Save(string path, IdsState state)
    {
        var directory = Path.GetDirectoryName(path);

        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var temporary = path + ".tmp";
        File.WriteAllText(
            temporary,
            JsonSerializer.Serialize(state, Options),
            new UTF8Encoding(false));

        File.Move(temporary, path, overwrite: true);
    }
}

/// <summary>
/// 3.7：告警追加日志（单文件 JSONL）。
///
/// 告警很少，按天切文件收益不大；单文件 + 读取时按保留期过滤即可。
/// 追加写只加一行，不重写历史；坏行在读取时跳过。
/// </summary>
public sealed class IdsAlertStore
{
    private static readonly JsonSerializerOptions Options = new();

    private readonly object _gate = new();
    private readonly string _alertsFile;

    public IdsAlertStore(string directory)
    {
        Directory = directory;
        _alertsFile = Path.Combine(directory, "alerts.jsonl");

        try
        {
            System.IO.Directory.CreateDirectory(directory);
        }
        catch (Exception)
        {
            // 建不了目录时后续写入会失败，由调用方记录日志。
        }
    }

    public string Directory { get; }

    public void Append(IdsAlert alert)
    {
        var line = JsonSerializer.Serialize(alert, Options);

        lock (_gate)
        {
            File.AppendAllText(
                _alertsFile,
                line + Environment.NewLine,
                new UTF8Encoding(false));
        }
    }

    public List<IdsAlert> LoadRecent(int retentionDays, int max)
    {
        lock (_gate)
        {
            if (!File.Exists(_alertsFile))
            {
                return new List<IdsAlert>();
            }

            var cutoff = DateTime.UtcNow.AddDays(-Math.Clamp(retentionDays, 1, 365));
            var alerts = new List<IdsAlert>();
            var seen = new HashSet<string>(StringComparer.Ordinal);

            foreach (var line in File.ReadLines(_alertsFile, Encoding.UTF8))
            {
                if (string.IsNullOrWhiteSpace(line))
                {
                    continue;
                }

                try
                {
                    var alert = JsonSerializer.Deserialize<IdsAlert>(line, Options);

                    if (alert is null
                        || alert.TimeUtc < cutoff
                        || string.IsNullOrEmpty(alert.Id)
                        || !seen.Add(alert.Id))
                    {
                        continue;
                    }

                    Normalize(alert);
                    alerts.Add(alert);
                }
                catch (Exception)
                {
                    // 半行/坏行：跳过，不影响其他告警。
                }
            }

            return alerts
                .OrderByDescending(alert => alert.TimeUtc)
                .Take(Math.Clamp(max, 1, 5000))
                .ToList();
        }
    }

    public void Clear()
    {
        lock (_gate)
        {
            try
            {
                if (File.Exists(_alertsFile))
                {
                    File.Delete(_alertsFile);
                }
            }
            catch (Exception)
            {
                // 删除失败由宿主记录；界面会显示未清空。
            }
        }
    }

    private static void Normalize(IdsAlert alert)
    {
        alert.Severity = string.IsNullOrEmpty(alert.Severity)
            ? IdsSeverity.Medium
            : alert.Severity;
        alert.RuleId ??= string.Empty;
        alert.RuleName ??= string.Empty;
        alert.ProcessName ??= string.Empty;
        alert.Target ??= string.Empty;
        alert.Evidence ??= string.Empty;
        alert.Status = string.IsNullOrEmpty(alert.Status) ? "new" : alert.Status;
        alert.DedupKey ??= string.Empty;
    }

    /// <summary>
    /// 3.7：按保留期重写告警文件，避免文件无限增长。
    /// 返回删掉的条数；坏行会一并丢弃。
    /// </summary>
    public int Prune(int retentionDays)
    {
        lock (_gate)
        {
            if (!File.Exists(_alertsFile))
            {
                return 0;
            }

            var cutoff = DateTime.UtcNow.AddDays(-Math.Clamp(retentionDays, 1, 365));
            var kept = new List<string>();
            var seen = new HashSet<string>(StringComparer.Ordinal);
            var removed = 0;

            try
            {
                foreach (var line in File.ReadLines(_alertsFile, Encoding.UTF8))
                {
                    if (string.IsNullOrWhiteSpace(line))
                    {
                        removed++;
                        continue;
                    }

                    try
                    {
                        var alert = JsonSerializer.Deserialize<IdsAlert>(line, Options);

                        if (alert is null
                            || alert.TimeUtc < cutoff
                            || string.IsNullOrEmpty(alert.Id)
                            || !seen.Add(alert.Id))
                        {
                            removed++;
                            continue;
                        }

                        kept.Add(line);
                    }
                    catch (Exception)
                    {
                        removed++;
                    }
                }

                if (removed == 0)
                {
                    return 0;
                }

                var temporary = _alertsFile + ".tmp";
                File.WriteAllLines(temporary, kept, new UTF8Encoding(false));
                File.Move(temporary, _alertsFile, overwrite: true);

                return removed;
            }
            catch (Exception)
            {
                // 重写失败不致命：读取时仍会按保留期过滤。
                return 0;
            }
        }
    }
}
