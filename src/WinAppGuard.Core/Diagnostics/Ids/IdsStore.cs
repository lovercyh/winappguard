using System.Text.Json;
using WinAppGuard.Core.Storage;

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

/// <summary>
/// 3.7：IDS 状态文件。
///
/// 5.9 起统一走 <see cref="JsonStateFile{T}"/>：
///   - 新格式带 <c>schema/data</c> 外壳，原子写入；
///   - 旧的无外壳 JSON 仍可直接读取；
///   - 坏文件改名为 <c>.corrupt-*</c>，不再静默覆盖；
///   - 读取旧格式时由调用方立即重写一次，完成“读旧写新”。
/// </summary>
public static class IdsStateFile
{
    private const int SchemaVersion = 1;

    public static IdsState Load(string path)
        => Load(path, out _, out _);

    public static IdsState Load(string path, out string? error)
        => Load(path, out error, out _);

    public static IdsState Load(string path, out string? error, out bool migrated)
    {
        var state = CreateFile(path).Load(out error, out migrated);

        if (state is null)
        {
            return new IdsState();
        }

        Normalize(state);
        return state;
    }

    public static void Save(string path, IdsState state)
        => CreateFile(path).Save(state);

    private static JsonStateFile<IdsState> CreateFile(string path)
        => new(path, SchemaVersion)
        {
            // 目前只有 schema 1；保留入口，后续加字段时按 data 元素迁移。
            Migrate = JsonStateFile<IdsState>.Deserialize,
        };

    private static void Normalize(IdsState state)
    {
        state.Settings ??= new IdsSettings();
        state.Suppressions ??= new List<IdsSuppression>();
        state.AlertStatuses ??= new Dictionary<string, string>(StringComparer.Ordinal);

        state.Settings.RetentionDays = Math.Clamp(state.Settings.RetentionDays, 1, 365);

        state.Settings.Sensitivity = string.Equals(
            state.Settings.Sensitivity, "conservative", StringComparison.OrdinalIgnoreCase)
            ? "conservative"
            : "standard";

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
    }
}

/// <summary>
/// 3.7：告警追加日志。
///
/// 5.9 起统一走 <see cref="JsonlEventLog{T}"/>：
///   - 新记录写入按天分段、按大小轮转的 <c>alerts-yyyyMMdd-NN.jsonl</c>；
///   - 旧版单文件 <c>alerts.jsonl</c> 仍会一起读取；
///   - 旧文件和新分段文件都会按告警时间裁剪，过期分片整文件清理；
///   - 坏行跳过，读取时按 id 去重、按保留期过滤。
/// </summary>
public sealed class IdsAlertStore
{
    private const long MaxBytesPerFile = 4 * 1024 * 1024;

    private readonly object _gate = new();
    private readonly JsonlEventLog<IdsAlert> _log;

    public IdsAlertStore(string directory, int retentionDays = 30)
    {
        Directory = directory;
        _log = new JsonlEventLog<IdsAlert>(
            directory,
            "alerts",
            retentionDays,
            MaxBytesPerFile,
            alert => alert.TimeUtc);
    }

    public string Directory { get; }

    public void Append(IdsAlert alert)
    {
        lock (_gate)
        {
            _log.Append(alert);
        }
    }

    public List<IdsAlert> LoadRecent(int retentionDays, int max)
    {
        lock (_gate)
        {
            var cutoff = DateTime.UtcNow.AddDays(-Math.Clamp(retentionDays, 1, 365));
            var alerts = new List<IdsAlert>();
            var seen = new HashSet<string>(StringComparer.Ordinal);

            foreach (var alert in _log.ReadAll())
            {
                Normalize(alert);

                if (alert.TimeUtc < cutoff
                    || string.IsNullOrEmpty(alert.Id)
                    || !seen.Add(alert.Id))
                {
                    continue;
                }

                alerts.Add(alert);
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
            _log.Clear();
        }
    }

    /// <summary>
    /// 按保留期清理，返回删除/裁剪掉的记录数。
    /// 旧版单文件按时间逐条裁剪；新分段文件按日期整文件删除。
    /// </summary>
    public int Prune(int retentionDays)
    {
        lock (_gate)
        {
            var before = _log.ReadAll().Count;
            _log.Prune(DateTime.UtcNow, retentionDays);
            var after = _log.ReadAll().Count;

            return Math.Max(0, before - after);
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
}
