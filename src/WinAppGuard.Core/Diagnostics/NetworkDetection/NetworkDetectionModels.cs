using System.Text.Json;
using System.Text.Json.Serialization;
using WinAppGuard.Core.Storage;

namespace WinAppGuard.Core.Diagnostics.NetworkDetection;

/// <summary>
/// 5.0：网络被动检测配置。
///
/// 这里只保存“用户选择”，不保存 Suricata 的完整配置；Suricata 的 yaml
/// 由服务根据本机接口和规则目录生成，避免用户手改后无法恢复。
/// </summary>
public sealed class NetworkDetectionSettings
{
    public bool Enabled { get; set; } = true;

    /// <summary>standard / full。标准档只加载客户端高价值规则。</summary>
    public string RuleProfile { get; set; } = "standard";

    public bool Notify { get; set; } = true;

    public int RetentionDays { get; set; } = 30;

    /// <summary>5.1：标准档启用的规则分类；全量档忽略。</summary>
    public List<string> EnabledRuleCategories { get; set; } =
        NetworkRuleCategories.DefaultEnabled.ToList();

    /// <summary>5.2：监听网卡 GUID；空字符串表示自动。</summary>
    public string CaptureDeviceId { get; set; } = string.Empty;
}

/// <summary>
/// 5.0：一条 Suricata/ET Open 告警。
///
/// 只保存元数据和截断后的证据摘要，默认不保存 payload。
/// </summary>
public sealed class NetworkAlert
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");

    public DateTime TimeUtc { get; set; }

    public long SignatureId { get; set; }

    public string Signature { get; set; } = string.Empty;

    /// <summary>high / medium / low。</summary>
    public string Severity { get; set; } = "medium";

    public string Category { get; set; } = string.Empty;

    public string Protocol { get; set; } = string.Empty;

    public string AppProto { get; set; } = string.Empty;

    public string LocalAddress { get; set; } = string.Empty;

    public int LocalPort { get; set; }

    public string RemoteAddress { get; set; } = string.Empty;

    public int RemotePort { get; set; }

    public int Pid { get; set; }

    public string ProcessName { get; set; } = string.Empty;

    public string? ProcessPath { get; set; }

    public long FlowId { get; set; }

    public string Evidence { get; set; } = string.Empty;

    /// <summary>new / ack / ignored。</summary>
    public string Status { get; set; } = "new";

    /// <summary>none / blocked。</summary>
    public string BlockState { get; set; } = "none";

    [JsonIgnore]
    public string TargetText =>
        string.IsNullOrEmpty(RemoteAddress)
            ? string.Empty
            : RemotePort > 0
                ? $"{RemoteAddress}:{RemotePort}"
                : RemoteAddress;

    [JsonIgnore]
    public string ProcessText =>
        string.IsNullOrEmpty(ProcessName)
            ? Pid > 0 ? $"PID {Pid}" : "未知进程"
            : ProcessName;
}

/// <summary>
/// 5.0：一个用户手动 WFP 拦截。
///
/// 只存在于当前服务会话；服务重启时动态过滤器清空，界面也同步清空，
/// 避免“界面显示已拦截、实际没有过滤器”的假象。
/// </summary>
public sealed class NetworkBlock
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");

    /// <summary>connection / ip-port / ip / process。</summary>
    public string Kind { get; set; } = string.Empty;

    public string Target { get; set; } = string.Empty;

    public string? RuleName { get; set; }

    public string? AlertId { get; set; }

    public DateTime CreatedUtc { get; set; }

    public DateTime ExpiresUtc { get; set; }

    /// <summary>WFP 过滤器 key，仅服务内部使用。</summary>
    internal Guid FilterKey { get; set; }
}

/// <summary>5.0：网络检测的持久化状态。</summary>
public sealed class NetworkDetectionState
{
    public NetworkDetectionSettings Settings { get; set; } = new();

    public Dictionary<string, string> AlertStatuses { get; set; } =
        new(StringComparer.Ordinal);
}

/// <summary>
/// 5.0：网络检测状态文件。
///
/// 5.9 起统一走 <see cref="JsonStateFile{T}"/>：新格式带 <c>schema/data</c> 外壳，
/// 旧的无外壳 JSON 仍可直接读取；读到旧格式后由宿主立即重写一次。
/// </summary>
public static class NetworkDetectionStateFile
{
    private const int SchemaVersion = 1;

    public static NetworkDetectionState Load(string path)
        => Load(path, out _, out _);

    public static NetworkDetectionState Load(string path, out string? error)
        => Load(path, out error, out _);

    public static NetworkDetectionState Load(
        string path, out string? error, out bool migrated)
    {
        var state = CreateFile(path).Load(out error, out migrated);

        if (state is null)
        {
            return new NetworkDetectionState();
        }

        Normalize(state);
        return state;
    }

    public static void Save(string path, NetworkDetectionState state)
        => CreateFile(path).Save(state);

    private static JsonStateFile<NetworkDetectionState> CreateFile(string path)
        => new(path, SchemaVersion)
        {
            Migrate = JsonStateFile<NetworkDetectionState>.Deserialize,
        };

    private static void Normalize(NetworkDetectionState state)
    {
        state.Settings ??= new NetworkDetectionSettings();
        state.AlertStatuses ??= new Dictionary<string, string>(StringComparer.Ordinal);
        state.Settings.RetentionDays = Math.Clamp(state.Settings.RetentionDays, 1, 365);

        state.Settings.EnabledRuleCategories ??= new List<string>();

        var categories = state.Settings.EnabledRuleCategories
            .Where(NetworkRuleCategories.IsKnown)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        state.Settings.EnabledRuleCategories = categories.Count > 0
            ? categories
            : NetworkRuleCategories.DefaultEnabled.ToList();

        if (string.IsNullOrWhiteSpace(state.Settings.CaptureDeviceId))
        {
            state.Settings.CaptureDeviceId = string.Empty;
        }
        else
        {
            state.Settings.CaptureDeviceId = state.Settings.CaptureDeviceId.Trim();
        }

        state.Settings.RuleProfile = string.Equals(
            state.Settings.RuleProfile, "full", StringComparison.OrdinalIgnoreCase)
            ? "full"
            : "standard";

        state.AlertStatuses = new Dictionary<string, string>(
            state.AlertStatuses, StringComparer.Ordinal);
    }
}

/// <summary>
/// 5.0：网络告警追加日志。
///
/// 5.9 起统一走 <see cref="JsonlEventLog{T}"/>：新记录写入按天分段、
/// 按大小轮转的文件；旧 <c>alerts.jsonl</c> 继续读取并按时间裁剪。
/// </summary>
public sealed class NetworkAlertStore
{
    private const long MaxBytesPerFile = 4 * 1024 * 1024;

    private readonly object _gate = new();
    private readonly JsonlEventLog<NetworkAlert> _log;

    public NetworkAlertStore(string directory, int retentionDays = 30)
    {
        Directory = directory;
        _log = new JsonlEventLog<NetworkAlert>(
            directory,
            "alerts",
            retentionDays,
            MaxBytesPerFile,
            alert => alert.TimeUtc);
    }

    public string Directory { get; }

    public void Append(NetworkAlert alert)
    {
        lock (_gate)
        {
            _log.Append(alert);
        }
    }

    public List<NetworkAlert> LoadRecent(int retentionDays, int max)
    {
        lock (_gate)
        {
            var cutoff = DateTime.UtcNow.AddDays(-Math.Clamp(retentionDays, 1, 365));
            var alerts = new List<NetworkAlert>();
            var seen = new HashSet<string>(StringComparer.Ordinal);

            foreach (var alert in _log.ReadAll())
            {
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

    /// <summary>按保留期清理，返回删除/裁剪掉的记录数。</summary>
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
}
