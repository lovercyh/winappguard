using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

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

/// <summary>5.0：网络检测状态文件的原子读写。</summary>
public static class NetworkDetectionStateFile
{
    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
    };

    public static NetworkDetectionState Load(string path)
    {
        try
        {
            if (!File.Exists(path))
            {
                return new NetworkDetectionState();
            }

            var state = JsonSerializer.Deserialize<NetworkDetectionState>(
                File.ReadAllText(path, Encoding.UTF8), Options);

            if (state is null)
            {
                return new NetworkDetectionState();
            }

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

            if (!string.Equals(
                    state.Settings.RuleProfile, "full", StringComparison.OrdinalIgnoreCase))
            {
                state.Settings.RuleProfile = "standard";
            }
            else
            {
                state.Settings.RuleProfile = "full";
            }

            state.AlertStatuses = new Dictionary<string, string>(
                state.AlertStatuses, StringComparer.Ordinal);

            return state;
        }
        catch (Exception)
        {
            return new NetworkDetectionState();
        }
    }

    public static void Save(string path, NetworkDetectionState state)
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

/// <summary>5.0：网络告警的 JSONL 追加存储。</summary>
public sealed class NetworkAlertStore
{
    private static readonly JsonSerializerOptions Options = new();

    private readonly object _gate = new();
    private readonly string _alertsFile;

    public NetworkAlertStore(string directory)
    {
        Directory = directory;
        _alertsFile = Path.Combine(directory, "alerts.jsonl");

        try
        {
            System.IO.Directory.CreateDirectory(directory);
        }
        catch (Exception)
        {
            // 目录创建失败由调用方记录；读取时按空历史处理。
        }
    }

    public string Directory { get; }

    public void Append(NetworkAlert alert)
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

    public List<NetworkAlert> LoadRecent(int retentionDays, int max)
    {
        lock (_gate)
        {
            if (!File.Exists(_alertsFile))
            {
                return new List<NetworkAlert>();
            }

            var cutoff = DateTime.UtcNow.AddDays(-Math.Clamp(retentionDays, 1, 365));
            var alerts = new List<NetworkAlert>();
            var seen = new HashSet<string>(StringComparer.Ordinal);

            foreach (var line in File.ReadLines(_alertsFile, Encoding.UTF8))
            {
                if (string.IsNullOrWhiteSpace(line))
                {
                    continue;
                }

                try
                {
                    var alert = JsonSerializer.Deserialize<NetworkAlert>(line, Options);

                    if (alert is null
                        || alert.TimeUtc < cutoff
                        || string.IsNullOrEmpty(alert.Id)
                        || !seen.Add(alert.Id))
                    {
                        continue;
                    }

                    alerts.Add(alert);
                }
                catch (Exception)
                {
                    // 单行损坏不影响其他告警。
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
                // 清理失败不阻塞界面。
            }
        }
    }

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
            var removed = 0;

            foreach (var line in File.ReadLines(_alertsFile, Encoding.UTF8))
            {
                if (string.IsNullOrWhiteSpace(line))
                {
                    continue;
                }

                try
                {
                    var alert = JsonSerializer.Deserialize<NetworkAlert>(line, Options);

                    if (alert is not null && alert.TimeUtc >= cutoff)
                    {
                        kept.Add(line);
                    }
                    else
                    {
                        removed++;
                    }
                }
                catch (Exception)
                {
                    removed++;
                }
            }

            if (removed > 0)
            {
                File.WriteAllLines(
                    _alertsFile,
                    kept,
                    new UTF8Encoding(false));
            }

            return removed;
        }
    }
}
