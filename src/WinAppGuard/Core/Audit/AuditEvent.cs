using System.Text.Json;
using System.Text.Json.Serialization;

namespace WinAppGuard.Core.Audit;

/// <summary>一条审计事件的类型。</summary>
internal enum AuditEventKind
{
    /// <summary>正常建立的连接（来自轮询快照）。</summary>
    Connect = 0,

    /// <summary>被本工具拦掉的连接（来自 WFP 网络事件，准确到命中的规则）。</summary>
    Blocked = 1,
}

/// <summary>
/// 一条审计记录。
///
/// 设计原则：**只记事实，不记猜测的结论**。
///   - 进程、远端 IP、端口、时间、是否被拦 —— 这些是事实；
///   - 域名是**推测**（见 <see cref="DomainText"/>），单独存放并且永远带"推测"标记；
///   - 不记 URL、不记报文内容（那需要内核驱动，且本项目已经明确不做）。
/// </summary>
internal sealed record AuditEvent
{
    /// <summary>UTC 时间。</summary>
    [JsonPropertyName("t")]
    public DateTime TimeUtc { get; init; }

    /// <summary>事件类型。</summary>
    [JsonPropertyName("k")]
    public AuditEventKind Kind { get; init; }

    /// <summary>发起连接的程序完整路径。</summary>
    [JsonPropertyName("p")]
    public string ProcessPath { get; init; } = string.Empty;

    /// <summary>发起连接的进程 ID（可能已退出，仅作参考）。</summary>
    [JsonPropertyName("pid")]
    public uint ProcessId { get; init; }

    /// <summary>远端 IP。</summary>
    [JsonPropertyName("a")]
    public string RemoteAddress { get; init; } = string.Empty;

    /// <summary>远端端口。</summary>
    [JsonPropertyName("pt")]
    public ushort RemotePort { get; init; }

    /// <summary>IP 协议号（6 = TCP，17 = UDP）。</summary>
    [JsonPropertyName("pr")]
    public byte Protocol { get; init; }

    /// <summary>命中的过滤器 ID（只有 <see cref="AuditEventKind.Blocked"/> 有值）。</summary>
    [JsonPropertyName("fid")]
    public ulong FilterId { get; init; }

    /// <summary>
    /// 域名（**推测**）。为空表示没有可用的解析记录；
    /// 多个候选用 <c> / </c> 连接，并在界面上标注"不唯一"。
    /// </summary>
    [JsonPropertyName("d")]
    public string? Domain { get; init; }

    /// <summary>域名是否为推测（当前恒为 true；留字段是为了将来能兼容更确定的来源）。</summary>
    [JsonPropertyName("dg")]
    public bool DomainIsGuess { get; init; } = true;

    /// <summary>给日志/界面看的一行摘要。</summary>
    internal string Describe()
    {
        var action = Kind == AuditEventKind.Blocked ? "拦截" : "连接";
        var process = string.IsNullOrEmpty(ProcessPath) ? "（未知程序）" : Path.GetFileName(ProcessPath);
        var domain = string.IsNullOrEmpty(Domain) ? "域名未知" : Domain;

        return $"{TimeUtc.ToLocalTime():HH:mm:ss} {action} {process} → {RemoteAddress}:{RemotePort}（{domain}）";
    }

    // ==================================================================
    // 序列化（一行一条 JSON，便于追加与轮转）
    // ==================================================================

    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = false,
    };

    internal string ToJsonLine() => JsonSerializer.Serialize(this, Options);

    internal static AuditEvent? TryParse(string? line)
    {
        if (string.IsNullOrWhiteSpace(line))
        {
            return null;
        }

        try
        {
            var parsed = JsonSerializer.Deserialize<AuditEvent>(line, Options);
            return parsed is null || string.IsNullOrEmpty(parsed.RemoteAddress) ? null : parsed;
        }
        catch (JsonException)
        {
            // 半行（断电时最后一行可能不完整）直接跳过，不影响其它记录。
            return null;
        }
    }
}
