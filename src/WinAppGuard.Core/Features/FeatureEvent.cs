namespace WinAppGuard.Core.Features;

/// <summary>5.9：事件级别。新架构的事件统一使用它，旧 DTO 可继续保留字符串。</summary>
public enum EventSeverity
{
    Info = 0,
    Warning = 1,
    Critical = 2,
}

/// <summary>
/// 5.9：所有检测特性的公共事件骨架。
///
/// 只放跨特性真正共用的字段；各特性自己的字段放在派生类里。
/// 不把旧 DTO 立刻改成派生类，避免破坏 JSON、CLI 和 UI 绑定。
/// </summary>
public abstract class FeatureEvent
{
    public string Id { get; init; } = Guid.NewGuid().ToString("N");

    public DateTime TimeUtc { get; init; } = DateTime.UtcNow;

    public EventSeverity Severity { get; init; } = EventSeverity.Info;

    public string RuleId { get; init; } = string.Empty;

    public string Title { get; init; } = string.Empty;

    public string? Detail { get; init; }

    public bool Acknowledged { get; set; }

    public DateTime? SuppressedUntilUtc { get; set; }
}

/// <summary>5.9：公共设置骨架。各特性的设置只写自己的扩展字段。</summary>
public abstract class FeatureSettings
{
    public int SchemaVersion { get; set; } = 1;

    public bool Enabled { get; set; }

    public int RetentionDays { get; set; } = 7;
}
