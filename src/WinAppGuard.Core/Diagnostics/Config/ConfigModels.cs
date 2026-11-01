namespace WinAppGuard.Core.Diagnostics.Config;

/// <summary>4.5：本机配置监控项种类。</summary>
public static class ConfigKinds
{
    public const string Hosts = "hosts";
    public const string Proxy = "proxy";
    public const string Pac = "pac";
    public const string WinHttp = "winhttp";
    public const string Policy = "policy";
    public const string Dns = "dns";

    public static bool IsKnown(string? kind) => kind is
        Hosts or Proxy or Pac or WinHttp or Policy or Dns;

    /// <summary>高：hosts / WinINET 代理 / PAC；中：WinHTTP、组策略、DNS。</summary>
    public static string SeverityOf(string kind) => kind switch
    {
        WinHttp or Policy or Dns => "medium",
        _ => "high",
    };
}

/// <summary>4.5：一个被监控的配置项（值已规范化，便于直接比较）。</summary>
public sealed class ConfigEntry
{
    public string Kind { get; set; } = string.Empty;

    /// <summary>作用域：空 = 系统级；代理/PAC 为用户的 SID 或显示名。</summary>
    public string Scope { get; set; } = string.Empty;

    /// <summary>规范化后的完整值，只用于比较和落盘基线。</summary>
    public string Value { get; set; } = string.Empty;

    /// <summary>给界面看的一行摘要（不含敏感路径，截断到 240 字符）。</summary>
    public string Summary { get; set; } = string.Empty;
}

/// <summary>4.5：一次配置变更。</summary>
public sealed class ConfigChange
{
    public string Kind { get; init; } = string.Empty;

    public string Scope { get; init; } = string.Empty;

    public string Severity { get; init; } = "high";

    public string OldSummary { get; init; } = string.Empty;

    public string NewSummary { get; init; } = string.Empty;

    public string Detail { get; init; } = string.Empty;

    public string EventKind => ConfigEventKinds.ForKind(Kind);
}

/// <summary>4.5：配置事件种类（事件存在 config/ 目录）。</summary>
public static class ConfigEventKinds
{
    public const string HostsChanged = "config_hosts_changed";
    public const string ProxyChanged = "config_proxy_changed";
    public const string PacChanged = "config_pac_changed";
    public const string WinHttpChanged = "config_winhttp_proxy_changed";
    public const string PolicyChanged = "config_policy_proxy_changed";
    public const string DnsChanged = "config_dns_servers_changed";

    public static string ForKind(string kind) => kind switch
    {
        ConfigKinds.Hosts => HostsChanged,
        ConfigKinds.Proxy => ProxyChanged,
        ConfigKinds.Pac => PacChanged,
        ConfigKinds.WinHttp => WinHttpChanged,
        ConfigKinds.Policy => PolicyChanged,
        ConfigKinds.Dns => DnsChanged,
        _ => HostsChanged,
    };
}

/// <summary>4.5：`config/state.json`。</summary>
public sealed class ConfigState
{
    public DateTime? BaselineUtc { get; set; }

    /// <summary>用户确认过的基线（界面里的「基线值」）。</summary>
    public List<ConfigEntry> Baseline { get; set; } = new();

    /// <summary>上一次观察到的值，用于判断“又变了”，避免每 10 分钟重复告警。</summary>
    public List<ConfigEntry> Observed { get; set; } = new();
}
