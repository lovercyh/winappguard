using System.Text.Json.Serialization;
using WinAppGuard.Localization;

namespace WinAppGuard.Models;

/// <summary>5.8：用户在默认阻止弹窗里做出的选择。</summary>
public enum FirstSeenDecision
{
    None = 0,
    Allowed = 1,
    Blocked = 2,
}

/// <summary>
/// 5.8：「新程序联网提醒」页面里的一条记录。
///
/// 只记录本模式开启后观察到的程序路径和联网时间；
/// 不记录 IP、域名、端口或命令行，也不上传。
/// </summary>
public sealed class FirstSeenProgramRecord
{
    public string Path { get; set; } = string.Empty;

    public string ProcessName { get; set; } = string.Empty;

    public DateTime FirstSeenUtc { get; set; }

    public DateTime LastSeenUtc { get; set; }

    /// <summary>用户是否已经确认过这个程序。</summary>
    public bool Acknowledged { get; set; }

    /// <summary>是否为「模式开启时已经在线」的基线记录。</summary>
    public bool IsBaseline { get; set; }

    /// <summary>上一次弹托盘气泡的时间；null = 还没提醒过。</summary>
    public DateTime? LastNotifiedUtc { get; set; }

    /// <summary>用户在默认阻止弹窗里的选择。</summary>
    public FirstSeenDecision Decision { get; set; } = FirstSeenDecision.None;

    /// <summary>界面刷新时填充：当前是否有普通防火墙规则阻止它。</summary>
    [JsonIgnore]
    public bool IsBlockedByRule { get; set; }

    /// <summary>界面刷新时填充：当前是否有本功能的临时阻止。</summary>
    [JsonIgnore]
    public bool IsGuarded { get; set; }

    [JsonIgnore]
    public bool IsNew => !Acknowledged;

    [JsonIgnore]
    public string ProcessNameText =>
        string.IsNullOrEmpty(ProcessName) ? Localizer.T("（未知程序）") : ProcessName;

    [JsonIgnore]
    public string FirstSeenText => FirstSeenUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");

    [JsonIgnore]
    public string LastSeenText => LastSeenUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");

    [JsonIgnore]
    public string StatusText => Localizer.T(Acknowledged ? "已知" : "新");

    [JsonIgnore]
    public string SourceText => Localizer.T(
        IsBaseline ? "模式开启时已在线" : "首次发现");

    /// <summary>页面上的「处理状态」列。</summary>
    [JsonIgnore]
    public string ProcessingText
    {
        get
        {
            if (IsBlockedByRule)
            {
                return Localizer.T("已阻止");
            }

            if (IsGuarded)
            {
                return Localizer.T("已临时阻止");
            }

            return Decision switch
            {
                FirstSeenDecision.Allowed => Localizer.T("已允许"),
                FirstSeenDecision.Blocked => Localizer.T("已解除"),
                _ => "—",
            };
        }
    }
}
