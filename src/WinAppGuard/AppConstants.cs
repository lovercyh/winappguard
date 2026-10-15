namespace WinAppGuard;

/// <summary>
/// 全局常量。
///
/// 所有需要「和 Windows 系统对上暗号」的固定名称都集中放在这里：
/// 防火墙规则前缀、计划任务名称、启动参数等。
/// 集中管理的目的是方便审计——只要看这一个文件，就知道本程序会往系统里写哪些名字。
/// </summary>
public static class AppConstants
{
    /// <summary>程序显示名称。</summary>
    public const string AppName = "WinAppGuard";

    /// <summary>
    /// 本工具创建的所有防火墙规则都必须以此前缀开头。
    ///
    /// 安全约定：删除规则时只允许删除该前缀的规则。
    /// Windows 防火墙规则本身没有「创建者」字段，所以只能靠命名前缀来区分归属，
    /// 这个约定必须严格遵守，否则可能误删用户或其他软件设置的防火墙规则。
    /// </summary>
    public const string RulePrefix = "AppGuard_";

    /// <summary>阻止规则名前缀，例如 AppGuard_Block_chrome.exe_a1b2c3d4。</summary>
    public const string RulePrefixBlock = RulePrefix + "Block_";

    /// <summary>允许规则名前缀。仅在系统出站默认策略为「阻止」时才会用到。</summary>
    public const string RulePrefixAllow = RulePrefix + "Allow_";

    /// <summary>
    /// 规则的「分组」名。
    /// 设了分组之后，在「高级安全 Windows 防火墙」(wf.msc) 里这些规则会归在一起，
    /// 用户一眼就能看出哪些规则是 WinAppGuard 建的。
    /// </summary>
    public const string RuleGroupingName = "AppGuard";

    /// <summary>
    /// 单条规则的名称长度上限（Windows 防火墙的限制是 255）。
    /// 留一点余量，避免边界情况被系统拒绝。
    /// </summary>
    public const int RuleNameMaxLength = 200;

    /// <summary>
    /// 开机自启所使用的计划任务名称。
    /// 固定为 WinAppGuard，便于用户在「任务计划程序」里一眼找到并自行删除。
    /// </summary>
    public const string ScheduledTaskName = "WinAppGuard";

    /// <summary>
    /// 开机自启时传给程序的命令行参数。
    /// 检测到该参数时，程序启动后不显示主窗口，直接最小化到系统托盘。
    /// </summary>
    public const string AutostartArgument = "--autostart";
}
