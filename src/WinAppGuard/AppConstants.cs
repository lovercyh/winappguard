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

    // ==================================================================
    // IP 归属查询（Team Cymru WHOIS）
    //
    // ★ 这是本项目**唯一**的联网目标。除了下面这个地址，程序不会主动连接任何其它主机。
    //   对应的代码在 Core/IpOwnershipLookup.cs —— 审计联网行为只需要看那一处。
    //   改动这里的任何一个值，都等于改变了「程序会对哪些外部主机说话」，必须写进文档。
    // ==================================================================

    /// <summary>IP 归属查询使用的 WHOIS 服务器主机名。</summary>
    public const string OwnershipLookupHost = "whois.cymru.com";

    /// <summary>
    /// WHOIS 的标准端口。固定值，不提供配置入口
    /// —— 允许改端口就等于允许把 IP 发到任意主机，那条路不能留。
    /// </summary>
    public const int OwnershipLookupPort = 43;

    /// <summary>
    /// 一次请求最多提交多少个 IP。
    /// 服务端支持批量，实测 50 个约 1.3 秒；分批是为了避免单次请求过大。
    /// </summary>
    public const int OwnershipMaxIpsPerQuery = 50;

    /// <summary>建立连接的超时时间（毫秒）。连不上就快速放弃，不让界面后台线程干等。</summary>
    public const int OwnershipConnectTimeoutMs = 3000;

    /// <summary>读响应 / 写请求的超时时间（毫秒）。</summary>
    public const int OwnershipReadTimeoutMs = 10000;

    /// <summary>
    /// 响应字节数上限。正常响应只有几 KB，这是防御性上限，
    /// 防止异常情况下无限读取把内存吃光。
    /// </summary>
    public const int OwnershipMaxResponseBytes = 1024 * 1024;

    /// <summary>
    /// 归属结果的缓存有效期（小时）。
    /// AS 分配数据很少变动，24 小时足够；定太短会导致反复查询同一个地址。
    /// </summary>
    public const int OwnershipCacheTtlHours = 24;

    /// <summary>
    /// 查询失败后的重试间隔（秒）。
    /// 刻意比成功时短得多：一次网络抖动不该把「查询失败」这个结论
    /// 压住 24 小时，否则用户会觉得功能坏了。
    /// </summary>
    public const int OwnershipFailureRetrySeconds = 120;

    /// <summary>
    /// 缓存最多保留多少条。超出后按写入顺序淘汰最旧的。
    /// 缓存只在内存里，但长时间运行仍需要一个上限。
    /// </summary>
    public const int OwnershipCacheCapacity = 2000;

    // ==================================================================
    // 本机数据目录（%LOCALAPPDATA%\WinAppGuard）
    //
    // 这里放的都是「只写本机、绝不上传」的东西：日志和设置。
    // ==================================================================

    /// <summary>本程序在 %LOCALAPPDATA% 下的目录名。</summary>
    public const string AppDataFolderName = "WinAppGuard";

    /// <summary>设置文件名，位于 %LOCALAPPDATA%\WinAppGuard\ 下。</summary>
    public const string SettingsFileName = "settings.json";
}
