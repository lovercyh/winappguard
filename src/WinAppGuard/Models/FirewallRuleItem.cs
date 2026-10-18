namespace WinAppGuard.Models;

/// <summary>
/// 一条防火墙规则。
///
/// 由 <see cref="WinAppGuard.Core.FirewallManager"/> 从 Windows 防火墙里读出来，
/// 界面只读取本类型，不直接接触 COM 对象。
/// </summary>
public sealed class FirewallRuleItem
{
    /// <summary>规则名。本工具创建的规则一律以 AppGuard_ 开头。</summary>
    public required string Name { get; init; }

    /// <summary>规则作用的程序完整路径。</summary>
    public required string ApplicationPath { get; init; }

    /// <summary>
    /// 「封禁 IP」规则里的 IP 地址；普通程序规则为 null。
    /// 界面上程序名/路径两列都会显示这个 IP。
    /// </summary>
    public string? IpAddress { get; init; }

    /// <summary>规则说明。</summary>
    public required string Description { get; init; }

    /// <summary>规则分组名，用于在「高级安全 Windows 防火墙」里归类显示。</summary>
    public required string Grouping { get; init; }

    /// <summary>规则是否处于启用状态。</summary>
    public required bool Enabled { get; init; }

    /// <summary>动作：阻止 / 允许。</summary>
    public required FirewallAction Action { get; init; }

    /// <summary>方向：出站 / 入站。</summary>
    public required FirewallDirection Direction { get; init; }

    /// <summary>协议号。256 表示「任意协议」。</summary>
    public required int Protocol { get; init; }

    /// <summary>
    /// 这条规则的「自动解除」信息。
    /// 从规则的说明字段里解析出来（见 <see cref="RuleExpiry"/> 的说明）。
    /// 旧版本创建的规则没有标记，会解析成「永久」。
    /// </summary>
    public RuleExpiry Expiry { get; init; } = RuleExpiry.Never;

    // ------------------------------------------------------------------
    // 以下为界面显示用属性
    // ------------------------------------------------------------------

    /// <summary>
    /// 自动解除方式的显示文本（如「永久」「剩余 12 分钟」「重启后自动解除」）。
    /// 取的是读取规则那一刻的时间点，属于快照。
    /// </summary>
    public string ExpiryText => Expiry.Describe(DateTime.UtcNow);

    /// <summary>动作的显示文本。</summary>
    public string ActionText => Action == FirewallAction.Block ? "阻止" : "允许";

    /// <summary>方向的显示文本。</summary>
    public string DirectionText => Direction == FirewallDirection.Outbound ? "出站" : "入站";

    /// <summary>启用状态的显示文本。</summary>
    public string EnabledText => Enabled ? "已启用" : "已停用";

    /// <summary>协议的显示文本。</summary>
    public string ProtocolText => Protocol == 256 ? "任意" : Protocol.ToString();

    /// <summary>
    /// 程序名的显示文本（只取文件名，路径太长不适合放在表格里）。
    /// 对「封禁 IP」规则显示 IP 本身。
    /// </summary>
    public string ApplicationNameText =>
        !string.IsNullOrEmpty(IpAddress)
            ? IpAddress
            : string.IsNullOrEmpty(ApplicationPath) ? "（所有程序）" : Path.GetFileName(ApplicationPath);

    /// <summary>
    /// 这条规则拦的是「程序」还是「IP」。
    /// 黑名单页把两类规则放在一起，必须让用户一眼看出区别 ——
    /// 「解除阻止」对程序是恢复联网，对 IP 是解除封禁，含义并不一样。
    /// </summary>
    public string RuleKindText => string.IsNullOrEmpty(IpAddress) ? "程序" : "IP";
}
