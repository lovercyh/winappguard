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

    // ------------------------------------------------------------------
    // 以下为界面显示用属性
    // ------------------------------------------------------------------

    /// <summary>动作的显示文本。</summary>
    public string ActionText => Action == FirewallAction.Block ? "阻止" : "允许";

    /// <summary>方向的显示文本。</summary>
    public string DirectionText => Direction == FirewallDirection.Outbound ? "出站" : "入站";

    /// <summary>启用状态的显示文本。</summary>
    public string EnabledText => Enabled ? "已启用" : "已停用";

    /// <summary>协议的显示文本。</summary>
    public string ProtocolText => Protocol == 256 ? "任意" : Protocol.ToString();

    /// <summary>程序名的显示文本（只取文件名，路径太长不适合放在表格里）。</summary>
    public string ApplicationNameText =>
        string.IsNullOrEmpty(ApplicationPath) ? "（所有程序）" : Path.GetFileName(ApplicationPath);
}
