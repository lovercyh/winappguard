namespace WinAppGuard.Models;

/// <summary>
/// 防火墙规则的动作。
/// 数值对应 Win32 的 NET_FW_ACTION，不能随意改动。
/// </summary>
public enum FirewallAction
{
    /// <summary>阻止。</summary>
    Block = 0,

    /// <summary>允许。</summary>
    Allow = 1,
}

/// <summary>
/// 防火墙规则的方向。
/// 数值对应 Win32 的 NET_FW_RULE_DIRECTION，不能随意改动。
/// </summary>
public enum FirewallDirection
{
    /// <summary>入站：别人连进来的流量。</summary>
    Inbound = 1,

    /// <summary>出站：本机程序连出去的流量。本工具只创建出站规则。</summary>
    Outbound = 2,
}
