namespace WinAppGuard.Models;

/// <summary>
/// 某个程序在「严格模式」白名单里的状态。
///
/// 「严格模式」= 把防火墙的默认出站动作改成「阻止」，于是**没被任何允许规则匹配到**
/// 的出站流量全部被拦掉。所以这个状态要分三档，不能只分「放行 / 不放行」——
/// 因为「放行」可能来自**别人**（Windows 自带规则、其它软件、安装程序），
/// 而严格模式**挡不住**那些。这个事实必须让用户看得见。
/// </summary>
public enum WhitelistState
{
    /// <summary>拿不到程序路径，没法判断（显示为破折号）。</summary>
    NotApplicable,

    /// <summary>被**本工具**建的 <c>AppGuard_Allow_*</c> 规则放行 —— 也就是用户自己加的白名单。</summary>
    Ours,

    /// <summary>
    /// 被**系统或其它软件**建的、针对这个程序的允许规则放行。
    ///
    /// 这一档很重要：它意味着"严格模式并不能保证只有你放行的程序才能上网"。
    /// 本工具的边界是不碰别人的规则，所以只能如实显示，不能假装它不存在。
    /// </summary>
    OtherSource,

    /// <summary>没有任何针对这个程序的允许规则 —— 严格模式下它会被拦。</summary>
    NotWhitelisted,
}
