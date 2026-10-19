namespace WinAppGuard.Models;

/// <summary>IP 归属查询的结果分类。</summary>
public enum IpOwnershipState
{
    /// <summary>还没查询。功能关闭时是这个值；开启后只在后台查询完成之前短暂出现。</summary>
    Unknown,

    /// <summary>查到了归属信息：至少拿到 AS 号或国家/地区。</summary>
    Known,

    /// <summary>查询本身成功，但该地址不属于任何已分配的网络（自治系统）。</summary>
    NotCovered,

    /// <summary>查询失败：服务不可达、超时、或响应无法解析。</summary>
    Failed,

    /// <summary>本机 / 局域网 / 链路本地 / 未指定地址。设计上就不会发出去查询。</summary>
    LocalOnly,
}

/// <summary>
/// 一个 IP 地址的归属信息。
///
/// 放在 Models 里而不是 Core 里，是因为它是纯数据：
/// 界面只读它，产生它的逻辑在 Core/IpOwnershipLookup.cs。
///
/// 数据来源是 Team Cymru 的 WHOIS 服务（whois.cymru.com），
/// 这是本程序**唯一**会主动联网去取的外部数据。
///
/// 设计说明：「无 AS 号」不等于「无数据」—— 实测有些地址查得到国家/地区但没有 AS 号，
/// 所以把两个字段分开存，不要用其中一个去推断另一个。
/// </summary>
/// <param name="State">结果分类。</param>
/// <param name="Asn">自治系统号，例如 15169。取不到时为空字符串。</param>
/// <param name="AsName">自治系统名称，例如 GOOGLE - Google LLC, US。取不到时为空字符串。</param>
/// <param name="CountryCode">两位国家/地区代码，例如 US、CN。取不到时为空字符串。</param>
/// <param name="Prefix">该地址所属的 BGP 网段，例如 8.8.8.0/24。</param>
/// <param name="Registry">注册局，例如 arin、apnic。</param>
/// <param name="Allocated">该网段的分配日期，例如 2023-12-28。</param>
/// <param name="Detail">失败原因等附加说明，只在 <see cref="IpOwnershipState.Failed"/> 时使用。</param>
public sealed record IpOwnershipInfo(
    IpOwnershipState State = IpOwnershipState.Unknown,
    string Asn = "",
    string AsName = "",
    string CountryCode = "",
    string Prefix = "",
    string Registry = "",
    string Allocated = "",
    string Detail = "")
{
    /// <summary>悬停提示的固定抬头，让用户一眼看出数据来自哪里。</summary>
    private const string Header = "IP 归属（来源：whois.cymru.com）";

    /// <summary>「还没查询」的占位值。</summary>
    public static readonly IpOwnershipInfo None = new();

    /// <summary>本机 / 局域网地址：不发送，界面直接说明。</summary>
    public static readonly IpOwnershipInfo LocalOnly = new(IpOwnershipState.LocalOnly);

    /// <summary>查询成功，但该地址没有归属信息。</summary>
    public static readonly IpOwnershipInfo NotCovered = new(IpOwnershipState.NotCovered);

    /// <summary>构造一个「查询失败」的结果，并把原因带进提示里。</summary>
    public static IpOwnershipInfo Failed(string detail) => new(IpOwnershipState.Failed, Detail: detail);

    /// <summary>
    /// 给界面用的悬停提示文本。
    ///
    /// 返回空字符串表示「这个格子不该显示归属提示」——
    /// 功能关闭时就是这个状态，界面据此完全不显示，避免让人误以为查过。
    /// </summary>
    public string TooltipText => State switch
    {
        IpOwnershipState.Unknown => string.Empty,
        IpOwnershipState.LocalOnly => $"{Header}\n本机或局域网地址，未向外部查询。",
        IpOwnershipState.NotCovered => $"{Header}\n该地址不属于任何已分配的网络（自治系统）。",
        IpOwnershipState.Failed => $"{Header}\n查询失败：{Detail}",
        IpOwnershipState.Known => BuildKnownText(),
        _ => string.Empty,
    };

    /// <summary>把查到的字段拼成多行提示，空字段直接省略，不留空行。</summary>
    private string BuildKnownText()
    {
        var lines = new List<string> { Header };

        if (!string.IsNullOrEmpty(CountryCode))
        {
            lines.Add($"国家/地区：{CountryCode}");
        }

        if (!string.IsNullOrEmpty(AsName))
        {
            lines.Add($"AS 名称：{AsName}");
        }

        if (!string.IsNullOrEmpty(Asn))
        {
            lines.Add($"AS 号：{Asn}");
        }

        if (!string.IsNullOrEmpty(Prefix))
        {
            lines.Add($"网段：{Prefix}");
        }

        if (!string.IsNullOrEmpty(Registry))
        {
            lines.Add(string.IsNullOrEmpty(Allocated)
                ? $"注册局：{Registry}"
                : $"注册局：{Registry}（分配于 {Allocated}）");
        }

        return string.Join("\n", lines);
    }
}
