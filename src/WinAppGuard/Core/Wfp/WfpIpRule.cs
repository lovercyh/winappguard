using System.Net;

namespace WinAppGuard.Core.Wfp;

/// <summary>
/// 「封禁 IP」规则：直接按**远端 IP** 拦截，不做域名解析。
///
/// 设计取舍（产品负责人确认）：
///   - 用户拦的就是这个 IP，语义明确，不会出现"域名换了 IP 就失效"的问题；
///   - 代价是**同一个 IP 上的其它服务也会被一起拦**（共享主机/CDN），
///     所以界面上添加时必须把这条写清楚。
///
/// 存放方式与程序规则一致：规则内容写在过滤器自己的说明字段里
/// （<c>AppGuard|1|BlockIp|1.2.3.4|</c>），不另建存储。
/// </summary>
internal sealed record WfpIpRule
{
    private const string Marker = "AppGuard";
    private const string Version = "1";
    private const string Kind = "BlockIp";
    private const char Separator = '|';

    internal WfpIpRule(string address)
    {
        Address = NormalizeAddress(address);
    }

    /// <summary>规范化后的 IP（IPv6 统一小写压缩形式）。</summary>
    internal string Address { get; }

    /// <summary>解析成 IPAddress（调用方已确认合法；非法时抛异常）。</summary>
    internal IPAddress ToIPAddress() => IPAddress.Parse(Address);

    /// <summary>显示名称，例如 AppGuard_BlockIp_216.31.12.15。</summary>
    internal string DisplayName => $"{AppConstants.RulePrefixBlock}Ip_{Address}";

    /// <summary>写进过滤器说明字段的机器可读串。</summary>
    internal string Description => string.Join(Separator, Marker, Version, Kind, Address, string.Empty);

    /// <summary>从说明字段还原；不是 IP 规则时返回 false。</summary>
    internal static bool TryParse(string? description, out WfpIpRule rule)
    {
        rule = null!;

        if (string.IsNullOrEmpty(description))
        {
            return false;
        }

        var parts = description.Split(Separator);
        if (parts.Length != 5
            || !string.Equals(parts[0], Marker, StringComparison.Ordinal)
            || !string.Equals(parts[1], Version, StringComparison.Ordinal)
            || !string.Equals(parts[2], Kind, StringComparison.Ordinal))
        {
            return false;
        }

        if (!IPAddress.TryParse(parts[3], out _))
        {
            return false;
        }

        rule = new WfpIpRule(parts[3]);
        return true;
    }

    /// <summary>IP 的规范化形式（用于比较与去重）。</summary>
    internal static string NormalizeAddress(string address)
    {
        if (!IPAddress.TryParse(address.Trim(), out var parsed))
        {
            throw new FormatException($"不是合法的 IP 地址：{address}");
        }

        return parsed.ToString();
    }
}
