using System.Globalization;

namespace WinAppGuard.Models;

/// <summary>规则限定的协议。</summary>
internal enum RuleProtocol
{
    /// <summary>不限协议（只有这种取值下不能指定端口）。</summary>
    Any = 0,

    /// <summary>TCP（IP 协议号 6）。</summary>
    Tcp = 6,

    /// <summary>UDP（IP 协议号 17）。</summary>
    Udp = 17,
}

/// <summary>
/// 网络位置。数值取自 <c>NLM_NETWORK_CATEGORY</c>（netlistmgr.h），
/// 也正是 WFP 的 <c>FWPM_CONDITION_CURRENT_PROFILE_ID</c> 期望的「网络类别」。
/// </summary>
internal enum NetworkProfile
{
    /// <summary>不限网络位置。</summary>
    Any = -1,

    /// <summary>公用网络（NLM_NETWORK_CATEGORY_PUBLIC = 0）。</summary>
    Public = 0,

    /// <summary>专用网络（NLM_NETWORK_CATEGORY_PRIVATE = 1）。</summary>
    Private = 1,

    /// <summary>域网络（NLM_NETWORK_CATEGORY_DOMAIN_AUTHENTICATED = 2）。</summary>
    Domain = 2,
}

/// <summary>
/// 2.5 的「精细化范围」：协议 / 远端端口 / 网络位置。
///
/// 为什么是"远端端口"而不是本地端口：用户说"只允许它连 443"时想的是目标端口；
/// 本地端口通常是随机分配的，按它限制没有意义。
///
/// 约束（来自 WFP 的行为，不是我们的偏好）：
///   - **端口必须配合 TCP 或 UDP**：协议为「任意」时指定端口，WFP 无法匹配；
///   - 端口范围 1–65535，且起止顺序必须正确。
/// </summary>
internal sealed record RuleScope(
    RuleProtocol Protocol,
    int PortFrom,
    int PortTo,
    NetworkProfile Profile)
{
    /// <summary>完全不限制。</summary>
    internal static readonly RuleScope Any = new(RuleProtocol.Any, 0, 0, NetworkProfile.Any);

    internal bool HasPort => PortFrom > 0 || PortTo > 0;

    internal bool HasProfile => Profile != NetworkProfile.Any;

    internal bool IsAny => Protocol == RuleProtocol.Any && !HasPort && !HasProfile;

    /// <summary>单端口（不是范围）时返回 true。</summary>
    internal bool IsSinglePort => HasPort && PortFrom == PortTo;

    /// <summary>
    /// 校验；不合法时返回一句能直接显示给用户的原因，合法返回 null。
    /// </summary>
    internal string? Validate()
    {
        if (PortFrom < 0 || PortTo < 0 || PortFrom > 65535 || PortTo > 65535)
        {
            return "端口必须在 1–65535 之间（留空表示不限）。";
        }

        if (HasPort && PortFrom == 0)
        {
            return "端口范围的起始值不能是 0。";
        }

        if (HasPort && PortTo == 0)
        {
            return "端口范围的结束值不能是 0。";
        }

        if (HasPort && PortFrom > PortTo)
        {
            return "端口范围的起始值不能大于结束值。";
        }

        if (HasPort && Protocol == RuleProtocol.Any)
        {
            return "指定端口时必须选择 TCP 或 UDP（协议为「任意」时 WFP 无法按端口匹配）。";
        }

        if (Protocol is not (RuleProtocol.Any or RuleProtocol.Tcp or RuleProtocol.Udp))
        {
            return "协议取值不合法。";
        }

        if (Profile is not (NetworkProfile.Any or NetworkProfile.Public
            or NetworkProfile.Private or NetworkProfile.Domain))
        {
            return "网络位置取值不合法。";
        }

        return null;
    }

    /// <summary>协议的中文名。</summary>
    internal string ProtocolText => Protocol switch
    {
        RuleProtocol.Tcp => "TCP",
        RuleProtocol.Udp => "UDP",
        _ => "任意协议",
    };

    /// <summary>端口的中文名。</summary>
    internal string PortText => !HasPort
        ? "任意端口"
        : IsSinglePort ? PortFrom.ToString(CultureInfo.InvariantCulture)
        : $"{PortFrom}-{PortTo}";

    /// <summary>网络位置的中文名。</summary>
    internal string ProfileText => Profile switch
    {
        NetworkProfile.Public => "公用网络",
        NetworkProfile.Private => "专用网络",
        NetworkProfile.Domain => "域网络",
        _ => "任意网络",
    };

    /// <summary>给表格显示的一行说明，例如「TCP 443 · 公用网络」。</summary>
    internal string Describe() => IsAny
        ? "任意"
        : string.Join(" · ", new[] { ProtocolText, PortText, ProfileText }
            .Where(part => !part.StartsWith("任意", StringComparison.Ordinal)));

    /// <summary>
    /// 写进 WFP 说明字段的紧凑标记（只含 ASCII，且不含 <c>|</c>）：
    /// <c>tcp-443-443-any</c> / <c>udp-8000-8100-pub</c>；完全不限制时为空字符串。
    /// </summary>
    internal string Encode()
    {
        if (IsAny)
        {
            return string.Empty;
        }

        var protocol = Protocol switch
        {
            RuleProtocol.Tcp => "tcp",
            RuleProtocol.Udp => "udp",
            _ => "any",
        };

        var profile = Profile switch
        {
            NetworkProfile.Public => "pub",
            NetworkProfile.Private => "pri",
            NetworkProfile.Domain => "dom",
            _ => "any",
        };

        return $"{protocol}-{PortFrom}-{PortTo}-{profile}";
    }

    /// <summary>解析 <see cref="Encode"/> 的产物；认不出来就当「不限」（但会给出 false）。</summary>
    internal static bool TryParse(string? token, out RuleScope scope)
    {
        scope = Any;

        if (string.IsNullOrWhiteSpace(token))
        {
            return true;
        }

        var parts = token.Trim().Split('-');

        if (parts.Length != 4)
        {
            return false;
        }

        var protocol = parts[0].ToLowerInvariant() switch
        {
            "tcp" => RuleProtocol.Tcp,
            "udp" => RuleProtocol.Udp,
            "any" => RuleProtocol.Any,
            _ => (RuleProtocol)(-1),
        };

        var profile = parts[3].ToLowerInvariant() switch
        {
            "pub" => NetworkProfile.Public,
            "pri" => NetworkProfile.Private,
            "dom" => NetworkProfile.Domain,
            "any" => NetworkProfile.Any,
            _ => (NetworkProfile)(-2),
        };

        if ((int)protocol < 0 || (int)profile == -2)
        {
            return false;
        }

        if (!int.TryParse(parts[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out var from)
            || !int.TryParse(parts[2], NumberStyles.Integer, CultureInfo.InvariantCulture, out var to))
        {
            return false;
        }

        var parsed = new RuleScope(protocol, from, to, profile);

        if (parsed.Validate() is not null)
        {
            return false;
        }

        scope = parsed;
        return true;
    }

    /// <summary>
    /// 规则名后缀（区分同一程序的不同范围）：
    /// 例如 <c>tcp443</c> / <c>udp8000-8100</c> / <c>tcp443-pub</c>；不限制时为空。
    /// </summary>
    internal string NameSuffix()
    {
        if (IsAny)
        {
            return string.Empty;
        }

        var builder = new System.Text.StringBuilder();

        if (Protocol != RuleProtocol.Any)
        {
            builder.Append(Protocol == RuleProtocol.Tcp ? "tcp" : "udp");
        }

        if (HasPort)
        {
            builder.Append(IsSinglePort
                ? PortFrom.ToString(CultureInfo.InvariantCulture)
                : $"{PortFrom}-{PortTo}");
        }

        if (HasProfile)
        {
            if (builder.Length > 0)
            {
                builder.Append('-');
            }

            builder.Append(Profile switch
            {
                NetworkProfile.Public => "pub",
                NetworkProfile.Private => "pri",
                _ => "dom",
            });
        }

        return builder.ToString();
    }
}
