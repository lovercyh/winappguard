using WinAppGuard.Models;

namespace WinAppGuard.Core.Wfp;

/// <summary>
/// 2.0 的一条规则：以**程序**为单位控制它的出站连接（阻止 / 允许）。
///
/// ==================== 规则存在哪里 ====================
/// 不另建规则文件，就存在 <b>WFP 过滤器自己</b>的说明字段里，格式是：
/// <code>
///   AppGuard|1|Block|C:\Tools\a.exe|自动解除=2026-10-16T10:30:00Z
///   ^^^^^^^^ ^ ^^^^^ ^^^^^^^^^^^^^^^ ^^^^^^^^^^^^^^^^^^^^^^^^^^^
///   固定前缀 版本 动作   程序完整路径    到期标记（永久时为空）
/// </code>
///
/// 为什么这么设计：
///   1. 规则和它的元数据永远绑在一起 —— 不会出现"过滤器还在、规则信息丢了"；
///   2. 不新增任何本机文件，也就不会碰「设置文件只存布尔值」那条既有约定；
///   3. 用 <c>netsh wfp show filters</c> 也能直接看到说明，属于可审计的。
///
/// 分隔符用 <c>|</c>：Windows 路径里不允许出现这个字符，所以解析不会有歧义。
///
/// 到期信息复用 1.x 的 <see cref="RuleExpiry"/>，语义完全不变 ——
/// 这样"临时阻断"在 2.0 里的行为和用户已经熟悉的 1.x 一致。
/// </summary>
internal sealed record WfpRule
{
    /// <summary>说明字段的固定前缀。</summary>
    private const string MarkerPrefix = "AppGuard";

    /// <summary>说明字段的版本号。将来格式要变时靠它区分。</summary>
    private const string FormatVersion = "1";

    /// <summary>分隔符。Windows 路径中不允许出现，因此可以安全地用来切分。</summary>
    private const char Separator = '|';

    internal WfpRule(string applicationPath, FirewallAction action, RuleExpiry? expiry = null)
    {
        ApplicationPath = applicationPath;
        Action = action;
        Expiry = expiry ?? RuleExpiry.Never;
    }

    /// <summary>目标程序的完整路径。</summary>
    internal string ApplicationPath { get; }

    /// <summary>阻止还是允许。</summary>
    internal FirewallAction Action { get; }

    /// <summary>自动解除信息（永久 / 到某时刻 / 下次重启）。</summary>
    internal RuleExpiry Expiry { get; }

    /// <summary>动作的固定文本（写进说明字段，同时用于比较）。</summary>
    private string ActionToken => Action == FirewallAction.Block ? "Block" : "Allow";

    /// <summary>显示名称。沿用 1.x 的命名习惯，一眼能看出是本工具建的。</summary>
    internal string DisplayName
    {
        get
        {
            var prefix = Action == FirewallAction.Block
                ? AppConstants.RulePrefixBlock
                : AppConstants.RulePrefixAllow;

            var name = prefix + Path.GetFileName(ApplicationPath);
            return name.Length <= AppConstants.RuleNameMaxLength
                ? name
                : name[..AppConstants.RuleNameMaxLength];
        }
    }

    /// <summary>写进 WFP 过滤器说明字段的机器可读串。</summary>
    internal string Description
        => string.Join(
            Separator,
            MarkerPrefix,
            FormatVersion,
            ActionToken,
            ApplicationPath,
            Expiry.Encode());

    /// <summary>
    /// 从过滤器的说明字段还原成规则。
    /// 认不出来（不是我们写的、版本不匹配、字段缺失）就返回 false ——
    /// 宁可忽略一条看不懂的过滤器，也不要按错误的理解去删它。
    /// </summary>
    internal static bool TryParse(string? description, out WfpRule rule)
    {
        rule = null!;

        if (string.IsNullOrEmpty(description))
        {
            return false;
        }

        // 路径里不会有 '|'，所以正好切成 5 段；多一段少一段都说明不是我们的格式。
        var parts = description.Split(Separator);
        if (parts.Length != 5)
        {
            return false;
        }

        if (!string.Equals(parts[0], MarkerPrefix, StringComparison.Ordinal)
            || !string.Equals(parts[1], FormatVersion, StringComparison.Ordinal))
        {
            return false;
        }

        FirewallAction action;
        if (string.Equals(parts[2], "Block", StringComparison.Ordinal))
        {
            action = FirewallAction.Block;
        }
        else if (string.Equals(parts[2], "Allow", StringComparison.Ordinal))
        {
            action = FirewallAction.Allow;
        }
        else
        {
            return false;
        }

        var path = parts[3];
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        // 到期标记解析不出来时 RuleExpiry.Parse 会返回"永久"，
        // 这与 1.x 的约定一致：宁可让用户手动解除，也不要自动删掉看不懂的规则。
        rule = new WfpRule(path, action, RuleExpiry.Parse(parts[4]));
        return true;
    }
}
