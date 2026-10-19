using WinAppGuard.Interop;
using WinAppGuard.Models;

namespace WinAppGuard.Core.Wfp;

/// <summary>
/// 规则库：把 <see cref="WfpRule"/> 落到 WFP 过滤器上，或者从过滤器里读回来。
///
/// ==================== 一条规则 = 两条过滤器 ====================
/// WFP 的层是按 IP 协议族分开的（V4 / V6）。**只挂一层等于门只关一半**：
/// 程序改走 IPv6 就绕过去了。所以每条规则固定写两层，
/// 两层的过滤器 key 不同（由"规则内容 + 层"确定性算出）。
///
/// ==================== 权重 ====================
/// 同一子层内，权重大的过滤器先命中。这里定成：
/// <code>
///   阻止全部（严格模式用）  0
///   允许（白名单）          0x1000
///   阻止（普通规则）        0x2000
/// </code>
/// 即：普通"阻止"压过"允许"（与 Windows 防火墙"显式阻止优先"的习惯一致），
/// 而严格模式的"阻止全部"垫在最底下，白名单才能放行。
/// 严格模式本身要到 2.0-b 才接，这里先把坑位留好。
/// </summary>
internal static class WfpRuleStore
{
    /// <summary>严格模式"阻止全部"的权重（最低）。</summary>
    internal const ulong WeightBlockAll = 0;

    /// <summary>普通"允许"规则的权重。</summary>
    internal const ulong WeightAllow = 0x1000;

    /// <summary>普通"阻止"规则的权重（高于允许，与 Windows 防火墙一致）。</summary>
    internal const ulong WeightBlock = 0x2000;

    /// <summary>出站方向要写的全部层。</summary>
    internal static readonly Guid[] OutboundLayers =
    {
        WfpNativeMethods.LayerAleAuthConnectV4,
        WfpNativeMethods.LayerAleAuthConnectV6,
    };

    /// <summary>算出一条规则在某一层上的过滤器 key（确定性，重复执行结果相同）。</summary>
    internal static Guid FilterKeyFor(WfpRule rule, Guid layerKey)
        => WfpEngine.BuildFilterKey(
            $"rule|{rule.Action}|{rule.ApplicationPath}|{rule.Scope.Encode()}|{layerKey}");

    /// <summary>
    /// 写入一条规则（两层都写），返回实际写入的过滤器条数。
    ///
    /// 幂等：先按 key 删掉可能存在的旧过滤器再加。
    /// 这样同一路径的规则内容变了（比如改成了限期解除），系统里留下的也是新内容；
    /// 只靠"已存在就算成功"会把旧内容一直留在那儿。
    /// </summary>
    internal static int Add(WfpEngine engine, WfpRule rule)
    {
        var (action, weight) = rule.Action == FirewallAction.Block
            ? (WfpNativeMethods.FWP_ACTION_BLOCK, WeightBlock)
            : (WfpNativeMethods.FWP_ACTION_PERMIT, WeightAllow);

        // ⚠️ 过滤器的持久化必须**跟随子层**：
        //   持久化过滤器挂在非持久化子层上会被 WFP 拒绝（0x80320016，生存时间不兼容）。
        //   动态会话里本来就不允许建持久对象，所以也排除在外。
        var persistent = !engine.IsDynamic && engine.SublayerPersistent;

        var written = 0;

        foreach (var layer in OutboundLayers)
        {
            var key = FilterKeyFor(rule, layer);

            engine.TryDeleteFilter(key);

            if (rule.Scope.IsAny)
            {
                engine.AddAppIdFilter(
                    key,
                    rule.DisplayName,
                    rule.Description,
                    rule.ApplicationPath,
                    layer,
                    action,
                    weight,
                    persistent);
            }
            else
            {
                engine.AddScopedAppIdFilter(
                    key,
                    rule.DisplayName,
                    rule.Description,
                    rule.ApplicationPath,
                    layer,
                    action,
                    weight,
                    persistent,
                    rule.Scope);
            }

            written++;
        }

        return written;
    }

    /// <summary>
    /// 读出当前所有规则。
    ///
    /// 一条规则在各层上各有一条过滤器，所以这里按"动作 + 路径"去重
    /// （不区分大小写：Windows 路径本来就不区分）。
    /// </summary>
    internal static IReadOnlyList<WfpRule> List(WfpEngine engine)
    {
        var rules = new List<WfpRule>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var filter in engine.ListOurFilters())
        {
            if (!WfpRule.TryParse(filter.Description, out var rule))
            {
                continue;
            }

            if (seen.Add($"{rule.Action}|{rule.ApplicationPath}|{rule.Scope.Encode()}"))
            {
                rules.Add(rule);
            }
        }

        return rules;
    }

    /// <summary>删除一条规则（两层都删），返回实际删掉的过滤器条数。</summary>
    internal static int Remove(WfpEngine engine, WfpRule rule)
    {
        var removed = 0;

        foreach (var layer in OutboundLayers)
        {
            if (engine.TryDeleteFilter(FilterKeyFor(rule, layer)))
            {
                removed++;
            }
        }

        return removed;
    }

    /// <summary>删光所有规则（= 本子层下所有过滤器）。</summary>
    internal static int RemoveAll(WfpEngine engine) => engine.DeleteAllOurFilters();

    // ==================================================================
    // 封禁 IP
    // ==================================================================

    /// <summary>IP 规则的过滤器 key（确定性）。</summary>
    internal static Guid IpFilterKey(WfpIpRule rule)
        => WfpEngine.BuildFilterKey($"iprule|{rule.Address}");

    /// <summary>写入一条"封禁 IP"规则（IPv4 走 V4 层、IPv6 走 V6 层，只写一条）。</summary>
    internal static void AddIp(WfpEngine engine, WfpIpRule rule)
    {
        var key = IpFilterKey(rule);
        var persistent = !engine.IsDynamic && engine.SublayerPersistent;

        engine.TryDeleteFilter(key);
        engine.AddIpFilter(
            key,
            rule.DisplayName,
            rule.Description,
            rule.ToIPAddress(),
            WfpNativeMethods.FWP_ACTION_BLOCK,
            WeightBlock,
            persistent);
    }

    /// <summary>删除一条 IP 规则，返回删掉的过滤器条数。</summary>
    internal static int RemoveIp(WfpEngine engine, WfpIpRule rule)
        => engine.TryDeleteFilter(IpFilterKey(rule)) ? 1 : 0;

    /// <summary>列出所有 IP 规则（按地址去重）。</summary>
    internal static IReadOnlyList<WfpIpRule> ListIpRules(WfpEngine engine)
    {
        var rules = new List<WfpIpRule>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var filter in engine.ListOurFilters())
        {
            if (WfpIpRule.TryParse(filter.Description, out var rule) && seen.Add(rule.Address))
            {
                rules.Add(rule);
            }
        }

        return rules;
    }
}
