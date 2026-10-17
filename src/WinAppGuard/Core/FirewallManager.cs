using System.Security.Cryptography;
using System.Text;
using WinAppGuard.Models;

namespace WinAppGuard.Core;

/// <summary>
/// 防火墙全局状态快照。
/// 用来在操作前后对比，证明本工具没有改动全局策略。
/// </summary>
/// <param name="FirewallEnabled">Windows 防火墙是否处于启用状态。</param>
/// <param name="DefaultInboundAction">入站默认动作（0=阻止，1=允许）。</param>
/// <param name="DefaultOutboundAction">出站默认动作（0=阻止，1=允许）。</param>
public sealed record FirewallGlobalState(
    bool FirewallEnabled,
    FirewallAction DefaultInboundAction,
    FirewallAction DefaultOutboundAction);

/// <summary>
/// 「哪些程序已经被放行」的快照，用于严格模式的「放行」列。
///
/// 为什么要分三个字段而不是一个集合：「放行了但没有归到某个程序头上」的规则
/// （系统自带的多是这类，例如 Core Networking 那批）**无法**判断它放行了哪个程序，
/// 只能单列条数，让界面如实说明"严格模式挡不住它们"。
/// </summary>
/// <param name="OurAllowRulePrograms">本工具建的允许规则（AppGuard_Allow_*）覆盖的程序路径。</param>
/// <param name="OtherSoftwareAllowRulePrograms">系统或其它软件建的允许规则覆盖的程序路径。</param>
/// <param name="ProgramlessAllowRuleCount">「不限程序」的允许规则条数。</param>
public sealed record OutboundAllowTargets(
    IReadOnlySet<string> OurAllowRulePrograms,
    IReadOnlySet<string> OtherSoftwareAllowRulePrograms,
    int ProgramlessAllowRuleCount);

/// <summary>
/// 三套网络配置文件的「默认出站动作」快照。
///
/// 「严格模式」开启 / 还原时用它记住原值 —— **必须三套都记**，
/// 因为用户会在不同网络（域 / 专用 / 公用）之间切换，只记一套等于留了个隐患。
/// </summary>
/// <param name="DomainAllowed">域配置文件：true = 默认允许出站。</param>
/// <param name="PrivateAllowed">专用配置文件：true = 默认允许出站。</param>
/// <param name="PublicAllowed">公用配置文件：true = 默认允许出站。</param>
public sealed record OutboundDefaultState(
    bool DomainAllowed,
    bool PrivateAllowed,
    bool PublicAllowed)
{
    /// <summary>
    /// 三套是否**都**是「默认允许」。
    ///
    /// 严格模式**只有**在原值全为「允许」时才允许开启：
    /// 只要有一套本来就是「阻止」，那说明机器上已经有别的默认阻止策略
    /// （可能是别的安全软件），我们去改它就是覆盖别人的设置。
    /// </summary>
    public bool AllAllowed => DomainAllowed && PrivateAllowed && PublicAllowed;

    /// <summary>供界面和日志显示的一句话。</summary>
    public string Describe()
        => $"域＝{(DomainAllowed ? "允许" : "阻止")}／专用＝{(PrivateAllowed ? "允许" : "阻止")}／公用＝{(PublicAllowed ? "允许" : "阻止")}";
}

/// <summary>
/// Windows 防火墙规则的增 / 查 / 删。
///
/// 实现方式：调用系统自带的防火墙 COM 组件（HNetCfg.FwPolicy2）。
/// 这是 Windows 官方提供的防火墙脚本接口，不需要引入任何第三方库。
///
/// ============================ 安全约定 ============================
/// 本类严格遵守以下四条，任何一条被破坏都属于严重缺陷：
///   1. 只创建以 AppGuard_ 开头的规则；
///   2. 只删除以 AppGuard_ 开头的规则，其余一律拒绝；
///   3. 不修改全局防火墙策略（不关防火墙、不改默认动作）。
///      **唯一例外**：用户在界面上**显式开启「严格模式」**时，会通过
///      <see cref="SetOutboundDefaultAllowed"/> 临时把「默认出站动作」改成「阻止」。
///      该方法是**全项目唯一**会写全局策略的地方，只被严格模式路径调用；
///      调用方有义务记住原值，并在退出 / 异常 / `--cleanup` 时还原（见方法注释）；
///   4. 从不启用/禁用防火墙本身（`FirewallEnabled` 只读，永远不写）。
///   5. 受保护进程（本程序自身、svchost / lsass 等系统关键进程）**只禁止「阻止」**，
///      不禁止「允许」—— 放行永远不会把用户锁在外面，而严格模式**必须**能放行本程序自己
///      （否则它自己连 IP 归属都查不了）。见 <see cref="ValidateProgramPath"/>。
/// ==================================================================
///
/// 线程要求：COM 对象有线程亲和性，请**只在界面线程（STA）上调用本类**。
/// </summary>
public static class FirewallManager
{
    // ---- COM 组件的 ProgID ----
    private const string PolicyProgId = "HNetCfg.FwPolicy2";
    private const string RuleProgId = "HNetCfg.FwRule";

    // ---- Win32 常量（数值来自 NetFwTypeLib，不能改动）----

    /// <summary>NET_FW_RULE_DIR_OUT：出站方向。</summary>
    private const int RuleDirectionOut = 2;

    /// <summary>NET_FW_ACTION_BLOCK：阻止。</summary>
    private const int ActionBlock = 0;

    /// <summary>NET_FW_ACTION_ALLOW：允许。</summary>
    private const int ActionAllow = 1;

    /// <summary>NET_FW_PROFILE2_ALL：对所有网络配置文件生效（域/专用/公用）。</summary>
    private const int ProfileAll = 0x7FFFFFFF;

    /// <summary>NET_FW_IP_PROTOCOL_ANY：任意协议，即 TCP 和 UDP 一起管。</summary>
    private const int ProtocolAny = 256;

    /// <summary>
    /// NET_FW_PROFILE2_DOMAIN。
    /// 防火墙的「是否启用」「默认动作」都是**按网络配置文件分别设置**的，
    /// 所以读写都要指明是哪一套。（数值来自 NetFwTypeLib，不能改动。）
    /// </summary>
    private const int ProfileDomain = 1;

    /// <summary>NET_FW_PROFILE2_PRIVATE：专用网络配置文件。</summary>
    private const int ProfilePrivate = 2;

    /// <summary>NET_FW_PROFILE2_PUBLIC：公用网络配置文件。</summary>
    private const int ProfilePublic = 4;

    // ==================================================================
    // 查询
    // ==================================================================

    /// <summary>
    /// 读取所有由本工具创建的规则（即规则名以 AppGuard_ 开头的规则）。
    /// </summary>
    public static List<FirewallRuleItem> GetAppGuardRules()
    {
        var policy = CreateComObject(PolicyProgId);
        var result = new List<FirewallRuleItem>();

        foreach (var item in policy.Rules)
        {
            var name = Convert.ToString(item.Name) ?? string.Empty;
            if (!name.StartsWith(AppConstants.RulePrefix, StringComparison.Ordinal))
            {
                continue;
            }

            result.Add(new FirewallRuleItem
            {
                Name = name,
                ApplicationPath = Convert.ToString(item.ApplicationName) ?? string.Empty,
                Description = Convert.ToString(item.Description) ?? string.Empty,
                Grouping = Convert.ToString(item.Grouping) ?? string.Empty,
                Enabled = Convert.ToBoolean(item.Enabled),
                Action = (FirewallAction)Convert.ToInt32(item.Action),
                Direction = (FirewallDirection)Convert.ToInt32(item.Direction),
                Protocol = Convert.ToInt32(item.Protocol),

                // 到期信息就藏在说明字段里（见 RuleExpiry 的说明）。
                // 解析不出来一律当「永久」—— 宁可让用户手动解除，也不要自动删掉看不懂的规则。
                Expiry = RuleExpiry.Parse(Convert.ToString(item.Description)),
            });
        }

        // 按规则名排序，界面显示和日志记录都更稳定。
        result.Sort(static (a, b) => string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase));
        return result;
    }

    /// <summary>
    /// 读取「哪些程序已经被放行」—— 即所有**针对具体程序**的出站允许规则。
    ///
    /// 分两类返回：本工具建的（<c>AppGuard_Allow_*</c>）和别的来源
    /// （Windows 自带、其它软件、安装程序）。严格模式**挡不住**后一类，
    /// 所以界面必须把它们分开显示，不能含糊。
    ///
    /// 「不限程序」的允许规则（系统自带的多是这类）不归到任何程序头上，
    /// 只统计条数 —— 它们放行的是"某个端口/协议"，无法回答
    /// "某个程序能不能上网"这个问题。
    ///
    /// 本方法**只读**，不做任何修改。开销：要把系统里全部规则枚举一遍并逐条读
    /// ApplicationName，比单纯数条数贵，所以调用方应当缓存（见 MainForm.RefreshAllowTargets）。
    /// </summary>
    public static OutboundAllowTargets GetOutboundAllowTargets()
    {
        var policy = CreateComObject(PolicyProgId);

        var ours = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var others = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var programless = 0;

        foreach (var item in policy.Rules)
        {
            // 只看「出站 + 允许」的规则。
            if (Convert.ToInt32(item.Direction) != RuleDirectionOut
                || Convert.ToInt32(item.Action) != ActionAllow)
            {
                continue;
            }

            var program = Convert.ToString(item.ApplicationName);

            if (string.IsNullOrWhiteSpace(program))
            {
                programless++;
                continue;
            }

            var ruleName = Convert.ToString(item.Name) ?? string.Empty;

            if (ruleName.StartsWith(AppConstants.RulePrefixAllow, StringComparison.Ordinal))
            {
                ours.Add(program);
            }
            else
            {
                others.Add(program);
            }
        }

        return new OutboundAllowTargets(ours, others, programless);
    }

    /// <summary>
    /// 读取系统中防火墙规则的总条数。
    /// 用途是在操作前后对比，证明本工具没有动到别人的规则。
    /// </summary>
    public static int GetTotalRuleCount()
    {
        var policy = CreateComObject(PolicyProgId);
        var count = 0;

        foreach (var _ in policy.Rules)
        {
            count++;
        }

        return count;
    }

    /// <summary>
    /// 读取防火墙全局状态。本方法只读，不做任何修改。
    /// </summary>
    public static FirewallGlobalState GetGlobalState()
    {
        var policy = CreateComObject(PolicyProgId);

        return new FirewallGlobalState(
            FirewallEnabled: Convert.ToBoolean(policy.FirewallEnabled[ProfileDomain]),
            DefaultInboundAction: (FirewallAction)Convert.ToInt32(policy.DefaultInboundAction[ProfileDomain]),
            DefaultOutboundAction: (FirewallAction)Convert.ToInt32(policy.DefaultOutboundAction[ProfileDomain]));
    }

    /// <summary>
    /// 读取三套配置文件当前的「默认出站动作」。本方法只读，不做任何修改。
    /// </summary>
    public static OutboundDefaultState GetOutboundDefaultAllowed()
    {
        var policy = CreateComObject(PolicyProgId);

        return new OutboundDefaultState(
            DomainAllowed: Convert.ToInt32(policy.DefaultOutboundAction[ProfileDomain]) == ActionAllow,
            PrivateAllowed: Convert.ToInt32(policy.DefaultOutboundAction[ProfilePrivate]) == ActionAllow,
            PublicAllowed: Convert.ToInt32(policy.DefaultOutboundAction[ProfilePublic]) == ActionAllow);
    }

    /// <summary>
    /// ⚠⚠ **全项目唯一会修改全局防火墙策略的方法** ⚠⚠
    ///
    /// 把三套配置文件的「默认出站动作」设成「允许」或「阻止」。
    /// 只有「严格模式」会调用它（见 <c>Core/StrictModeManager.cs</c>）。
    ///
    /// 调用方**必须**做到这三件事，否则会把用户锁在断网状态：
    ///   1. 调用前先用 <see cref="GetOutboundDefaultAllowed"/> 记下原值；
    ///   2. 在**正常退出**、**`--cleanup`**、以及**「上次没正常退出」的启动兜底**里还原原值；
    ///   3. 原值不是「全允许」时**拒绝开启**（那说明机器上已经有别人的默认阻止策略）。
    ///
    /// 为什么这么小心：默认动作是**系统级设置，不随本程序退出而恢复**。
    /// 一旦改错又没还原，用户会直接上不了网 —— 而他很可能正是不敢碰 <c>wf.msc</c> 的那类人。
    ///
    /// 实现细节：`DefaultOutboundAction` 是 COM **索引属性**（按网络配置文件取值），
    /// 读的时候项目里一直用的是 <c>policy.DefaultOutboundAction[配置文件]</c>，
    /// 写也照同样形状写；**这个写语法能不能真生效必须实测**
    /// （自检 <c>--strict-mode-test</c> 会写进去再读回来断言，不会靠猜）。
    /// </summary>
    /// <param name="allowed">
    /// true = 默认允许出站（Windows 的出厂状态）；
    /// false = 默认阻止出站（严格模式：没匹配到任何允许规则的出站流量全部拦掉）。
    /// </param>
    public static void SetOutboundDefaultAllowed(bool allowed)
    {
        var policy = CreateComObject(PolicyProgId);
        var action = allowed ? ActionAllow : ActionBlock;

        policy.DefaultOutboundAction[ProfileDomain] = action;
        policy.DefaultOutboundAction[ProfilePrivate] = action;
        policy.DefaultOutboundAction[ProfilePublic] = action;
    }

    /// <summary>
    /// 判断某个程序当前是否被本工具阻止联网。
    /// </summary>
    /// <param name="programPath">程序的完整路径。</param>
    public static bool IsProgramBlocked(string programPath)
    {
        var fullPath = NormalizePath(programPath);
        if (fullPath is null)
        {
            return false;
        }

        return GetAppGuardRules().Any(rule =>
            rule.Action == FirewallAction.Block &&
            PathsEqual(rule.ApplicationPath, fullPath));
    }

    // ==================================================================
    // 创建
    // ==================================================================

    /// <summary>
    /// 为指定程序创建「阻止联网」规则。重复调用不会产生重复规则。
    /// </summary>
    /// <param name="programPath">程序的完整路径。</param>
    /// <returns>创建（或已存在）的规则名。</returns>
    public static string CreateBlockRule(string programPath)
        => CreateBlockRule(programPath, RuleExpiry.Never);

    /// <summary>
    /// 为指定程序创建「阻止联网」规则，并指定**什么时候自动解除**。
    ///
    /// 到期时间写在规则的**说明字段**里（见 <see cref="RuleExpiry"/>）：
    /// 这样用户在 <c>wf.msc</c> 里就能看到，重启程序也不会丢，而且不需要新增任何本机文件。
    ///
    /// 如果同名规则已经存在但**到期方式不同**（例如原来是「永久」，现在要「30 分钟」），
    /// 会把它删掉重建 —— 规则名是确定性的，所以删建之后还是同一条。
    /// </summary>
    /// <param name="programPath">程序的完整路径。</param>
    /// <param name="expiry">到期方式；传 <see cref="RuleExpiry.Never"/> 表示永久。</param>
    /// <returns>创建（或已存在）的规则名。</returns>
    public static string CreateBlockRule(string programPath, RuleExpiry expiry)
        => CreateRule(AppConstants.RulePrefixBlock, programPath, ActionBlock, expiry);

    /// <summary>
    /// 为指定程序创建「允许联网」规则。重复调用不会产生重复规则。
    ///
    /// 注意：Windows 防火墙里**阻止规则的优先级高于允许规则**。
    /// 所以如果同一个程序同时存在 AppGuard 的阻止规则和允许规则，起作用的仍然是阻止。
    /// 「解除阻止」的正确做法是删除阻止规则，见 <see cref="DeleteRulesForProgram"/>。
    /// </summary>
    /// <param name="programPath">程序的完整路径。</param>
    /// <returns>创建（或已存在）的规则名。</returns>
    public static string CreateAllowRule(string programPath)
        => CreateRule(AppConstants.RulePrefixAllow, programPath, ActionAllow, RuleExpiry.Never);

    private static string CreateRule(string prefix, string programPath, int action, RuleExpiry expiry)
    {
        // 所有校验都在这里统一完成：路径合法性、是否系统关键进程。
        // 注意 forBlocking 只在「阻止」时为真 —— 受保护进程可以被放行，见 ValidateProgramPath。
        var fullPath = ValidateProgramPath(programPath, forBlocking: action == ActionBlock);
        var ruleName = RuleNaming.Build(prefix, fullPath);

        var policy = CreateComObject(PolicyProgId);

        // 幂等：同名规则已存在时……
        if (RuleExists(policy, ruleName))
        {
            // ……到期方式也一样，就直接返回，什么都不用做。
            if (ReadExpiry(policy, ruleName) == expiry)
            {
                return ruleName;
            }

            // 到期方式变了（例如「永久」改成「30 分钟」）：删掉同名规则再重建。
            //
            // 为什么不用「就地改属性」：从 HNetCfg 取出来的规则对象改属性不一定能持久化，
            // 而规则名是确定性的，删掉重建之后还是同一条规则，行为可预期。
            // 名字是我们自己按 AppConstants.RulePrefixBlock 拼的，一定带 AppGuard_ 前缀。
            policy.Rules.Remove(ruleName);
        }

        var rule = CreateComObject(RuleProgId);
        rule.Name = ruleName;
        rule.Description = BuildRuleDescription(fullPath, expiry);
        rule.ApplicationName = fullPath;
        rule.Direction = RuleDirectionOut;
        rule.Action = action;
        rule.Enabled = true;
        rule.Profiles = ProfileAll;
        rule.Protocol = ProtocolAny;
        rule.Grouping = AppConstants.RuleGroupingName;

        policy.Rules.Add(rule);

        return ruleName;
    }

    /// <summary>
    /// 生成规则说明 = 人类可读的说明 + 末尾的到期标记。
    ///
    /// 顺序很关键：**到期标记放在最后，而且截断时优先保证它不被砍掉**。
    /// 否则一个很长的程序路径会把标记挤掉，规则就被当成「永久」——
    /// 用户的「30 分钟后解除」永远不会发生，而且他不会知道为什么。
    /// </summary>
    private static string BuildRuleDescription(string fullPath, RuleExpiry expiry)
    {
        const string prefix = "由 WinAppGuard 创建。目标程序：";
        const int maxLength = 255;

        var marker = expiry.Encode();
        var suffix = marker.Length == 0 ? string.Empty : " ｜ " + marker;

        // 先给标记留出位置，再看路径还能占多少字符。
        var budget = maxLength - prefix.Length - suffix.Length;
        var path = fullPath.Length <= budget
            ? fullPath
            : fullPath[..Math.Max(0, budget - 1)] + "…";

        return prefix + path + suffix;
    }

    /// <summary>读一条已存在规则的到期方式（读不到、解析不出来都当永久）。</summary>
    private static RuleExpiry ReadExpiry(dynamic policy, string ruleName)
    {
        foreach (var item in policy.Rules)
        {
            if (string.Equals(Convert.ToString(item.Name), ruleName, StringComparison.OrdinalIgnoreCase))
            {
                return RuleExpiry.Parse(Convert.ToString(item.Description));
            }
        }

        return RuleExpiry.Never;
    }

    /// <summary>
    /// 清理**已经到期**的临时阻断规则。
    ///
    /// 安全边界：只处理名字以 <c>AppGuard_</c> 开头的规则，而且是通过
    /// <see cref="DeleteRule"/> 删的 —— 那里的前缀校验会再拦一次。
    /// 别人的规则、以及解析不出到期信息的规则（一律当永久），都**不会**被碰。
    /// </summary>
    /// <param name="nowUtc">当前 UTC 时间。</param>
    /// <param name="currentBootTimeUtc">当前这次开机的时刻（用于判断「下次重启」那类规则）。</param>
    /// <param name="freshLogonSession">
    /// 本次程序是不是由**登录触发的开机自启**拉起的。
    /// 是的话，「下次重启」那类规则一律视为到期 —— 原因见
    /// <see cref="RuleExpiry.IsExpired"/> 的参数说明（快速启动会让开机时长不归零）。
    /// </param>
    /// <returns>被删掉的规则（名字 + 目标程序），供调用方记日志和提示用户。</returns>
    public static List<(string RuleName, string ProgramPath)> PurgeExpiredRules(
        DateTime nowUtc, DateTime currentBootTimeUtc, bool freshLogonSession = false)
    {
        var removed = new List<(string RuleName, string ProgramPath)>();

        var expired = GetAppGuardRules()
            .Where(rule => !rule.Expiry.IsPermanent
                           && rule.Expiry.IsExpired(nowUtc, currentBootTimeUtc, freshLogonSession))
            .ToList();

        foreach (var rule in expired)
        {
            if (DeleteRule(rule.Name))
            {
                removed.Add((rule.Name, rule.ApplicationPath));
            }
        }

        return removed;
    }

    // ==================================================================
    // 删除
    // ==================================================================

    /// <summary>
    /// 删除一条本工具创建的规则。
    /// </summary>
    /// <param name="ruleName">规则名。必须以 AppGuard_ 开头，否则直接拒绝。</param>
    /// <returns>确实删掉了返回 true；规则本来就不存在返回 false。</returns>
    public static bool DeleteRule(string ruleName)
    {
        // 这是最关键的一道安全闸：非 AppGuard_ 前缀的规则一律不碰。
        EnsureAppGuardRuleName(ruleName);

        var policy = CreateComObject(PolicyProgId);
        if (!RuleExists(policy, ruleName))
        {
            return false;
        }

        policy.Rules.Remove(ruleName);
        return true;
    }

    /// <summary>
    /// 删除所有作用于指定程序的 AppGuard 规则（通常就是一条阻止规则）。
    /// 这就是「允许该程序联网」的底层实现。
    /// </summary>
    /// <param name="programPath">程序的完整路径。</param>
    /// <returns>实际删除的规则条数。</returns>
    public static int DeleteRulesForProgram(string programPath)
    {
        var fullPath = NormalizePath(programPath);
        if (fullPath is null)
        {
            return 0;
        }

        var targets = GetAppGuardRules()
            .Where(rule => PathsEqual(rule.ApplicationPath, fullPath))
            .Select(rule => rule.Name)
            .ToList();

        var deleted = 0;
        foreach (var name in targets)
        {
            if (DeleteRule(name))
            {
                deleted++;
            }
        }

        return deleted;
    }

    /// <summary>
    /// 删除本工具创建的全部规则。非 AppGuard_ 前缀的规则不会受影响。
    /// </summary>
    /// <returns>实际删除的规则条数。</returns>
    public static int DeleteAllAppGuardRules()
    {
        // 先取出名字列表再逐个删。不要在遍历过程中删，那样会漏。
        var names = GetAppGuardRules().Select(rule => rule.Name).ToList();

        var deleted = 0;
        foreach (var name in names)
        {
            if (DeleteRule(name))
            {
                deleted++;
            }
        }

        return deleted;
    }

    // ==================================================================
    // 规则命名
    // ==================================================================

    /// <summary>
    /// 生成阻止规则名，例如 AppGuard_Block_chrome.exe_1a2b3c4d。
    /// </summary>
    public static string BuildBlockRuleName(string programPath)
        => RuleNaming.BuildBlockRuleName(programPath);

    /// <summary>
    /// 生成允许规则名，例如 AppGuard_Allow_chrome.exe_1a2b3c4d。
    /// </summary>
    public static string BuildAllowRuleName(string programPath)
        => RuleNaming.BuildAllowRuleName(programPath);

    // ==================================================================
    // 内部工具
    // ==================================================================

    /// <summary>创建防火墙相关的 COM 对象。</summary>
    private static dynamic CreateComObject(string progId)
    {
        var type = Type.GetTypeFromProgID(progId, throwOnError: false);

        if (type is null)
        {
            throw new PlatformNotSupportedException(
                $"当前系统没有注册 COM 组件 {progId}，无法操作 Windows 防火墙。");
        }

        return Activator.CreateInstance(type)
            ?? throw new PlatformNotSupportedException($"无法创建 COM 组件 {progId} 的实例。");
    }

    /// <summary>判断指定名字的规则是否存在。</summary>
    private static bool RuleExists(dynamic policy, string ruleName)
    {
        foreach (var item in policy.Rules)
        {
            var name = Convert.ToString(item.Name) ?? string.Empty;
            if (string.Equals(name, ruleName, StringComparison.OrdinalIgnoreCase))
            {
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// 删除前的最后一道闸：非 AppGuard_ 前缀的规则名一律拒绝。
    /// 即使是本工具自己传进来的名字，也要在这里再验一次。
    /// </summary>
    private static void EnsureAppGuardRuleName(string ruleName)
    {
        if (string.IsNullOrWhiteSpace(ruleName))
        {
            throw new ArgumentException("规则名不能为空。", nameof(ruleName));
        }

        if (!ruleName.StartsWith(AppConstants.RulePrefix, StringComparison.Ordinal))
        {
            throw new InvalidOperationException(
                $"出于安全考虑，只允许删除以 {AppConstants.RulePrefix} 开头的规则。" +
                $"「{ruleName}」不是本工具创建的规则，已拒绝删除。");
        }

        if (ruleName.Length > AppConstants.RuleNameMaxLength)
        {
            throw new ArgumentException($"规则名过长：{ruleName.Length} 个字符。", nameof(ruleName));
        }
    }

    /// <summary>
    /// 校验程序路径，返回规范化后的完整路径。
    /// 任何一条不满足都抛异常，绝不「将就着」把规则建出去。
    /// </summary>
    /// <param name="programPath">程序的完整路径。</param>
    /// <param name="forBlocking">
    /// 这条规则是不是「阻止」规则。
    ///
    /// 受保护进程（本程序自身、svchost / lsass 等系统关键进程）**只在阻止时被拒绝**：
    /// 它们的危险在于「拦掉之后会出事」，而**放行永远不会把用户锁在外面**。
    /// 反向放行是必须的 —— 严格模式下本程序要靠一条允许规则才能查 IP 归属，
    /// 系统关键进程也常常是用户主动想放行的对象。
    /// </param>
    internal static string ValidateProgramPath(string programPath, bool forBlocking)
    {
        if (string.IsNullOrWhiteSpace(programPath))
        {
            throw new ArgumentException("程序路径不能为空。", nameof(programPath));
        }

        string fullPath;
        try
        {
            fullPath = Path.GetFullPath(programPath);
        }
        catch (Exception ex)
        {
            throw new ArgumentException($"程序路径格式不正确：{programPath}", nameof(programPath), ex);
        }

        // 防火墙规则只认本机文件，网络共享路径不适用。
        if (fullPath.StartsWith(@"\\", StringComparison.Ordinal))
        {
            throw new ArgumentException(
                $"不支持把网络共享（UNC）路径加入防火墙规则：{fullPath}", nameof(programPath));
        }

        if (!File.Exists(fullPath))
        {
            throw new FileNotFoundException($"找不到该程序文件：{fullPath}", fullPath);
        }

        var extension = Path.GetExtension(fullPath);
        if (!string.Equals(extension, ".exe", StringComparison.OrdinalIgnoreCase))
        {
            // 没有扩展名的文件（例如 hosts）要让提示信息读得通，不能显示成一对空引号。
            var shownExtension = string.IsNullOrEmpty(extension) ? "没有扩展名" : $"是「{extension}」";
            throw new ArgumentException(
                $"只能对 .exe 文件设置防火墙规则，当前文件{shownExtension}。", nameof(programPath));
        }

        // 系统关键进程保护 —— **只拦「阻止」**，不拦「允许」。
        if (forBlocking && ProtectedProcesses.IsProtected(fullPath, out var reason))
        {
            throw new InvalidOperationException($"拒绝操作：{reason}");
        }

        return fullPath;
    }

    /// <summary>把路径规范化成可比较的形式；路径非法时返回 null。</summary>
    private static string? NormalizePath(string programPath)
    {
        if (string.IsNullOrWhiteSpace(programPath))
        {
            return null;
        }

        try
        {
            return Path.GetFullPath(programPath);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>比较两个程序路径是否指向同一个文件。</summary>
    private static bool PathsEqual(string left, string right)
        => !string.IsNullOrEmpty(left)
           && !string.IsNullOrEmpty(right)
           && string.Equals(left, right, StringComparison.OrdinalIgnoreCase);

    /// <summary>按字符数截断字符串。</summary>
    private static string Truncate(string value, int maxLength)
        => value.Length <= maxLength ? value : value[..maxLength];
}
