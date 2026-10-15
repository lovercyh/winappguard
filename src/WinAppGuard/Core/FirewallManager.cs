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
/// Windows 防火墙规则的增 / 查 / 删。
///
/// 实现方式：调用系统自带的防火墙 COM 组件（HNetCfg.FwPolicy2）。
/// 这是 Windows 官方提供的防火墙脚本接口，不需要引入任何第三方库。
///
/// ============================ 安全约定 ============================
/// 本类严格遵守以下三条，任何一条被破坏都属于严重缺陷：
///   1. 只创建以 AppGuard_ 开头的规则；
///   2. 只删除以 AppGuard_ 开头的规则，其余一律拒绝；
///   3. 从不修改全局防火墙策略（不关防火墙、不改默认动作）。
/// 因此本类里没有任何「设置默认动作」「启用/禁用防火墙」的代码。
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
    /// 防火墙的「是否启用」「默认动作」都是按网络配置文件分别设置的，
    /// 这里固定读取域配置文件，仅用于「操作前后对比」这一个用途。
    /// 阶段 3 需要按当前生效的配置文件判断时，会改用 CurrentProfileTypes 动态取值。
    /// </summary>
    private const int ProfileDomain = 1;

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
            });
        }

        // 按规则名排序，界面显示和日志记录都更稳定。
        result.Sort(static (a, b) => string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase));
        return result;
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
        => CreateRule(AppConstants.RulePrefixBlock, programPath, ActionBlock);

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
        => CreateRule(AppConstants.RulePrefixAllow, programPath, ActionAllow);

    private static string CreateRule(string prefix, string programPath, int action)
    {
        // 所有校验都在这里统一完成：路径合法性、是否系统关键进程。
        var fullPath = ValidateProgramPath(programPath);
        var ruleName = BuildRuleName(prefix, fullPath);

        var policy = CreateComObject(PolicyProgId);

        // 幂等：同名规则已存在就直接返回，不重复创建。
        // 因为规则名里带了路径的哈希，同一个程序算出来的名字永远一样。
        if (RuleExists(policy, ruleName))
        {
            return ruleName;
        }

        var rule = CreateComObject(RuleProgId);
        rule.Name = ruleName;
        rule.Description = Truncate($"由 WinAppGuard 创建。目标程序：{fullPath}", 255);
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
        => BuildRuleName(AppConstants.RulePrefixBlock, programPath);

    /// <summary>
    /// 生成允许规则名，例如 AppGuard_Allow_chrome.exe_1a2b3c4d。
    /// </summary>
    public static string BuildAllowRuleName(string programPath)
        => BuildRuleName(AppConstants.RulePrefixAllow, programPath);

    /// <summary>
    /// 规则名 = 前缀 + 程序文件名 + 路径哈希。
    ///
    /// 为什么要带哈希：同一个程序如果放在不同目录，光靠文件名会撞名。
    /// 哈希取自完整路径，保证「一个路径对应一个规则名」，重复创建才能真正幂等。
    /// </summary>
    private static string BuildRuleName(string prefix, string programPath)
    {
        var fileName = Path.GetFileName(programPath);
        var safeName = SanitizeForRuleName(fileName);

        if (safeName.Length > 40)
        {
            safeName = safeName[..40];
        }

        return $"{prefix}{safeName}_{ShortHash(programPath)}";
    }

    /// <summary>
    /// 规则名里只保留字母、数字和 . _ - ，其余一律换成下划线。
    /// 目的是保证规则名在各种界面里都能正常显示，不会因为特殊字符出问题。
    /// </summary>
    private static string SanitizeForRuleName(string value)
    {
        var builder = new StringBuilder(value.Length);

        foreach (var c in value)
        {
            builder.Append(char.IsLetterOrDigit(c) || c is '.' or '_' or '-' ? c : '_');
        }

        return builder.ToString();
    }

    /// <summary>
    /// 取路径的短哈希（8 个十六进制字符）。
    /// 先统一转成小写，保证同一个路径大小写不同也算同一个规则。
    /// </summary>
    private static string ShortHash(string value)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(value.ToLowerInvariant()));
        return Convert.ToHexString(bytes, 0, 4).ToLowerInvariant();
    }

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
    private static string ValidateProgramPath(string programPath)
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

        // 系统关键进程保护。
        if (ProtectedProcesses.IsProtected(fullPath, out var reason))
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
