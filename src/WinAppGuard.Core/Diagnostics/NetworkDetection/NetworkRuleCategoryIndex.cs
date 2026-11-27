using System.Text.RegularExpressions;
using WinAppGuard.Contracts;

namespace WinAppGuard.Core.Diagnostics.NetworkDetection;

/// <summary>
/// 5.14：把 Suricata 告警的 SID 映射回设置里的规则分类。
///
/// <b>为什么需要映射</b>：设置里的分类（恶意软件 / 漏洞利用 / DNS / TLS / JA3 …）
/// 是按规则文件拆分的，而 EVE 告警只带 Suricata 自己的粗分类
/// （如 <c>A Network Trojan was detected</c>），两者不是同一套分类。
/// 每条规则都带唯一 <c>sid</c>，所以用「SID → 分类文件」的索引最准确。
///
/// <b>数据来源</b>：安装目录 <c>rules\standard\*.rules</c>；标准档和全量档都会安装。
/// 索引只构建一次，文件缺失时静默降级（界面显示“未分类”），不影响检测。
///
/// <b>为什么不落库</b>：分类完全由 SID 推出来，历史告警也能补出分类；
/// 规则更新后服务重启即可得到新索引，不需要迁移告警存储。
/// </summary>
public static class NetworkRuleCategoryIndex
{
    private static readonly object Gate = new();

    /// <summary>
    /// 只匹配规则选项里的 <c>; sid:1234</c>。
    /// 前面要求分号，避免命中 <c>content</c> / <c>pcre</c> 里出现的 "sid:" 文本。
    /// </summary>
    private static readonly Regex SidPattern = new(
        @"(?:^|;)\s*sid\s*:\s*(\d+)",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly TimeSpan RetryInterval = TimeSpan.FromMinutes(5);

    private static Dictionary<long, string>? _map;
    private static bool _loaded;
    private static DateTime _lastAttemptUtc = DateTime.MinValue;

    /// <summary>
    /// 解析一条告警的 SID；解析不出来返回空字符串（界面显示“未分类”）。
    /// </summary>
    public static string Resolve(long signatureId)
    {
        if (signatureId <= 0)
        {
            return string.Empty;
        }

        var map = EnsureLoaded();
        return map.TryGetValue(signatureId, out var category) ? category : string.Empty;
    }

    /// <summary>规则文件更新后（通常伴随服务重启）重新建立索引。</summary>
    public static void Reload()
    {
        lock (Gate)
        {
            _map = null;
            _loaded = false;
            _lastAttemptUtc = DateTime.MinValue;
        }
    }

    /// <summary>启动时后台预热，避免第一条告警/第一次查询承担解析耗时。</summary>
    public static void WarmUp() => _ = Task.Run(EnsureLoaded);

    private static Dictionary<long, string> EnsureLoaded()
    {
        lock (Gate)
        {
            if (_loaded && _map is not null)
            {
                return _map;
            }

            // 安装目录还不存在时不要每次告警都重扫磁盘。
            if (_map is not null
                && _lastAttemptUtc != DateTime.MinValue
                && DateTime.UtcNow - _lastAttemptUtc < RetryInterval)
            {
                return _map;
            }

            _lastAttemptUtc = DateTime.UtcNow;

            var map = new Dictionary<long, string>();
            _loaded = TryLoadFromDisk(map);
            _map = map;

            return map;
        }
    }

    private static bool TryLoadFromDisk(Dictionary<long, string> map)
    {
        var directory = ServicePaths.SuricataStandardRulesDirectory;

        if (!Directory.Exists(directory))
        {
            return false;
        }

        var loadedAny = false;

        foreach (var category in NetworkRuleCategories.All)
        {
            var path = Path.Combine(directory, NetworkRuleCategories.FileName(category));

            if (!File.Exists(path))
            {
                continue;
            }

            try
            {
                IndexLines(category, File.ReadLines(path), map);
                loadedAny = true;
            }
            catch (IOException)
            {
                // 单个分类文件读失败不影响其它分类。
            }
            catch (UnauthorizedAccessException)
            {
                // 同上。
            }
        }

        return loadedAny;
    }

    /// <summary>从一行规则文本里提取 SID；注释和空行返回 false。</summary>
    internal static bool TryParseSid(string? line, out long sid)
    {
        sid = 0;

        if (string.IsNullOrWhiteSpace(line))
        {
            return false;
        }

        var trimmed = line.TrimStart();

        if (trimmed.Length == 0 || trimmed[0] == '#')
        {
            return false;
        }

        var match = SidPattern.Match(trimmed);

        return match.Success
            && long.TryParse(match.Groups[1].Value, out sid)
            && sid > 0;
    }

    /// <summary>
    /// 把一个分类的规则行索引到 map 里；已存在的 SID 保留第一次的分类。
    /// </summary>
    internal static int IndexLines(
        string category, IEnumerable<string> lines, IDictionary<long, string> map)
    {
        var added = 0;

        foreach (var line in lines)
        {
            if (!TryParseSid(line, out var sid))
            {
                continue;
            }

            if (map.TryAdd(sid, category))
            {
                added++;
            }
        }

        return added;
    }
}
