using System.Net;
using System.Net.Sockets;
using WinAppGuard.Models;

namespace WinAppGuard.Core;

/// <summary>
/// 「联网连接」列表支持的排序列。
///
/// 刻意做成枚举，而不是直接用表格的列索引：
/// 列的顺序将来可能调整，用索引会把「排序逻辑」和「界面布局」绑死在一起。
/// </summary>
public enum ConnectionSortColumn
{
    /// <summary>不排序 —— 保持扫描给出的顺序。</summary>
    None = 0,

    /// <summary>按程序名（不区分大小写）。</summary>
    ProcessName,

    /// <summary>按 PID（数字）。</summary>
    Pid,

    /// <summary>按本地端口（数字）。</summary>
    LocalPort,

    /// <summary>按远程地址（先分族，同族内按地址数值）。</summary>
    RemoteAddress,

    /// <summary>按远程端口（数字）。</summary>
    RemotePort,

    /// <summary>按连接状态（枚举值）。</summary>
    State,
}

/// <summary>
/// 连接列表的过滤与排序 —— **纯逻辑，完全不依赖界面**。
///
/// 为什么要单独抽出来：
///   1. 界面那套「每 3 秒重绑一次」的刷新机制很难断言，纯逻辑可以；
///   2. 排序有两个**很容易写错**的地方，放在这里能用断言钉死。
///
/// 两个容易写错的地方：
///   - **地址不能按字符串排**：字符串比较会让 `192.168.1.10` 排在 `192.168.1.9` **前面**；
///   - **端口 / PID 不能按字符串排**：字符串比较会让 `80` 排在 `443` **后面**。
///   所以一律按**数值**比较；地址还要先分族（IPv4 全部排在 IPv6 前面，因为两族没有
///   可比的大小关系，硬混在一起排没有意义）。
///
/// 排序是**稳定**的：主键相同时保持传入的顺序。
/// 注意实现上用 LINQ 的 `OrderBy` 而不是 `List.Sort` —— 后者是不稳定排序，
/// 相等元素的前后关系会变，用户会看到「同一批连接每次刷新顺序都不一样」。
/// </summary>
public static class ConnectionFilter
{
    /// <summary>
    /// 按关键词过滤、再按指定列排序，返回**应该显示**的列表。
    ///
    /// 返回新列表，不修改传入的集合 —— 调用方拿到之后自己
    /// `Clear()` + `AddRange()` 更新那个唯一的绑定列表（见界面里的约定）。
    /// </summary>
    /// <param name="all">全部连接（扫描结果）。</param>
    /// <param name="keyword">搜索关键词，空 / 全空白表示不过滤。</param>
    /// <param name="sortColumn">排序列。</param>
    /// <param name="ascending">是否升序。</param>
    public static List<TcpConnectionItem> Apply(
        IReadOnlyList<TcpConnectionItem> all,
        string? keyword,
        ConnectionSortColumn sortColumn,
        bool ascending)
    {
        var matched = new List<TcpConnectionItem>(all.Count);

        foreach (var item in all)
        {
            if (Matches(item, keyword))
            {
                matched.Add(item);
            }
        }

        if (sortColumn == ConnectionSortColumn.None)
        {
            // 不排序：保持扫描顺序。
            return matched;
        }

        var comparer = Comparer<TcpConnectionItem>.Create((a, b) => Compare(a, b, sortColumn));

        return (ascending
                ? matched.OrderBy(item => item, comparer)
                : matched.OrderByDescending(item => item, comparer))
            .ToList();
    }

    /// <summary>
    /// 判断一条连接是否命中关键词。
    ///
    /// 匹配规则（刻意做成「包含」，因为用户往往只记得片段）：
    /// **进程名 / PID / 远程 IP / 远程端口**，任一字段包含关键词即算命中，不区分大小写。
    /// 例如 `chrom` 命中 `chrome.exe`，`192.168` 命中 `192.168.1.5`，`443` 命中远程端口 443。
    ///
    /// 空关键词（或只有空白）视为「不过滤」，一律返回 true。
    /// </summary>
    public static bool Matches(TcpConnectionItem item, string? keyword)
    {
        if (item is null)
        {
            return false;
        }

        var needle = keyword?.Trim();
        if (string.IsNullOrEmpty(needle))
        {
            return true;
        }

        return Contains(item.ProcessName, needle)
               || Contains(item.Pid.ToString(), needle)
               || Contains(item.RemoteAddressText, needle)
               || Contains(item.RemotePortText, needle);
    }

    private static bool Contains(string? haystack, string needle)
        => !string.IsNullOrEmpty(haystack)
           && haystack.Contains(needle, StringComparison.OrdinalIgnoreCase);

    /// <summary>比较两个连接在指定列上的先后。</summary>
    private static int Compare(TcpConnectionItem a, TcpConnectionItem b, ConnectionSortColumn column)
        => column switch
        {
            ConnectionSortColumn.ProcessName =>
                string.Compare(a.ProcessName, b.ProcessName, StringComparison.OrdinalIgnoreCase),

            ConnectionSortColumn.Pid => a.Pid.CompareTo(b.Pid),
            ConnectionSortColumn.LocalPort => a.LocalPort.CompareTo(b.LocalPort),
            ConnectionSortColumn.RemoteAddress => CompareAddress(a.RemoteAddress, b.RemoteAddress),
            ConnectionSortColumn.RemotePort => a.RemotePort.CompareTo(b.RemotePort),
            ConnectionSortColumn.State => ((int)a.State).CompareTo((int)b.State),
            _ => 0,
        };

    /// <summary>
    /// 比较两个地址。规则：
    ///   1. **IPv4 全部排在 IPv6 前面**（先比族）；
    ///   2. 同族内按**字节数值**比，而不是按字符串。
    /// </summary>
    private static int CompareAddress(IPAddress a, IPAddress b)
    {
        var familyA = a.AddressFamily == AddressFamily.InterNetwork ? 0 : 1;
        var familyB = b.AddressFamily == AddressFamily.InterNetwork ? 0 : 1;

        if (familyA != familyB)
        {
            return familyA.CompareTo(familyB);
        }

        return CompareBytes(a.GetAddressBytes(), b.GetAddressBytes());
    }

    /// <summary>按字节逐位比较两个地址（同族时长度相同，末位的长度比较只是防御）。</summary>
    private static int CompareBytes(byte[] a, byte[] b)
    {
        var length = Math.Min(a.Length, b.Length);

        for (var i = 0; i < length; i++)
        {
            var diff = a[i].CompareTo(b[i]);
            if (diff != 0)
            {
                return diff;
            }
        }

        return a.Length.CompareTo(b.Length);
    }
}
