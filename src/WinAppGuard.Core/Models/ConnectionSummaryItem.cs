using WinAppGuard.Localization;

namespace WinAppGuard.Models;

/// <summary>
/// 5.7：「按程序汇总」模式里的一行。
///
/// 这个类型只负责显示和排序，不参与扫描。
/// 分组键是程序路径（拿不到路径时退化成 PID），因为防火墙规则就是按路径生效的。
///
/// 流量取自代表连接（<see cref="Representative"/>）的程序级累计值，
/// **不能把组内每一行的流量相加** —— 服务端按程序聚合的数字已经贴到了每一行上，
/// 相加会按连接数重复计算。
/// </summary>
public sealed class ConnectionSummaryItem
{
    /// <summary>分组键：有路径时是路径，否则是 <c>pid:1234</c>。</summary>
    public required string Key { get; init; }

    /// <summary>程序名。拿不到路径时可能退化成「PID 1234」。</summary>
    public required string ProcessName { get; init; }

    /// <summary>程序完整路径；拿不到时为空字符串。</summary>
    public required string ProcessPath { get; init; }

    /// <summary>组内出现过的 PID（去重、升序）。</summary>
    public required IReadOnlyList<int> Pids { get; init; }

    /// <summary>
    /// 该组的代表连接。现有阻止 / 允许 / 白名单 / 复制路径逻辑都只依赖
    /// <see cref="TcpConnectionItem.ProcessPath"/> 和 <see cref="TcpConnectionItem.ProcessName"/>，
    /// 所以用代表行就能复用，不必为汇总视图重写一套动作。
    /// </summary>
    public required TcpConnectionItem Representative { get; init; }

    /// <summary>组内连接数。</summary>
    public required int ConnectionCount { get; init; }

    /// <summary>组内不同的远端地址（不含监听端点的 0.0.0.0:0 / [::]:0）。</summary>
    public required IReadOnlyList<string> RemoteEndpoints { get; init; }

    /// <summary>已建立（ESTABLISHED）的连接数。</summary>
    public required int EstablishedCount { get; init; }

    /// <summary>监听（LISTEN）的连接数。</summary>
    public required int ListeningCount { get; init; }

    public string ProcessPathText =>
        string.IsNullOrEmpty(ProcessPath) ? Localizer.T("（无法获取）") : ProcessPath;

    public string PidText => Pids.Count switch
    {
        0 => "—",
        1 => Pids[0].ToString(),
        _ => Localizer.F("多进程（{0}）", Pids.Count),
    };

    public string ConnectionCountText => ConnectionCount.ToString();

    public string RemoteEndpointCountText => RemoteEndpoints.Count.ToString();

    public string StateSummaryText
    {
        get
        {
            var parts = new List<string>();

            if (EstablishedCount > 0)
            {
                parts.Add(Localizer.F("已建立 {0}", EstablishedCount));
            }

            if (ListeningCount > 0)
            {
                parts.Add(Localizer.F("监听 {0}", ListeningCount));
            }

            var other = ConnectionCount - EstablishedCount - ListeningCount;
            if (other > 0)
            {
                parts.Add(Localizer.F("其它 {0}", other));
            }

            return parts.Count == 0 ? "—" : string.Join(" / ", parts);
        }
    }

    public string TrafficOutText => Representative.TrafficOutText;

    public string TrafficInText => Representative.TrafficInText;

    public string TrafficTotalText => Representative.TrafficTotalText;

    public bool HasTrafficData => Representative.HasTrafficData;

    public bool IsBlocked => Representative.IsBlocked;

    public string BlockStateText => Representative.BlockStateText;

    public string WhitelistText => Representative.WhitelistText;

    public string SignatureText => Representative.SignatureText;

    /// <summary>远端地址列的悬停提示：把组内实际端点列出来，最多 8 个。</summary>
    public string EndpointsTooltip
    {
        get
        {
            if (RemoteEndpoints.Count == 0)
            {
                return Localizer.T("没有远端地址（监听端点）。");
            }

            var shown = string.Join("\n", RemoteEndpoints.Take(8));

            return RemoteEndpoints.Count > 8
                ? shown + "\n" + Localizer.F("……还有 {0} 个", RemoteEndpoints.Count - 8)
                : shown;
        }
    }
}
