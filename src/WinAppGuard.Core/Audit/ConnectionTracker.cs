using System.Net;
using WinAppGuard.Models;

namespace WinAppGuard.Core.Audit;

/// <summary>一条连接的身份（用于判断"是不是新出现的连接"）。</summary>
internal sealed record ConnectionKey(
    string ProcessPath,
    uint ProcessId,
    string Address,
    ushort Port,
    byte Protocol);

/// <summary>
/// 连接快照的**差集**：只把"第一次出现"的连接算成新事件。
///
/// 为什么用差集而不是"时间窗去重"：
///   - 长连接每一轮都会出现在快照里，时间窗一过就会被重复记录；
///   - 差集只用"上一轮存在、这一轮不存在"来判断连接是否结束，
///     长连接永远只记一次，断开重连则会再记一次 —— 正是审计想要的语义。
///
/// 代价：同一个连接如果在两次扫描之间建立又断开，会漏掉（3 秒窗口）。
/// 这是轮询方案的固有限制，文档里如实写明。
/// </summary>
internal sealed class ConnectionTracker
{
    private HashSet<string> _previous = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>传入"当前所有连接"，返回其中新出现的那些。</summary>
    internal IReadOnlyList<ConnectionKey> Update(IEnumerable<ConnectionKey> current)
    {
        var map = new Dictionary<string, ConnectionKey>(StringComparer.OrdinalIgnoreCase);

        foreach (var key in current)
        {
            map[Identity(key)] = key;
        }

        var added = map
            .Where(pair => !_previous.Contains(pair.Key))
            .Select(pair => pair.Value)
            .ToList();

        _previous = new HashSet<string>(map.Keys, StringComparer.OrdinalIgnoreCase);
        return added;
    }

    /// <summary>从连接扫描结果里挑出"真正的对外连接"（排除监听、回环、未建立）。</summary>
    internal static IEnumerable<ConnectionKey> FromSnapshot(IEnumerable<TcpConnectionItem> items)
    {
        foreach (var item in items)
        {
            if (item.RemotePort == 0 || item.State != TcpState.Established)
            {
                continue;
            }

            var address = item.RemoteAddress;

            if (address.Equals(IPAddress.Any)
                || address.Equals(IPAddress.IPv6Any)
                || IPAddress.IsLoopback(address))
            {
                // 回环连接不是"上网"，记进来只会把审计刷满。
                continue;
            }

            yield return new ConnectionKey(
                item.ProcessPath,
                (uint)item.Pid,
                address.ToString(),
                item.RemotePort,
                Protocol: 6);
        }
    }

    private static string Identity(ConnectionKey key)
        => $"{key.Protocol}|{key.ProcessPath}|{key.Address}|{key.Port}";
}
