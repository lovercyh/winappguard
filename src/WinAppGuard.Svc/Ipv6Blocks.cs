using System.Net;
using WinAppGuard.Core.Wfp;

namespace WinAppGuard.Service;

/// <summary>
/// 4.4：IPv6 临时阻断登记册（DHCPv6 / RA，10 分钟上限）。
///
/// 阻断是**临时**的，不落盘：
/// - 服务重启 → 会话消失 → 过滤器由 WFP 自动删除，阻断跟着解除；
/// - 到期 → 由 <see cref="Prune"/> 删除过滤器并移除登记。
///
/// DHCPv6 与 RA 都已在 VM 实验网通过 WFP 传输层 POC（2026-10-31）：
/// - DHCPv6：UDP 547→546，精确到服务器；
/// - RA：传输层不支持 ICMP type，等价于拦该地址的**全部 ICMPv6**
///   （含 NS/NA），所以只允许对"已检测到且未信任"的路由器临时使用。
/// </summary>
internal sealed class Ipv6BlockRegistry : IDisposable
{
    internal const int MaxMinutes = 10;
    internal const string DhcpKind = "dhcpv6";
    internal const string RaKind = "ra";

    private readonly object _gate = new();
    private readonly Dictionary<string, Ipv6BlockEntry> _blocks =
        new(StringComparer.OrdinalIgnoreCase);

    private Ipv6BlockHost? _host;
    private bool _disposed;

    /// <summary>当前阻断中的目标数。</summary>
    internal int Count
    {
        get
        {
            lock (_gate)
            {
                return _blocks.Count;
            }
        }
    }

    /// <summary>查询某个地址是否在阻断中（地址按字符串匹配，忽略大小写）。</summary>
    internal bool TryGet(string address, out Ipv6BlockEntry entry)
    {
        lock (_gate)
        {
            return _blocks.TryGetValue(address, out entry!);
        }
    }

    /// <summary>
    /// 加一条临时阻断。失败时 <paramref name="error"/> 是可以直接显示给用户的中文原因。
    /// </summary>
    internal bool TryBlock(
        string kind,
        IPAddress address,
        int minutes,
        out string scope,
        out string error)
    {
        scope = string.Empty;
        error = string.Empty;

        if (!string.Equals(kind, DhcpKind, StringComparison.OrdinalIgnoreCase)
            && !string.Equals(kind, RaKind, StringComparison.OrdinalIgnoreCase))
        {
            error = "不支持的 IPv6 阻断类型。";
            return false;
        }

        var text = address.ToString();
        var duration = TimeSpan.FromMinutes(Math.Clamp(minutes, 1, MaxMinutes));

        lock (_gate)
        {
            if (_disposed)
            {
                error = "服务正在停止，无法阻断。";
                return false;
            }

            try
            {
                _host ??= new Ipv6BlockHost();

                var added = string.Equals(kind, RaKind, StringComparison.OrdinalIgnoreCase)
                    ? _host.AddRouter(address, out scope)
                    : _host.AddDhcp(address, out scope);

                if (!added)
                {
                    error = "添加阻断过滤器失败。";
                    return false;
                }
            }
            catch (Exception ex)
            {
                error = $"添加阻断过滤器失败：{ex.Message}";
                return false;
            }

            _blocks[text] = new Ipv6BlockEntry
            {
                Kind = kind,
                Address = text,
                ExpiresUtc = DateTime.UtcNow.Add(duration),
            };

            return true;
        }
    }

    /// <summary>解除某个地址的阻断。返回 true = 原本在阻断中。</summary>
    internal bool Release(string address)
    {
        lock (_gate)
        {
            if (!_blocks.Remove(address, out var entry))
            {
                return false;
            }

            RemoveFilter(entry);
            return true;
        }
    }

    /// <summary>解除全部阻断（服务停止 / 清空事件时用）。</summary>
    internal int ReleaseAll()
    {
        lock (_gate)
        {
            var count = _blocks.Count;
            _blocks.Clear();

            try
            {
                _host?.RemoveAll();
            }
            catch (Exception)
            {
                // 动态会话结束时 WFP 会兜底删除。
            }

            return count;
        }
    }

    /// <summary>删除到期阻断，返回被解除的地址（用于记日志）。</summary>
    internal List<string> Prune(DateTime nowUtc)
    {
        lock (_gate)
        {
            var expired = _blocks
                .Where(item => item.Value.ExpiresUtc <= nowUtc)
                .ToList();

            foreach (var item in expired)
            {
                _blocks.Remove(item.Key);
                RemoveFilter(item.Value);
            }

            return expired.Select(item => item.Key).ToList();
        }
    }

    public void Dispose()
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return;
            }

            _disposed = true;
            _blocks.Clear();

            try
            {
                _host?.RemoveAll();
                _host?.Dispose();
            }
            catch (Exception)
            {
                // 动态会话由 WFP 兜底清理。
            }

            _host = null;
        }
    }

    private void RemoveFilter(Ipv6BlockEntry entry)
    {
        try
        {
            if (!IPAddress.TryParse(entry.Address, out var parsed))
            {
                return;
            }

            if (string.Equals(entry.Kind, RaKind, StringComparison.OrdinalIgnoreCase))
            {
                _host?.RemoveRouter(parsed);
            }
            else
            {
                _host?.RemoveDhcp(parsed);
            }
        }
        catch (Exception)
        {
            // 删失败也不要紧：动态会话结束时会自动清，或下次启动时 RemoveAll。
        }
    }
}

/// <summary>4.4：一条 IPv6 临时阻断。</summary>
internal sealed class Ipv6BlockEntry
{
    public string Kind { get; init; } = string.Empty;

    public string Address { get; init; } = string.Empty;

    public DateTime ExpiresUtc { get; init; }
}
