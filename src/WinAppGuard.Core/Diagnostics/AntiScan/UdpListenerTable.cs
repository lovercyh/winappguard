using System.Net;
using System.Net.NetworkInformation;

namespace WinAppGuard.Core.Diagnostics.AntiScan;

/// <summary>
/// 4.5：本机 UDP 监听端口快照（每 5 秒刷新一次）。
///
/// 用途：入站 UDP 只有打到“没人监听”的端口才可能是扫描；
/// 打到监听端口的是正常响应/业务流量，不能计入扫描，否则 DNS、媒体、游戏全会误报。
///
/// 只看端口号、不区分绑定地址（保守）：[::] 上的双栈监听会让同端口的 IPv4 流量
/// 也被当成“有人监听”，代价是可能漏掉少量扫描，但不会误报。
///
/// 热路径（每个 UDP 包）只读一次 volatile 引用，不抢锁；刷新才加锁。
/// </summary>
public sealed class UdpListenerTable
{
    private static readonly TimeSpan RefreshInterval = TimeSpan.FromSeconds(5);

    private readonly object _gate = new();
    private volatile HashSet<ushort> _ports = new();
    private DateTime _nextRefreshUtc = DateTime.MinValue;

    public int Count => _ports.Count;

    public bool IsListening(ushort port)
    {
        if (port == 0)
        {
            return false;
        }

        var now = DateTime.UtcNow;

        if (now >= _nextRefreshUtc)
        {
            lock (_gate)
            {
                if (now >= _nextRefreshUtc)
                {
                    RefreshLocked();
                    _nextRefreshUtc = now.Add(RefreshInterval);
                }
            }
        }

        return _ports.Contains(port);
    }

    /// <summary>强制刷新（测试 / 诊断用）。</summary>
    public void Refresh()
    {
        lock (_gate)
        {
            RefreshLocked();
            _nextRefreshUtc = DateTime.UtcNow.Add(RefreshInterval);
        }
    }

    private void RefreshLocked()
    {
        try
        {
            var ports = new HashSet<ushort>();

            foreach (IPEndPoint endpoint in IPGlobalProperties
                         .GetIPGlobalProperties()
                         .GetActiveUdpListeners())
            {
                if (endpoint.Port is > 0 and <= ushort.MaxValue)
                {
                    ports.Add((ushort)endpoint.Port);
                }
            }

            _ports = ports;
        }
        catch (Exception)
        {
            // 枚举失败时保留上一次的快照；宁可少报也不误报。
        }
    }
}
