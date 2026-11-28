using System.Net;
using System.Net.NetworkInformation;
using WinAppGuard.Core.Diagnostics.Ids;

namespace WinAppGuard.Core.Diagnostics;

/// <summary>
/// 6.0：DNS 绕过检测（最小可用版）。
///
/// 只根据网络流判断：
///   - 出站 UDP/TCP 53 到非系统 DNS；
///   - 出站 TCP 853（DoT）。
///
/// 不解析 DNS 正文，不记录域名。DoH（443）无法仅凭五元组可靠区分，暂不误报。
/// </summary>
internal static class DnsBypassDetector
{
    private static readonly object Gate = new();
    private static readonly HashSet<string> SystemDns = new(StringComparer.OrdinalIgnoreCase);
    private static DateTime _dnsLoadedUtc = DateTime.MinValue;
    private static long _count;
    private static string _lastRemote = string.Empty;
    private static DateTime? _lastUtc;

    internal static void Observe(NetworkFlowObservation flow)
    {
        if (!flow.IsOutbound || flow.RemotePort is not (53 or 853))
        {
            return;
        }

        if (string.IsNullOrWhiteSpace(flow.RemoteAddress))
        {
            return;
        }

        if (flow.RemotePort == 53 && IsSystemDns(flow.RemoteAddress))
        {
            return;
        }

        lock (Gate)
        {
            _count++;
            _lastRemote = $"{flow.RemoteAddress}:{flow.RemotePort}/{flow.Protocol}";
            _lastUtc = flow.TimeUtc;
        }
    }

    internal static (long Count, string LastRemote, DateTime? LastUtc) Snapshot()
    {
        lock (Gate)
        {
            return (_count, _lastRemote, _lastUtc);
        }
    }

    private static bool IsSystemDns(string address)
    {
        lock (Gate)
        {
            if (DateTime.UtcNow - _dnsLoadedUtc > TimeSpan.FromMinutes(1))
            {
                _dnsLoadedUtc = DateTime.UtcNow;
                SystemDns.Clear();

                try
                {
                    foreach (var adapter in NetworkInterface.GetAllNetworkInterfaces())
                    {
                        foreach (var dns in adapter.GetIPProperties().DnsAddresses)
                        {
                            SystemDns.Add(dns.ToString());
                        }
                    }
                }
                catch (Exception)
                {
                    // 读不到系统 DNS 时不做白名单，宁可多报也不漏掉明显绕过。
                }
            }

            return SystemDns.Contains(address);
        }
    }
}
