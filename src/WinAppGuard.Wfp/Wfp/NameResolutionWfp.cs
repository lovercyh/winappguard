using System.Net;
using WinAppGuard.Interop;

namespace WinAppGuard.Core.Wfp;

/// <summary>
/// 4.5：按来源地址阻断 LLMNR / NBNS / mDNS 应答。
///
/// 传输层没有 ICMP type 那种“按报文类型”条件，但名称解析都是固定 UDP 端口：
/// 只拦「远端地址 + 源端口 5355 / 137 / 5353」的入站 UDP，范围最小。
///
/// 使用 WFP 动态会话：服务退出/崩溃时过滤器自动删除，10 分钟阻断不会变成永久封禁。
/// </summary>
internal sealed class NameBlockHost : IDisposable
{
    private const string DescriptionPrefix = "AppGuard|1|NameBlock|";
    private static readonly ushort[] Ports = { 5355, 137, 5353 };

    private readonly object _gate = new();
    private readonly WfpEngine _engine;
    private bool _disposed;

    internal NameBlockHost()
    {
        _engine = WfpEngine.Open(dynamicSession: true);
        _engine.EnsureSublayer(persistent: false);
    }

    internal bool Add(IPAddress address, out string scope)
    {
        lock (_gate)
        {
            ThrowIfDisposed();

            var layer = address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
                ? WfpNativeMethods.LayerInboundTransportV4
                : WfpNativeMethods.LayerInboundTransportV6;

            foreach (var port in Ports)
            {
                var key = Key(address, port);
                _engine.TryDeleteFilter(key);

                _engine.AddTransportInboundFilter(
                    key,
                    $"{AppConstants.RulePrefix}NameBlock_{address}_{port}",
                    $"{DescriptionPrefix}{address}|{port}|",
                    address,
                    protocol: 17,
                    remotePort: port,
                    localPort: null,
                    WfpNativeMethods.FWP_ACTION_BLOCK,
                    WfpRuleStore.WeightBlock,
                    persistent: false,
                    layerKey: layer);
            }

            scope = "UDP 5355/137/5353";
            return true;
        }
    }

    internal bool Remove(IPAddress address)
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return false;
            }

            var removed = false;

            foreach (var port in Ports)
            {
                removed |= _engine.TryDeleteFilter(Key(address, port));
            }

            return removed;
        }
    }

    internal int RemoveAll()
    {
        lock (_gate)
        {
            if (_disposed)
            {
                return 0;
            }

            var removed = 0;

            foreach (var filter in _engine.ListOurFilters())
            {
                if (filter.Description is null
                    || !filter.Description.StartsWith(DescriptionPrefix, StringComparison.Ordinal))
                {
                    continue;
                }

                if (_engine.TryDeleteFilter(filter.Key))
                {
                    removed++;
                }
            }

            return removed;
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
            _engine.Dispose();
        }
    }

    private static Guid Key(IPAddress address, ushort port)
        => WfpEngine.BuildFilterKey($"nameblock|{address}|{port}");

    private void ThrowIfDisposed()
    {
        if (_disposed)
        {
            throw new ObjectDisposedException(nameof(NameBlockHost));
        }
    }
}
