using System.Net;
using WinAppGuard.Core.Wfp;

namespace WinAppGuard.Service;

/// <summary>
/// 4.5：LLMNR / NBNS / mDNS 来源的临时阻断登记册（10 分钟上限）。
///
/// 只拦该来源的 5355/137/5353 入站 UDP；使用 WFP 动态会话，
/// 服务重启即解除，不落盘、不整机封禁。
/// </summary>
internal sealed class NameBlockRegistry : IDisposable
{
    internal const int MaxMinutes = 10;

    private readonly object _gate = new();
    private readonly Dictionary<string, DateTime> _blocks = new(StringComparer.OrdinalIgnoreCase);

    private NameBlockHost? _host;
    private bool _disposed;

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

    internal bool TryGet(string address, out DateTime expiresUtc)
    {
        lock (_gate)
        {
            return _blocks.TryGetValue(address, out expiresUtc);
        }
    }

    internal bool TryBlock(IPAddress address, int minutes, out string error)
    {
        error = string.Empty;
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
                _host ??= new NameBlockHost();

                if (!_host.Add(address, out _))
                {
                    error = "添加名称解析阻断过滤器失败。";
                    return false;
                }
            }
            catch (Exception ex)
            {
                error = $"添加名称解析阻断过滤器失败：{ex.Message}";
                return false;
            }

            _blocks[text] = DateTime.UtcNow.Add(duration);
            return true;
        }
    }

    internal bool Release(string address)
    {
        lock (_gate)
        {
            if (!_blocks.Remove(address))
            {
                return false;
            }

            try
            {
                if (IPAddress.TryParse(address, out var parsed))
                {
                    _host?.Remove(parsed);
                }
            }
            catch (Exception)
            {
                // 动态会话结束时 WFP 会兜底清理。
            }

            return true;
        }
    }

    internal List<string> Prune(DateTime nowUtc)
    {
        lock (_gate)
        {
            var expired = _blocks
                .Where(item => item.Value <= nowUtc)
                .Select(item => item.Key)
                .ToList();

            foreach (var address in expired)
            {
                _blocks.Remove(address);

                try
                {
                    if (IPAddress.TryParse(address, out var parsed))
                    {
                        _host?.Remove(parsed);
                    }
                }
                catch (Exception)
                {
                    // 动态会话结束时 WFP 会兜底清理。
                }
            }

            return expired;
        }
    }

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
                // 动态会话结束时 WFP 会兜底清理。
            }

            return count;
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
}
