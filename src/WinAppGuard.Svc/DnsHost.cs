using WinAppGuard.Contracts;
using WinAppGuard.Core.Diagnostics;

namespace WinAppGuard.Service;

/// <summary>
/// 3.5：DNS 采集宿主（服务端）。
///
/// 真正抓事件的是 <see cref="DnsEtwMonitor"/>（Core）；这里只负责：
///   - 随服务启动 / 停止；
///   - 会话挂掉后自动重启（30 秒看门狗）；
///   - 把内存记录转换成 IPC DTO。
///
/// 进程路径在**事件发生的那一刻**解析（见 <see cref="DnsEtwMonitor"/>），
/// 不在这里事后补：PID 会复用，事后解析可能把域名算到另一个程序头上。
/// </summary>
internal static class DnsHost
{
    private static readonly object Gate = new();

    private static DnsEtwMonitor? _monitor;
    private static System.Threading.Timer? _watchdog;
    private static int _startFailures;
    private static bool _stopping;
    private static Action<DnsQueryRecord>? _querySink;

    internal static bool Collecting
    {
        get { lock (Gate) { return _monitor?.IsRunning == true; } }
    }

    /// <summary>3.7：把 IDS 的 DNS 回调挂到当前/后续的 ETW 会话上。</summary>
    internal static void SetQuerySink(Action<DnsQueryRecord>? sink)
    {
        lock (Gate)
        {
            _querySink = sink;

            if (_monitor is not null)
            {
                _monitor.QueryObserved = sink;
            }
        }
    }
    internal static void Start()
    {
        lock (Gate)
        {
            _stopping = false;
        }

        EnsureRunning();

        lock (Gate)
        {
            // 采集挂了要能自己回来；不要因为一次 StartTrace 失败就永久沉默。
            _watchdog ??= new System.Threading.Timer(
                _ => EnsureRunning(),
                state: null,
                dueTime: TimeSpan.FromSeconds(30),
                period: TimeSpan.FromSeconds(30));
        }
    }

    internal static void Stop()
    {
        DnsEtwMonitor? monitor;

        lock (Gate)
        {
            _stopping = true;
            _watchdog?.Dispose();
            _watchdog = null;

            monitor = _monitor;
            _monitor = null;
            _querySink = null;
        }

        monitor?.Dispose();
        ServiceLog.Info("WAG-DNS-003", "DNS ETW collection stopped.");
    }

    internal static List<DnsDto> Snapshot(int max)
    {
        DnsEtwMonitor? monitor;

        lock (Gate)
        {
            monitor = _monitor;
        }

        if (monitor is null)
        {
            return new List<DnsDto>();
        }

        var records = monitor.Snapshot(max);
        var result = new List<DnsDto>(records.Count);

        foreach (var record in records)
        {
            result.Add(new DnsDto
            {
                TimeUtc = record.TimeUtc,
                Pid = record.Pid,
                ProcessPath = record.ProcessPath,
                ProcessName = record.ProcessName,
                QueryName = record.QueryName,
                Status = record.Status,
                EventId = record.EventId,
            });
        }

        return result;
    }

    /// <summary>清空内存记录，返回清掉的条数。</summary>
    internal static int Clear()
    {
        DnsEtwMonitor? monitor;

        lock (Gate)
        {
            monitor = _monitor;
        }

        if (monitor is null)
        {
            return 0;
        }

        var count = monitor.Snapshot(10_000).Count;
        monitor.Clear();
        ServiceLog.Operation("WAG-DNS-005", $"DNS records cleared ({count} removed).");
        return count;
    }

    private static void EnsureRunning()
    {
        lock (Gate)
        {
            if (_stopping)
            {
                return;
            }

            if (_monitor is { IsRunning: true })
            {
                return;
            }

            if (_monitor is not null)
            {
                var stopped = _monitor;
                _monitor = null;

                try
                {
                    stopped.Dispose();
                }
                catch (Exception ex)
                {
                    ServiceLog.Warning("WAG-DNS-006", "Failed to dispose a stopped DNS ETW session.", ex);
                }

                ServiceLog.Warning("WAG-DNS-004", "DNS ETW session was not running; restarting it.");
            }

            var monitor = new DnsEtwMonitor();

            if (!monitor.Start())
            {
                _startFailures++;

                // 坏环境（例如系统禁用 ETW）下 30 秒重试一次，日志按 1/10 节流。
                if (_startFailures == 1 || _startFailures % 10 == 0)
                {
                    ServiceLog.Warning(
                        "WAG-DNS-001",
                        $"DNS ETW collection failed to start ({_startFailures} consecutive attempts): {monitor.LastError}.");
                }

                monitor.Dispose();
                return;
            }

            _startFailures = 0;
            monitor.QueryObserved = _querySink;
            _monitor = monitor;
            ServiceLog.Info(
                "WAG-DNS-002",
                "DNS ETW collection started (Microsoft-Windows-DNS-Client).");
        }
    }
}
