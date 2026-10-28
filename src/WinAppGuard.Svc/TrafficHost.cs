using WinAppGuard.Core.Diagnostics;
using WinAppGuard.Core.Diagnostics.Ids;

namespace WinAppGuard.Service;

/// <summary>
/// ETW 网络事件宿主。
///
/// 4.1 起它**不再**负责流量统计：流量改为 Npcap 按包精确计数（见
/// <see cref="TrafficCaptureHost"/>）。这里只保留一件事——
/// 把 <c>Microsoft-Windows-Kernel-Network</c> 的 flow 事件交给 IDS（3.7），
/// 因为 IDS 的 beaconing / 横向规则需要 ETW 自带的 PID 语义。
///
/// 注意：不要在这里重新加回字节累加。两套数字会互相污染，
/// 而且会让「流量页只有 Npcap 一套口径」这条设计约束失效。
/// </summary>
internal static class TrafficHost
{
    private static readonly object Gate = new();

    /// <summary>看门狗周期：ETW 会话被系统停掉后要能自动恢复。</summary>
    private static readonly TimeSpan WatchdogInterval = TimeSpan.FromSeconds(2);

    private static NetworkEtwMonitor? _monitor;
    private static System.Threading.Timer? _timer;
    private static int _startFailures;
    private static int _failureLogCounter;
    private static bool _stopping;
    private static DateTime _nextRetryUtc = DateTime.MinValue;
    private static Action<NetworkFlowObservation>? _flowSink;
    private static bool _captureFlows;

    internal static bool Collecting
    {
        get { lock (Gate) { return _monitor?.IsRunning == true; } }
    }

    internal static long EventsSeen
    {
        get { lock (Gate) { return _monitor?.EventsSeen ?? 0; } }
    }

    /// <summary>3.7：IDS 打开时地址/端口解析失败的事件数。</summary>
    internal static long FlowParseFailures
    {
        get { lock (Gate) { return _monitor?.FlowParseFailures ?? 0; } }
    }

    /// <summary>3.7：把 IDS 的 flow 回调挂到当前/后续的 ETW 会话上。</summary>
    internal static void SetFlowSink(Action<NetworkFlowObservation>? sink, bool capture)
    {
        lock (Gate)
        {
            _flowSink = sink;
            _captureFlows = capture;

            if (_monitor is not null)
            {
                _monitor.FlowObserved = sink;
                _monitor.CaptureFlows = capture;
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
            _timer ??= new System.Threading.Timer(
                _ => Watchdog(),
                state: null,
                dueTime: WatchdogInterval,
                period: WatchdogInterval);
        }

        ServiceLog.Info("WAG-TRAFFIC-001", "Network ETW session started (IDS flows only).");
    }

    internal static void Stop()
    {
        NetworkEtwMonitor? monitor;

        lock (Gate)
        {
            _stopping = true;

            _timer?.Dispose();
            _timer = null;

            monitor = _monitor;
            _monitor = null;
            _flowSink = null;
            _captureFlows = false;
        }

        monitor?.Dispose();
        ServiceLog.Info("WAG-TRAFFIC-002", "Network ETW session stopped.");
    }

    private static void Watchdog()
    {
        try
        {
            EnsureRunning();
        }
        catch (Exception ex)
        {
            _failureLogCounter++;

            if (_failureLogCounter == 1 || _failureLogCounter % 30 == 0)
            {
                ServiceLog.Warning(
                    "WAG-TRAFFIC-003",
                    $"Network ETW watchdog failed ({_failureLogCounter} consecutive times).",
                    ex);
            }
        }
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

            if (DateTime.UtcNow < _nextRetryUtc)
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
                    ServiceLog.Warning("WAG-TRAFFIC-004", "Failed to dispose a stopped ETW session.", ex);
                }

                ServiceLog.Warning("WAG-TRAFFIC-005", "Network ETW session was not running; restarting it.");
            }

            var monitor = new NetworkEtwMonitor();

            if (!monitor.Start())
            {
                _startFailures++;

                if (_startFailures == 1 || _startFailures % 30 == 0)
                {
                    ServiceLog.Warning(
                        "WAG-TRAFFIC-006",
                        $"Network ETW session failed to start ({_startFailures} consecutive attempts): {monitor.LastError}.");
                }

                monitor.Dispose();
                _nextRetryUtc = DateTime.UtcNow.AddSeconds(30);
                return;
            }

            _startFailures = 0;
            _nextRetryUtc = DateTime.MinValue;
            monitor.FlowObserved = _flowSink;
            monitor.CaptureFlows = _captureFlows;
            _monitor = monitor;
        }
    }
}
