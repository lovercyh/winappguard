using WinAppGuard.Contracts;
using WinAppGuard.Core;
using WinAppGuard.Core.Diagnostics;
using WinAppGuard.Core.Diagnostics.Ids;

namespace WinAppGuard.Service;

/// <summary>
/// 3.5：每程序流量采集（服务端）。
///
/// 数据来源是 ETW <c>Microsoft-Windows-Kernel-Network</c>：
///   - 事件 10/26（TCP 发送）、11/27（TCP 接收）；
///   - 事件 42/58（UDP 发送）、43/59（UDP 接收）；
///   - 每个事件的前两个字段就是 <c>PID</c> 和 <c>size</c>。
///
/// 为什么不用 TCP 扩展统计：VM 实测发现 <c>DataBytesIn</c> 只停在 371 B，
/// 50 MB 下载完全不计（发送方向正常）。这是系统行为，不是测试问题。
///
/// 边界（界面/文档必须同样写）：
///   - 短于一个采样周期的连接可能漏计；
///   - 按路径合并同一程序的多个实例/多次启动，「本次服务运行」内累计；
///   - 事件在数据操作层产生，数值是近似值，不做精确账单；
///   - 不落盘，服务重启归零。
/// </summary>
internal static class TrafficHost
{
    private static readonly object Gate = new();

    /// <summary>聚合周期。ETW 事件先放在内存里，2 秒合并一次到程序路径。</summary>
    private static readonly TimeSpan SampleInterval = TimeSpan.FromSeconds(2);

    private static readonly Dictionary<string, TrafficAccumulator> Totals =
        new(StringComparer.OrdinalIgnoreCase);

    private static NetworkEtwMonitor? _monitor;
    private static System.Threading.Timer? _timer;
    private static int _startFailures;
    private static int _failureLogCounter;
    private static bool _stopping;
    private static DateTime _nextRetryUtc = DateTime.MinValue;
    private static Action<NetworkFlowObservation>? _flowSink;
    private static bool _captureFlows;
    private static DateTime _startedUtc = DateTime.UtcNow;

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

    /// <summary>3.6：本次统计的起点（服务启动或最近一次清空）。</summary>
    internal static DateTime StartedUtc
    {
        get { lock (Gate) { return _startedUtc; } }
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
            _startedUtc = DateTime.UtcNow;
        }

        EnsureRunning();

        lock (Gate)
        {
            _timer ??= new System.Threading.Timer(
                _ => Sample(),
                state: null,
                dueTime: SampleInterval,
                period: SampleInterval);
        }

        ServiceLog.Info("WAG-TRAFFIC-001", "Traffic collection started (ETW Microsoft-Windows-Kernel-Network).");
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

            Totals.Clear();
        }

        monitor?.Dispose();
        ServiceLog.Info("WAG-TRAFFIC-002", "Traffic collection stopped.");
    }

    internal static List<TrafficDto> Snapshot()
    {
        lock (Gate)
        {
            return Totals.Values
                .OrderByDescending(item => item.BytesIn + item.BytesOut)
                .Select(item => item.ToDto())
                .ToList();
        }
    }

    /// <summary>
    /// 3.6：清空本次运行的计数并把统计起点重置为当前时间。
    /// 不重启 ETW 会话，后续事件继续累计。
    /// </summary>
    internal static int Clear()
    {
        lock (Gate)
        {
            var count = Totals.Count;
            Totals.Clear();
            _startedUtc = DateTime.UtcNow;

            ServiceLog.Operation(
                "WAG-TRAFFIC-007",
                $"Traffic counters cleared ({count} programs); start time reset.");

            return count;
        }
    }

    private static void Sample()
    {
        try
        {
            EnsureRunning();

            // 取 snapshot 和累加必须在同一把锁里：
            // 否则「清空」可能插在两者之间，把清空前的增量又加回去。
            lock (Gate)
            {
                var monitor = _monitor;

                if (monitor is null)
                {
                    return;
                }

                var deltas = monitor.TakeSnapshot();

                if (deltas.Count == 0)
                {
                    return;
                }

                var now = DateTime.UtcNow;

                foreach (var delta in deltas)
                {
                    AccumulateLocked(delta.Pid, delta.BytesIn, delta.BytesOut, now);
                }

                _failureLogCounter = 0;
            }
        }
        catch (Exception ex)
        {
            _failureLogCounter++;

            if (_failureLogCounter == 1 || _failureLogCounter % 30 == 0)
            {
                ServiceLog.Warning(
                    "WAG-TRAFFIC-003",
                    $"Traffic sampling failed ({_failureLogCounter} consecutive times).",
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
                    ServiceLog.Warning("WAG-TRAFFIC-004", "Failed to dispose a stopped traffic ETW session.", ex);
                }

                ServiceLog.Warning("WAG-TRAFFIC-005", "Traffic ETW session was not running; restarting it.");
            }

            var monitor = new NetworkEtwMonitor();

            if (!monitor.Start())
            {
                _startFailures++;

                if (_startFailures == 1 || _startFailures % 30 == 0)
                {
                    ServiceLog.Warning(
                        "WAG-TRAFFIC-006",
                        $"Traffic ETW session failed to start ({_startFailures} consecutive attempts): {monitor.LastError}.");
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

    private static void AccumulateLocked(int pid, ulong deltaIn, ulong deltaOut, DateTime now)
    {
        if (pid <= 0 || (deltaIn == 0 && deltaOut == 0))
        {
            return;
        }

        var (path, name, known) = ResolveProcess(pid);
        var key = known ? path! : $"pid:{pid}";

        if (!Totals.TryGetValue(key, out var item))
        {
            item = new TrafficAccumulator
            {
                Key = key,
                Path = known ? path : null,
                Name = name,
                IsPathKnown = known,
                Pids = known ? null : new List<int> { pid },
            };

            Totals[key] = item;
        }

        item.BytesIn = AddClamped(item.BytesIn, deltaIn);
        item.BytesOut = AddClamped(item.BytesOut, deltaOut);
        item.LastSeenUtc = now;
    }

    private static (string? Path, string Name, bool Known) ResolveProcess(int pid)
    {
        // 不做 PID → 路径缓存：PID 会复用，缓存会让新程序短暂继承旧程序的流量。
        string? path;

        try
        {
            path = ProcessResolver.TryGetImagePath(pid);
        }
        catch (Exception)
        {
            path = null;
        }

        return string.IsNullOrEmpty(path)
            ? (null, $"PID {pid}", false)
            : (path, Path.GetFileName(path), true);
    }

    private static long AddClamped(long current, ulong delta)
        => delta > (ulong)(long.MaxValue - current)
            ? long.MaxValue
            : current + (long)delta;

    private sealed class TrafficAccumulator
    {
        public string Key = string.Empty;
        public string? Path;
        public string Name = string.Empty;
        public bool IsPathKnown;
        public List<int>? Pids;
        public long BytesIn;
        public long BytesOut;
        public DateTime LastSeenUtc;

        public TrafficDto ToDto() => new()
        {
            Key = Key,
            Path = Path,
            Name = Name,
            IsPathKnown = IsPathKnown,
            Pids = Pids,
            BytesIn = BytesIn,
            BytesOut = BytesOut,
            LastSeenUtc = LastSeenUtc,
        };
    }
}
