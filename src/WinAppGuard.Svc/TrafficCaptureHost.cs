using WinAppGuard.Contracts;
using WinAppGuard.Core;
using WinAppGuard.Core.Diagnostics.AntiScan;
using WinAppGuard.Core.Diagnostics.Traffic;

namespace WinAppGuard.Service;

/// <summary>
/// 4.1：精确流量宿主（服务端）。
///
/// 数据来自 Npcap 的独立采集会话（与 4.0 反扫描的会话互不影响）：
///   - 采集线程只做「每包事实」；
///   - 本宿主每秒刷新端点表、聚合一次、更新速率曲线；
///   - 只存内存，服务重启或「清空」后归零。
///
/// ETW 不再参与流量统计：它只保留给 IDS 的 flow 回调（见 TrafficHost）。
/// </summary>
internal static class TrafficCaptureHost
{
    private static readonly object Gate = new();

    private static readonly TimeSpan TickInterval = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan StatsInterval = TimeSpan.FromSeconds(5);

    /// <summary>超过这个包速率才开始采样（默认关闭采样）。</summary>
    private const long SampleThresholdPps = 200_000;

    private static readonly TrafficAggregator Aggregator = new();

    private static NpcapTrafficCapture? _capture;
    private static System.Threading.Timer? _timer;
    private static bool _started;
    private static bool _paused;
    private static DateTime _startedUtc = DateTime.UtcNow;
    private static DateTime _nextRetryUtc = DateTime.MinValue;
    private static DateTime _nextStatsUtc = DateTime.MinValue;
    private static DateTime _lastPpsUtc = DateTime.UtcNow;
    private static long _lastPackets;
    private static long _pps;
    private static int _sampleFactor = 1;
    private static string? _lastError;

    internal static bool Collecting
    {
        get { lock (Gate) { return _capture?.IsRunning == true; } }
    }

    internal static bool Paused
    {
        get { lock (Gate) { return _paused; } }
    }

    internal static void Start()
    {
        lock (Gate)
        {
            _started = true;
            _paused = false;
            _startedUtc = DateTime.UtcNow;
            _lastPpsUtc = DateTime.UtcNow;
            _lastPackets = 0;
            _pps = 0;
            _sampleFactor = 1;
            _lastError = null;
            _nextRetryUtc = DateTime.MinValue;
            _nextStatsUtc = DateTime.MinValue;
        }

        Aggregator.Clear();
        EnsureCapture();

        lock (Gate)
        {
            _timer ??= new System.Threading.Timer(
                _ => Tick(),
                state: null,
                dueTime: TickInterval,
                period: TickInterval);
        }

        ServiceLog.Info(
            "WAG-TRAFFIC-010",
            $"Precise traffic collection started (npcap={NpcapLocator.FindWpcapPath() ?? "missing"}).");
    }

    internal static void Stop()
    {
        NpcapTrafficCapture? capture;

        lock (Gate)
        {
            _started = false;
            _timer?.Dispose();
            _timer = null;
            capture = _capture;
            _capture = null;
        }

        capture?.Stop();
        capture?.Dispose();
        Aggregator.Clear();

        ServiceLog.Info("WAG-TRAFFIC-011", "Precise traffic collection stopped.");
    }

    /// <summary>暂停 / 继续（本次服务运行有效，不落盘）。</summary>
    internal static ServiceResponse Configure(ServiceRequest request)
    {
        if (request.TrafficPaused is not { } paused)
        {
            return new ServiceResponse
            {
                Id = request.Id,
                Ok = false,
                Error = "缺少暂停状态。",
            };
        }

        lock (Gate)
        {
            _paused = paused;

            // 重试/恢复时清掉退避：装完 Npcap 或点「点击重试」后应当立刻再试一次。
            if (!paused)
            {
                _nextRetryUtc = DateTime.MinValue;
            }
        }

        if (paused)
        {
            NpcapTrafficCapture? capture;

            lock (Gate)
            {
                capture = _capture;
                _capture = null;
            }

            capture?.Stop();
            capture?.Dispose();
        }
        else
        {
            EnsureCapture();
        }

        ServiceLog.Operation(
            "WAG-TRAFFIC-012",
            paused ? "Precise traffic collection paused." : "Precise traffic collection resumed.");

        return Query(request);
    }

    internal static ServiceResponse Query(ServiceRequest request)
    {
        TrafficSnapshot snapshot;
        bool sampled;

        lock (Gate)
        {
            sampled = _sampleFactor > 1;
        }

        snapshot = Aggregator.Snapshot(sampled);

        return new ServiceResponse
        {
            Id = request.Id,
            Ok = true,
            Traffic = snapshot.Programs.Select(program => ToDto(program, sampled)).ToList(),
            TrafficStartedUtc = StartedUtc,
            TrafficSeries = new TrafficSeriesDto
            {
                StartUtc = snapshot.SeriesStartUtc,
                IntervalMs = snapshot.IntervalMs,
                BytesIn = snapshot.BytesIn,
                BytesOut = snapshot.BytesOut,
                Sampled = sampled,
            },
            TrafficStatus = GetStatus(),
        };
    }

    internal static ServiceResponse Clear(ServiceRequest request)
    {
        int affected;
        DateTime startedUtc;

        lock (Gate)
        {
            affected = Aggregator.Snapshot(sampled: false).Programs.Count;
            _startedUtc = DateTime.UtcNow;
            startedUtc = _startedUtc;
        }

        Aggregator.Clear();

        ServiceLog.Operation(
            "WAG-TRAFFIC-013",
            $"Precise traffic counters cleared ({affected} programs); start time reset.");

        return new ServiceResponse
        {
            Id = request.Id,
            Ok = true,
            Affected = affected,
            TrafficStartedUtc = startedUtc,
            Traffic = new List<TrafficDto>(),
            TrafficSeries = new TrafficSeriesDto
            {
                StartUtc = startedUtc,
                BytesIn = new List<long>(),
                BytesOut = new List<long>(),
            },
            TrafficStatus = GetStatus(),
        };
    }

    internal static TrafficStatusDto GetStatus()
    {
        lock (Gate)
        {
            return new TrafficStatusDto
            {
                Collecting = _capture?.IsRunning == true,
                Paused = _paused,
                Pps = _pps,
                Dropped = _capture?.DroppedPackets ?? 0,
                Sampled = _sampleFactor > 1,
                NpcapVersion = NpcapLocator.GetVersion(),
                LastError = _lastError,
            };
        }
    }

    internal static DateTime StartedUtc
    {
        get { lock (Gate) { return _startedUtc; } }
    }

    private static void Tick()
    {
        try
        {
            EnsureCapture();
            UpdateSampling();

            // 暂停 / 未启动时不做后面这些（建端点表不便宜，别白跑）。
            lock (Gate)
            {
                if (_capture is null)
                {
                    _pps = 0;
                    return;
                }
            }

            Aggregator.SetOwnerLookup(EndpointOwnerTable.Capture());
            Aggregator.Tick(DateTime.UtcNow);

            lock (Gate)
            {
                var capture = _capture;

                if (capture is null)
                {
                    _pps = 0;
                    return;
                }

                var now = DateTime.UtcNow;
                var packets = capture.PacketsSeen;

                if (now >= _nextStatsUtc)
                {
                    capture.RefreshStatistics();
                    _nextStatsUtc = now.Add(StatsInterval);
                }

                var elapsed = Math.Max(0.001, (now - _lastPpsUtc).TotalSeconds);
                _pps = (long)Math.Max(0, (packets - _lastPackets) / elapsed);
                _lastPackets = packets;
                _lastPpsUtc = now;
            }
        }
        catch (Exception ex)
        {
            ServiceLog.Warning("WAG-TRAFFIC-014", "Precise traffic tick failed.", ex);
        }
    }

    /// <summary>
    /// 包速率过高时才启用采样（默认永远不采样）。
    /// 4.1 不做性能优化，但必须让页面知道“数值是估算”。
    /// </summary>
    private static void UpdateSampling()
    {
        long pps;
        NpcapTrafficCapture? capture;

        lock (Gate)
        {
            pps = _pps;
            capture = _capture;
        }

        if (capture is null)
        {
            return;
        }

        var factor = 1;

        if (pps > SampleThresholdPps)
        {
            factor = pps > SampleThresholdPps * 8 ? 16
                : pps > SampleThresholdPps * 4 ? 8
                : pps > SampleThresholdPps * 2 ? 4
                : 2;
        }

        if (factor != capture.SampleFactor)
        {
            capture.SampleFactor = factor;

            lock (Gate)
            {
                _sampleFactor = factor;
            }

            if (factor > 1)
            {
                ServiceLog.Operation(
                    "WAG-TRAFFIC-015",
                    $"Traffic sampling enabled at 1/{factor} (pps={pps}); numbers are estimates.");
            }
            else
            {
                ServiceLog.Operation("WAG-TRAFFIC-016", "Traffic sampling disabled; numbers are exact again.");
            }
        }
    }

    private static void EnsureCapture()
    {
        lock (Gate)
        {
            if (!_started || _paused)
            {
                return;
            }

            if (_capture is { IsRunning: true })
            {
                return;
            }

            if (DateTime.UtcNow < _nextRetryUtc)
            {
                return;
            }
        }

        if (!NpcapLocator.IsAvailable)
        {
            lock (Gate)
            {
                _lastError = "Npcap 未安装。";
                _nextRetryUtc = DateTime.UtcNow.AddSeconds(30);
            }

            return;
        }

        var capture = new NpcapTrafficCapture
        {
            PacketObserved = packet => Aggregator.Observe(packet, DateTime.UtcNow),
            FragmentObserved = (direction, bytes) =>
                Aggregator.ObserveUnattributed(direction, bytes, DateTime.UtcNow),
            Log = message => ServiceLog.Info("WAG-TRAFFIC-017", message),
        };

        if (!capture.Start())
        {
            lock (Gate)
            {
                _lastError = capture.LastError ?? "Npcap 启动失败。";
                _nextRetryUtc = DateTime.UtcNow.AddSeconds(30);
            }

            capture.Dispose();
            ServiceLog.Warning(
                "WAG-TRAFFIC-018",
                $"Precise traffic capture failed to start: {capture.LastError}");
            return;
        }

        NpcapTrafficCapture? previous;

        lock (Gate)
        {
            previous = _capture;
            _capture = capture;
            _lastError = null;
            _nextRetryUtc = DateTime.MinValue;
            _lastPackets = capture.PacketsSeen;
            _lastPpsUtc = DateTime.UtcNow;
        }

        previous?.Stop();
        previous?.Dispose();
    }

    private static TrafficDto ToDto(TrafficProgramSnapshot program, bool sampled)
    {
        var isUnattributed = string.Equals(
            program.Key, TrafficAggregator.UnattributedKey, StringComparison.OrdinalIgnoreCase);

        var bytesIn = program.TcpBytesIn + program.UdpBytesIn + program.OtherBytesIn;
        var bytesOut = program.TcpBytesOut + program.UdpBytesOut + program.OtherBytesOut;

        return new TrafficDto
        {
            Key = program.Key,
            Path = program.Path,
            Name = isUnattributed ? program.Key : program.Name,
            IsPathKnown = program.IsPathKnown,
            Pids = program.Pid > 0 && !program.IsPathKnown ? new List<int> { program.Pid } : null,
            BytesIn = bytesIn,
            BytesOut = bytesOut,
            TcpBytesIn = program.TcpBytesIn,
            TcpBytesOut = program.TcpBytesOut,
            UdpBytesIn = program.UdpBytesIn,
            UdpBytesOut = program.UdpBytesOut,
            PacketsIn = program.PacketsIn,
            PacketsOut = program.PacketsOut,
            RateIn = program.RateIn,
            RateOut = program.RateOut,
            Sampled = sampled,
            LastSeenUtc = program.LastSeenUtc,
        };
    }
}
