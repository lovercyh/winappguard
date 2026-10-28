using WinAppGuard.Core.Diagnostics.AntiScan;

namespace WinAppGuard.Core.Diagnostics.Traffic;

/// <summary>
/// 4.1：把「每包事实」聚合成「每程序累计 + 每秒速率」。
///
/// 设计要点：
///   - 采集线程只调用 <see cref="Observe"/>，加锁累加，不做任何 IO/进程查询；
///   - 归属靠每秒刷新的端点表快照；查不到的包先放 pending，1 秒后重试，
///     3 秒仍查不到就归入「未归属」——宁可标出来，也不假装知道；
///   - 速率用 3 秒滑动平均，避免 1 秒桶的抖动；
///   - 纯内存，不落盘；服务重启或「清空」后归零。
/// </summary>
public sealed class TrafficAggregator
{
    /// <summary>速率曲线保留 5 分钟。</summary>
    public const int SeriesPoints = 300;

    private const int MaxPending = 2048;
    private static readonly TimeSpan PendingTimeout = TimeSpan.FromSeconds(3);
    private static readonly TimeSpan OwnerCacheTtl = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan NegativeCacheTtl = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan PidCacheTtl = TimeSpan.FromSeconds(30);

    private readonly object _gate = new();
    private readonly Dictionary<string, ProgramState> _programs = new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<TrafficEndpoint, PendingState> _pending = new();
    private readonly Dictionary<TrafficEndpoint, OwnerCacheEntry> _ownerCache = new();
    private readonly Dictionary<int, PidCacheEntry> _pidCache = new();
    private readonly long[] _ringIn = new long[SeriesPoints];
    private readonly long[] _ringOut = new long[SeriesPoints];

    private IEndpointOwnerLookup? _owners;
    private int _ringIndex;
    private int _ringCount;
    private long _secondIn;
    private long _secondOut;
    private DateTime _lastTickUtc = DateTime.UtcNow;

    public TrafficAggregator(IEndpointOwnerLookup? owners = null)
    {
        _owners = owners;
    }

    /// <summary>交换端点表快照（调用方每秒构建一次）。</summary>
    public void SetOwnerLookup(IEndpointOwnerLookup owners)
    {
        lock (_gate)
        {
            _owners = owners;
        }
    }

    /// <summary>采集线程调用：记一个包。</summary>
    public void Observe(in TrafficPacket packet, DateTime now)
    {
        if (packet.Bytes <= 0)
        {
            return;
        }

        lock (_gate)
        {
            if (packet.Direction == TrafficDirection.Inbound)
            {
                _secondIn += packet.Bytes;
            }
            else
            {
                _secondOut += packet.Bytes;
            }

            var pid = ResolveOwnerLocked(packet.Local, now);

            if (pid > 0)
            {
                ApplyLocked(pid, packet, now);
                return;
            }

            if (_pending.TryGetValue(packet.Local, out var pending))
            {
                AddPending(pending, packet);
                return;
            }

            if (_pending.Count >= MaxPending)
            {
                FlushOldestPendingLocked();
            }

            pending = new PendingState { Endpoint = packet.Local, FirstSeenUtc = now };
            AddPending(pending, packet);
            _pending[packet.Local] = pending;
        }
    }

    /// <summary>IP 分片的非首片：没有端口，无法归属，直接计入「未归属」。</summary>
    public void ObserveUnattributed(TrafficDirection direction, int bytes, DateTime now)
    {
        if (bytes <= 0)
        {
            return;
        }

        lock (_gate)
        {
            if (direction == TrafficDirection.Inbound)
            {
                _secondIn += bytes;
            }
            else
            {
                _secondOut += bytes;
            }

            var target = GetUnattributedLocked();

            if (direction == TrafficDirection.Inbound)
            {
                target.OtherIn += bytes;
                target.PacketsIn++;
            }
            else
            {
                target.OtherOut += bytes;
                target.PacketsOut++;
            }

            target.LastSeenUtc = now;
        }
    }

    /// <summary>每秒调用一次：重试归属、更新速率、写速率桶。</summary>
    public void Tick(DateTime now)
    {
        lock (_gate)
        {
            RetryPendingLocked(now);

            foreach (var program in _programs.Values)
            {
                var totalIn = program.TcpIn + program.UdpIn + program.OtherIn;
                var totalOut = program.TcpOut + program.UdpOut + program.OtherOut;
                var deltaIn = Math.Max(0, totalIn - program.LastTotalIn);
                var deltaOut = Math.Max(0, totalOut - program.LastTotalOut);

                program.RateIn = (program.RateIn * 2 + deltaIn) / 3;
                program.RateOut = (program.RateOut * 2 + deltaOut) / 3;
                program.LastTotalIn = totalIn;
                program.LastTotalOut = totalOut;
            }

            _ringIn[_ringIndex] = _secondIn;
            _ringOut[_ringIndex] = _secondOut;
            _ringIndex = (_ringIndex + 1) % SeriesPoints;

            if (_ringCount < SeriesPoints)
            {
                _ringCount++;
            }

            _secondIn = 0;
            _secondOut = 0;
            _lastTickUtc = now;

            PruneOwnerCacheLocked(now);
        }
    }

    /// <summary>清空累计与曲线（保留端点表）。</summary>
    public void Clear()
    {
        lock (_gate)
        {
            _programs.Clear();
            _pending.Clear();
            Array.Clear(_ringIn);
            Array.Clear(_ringOut);
            _ringIndex = 0;
            _ringCount = 0;
            _secondIn = 0;
            _secondOut = 0;
            _lastTickUtc = DateTime.UtcNow;
        }
    }

    public TrafficSnapshot Snapshot(bool sampled)
    {
        lock (_gate)
        {
            var programs = _programs.Values
                .Select(program => new TrafficProgramSnapshot
                {
                    Key = program.Key,
                    Path = program.Path,
                    Name = program.Name,
                    IsPathKnown = program.IsPathKnown,
                    Pid = program.Pid,
                    TcpBytesIn = program.TcpIn,
                    TcpBytesOut = program.TcpOut,
                    UdpBytesIn = program.UdpIn,
                    UdpBytesOut = program.UdpOut,
                    OtherBytesIn = program.OtherIn,
                    OtherBytesOut = program.OtherOut,
                    PacketsIn = program.PacketsIn,
                    PacketsOut = program.PacketsOut,
                    RateIn = program.RateIn,
                    RateOut = program.RateOut,
                    LastSeenUtc = program.LastSeenUtc,
                })
                .ToList();

            var bytesIn = new List<long>(_ringCount);
            var bytesOut = new List<long>(_ringCount);
            var start = (_ringIndex - _ringCount + SeriesPoints) % SeriesPoints;

            for (var i = 0; i < _ringCount; i++)
            {
                var index = (start + i) % SeriesPoints;
                bytesIn.Add(_ringIn[index]);
                bytesOut.Add(_ringOut[index]);
            }

            return new TrafficSnapshot
            {
                Programs = programs,
                BytesIn = bytesIn,
                BytesOut = bytesOut,
                SeriesStartUtc = _lastTickUtc.AddSeconds(-(_ringCount - 1)),
            };
        }
    }

    /// <summary>自检用：当前待归属的端点数。</summary>
    public int PendingCount
    {
        get { lock (_gate) { return _pending.Count; } }
    }

    private int ResolveOwnerLocked(in TrafficEndpoint endpoint, DateTime now)
    {
        if (_ownerCache.TryGetValue(endpoint, out var cached))
        {
            if (cached.ExpiresUtc > now)
            {
                return cached.Pid;
            }
        }

        var pid = _owners?.Lookup(endpoint) ?? 0;
        _ownerCache[endpoint] = new OwnerCacheEntry
        {
            Pid = pid,
            ExpiresUtc = now + (pid > 0 ? OwnerCacheTtl : NegativeCacheTtl),
        };

        return pid;
    }

    private void RetryPendingLocked(DateTime now)
    {
        if (_pending.Count == 0 || _owners is null)
        {
            return;
        }

        foreach (var pair in _pending.ToList())
        {
            var pid = _owners.Lookup(pair.Key);

            if (pid > 0)
            {
                _pending.Remove(pair.Key);
                ApplyPendingLocked(pid, pair.Value, now);
                continue;
            }

            if (now - pair.Value.FirstSeenUtc >= PendingTimeout)
            {
                _pending.Remove(pair.Key);
                ApplyUnattributedLocked(pair.Value, now);
            }
        }
    }

    private void FlushOldestPendingLocked()
    {
        var oldestKey = default(TrafficEndpoint);
        var oldest = DateTime.MaxValue;

        foreach (var pair in _pending)
        {
            if (pair.Value.FirstSeenUtc < oldest)
            {
                oldest = pair.Value.FirstSeenUtc;
                oldestKey = pair.Key;
            }
        }

        if (_pending.Remove(oldestKey, out var value))
        {
            ApplyUnattributedLocked(value, DateTime.UtcNow);
        }
    }

    private static void AddPending(PendingState pending, in TrafficPacket packet)
    {
        if (packet.Direction == TrafficDirection.Inbound)
        {
            pending.In += packet.Bytes;
            pending.PacketsIn++;
        }
        else
        {
            pending.Out += packet.Bytes;
            pending.PacketsOut++;
        }
    }

    private void ApplyPendingLocked(int pid, PendingState pending, DateTime now)
    {
        var program = GetProgramLocked(pid, now);

        // pending 里没区分协议（端口已经在端点里），这里按端点协议分别记。
        if (pending.Endpoint.Protocol == TrafficProtocol.Tcp)
        {
            program.TcpIn += pending.In;
            program.TcpOut += pending.Out;
        }
        else
        {
            program.UdpIn += pending.In;
            program.UdpOut += pending.Out;
        }

        program.PacketsIn += pending.PacketsIn;
        program.PacketsOut += pending.PacketsOut;
        program.LastSeenUtc = now;
    }

    private void ApplyUnattributedLocked(PendingState pending, DateTime now)
    {
        var target = GetUnattributedLocked();

        if (pending.Endpoint.Protocol == TrafficProtocol.Tcp)
        {
            target.TcpIn += pending.In;
            target.TcpOut += pending.Out;
        }
        else
        {
            target.UdpIn += pending.In;
            target.UdpOut += pending.Out;
        }

        target.PacketsIn += pending.PacketsIn;
        target.PacketsOut += pending.PacketsOut;
        target.LastSeenUtc = now;
    }

    private void ApplyLocked(int pid, in TrafficPacket packet, DateTime now)
    {
        var program = GetProgramLocked(pid, now);

        if (packet.Protocol == TrafficProtocol.Tcp)
        {
            if (packet.Direction == TrafficDirection.Inbound)
            {
                program.TcpIn += packet.Bytes;
                program.PacketsIn++;
            }
            else
            {
                program.TcpOut += packet.Bytes;
                program.PacketsOut++;
            }
        }
        else
        {
            if (packet.Direction == TrafficDirection.Inbound)
            {
                program.UdpIn += packet.Bytes;
                program.PacketsIn++;
            }
            else
            {
                program.UdpOut += packet.Bytes;
                program.PacketsOut++;
            }
        }

        program.LastSeenUtc = now;
    }

    private ProgramState GetProgramLocked(int pid, DateTime now)
    {
        if (!_pidCache.TryGetValue(pid, out var identity) || identity.ExpiresUtc <= now)
        {
            identity = ResolveIdentity(pid, now);
            _pidCache[pid] = identity;
        }

        if (!_programs.TryGetValue(identity.Key, out var program))
        {
            program = new ProgramState
            {
                Key = identity.Key,
                Path = identity.Path,
                Name = identity.Name,
                IsPathKnown = identity.IsPathKnown,
                Pid = pid,
            };

            _programs[identity.Key] = program;
        }

        return program;
    }

    private static PidCacheEntry ResolveIdentity(int pid, DateTime now)
    {
        string? path;

        try
        {
            path = ProcessResolver.TryGetImagePath(pid);
        }
        catch (Exception)
        {
            path = null;
        }

        return new PidCacheEntry
        {
            Key = string.IsNullOrEmpty(path) ? $"pid:{pid}" : path.ToLowerInvariant(),
            Path = string.IsNullOrEmpty(path) ? null : path,
            Name = string.IsNullOrEmpty(path) ? $"PID {pid}" : System.IO.Path.GetFileName(path),
            IsPathKnown = !string.IsNullOrEmpty(path),
            ExpiresUtc = now + PidCacheTtl,
        };
    }

    private ProgramState GetUnattributedLocked()
    {
        if (!_programs.TryGetValue(UnattributedKey, out var program))
        {
            program = new ProgramState
            {
                Key = UnattributedKey,
                Path = null,
                Name = UnattributedKey,
                IsPathKnown = false,
                Pid = 0,
            };

            _programs[UnattributedKey] = program;
        }

        return program;
    }

    private void PruneOwnerCacheLocked(DateTime now)
    {
        if (_ownerCache.Count < 8192)
        {
            return;
        }

        foreach (var pair in _ownerCache.ToList())
        {
            if (pair.Value.ExpiresUtc <= now)
            {
                _ownerCache.Remove(pair.Key);
            }
        }
    }

    public const string UnattributedKey = "unattributed";

    private sealed class ProgramState
    {
        public string Key = string.Empty;
        public string? Path;
        public string Name = string.Empty;
        public bool IsPathKnown;
        public int Pid;

        public long TcpIn;
        public long TcpOut;
        public long UdpIn;
        public long UdpOut;
        public long OtherIn;
        public long OtherOut;
        public long PacketsIn;
        public long PacketsOut;

        public long RateIn;
        public long RateOut;
        public long LastTotalIn;
        public long LastTotalOut;
        public DateTime LastSeenUtc;
    }

    private sealed class PendingState
    {
        public TrafficEndpoint Endpoint;
        public DateTime FirstSeenUtc;
        public long In;
        public long Out;
        public long PacketsIn;
        public long PacketsOut;
    }

    private readonly record struct OwnerCacheEntry(int Pid, DateTime ExpiresUtc);

    private readonly record struct PidCacheEntry(
        string Key, string? Path, string Name, bool IsPathKnown, DateTime ExpiresUtc);
}
