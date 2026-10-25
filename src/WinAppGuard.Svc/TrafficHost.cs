using System.Runtime.InteropServices;
using WinAppGuard.Contracts;
using WinAppGuard.Core;

namespace WinAppGuard.Service;

/// <summary>
/// 3.5：每程序 TCP 流量采集（服务端）。
///
/// 数据来源是 TCP 扩展统计（<c>GetPerTcpConnectionEStats</c>）：
///   - 服务每 2 秒枚举一次 ESTABLISHED 连接，对新连接启用统计；
///   - 相邻两次采样之差累加到「程序路径」上；
///   - 统计的是**数据字节**，不含 TCP/IP 头。
///
/// 必须如实说明的边界（界面/文档同样要写）：
///   - 只覆盖 TCP，UDP 完全不计；
///   - 连接存在时间短于一个采样周期时可能整个漏掉；
///   - 统计从「服务第一次看到这条连接」开始，启用之前的字节无法回溯；
///   - 按路径合并同一程序的多个实例/多次启动，「本次服务运行」内累计。
///
/// 不落盘：服务重启后从 0 开始。界面写「本次运行」，不写「总流量」。
/// </summary>
internal static class TrafficHost
{
    private const int AfInet = 2;
    private const int AfInet6 = 23;
    private const int TcpTableOwnerPidAll = 5;
    private const int TcpConnectionEstatsData = 1;
    private const uint TcpStateEstablished = 5;

    /// <summary>采样周期。再短会明显增加 API 调用量，再长会漏掉更多短连接。</summary>
    private static readonly TimeSpan SampleInterval = TimeSpan.FromSeconds(2);

    /// <summary>连接消失后保留多久，避免刚好在关闭瞬间丢掉最后一次增量。</summary>
    private static readonly TimeSpan ConnectionRetention = TimeSpan.FromSeconds(10);

    private static readonly object Gate = new();

    private static System.Threading.Timer? _timer;

    private static bool _collecting;

    /// <summary>连接键 → 上一条样本（只保留最近出现的连接）。</summary>
    private static readonly Dictionary<string, ConnectionState> Connections =
        new(StringComparer.Ordinal);

    /// <summary>聚合键（路径小写 / pid:123）→ 累计值。</summary>
    private static readonly Dictionary<string, TrafficAccumulator> Totals =
        new(StringComparer.OrdinalIgnoreCase);

    /// <summary>统计连续失败次数，日志按 1/30 节流，避免坏环境下每 2 秒刷一条。</summary>
    private static int _failureLogCounter;

    internal static bool Collecting
    {
        get { lock (Gate) { return _collecting; } }
    }

    internal static void Start()
    {
        lock (Gate)
        {
            if (_timer is not null)
            {
                return;
            }

            _collecting = true;
            _failureLogCounter = 0;

            // 1 秒后开始第一次采样：服务启动时网卡上通常已经有连接了。
            _timer = new System.Threading.Timer(
                _ => Sample(),
                state: null,
                dueTime: TimeSpan.FromSeconds(1),
                period: SampleInterval);

            ServiceLog.Info("WAG-TRAFFIC-001", "Traffic collection started (TCP extended statistics).");
        }
    }

    internal static void Stop()
    {
        lock (Gate)
        {
            _timer?.Dispose();
            _timer = null;
            _collecting = false;

            Connections.Clear();
            Totals.Clear();
        }

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

    private static void Sample()
    {
        try
        {
            var rows = new List<TcpRowSample>();

            rows.AddRange(EnumerateV4());
            rows.AddRange(EnumerateV6());

            lock (Gate)
            {
                var now = DateTime.UtcNow;

                foreach (var row in rows)
                {
                    if (!Connections.TryGetValue(row.Key, out var state) || state.Pid != row.Pid)
                    {
                        // 新连接（或 4 元组被复用）：启用统计，先记基线。
                        // 基线之前的字节拿不到 —— 这就是「近似值」的来源之一。
                        var enabled = row.EnableStats();

                        if (!enabled)
                        {
                            Connections[row.Key] = new ConnectionState
                            {
                                Pid = row.Pid,
                                LastSeenUtc = now,
                            };

                            continue;
                        }

                        _ = row.TryRead(out var baselineIn, out var baselineOut);

                        Connections[row.Key] = new ConnectionState
                        {
                            Pid = row.Pid,
                            Enabled = enabled,
                            LastIn = baselineIn,
                            LastOut = baselineOut,
                            LastSeenUtc = now,
                        };

                        continue;
                    }

                    state.LastSeenUtc = now;

                    // 第一次启用失败（例如连接刚建立/正在关闭）不能就此放弃：
                    // 每个周期重试一次，成功后从基线开始计。
                    if (!state.Enabled)
                    {
                        if (!row.EnableStats())
                        {
                            continue;
                        }

                        state.Enabled = true;
                        _ = row.TryRead(out var retryIn, out var retryOut);
                        state.LastIn = retryIn;
                        state.LastOut = retryOut;
                        continue;
                    }

                    if (!row.TryRead(out var currentIn, out var currentOut))
                    {
                        continue;
                    }

                    // 计数器变小 = 4 元组被复用成了新连接，不能把差值算成负数。
                    if (currentIn < state.LastIn || currentOut < state.LastOut)
                    {
                        state.LastIn = currentIn;
                        state.LastOut = currentOut;
                        continue;
                    }

                    var deltaIn = currentIn - state.LastIn;
                    var deltaOut = currentOut - state.LastOut;

                    state.LastIn = currentIn;
                    state.LastOut = currentOut;

                    if (deltaIn == 0 && deltaOut == 0)
                    {
                        continue;
                    }

                    Accumulate(row.Pid, deltaIn, deltaOut, now);
                }

                RemoveStaleConnections(now);

                _collecting = true;
                _failureLogCounter = 0;
            }
        }
        catch (Exception ex)
        {
            _collecting = false;
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

    private static void Accumulate(int pid, ulong deltaIn, ulong deltaOut, DateTime now)
    {
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
        // 刻意不做 PID → 路径缓存：PID 会复用，缓存会让「新程序」短暂继承旧程序的流量。
        // 只有真正产生流量的 PID 才会走到这里，每个采样周期最多几十次 OpenProcess，开销可以忽略。
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

    private static void RemoveStaleConnections(DateTime now)
    {
        var cutoff = now - ConnectionRetention;

        foreach (var key in Connections
                     .Where(pair => pair.Value.LastSeenUtc < cutoff)
                     .Select(pair => pair.Key)
                     .ToList())
        {
            Connections.Remove(key);
        }
    }

    private static long AddClamped(long current, ulong delta)
        => delta > (ulong)(long.MaxValue - current)
            ? long.MaxValue
            : current + (long)delta;

    // ---------------- 枚举 ----------------

    private static IEnumerable<TcpRowSample> EnumerateV4()
    {
        var buffer = GetTable(AfInet, TcpTableOwnerPidAll);

        if (buffer == IntPtr.Zero)
        {
            yield break;
        }

        try
        {
            var count = Marshal.ReadInt32(buffer);
            var rowSize = Marshal.SizeOf<MibTcpRowOwnerPid>();
            var rowPointer = IntPtr.Add(buffer, 4);

            for (var i = 0; i < count; i++)
            {
                var owner = Marshal.PtrToStructure<MibTcpRowOwnerPid>(
                    IntPtr.Add(rowPointer, i * rowSize));

                if (owner.State != TcpStateEstablished || owner.OwningPid == 0)
                {
                    continue;
                }

                yield return new TcpRowSample
                {
                    Key = $"4|{owner.LocalAddr:x8}|{owner.LocalPort}|{owner.RemoteAddr:x8}|{owner.RemotePort}",
                    Pid = (int)owner.OwningPid,
                    IsV6 = false,
                    LocalAddrV4 = owner.LocalAddr,
                    LocalPort = owner.LocalPort,
                    RemoteAddrV4 = owner.RemoteAddr,
                    RemotePort = owner.RemotePort,
                };
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static IEnumerable<TcpRowSample> EnumerateV6()
    {
        var buffer = GetTable(AfInet6, TcpTableOwnerPidAll);

        if (buffer == IntPtr.Zero)
        {
            yield break;
        }

        try
        {
            var count = Marshal.ReadInt32(buffer);
            var rowSize = Marshal.SizeOf<MibTcp6RowOwnerPid>();
            var rowPointer = IntPtr.Add(buffer, 4);

            for (var i = 0; i < count; i++)
            {
                var owner = Marshal.PtrToStructure<MibTcp6RowOwnerPid>(
                    IntPtr.Add(rowPointer, i * rowSize));

                if (owner.State != TcpStateEstablished || owner.OwningPid == 0)
                {
                    continue;
                }

                yield return new TcpRowSample
                {
                    Key = $"6|{Convert.ToHexString(owner.LocalAddr)}|{owner.LocalPort}|" +
                          $"{Convert.ToHexString(owner.RemoteAddr)}|{owner.RemotePort}",
                    Pid = (int)owner.OwningPid,
                    IsV6 = true,
                    LocalAddrV6 = owner.LocalAddr,
                    LocalScopeId = owner.LocalScopeId,
                    LocalPort = owner.LocalPort,
                    RemoteAddrV6 = owner.RemoteAddr,
                    RemoteScopeId = owner.RemoteScopeId,
                    RemotePort = owner.RemotePort,
                };
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static IntPtr GetTable(int family, int tableClass)
    {
        var size = 0;
        var rc = GetExtendedTcpTable(
            IntPtr.Zero, ref size, false, family, tableClass, 0);

        if (rc != 122 || size <= 0) // ERROR_INSUFFICIENT_BUFFER
        {
            return IntPtr.Zero;
        }

        var buffer = Marshal.AllocHGlobal(size);
        rc = GetExtendedTcpTable(buffer, ref size, false, family, tableClass, 0);

        if (rc != 0)
        {
            Marshal.FreeHGlobal(buffer);
            return IntPtr.Zero;
        }

        return buffer;
    }

    // ---------------- 内部模型 ----------------

    private sealed class ConnectionState
    {
        public int Pid;
        public bool Enabled;
        public ulong LastIn;
        public ulong LastOut;
        public DateTime LastSeenUtc;
    }

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

    private sealed class TcpRowSample
    {
        public required string Key { get; init; }

        public required int Pid { get; init; }

        public required bool IsV6 { get; init; }

        public uint LocalAddrV4 { get; init; }

        public byte[]? LocalAddrV6 { get; init; }

        public uint LocalScopeId { get; init; }

        public required uint LocalPort { get; init; }

        public uint RemoteAddrV4 { get; init; }

        public byte[]? RemoteAddrV6 { get; init; }

        public uint RemoteScopeId { get; init; }

        public required uint RemotePort { get; init; }

        public bool EnableStats()
        {
            byte enable = 1;

            if (!IsV6)
            {
                var row = new MibTcpRow
                {
                    State = TcpStateEstablished,
                    LocalAddr = LocalAddrV4,
                    LocalPort = LocalPort,
                    RemoteAddr = RemoteAddrV4,
                    RemotePort = RemotePort,
                };

                return SetPerTcpConnectionEStats(
                    ref row, TcpConnectionEstatsData, ref enable, 0, 1,
                    IntPtr.Zero, 0, 0) == 0;
            }

            var row6 = new MibTcp6Row
            {
                State = TcpStateEstablished,
                LocalAddr = LocalAddrV6!,
                LocalScopeId = LocalScopeId,
                LocalPort = LocalPort,
                RemoteAddr = RemoteAddrV6!,
                RemoteScopeId = RemoteScopeId,
                RemotePort = RemotePort,
            };

            return SetPerTcp6ConnectionEStats(
                ref row6, TcpConnectionEstatsData, ref enable, 0, 1,
                IntPtr.Zero, 0, 0) == 0;
        }

        public bool TryRead(out ulong bytesIn, out ulong bytesOut)
        {
            bytesIn = 0;
            bytesOut = 0;

            var rod = default(TcpEstatsDataRod);

            uint rc;

            if (!IsV6)
            {
                var row = new MibTcpRow
                {
                    State = TcpStateEstablished,
                    LocalAddr = LocalAddrV4,
                    LocalPort = LocalPort,
                    RemoteAddr = RemoteAddrV4,
                    RemotePort = RemotePort,
                };

                rc = GetPerTcpConnectionEStats(
                    ref row, TcpConnectionEstatsData,
                    IntPtr.Zero, 0, 0,
                    IntPtr.Zero, 0, 0,
                    ref rod, 0, (uint)Marshal.SizeOf<TcpEstatsDataRod>());
            }
            else
            {
                var row6 = new MibTcp6Row
                {
                    State = TcpStateEstablished,
                    LocalAddr = LocalAddrV6!,
                    LocalScopeId = LocalScopeId,
                    LocalPort = LocalPort,
                    RemoteAddr = RemoteAddrV6!,
                    RemoteScopeId = RemoteScopeId,
                    RemotePort = RemotePort,
                };

                rc = GetPerTcp6ConnectionEStats(
                    ref row6, TcpConnectionEstatsData,
                    IntPtr.Zero, 0, 0,
                    IntPtr.Zero, 0, 0,
                    ref rod, 0, (uint)Marshal.SizeOf<TcpEstatsDataRod>());
            }

            if (rc != 0)
            {
                return false;
            }

            bytesIn = rod.DataBytesIn;
            bytesOut = rod.DataBytesOut;
            return true;
        }
    }

    // ---------------- 结构 ----------------

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcpRow
    {
        public uint State;
        public uint LocalAddr;
        public uint LocalPort;
        public uint RemoteAddr;
        public uint RemotePort;
    }

    /// <summary>MIB_TCP6ROW：注意 State 在最前面（和 OWNER_PID 版本不同）。</summary>
    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcp6Row
    {
        public uint State;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] LocalAddr;

        public uint LocalScopeId;
        public uint LocalPort;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] RemoteAddr;

        public uint RemoteScopeId;
        public uint RemotePort;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcpRowOwnerPid
    {
        public uint State;
        public uint LocalAddr;
        public uint LocalPort;
        public uint RemoteAddr;
        public uint RemotePort;
        public uint OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MibTcp6RowOwnerPid
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] LocalAddr;

        public uint LocalScopeId;
        public uint LocalPort;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] RemoteAddr;

        public uint RemoteScopeId;
        public uint RemotePort;
        public uint State;
        public uint OwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TcpEstatsDataRod
    {
        public ulong DataBytesOut;
        public ulong DataBytesIn;
        public ulong DataSegsOut;
        public ulong DataSegsIn;
        public ulong SegsOut;
        public ulong SegsIn;
        public uint SoftErrors;
        public uint SoftErrorReason;
        public uint SndUna;
        public uint SndNxt;
        public uint SndMax;
        public ulong ThruBytesAcked;
        public uint RcvNxt;
        public ulong ThruBytesReceived;
    }

    // ---------------- P/Invoke ----------------

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr tcpTable, ref int size, bool order, int family, int tableClass, uint reserved);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint SetPerTcpConnectionEStats(
        ref MibTcpRow row, int estatsType, ref byte rw, uint rwVersion, uint rwSize,
        IntPtr ros, uint rosVersion, uint rosSize);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetPerTcpConnectionEStats(
        ref MibTcpRow row, int estatsType,
        IntPtr rw, uint rwVersion, uint rwSize,
        IntPtr ros, uint rosVersion, uint rosSize,
        ref TcpEstatsDataRod rod, uint rodVersion, uint rodSize);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint SetPerTcp6ConnectionEStats(
        ref MibTcp6Row row, int estatsType, ref byte rw, uint rwVersion, uint rwSize,
        IntPtr ros, uint rosVersion, uint rosSize);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetPerTcp6ConnectionEStats(
        ref MibTcp6Row row, int estatsType,
        IntPtr rw, uint rwVersion, uint rwSize,
        IntPtr ros, uint rosVersion, uint rosSize,
        ref TcpEstatsDataRod rod, uint rodVersion, uint rodSize);
}
