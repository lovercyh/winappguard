using System.Net;
using System.Runtime.InteropServices;
using WinAppGuard.Core.Diagnostics.Ids;

namespace WinAppGuard.Core.Diagnostics;

/// <summary>3.5：某个 PID 在上次快照以来的网络字节数。</summary>
public readonly record struct PidTraffic(int Pid, ulong BytesIn, ulong BytesOut);

/// <summary>
/// 3.5：用 ETW <c>Microsoft-Windows-Kernel-Network</c> 按 PID 统计网络流量。
///
/// 为什么要用它：VM 实测 <c>GetPerTcpConnectionEStats</c> 的 <c>DataBytesIn</c>
/// 在客户端连接上不增长（50 MB 下载只有 371 B），不能作为下载量来源。
/// 这个 provider 的每个数据事件都带 <c>PID + size</c>，发送/接收都有。
///
/// 事件 ID（Windows 7 起稳定）：
///   - TCP：10/26 发送，11/27 接收；
///   - UDP：42/58 发送，43/59 接收。
/// 每个模板的前两个字段都是 <c>PID</c>（UInt32）和 <c>size</c>（UInt32），
/// 所以回调里直接读 8 字节，不调用 TDH（每秒上万事件时 TDH 太慢）。
///
/// 回调只更新内存计数器；真正的「PID → 程序路径」聚合由 <c>TrafficHost</c>
/// 每 2 秒调用 <see cref="TakeSnapshot"/> 完成，避免在 ETW 线程里开进程句柄。
/// </summary>
public sealed class NetworkEtwMonitor : IDisposable
{
    private const string SessionName = "WinAppGuard-Net";

    /// <summary>会话 GUID（固定值；同一台机器只允许一个同名会话）。</summary>
    private static readonly Guid SessionGuid = new("9F1E2D3C-4B5A-4C6D-8E7F-0A1B2C3D4E5F");

    /// <summary>Microsoft-Windows-Kernel-Network。</summary>
    private static readonly Guid ProviderGuid = new("7DD42A49-5329-4832-8DFD-43D979153A88");

    /// <summary>KERNEL_NETWORK_KEYWORD_IPV4 (0x10) | IPV6 (0x20)。</summary>
    private const ulong Keywords = 0x10 | 0x20;

    private readonly object _gate = new();
    private readonly Dictionary<int, Counters> _totals = new();
    private readonly string _sessionName;
    private readonly Guid _sessionGuid;

    private EtwRealtimeSession? _session;
    private long _eventsSeen;
    private long _flowParseFailures;
    private volatile bool _captureFlows;

    /// <summary>3.7：IDS 开启时才解析地址/端口；关闭时保持 3.6 的低开销。</summary>
    public bool CaptureFlows
    {
        get => _captureFlows;
        set => _captureFlows = value;
    }

    /// <summary>3.7：连接/数据事件（元数据）交给 IDS；回调在 ETW 线程执行。</summary>
    public Action<NetworkFlowObservation>? FlowObserved { get; set; }

    public NetworkEtwMonitor(string sessionName = SessionName, Guid? sessionGuid = null)
    {
        _sessionName = sessionName;
        _sessionGuid = sessionGuid ?? SessionGuid;
    }

    public bool IsRunning => _session?.IsRunning == true;

    public string? LastError => _session?.LastError;

    /// <summary>累计解析到的网络数据事件数（诊断/验收用）。</summary>
    public long EventsSeen => Interlocked.Read(ref _eventsSeen);

    /// <summary>3.7：IDS 打开但地址/端口解析失败的次数（事件太短或模板不符）。</summary>
    public long FlowParseFailures => Interlocked.Read(ref _flowParseFailures);

    public bool Start()
    {
        lock (_gate)
        {
            if (_session is not null)
            {
                return _session.IsRunning;
            }

            var session = new EtwRealtimeSession(
                _sessionName, _sessionGuid, ProviderGuid, Keywords, OnEvent);

            if (!session.Start())
            {
                session.Dispose();
                return false;
            }

            _session = session;
            return true;
        }
    }

    public void Stop()
    {
        EtwRealtimeSession? session;

        lock (_gate)
        {
            session = _session;
            _session = null;
            _totals.Clear();
        }

        session?.Dispose();
    }

    public void Dispose() => Stop();

    /// <summary>
    /// 取走「上次调用以来」每个 PID 的增量，并清空。
    /// 这样即使服务短暂停顿，字节也不会丢；PID 复用的风险窗口也限制在一个采样周期。
    /// </summary>
    public List<PidTraffic> TakeSnapshot()
    {
        lock (_gate)
        {
            if (_totals.Count == 0)
            {
                return new List<PidTraffic>();
            }

            var list = new List<PidTraffic>(_totals.Count);

            foreach (var (pid, counters) in _totals)
            {
                list.Add(new PidTraffic(pid, counters.In, counters.Out));
            }

            _totals.Clear();
            return list;
        }
    }

    private void OnEvent(IntPtr recordPointer)
    {
        var record = EtwRealtimeSession.ReadRecord(recordPointer);
        var id = record.EventHeader.Id;

        var isData = TryClassifyEvent(id, out var isOut);
        var isConnection = id is 12 or 15 or 28 or 31;

        if (!isData && !isConnection)
        {
            return;
        }

        if (record.UserData == IntPtr.Zero || record.UserDataLength < 8)
        {
            return;
        }

        // 所有 Data sent/received 和 Connection 模板前两个字段都是 PID、size。
        var pid = Marshal.ReadInt32(record.UserData, 0);
        var size = unchecked((uint)Marshal.ReadInt32(record.UserData, 4));

        if (pid <= 0)
        {
            return;
        }

        if (isData && size > 0)
        {
            lock (_gate)
            {
                if (!_totals.TryGetValue(pid, out var counters))
                {
                    counters = new Counters();
                    _totals[pid] = counters;
                }

                if (isOut)
                {
                    counters.Out += size;
                }
                else
                {
                    counters.In += size;
                }

                Interlocked.Increment(ref _eventsSeen);
            }
        }

        if (_captureFlows && FlowObserved is { } sink)
        {
            var observation = TryCreateFlowObservation(
                record.UserData, record.UserDataLength, id, pid, size, isData, isOut, isConnection);

            if (observation is not null)
            {
                sink(observation.Value);
            }
            else
            {
                Interlocked.Increment(ref _flowParseFailures);
            }
        }
    }

    private static NetworkFlowObservation? TryCreateFlowObservation(
        IntPtr data,
        int length,
        ushort eventId,
        int pid,
        uint size,
        bool isData,
        bool isOut,
        bool isConnection)
    {
        var isV6 = eventId is 26 or 27 or 28 or 29 or 30 or 31 or 32 or 34 or 58 or 59;
        string remote;
        ushort remotePort;

        if (!isV6)
        {
            if (length < 20)
            {
                return null;
            }

            var address = (uint)Marshal.ReadInt32(data, 8);
            remote = new IPAddress(BitConverter.GetBytes(address)).ToString();
            remotePort = (ushort)IPAddress.NetworkToHostOrder(Marshal.ReadInt16(data, 16));
        }
        else
        {
            if (length < 44)
            {
                return null;
            }

            var bytes = new byte[16];
            Marshal.Copy(IntPtr.Add(data, 8), bytes, 0, 16);
            remote = new IPAddress(bytes).ToString();
            remotePort = (ushort)IPAddress.NetworkToHostOrder(Marshal.ReadInt16(data, 40));
        }

        if (remotePort == 0)
        {
            return null;
        }

        return new NetworkFlowObservation(
            DateTime.UtcNow,
            pid,
            eventId <= 34 ? "TCP" : "UDP",
            remote,
            remotePort,
            isData ? isOut : eventId is 12 or 28,
            isConnection,
            isData ? size : 0);
    }

    private sealed class Counters
    {
        public ulong In;
        public ulong Out;
    }

    /// <summary>事件 ID → 方向。TCP/UDP 的 IPv4/IPv6 发送/接收共 8 个。</summary>
    internal static bool TryClassifyEvent(ushort eventId, out bool isOut)
    {
        switch (eventId)
        {
            case 10:  // TCP IPv4 data sent
            case 26:  // TCP IPv6 data sent
            case 42:  // UDP IPv4 data sent
            case 58:  // UDP IPv6 data sent
                isOut = true;
                return true;

            case 11:  // TCP IPv4 data received
            case 27:  // TCP IPv6 data received
            case 43:  // UDP IPv4 data received
            case 59:  // UDP IPv6 data received
                isOut = false;
                return true;

            default:
                isOut = false;
                return false;
        }
    }
}
