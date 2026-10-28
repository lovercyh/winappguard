using System.Buffers.Binary;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using WinAppGuard.Core.Diagnostics.AntiScan;

namespace WinAppGuard.Core.Diagnostics.Traffic;

/// <summary>
/// 4.1：Npcap 精确流量采集（独立会话，与 4.0 的反扫描采集互不影响）。
///
/// 只做三件事：
///   - 用 libpcap 打开活动网卡，BPF 只保留 TCP/UDP；
///   - 解析 IP/TCP/UDP 头，算出「本机端点 / 方向 / 协议 / IP 载荷字节」；
///   - 多网卡去重后交给 <see cref="TrafficAggregator"/>。
///
/// 不读载荷内容（只读端口与长度）；不写盘；不注入/修改任何数据包。
/// </summary>
public sealed class NpcapTrafficCapture : IDisposable
{
    /// <summary>带 VLAN / IPv6 扩展头也够用的抓取长度；只解析头部。</summary>
    private const int SnapLength = 192;

    private const int ReadTimeoutMs = 100;
    private const string BpfFilter = "tcp or udp";

    private readonly object _gate = new();
    private readonly List<CaptureHandle> _captures = new();
    private readonly Dictionary<ulong, long> _dedup = new();
    private readonly HashSet<uint> _localV4 = new();
    private readonly HashSet<(ulong High, ulong Low)> _localV6 = new();

    private IntPtr _library;
    private bool _running;
    private DateTime _nextLocalRefreshUtc = DateTime.MinValue;
    private long _packets;
    private long _dropped;
    private int _sampleFactor = 1;
    private int _activeThreads;
    private string? _lastError;

    public Action<TrafficPacket>? PacketObserved { get; set; }

    /// <summary>IP 分片的非首片：没有端口，交给聚合器记「未归属」。</summary>
    public Action<TrafficDirection, int>? FragmentObserved { get; set; }

    public Action<string>? Log { get; set; }

    public bool IsRunning
    {
        get
        {
            lock (_gate)
            {
                return _running && Volatile.Read(ref _activeThreads) > 0;
            }
        }
    }

    public long PacketsSeen => Interlocked.Read(ref _packets);

    public long DroppedPackets
    {
        get { lock (_gate) { return _dropped; } }
    }

    /// <summary>
    /// 采样倍数（1 = 不采样）。超过阈值时由宿主调高；此时字节数会按倍数放大，
    /// 界面必须标注「估算」。
    /// </summary>
    public int SampleFactor
    {
        get { lock (_gate) { return _sampleFactor; } }
        set { lock (_gate) { _sampleFactor = Math.Clamp(value, 1, 16); } }
    }

    public string? LastError
    {
        get { lock (_gate) { return _lastError; } }
    }

    public bool Start()
    {
        lock (_gate)
        {
            if (_running)
            {
                if (IsRunning)
                {
                    return true;
                }

                CloseCapturesLocked();
                CleanupLocked();
            }

            _lastError = null;
            _captures.Clear();
            _dedup.Clear();

            var wpcapPath = NpcapLocator.FindWpcapPath();

            if (wpcapPath is null)
            {
                _lastError = "未找到 Npcap（wpcap.dll）。";
                return false;
            }

            try
            {
                _library = NativeLibrary.Load(wpcapPath);
                var api = new NpcapApi(_library);
                var devices = api.FindDevices(out var findError);

                if (devices.Count == 0)
                {
                    _lastError = findError ?? "Npcap 没有返回可用网卡。";
                    CleanupLocked();
                    return false;
                }

                var opened = 0;

                foreach (var device in devices)
                {
                    if (device.IsLoopback || !device.IsUp)
                    {
                        continue;
                    }

                    var handle = api.OpenLive(device.Name, out var openError);

                    if (handle == IntPtr.Zero)
                    {
                        Log?.Invoke($"Npcap 打开网卡失败：{device.Name}（{openError}）");
                        continue;
                    }

                    if (!api.SetFilter(handle, out var filterError))
                    {
                        Log?.Invoke($"Npcap 设置流量过滤器失败：{device.Name}（{filterError}）");
                        api.Close(handle);
                        continue;
                    }

                    var linkType = api.DataLink(handle);
                    _captures.Add(new CaptureHandle(device.Name, handle, linkType, api));
                    opened++;
                }

                if (opened == 0)
                {
                    _lastError = "Npcap 没有成功打开任何活动网卡。";
                    CleanupLocked();
                    return false;
                }

                RefreshLocalAddressesLocked();
                _running = true;
                Volatile.Write(ref _activeThreads, opened);

                foreach (var capture in _captures)
                {
                    var thread = new Thread(() => CaptureLoop(capture))
                    {
                        IsBackground = true,
                        Name = "WinAppGuard-Traffic",
                    };

                    thread.Start();
                }

                Log?.Invoke(
                    $"精确流量采集已启动：{opened} 张网卡，Npcap {NpcapLocator.GetVersion(wpcapPath)}。");

                return true;
            }
            catch (Exception ex)
            {
                _lastError = ex.Message;
                CloseCapturesLocked();
                CleanupLocked();
                return false;
            }
        }
    }

    public void Stop()
    {
        List<CaptureHandle> captures;

        lock (_gate)
        {
            _running = false;
            captures = _captures.ToList();
        }

        var deadline = DateTime.UtcNow.AddSeconds(2);

        while (Volatile.Read(ref _activeThreads) > 0 && DateTime.UtcNow < deadline)
        {
            Thread.Sleep(20);
        }

        lock (_gate)
        {
            foreach (var capture in captures)
            {
                try
                {
                    capture.Api.Close(capture.Handle);
                }
                catch (Exception)
                {
                    // 关闭失败不影响服务停止。
                }
            }

            _captures.Clear();
            CleanupLocked();
            Log?.Invoke("精确流量采集已停止。");
        }
    }

    public void Dispose() => Stop();

    /// <summary>宿主每秒调用：读取 pcap 丢包统计（0 = 数据完整）。</summary>
    public void RefreshStatistics()
    {
        lock (_gate)
        {
            long dropped = 0;

            foreach (var capture in _captures)
            {
                if (capture.Api.TryGetStats(capture.Handle, out var stats))
                {
                    dropped += stats.Dropped + stats.InterfaceDropped;
                }
            }

            _dropped = dropped;
        }
    }

    private void CloseCapturesLocked()
    {
        foreach (var capture in _captures)
        {
            try
            {
                capture.Api.Close(capture.Handle);
            }
            catch (Exception)
            {
                // 关闭失败不影响后续重试。
            }
        }

        _captures.Clear();
        _running = false;
    }

    private void CleanupLocked()
    {
        if (_library != IntPtr.Zero)
        {
            try
            {
                NativeLibrary.Free(_library);
            }
            catch (Exception)
            {
                // 释放失败不影响服务。
            }

            _library = IntPtr.Zero;
        }

        _running = false;
    }

    private void CaptureLoop(CaptureHandle capture)
    {
        var buffer = new byte[SnapLength];
        var dedupWindow = TimeSpan.FromSeconds(2);

        try
        {
            while (true)
            {
                lock (_gate)
                {
                    if (!_running)
                    {
                        break;
                    }
                }

                MaybeRefreshLocalAddresses();

                var rc = capture.Api.NextPacket(capture.Handle, out var header, out var data);

                if (rc == 0)
                {
                    continue;
                }

                if (rc < 0)
                {
                    var error = capture.Api.GetError(capture.Handle);

                    lock (_gate)
                    {
                        _lastError = string.IsNullOrWhiteSpace(error)
                            ? "Npcap 采集失败。"
                            : error;
                    }

                    Log?.Invoke($"Npcap 流量采集失败：{capture.DeviceName}（{error}）");
                    break;
                }

                try
                {
                    var packetHeader = Marshal.PtrToStructure<PcapPacketHeader>(header);

                    if (packetHeader.CaptureLength == 0)
                    {
                        continue;
                    }

                    var length = (int)Math.Min(packetHeader.CaptureLength, (uint)buffer.Length);
                    Marshal.Copy(data, buffer, 0, length);

                    var index = Interlocked.Increment(ref _packets);
                    var factor = SampleFactor;

                    // 采样：只解析 1/N 的包，字节数按 N 放大。
                    if (factor > 1 && index % factor != 0)
                    {
                        continue;
                    }

                    if (!TryParse(buffer, length, capture.LinkType, out var parsed, out var hash))
                    {
                        continue;
                    }

                    var now = DateTime.UtcNow;

                    if (IsDuplicate(hash, now, dedupWindow))
                    {
                        continue;
                    }

                    if (parsed.FragmentBytes > 0)
                    {
                        FragmentObserved?.Invoke(parsed.Direction, parsed.FragmentBytes * factor);
                    }
                    else
                    {
                        PacketObserved?.Invoke(
                            parsed.Packet with { Bytes = parsed.Packet.Bytes * factor });
                    }
                }
                catch (Exception ex)
                {
                    Log?.Invoke($"Npcap 流量解析失败：{ex.Message}");
                }
            }
        }
        finally
        {
            Interlocked.Decrement(ref _activeThreads);
        }
    }

    private bool IsDuplicate(ulong hash, DateTime now, TimeSpan window)
    {
        lock (_gate)
        {
            if (_dedup.TryGetValue(hash, out var ticks))
            {
                var seen = new DateTime(ticks, DateTimeKind.Utc);

                if (now - seen < window)
                {
                    return true;
                }
            }

            _dedup[hash] = now.Ticks;

            if (_dedup.Count > 8192)
            {
                var cutoff = now - window;

                foreach (var pair in _dedup
                             .Where(pair => new DateTime(pair.Value, DateTimeKind.Utc) < cutoff)
                             .Select(pair => pair.Key)
                             .ToList())
                {
                    _dedup.Remove(pair);
                }
            }

            return false;
        }
    }

    private void MaybeRefreshLocalAddresses()
    {
        lock (_gate)
        {
            if (DateTime.UtcNow < _nextLocalRefreshUtc)
            {
                return;
            }
        }

        lock (_gate)
        {
            RefreshLocalAddressesLocked();
            _nextLocalRefreshUtc = DateTime.UtcNow.AddSeconds(30);
        }
    }

    private void RefreshLocalAddressesLocked()
    {
        _localV4.Clear();
        _localV6.Clear();

        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up
                    || nic.NetworkInterfaceType == NetworkInterfaceType.Loopback)
                {
                    continue;
                }

                foreach (var address in nic.GetIPProperties().UnicastAddresses)
                {
                    var ip = address.Address;

                    if (ip.AddressFamily == AddressFamily.InterNetwork)
                    {
                        _localV4.Add(BinaryPrimitives.ReadUInt32LittleEndian(ip.GetAddressBytes()));
                    }
                    else if (ip.AddressFamily == AddressFamily.InterNetworkV6 && !ip.IsIPv6LinkLocal)
                    {
                        var bytes = ip.GetAddressBytes();
                        _localV6.Add((
                            BinaryPrimitives.ReadUInt64LittleEndian(bytes),
                            BinaryPrimitives.ReadUInt64LittleEndian(bytes.AsSpan(8))));
                    }
                }
            }
        }
        catch (Exception)
        {
            // 枚举失败时退化为「按目的地址无法判断」，不影响采集继续。
        }
    }

    private bool IsLocalV4(ReadOnlySpan<byte> address)
    {
        if (_localV4.Count == 0)
        {
            return true;
        }

        return _localV4.Contains(BinaryPrimitives.ReadUInt32LittleEndian(address));
    }

    private bool IsLocalV6(ReadOnlySpan<byte> address)
    {
        if (_localV6.Count == 0)
        {
            return true;
        }

        return _localV6.Contains((
            BinaryPrimitives.ReadUInt64LittleEndian(address),
            BinaryPrimitives.ReadUInt64LittleEndian(address[8..])));
    }

    private static bool IsLoopback(ReadOnlySpan<byte> address)
    {
        if (address.Length == 4)
        {
            return address[0] == 127;
        }

        return address.Length == 16
               && address[..15].IndexOfAnyExcept((byte)0) < 0
               && address[15] == 1;
    }

    private static bool IsBroadcastOrMulticast(ReadOnlySpan<byte> address)
    {
        if (address.Length == 4)
        {
            return address[0] is >= 224 and <= 239 || (address[0] == 255 && address[1] == 255 && address[2] == 255 && address[3] == 255);
        }

        return address.Length == 16 && address[0] == 0xFF;
    }

    private readonly record struct ParsedPacket(
        TrafficPacket Packet,
        int FragmentBytes,
        TrafficDirection Direction);

    private bool TryParse(
        byte[] packet,
        int length,
        int linkType,
        out ParsedPacket parsed,
        out ulong dedupHash)
    {
        parsed = default;
        dedupHash = 0;

        if (length < 20)
        {
            return false;
        }

        var span = packet.AsSpan(0, length);
        var offset = 0;
        var etherType = -1;

        if (linkType == NpcapApi.DltEthernet)
        {
            if (length < 14)
            {
                return false;
            }

            etherType = (span[12] << 8) | span[13];
            offset = 14;

            while (etherType is 0x8100 or 0x88a8 or 0x9100)
            {
                if (length < offset + 4)
                {
                    return false;
                }

                etherType = (span[offset + 2] << 8) | span[offset + 3];
                offset += 4;
            }
        }
        else if (linkType == NpcapApi.DltRaw)
        {
            etherType = (span[0] >> 4) == 6 ? 0x86DD : 0x0800;
        }
        else
        {
            return false;
        }

        if (etherType == 0x0800)
        {
            if (length < offset + 20 || (span[offset] >> 4) != 4)
            {
                return false;
            }

            var ihl = (span[offset] & 0x0F) * 4;

            if (ihl < 20 || length < offset + ihl)
            {
                return false;
            }

            var totalLength = BinaryPrimitives.ReadUInt16BigEndian(span[(offset + 2)..]);

            if (totalLength < ihl)
            {
                return false;
            }

            var protocol = span[offset + 9];

            if (protocol is not (6 or 17))
            {
                return false;
            }

            var fragmentField = BinaryPrimitives.ReadUInt16BigEndian(span[(offset + 6)..]);
            var fragmentOffset = fragmentField & 0x1FFF;
            var moreFragments = (fragmentField & 0x2000) != 0;
            var source = span.Slice(offset + 12, 4);
            var destination = span.Slice(offset + 16, 4);
            var payloadBytes = totalLength - ihl;

            if (IsLoopback(source) || IsLoopback(destination))
            {
                return false;
            }

            var inbound = !IsBroadcastOrMulticast(destination) && IsLocalV4(destination);

            if (fragmentOffset != 0 || (moreFragments && length < offset + ihl + 8))
            {
                // 非首片：没有端口，记「未归属」。
                parsed = new ParsedPacket(
                    default,
                    payloadBytes,
                    inbound ? TrafficDirection.Inbound : TrafficDirection.Outbound);
                return true;
            }

            if (length < offset + ihl + 8)
            {
                return false;
            }

            var headerOffset = offset + ihl;
            var sourcePort = BinaryPrimitives.ReadUInt16BigEndian(span[headerOffset..]);
            var destinationPort = BinaryPrimitives.ReadUInt16BigEndian(span[(headerOffset + 2)..]);
            var flowProtocol = protocol == 6 ? TrafficProtocol.Tcp : TrafficProtocol.Udp;

            var local = inbound
                ? TrafficEndpoint.FromIPv4(destination, destinationPort, flowProtocol)
                : TrafficEndpoint.FromIPv4(source, sourcePort, flowProtocol);

            dedupHash = BuildHash(
                protocol,
                BinaryPrimitives.ReadUInt32LittleEndian(source),
                BinaryPrimitives.ReadUInt32LittleEndian(destination),
                sourcePort,
                destinationPort,
                totalLength,
                BinaryPrimitives.ReadUInt16BigEndian(span[(offset + 4)..]),
                protocol == 6
                    ? BinaryPrimitives.ReadUInt32BigEndian(span[(headerOffset + 4)..])
                    : BinaryPrimitives.ReadUInt16BigEndian(span[(headerOffset + 6)..]));

            parsed = new ParsedPacket(
                new TrafficPacket(
                    local,
                    inbound ? TrafficDirection.Inbound : TrafficDirection.Outbound,
                    flowProtocol,
                    payloadBytes),
                0,
                inbound ? TrafficDirection.Inbound : TrafficDirection.Outbound);

            return true;
        }

        if (etherType == 0x86DD)
        {
            if (length < offset + 40 || (span[offset] >> 4) != 6)
            {
                return false;
            }

            var payloadLength = BinaryPrimitives.ReadUInt16BigEndian(span[(offset + 4)..]);
            var nextHeader = span[offset + 6];
            var source = span.Slice(offset + 8, 16);
            var destination = span.Slice(offset + 24, 16);
            var cursor = offset + 40;

            if (IsLoopback(source) || IsLoopback(destination))
            {
                return false;
            }

            var guard = 0;

            while (nextHeader != 6 && nextHeader != 17 && guard++ < 8)
            {
                if (length < cursor + 2)
                {
                    return false;
                }

                if (nextHeader is 0 or 43 or 60)
                {
                    var headerLength = (span[cursor + 1] + 1) * 8;

                    if (length < cursor + headerLength)
                    {
                        return false;
                    }

                    nextHeader = span[cursor];
                    cursor += headerLength;
                    continue;
                }

                if (nextHeader == 44)
                {
                    var fragmentField = BinaryPrimitives.ReadUInt16BigEndian(span[(cursor + 2)..]);
                    nextHeader = span[cursor];
                    cursor += 8;

                    if ((fragmentField & 0xFFF8) != 0)
                    {
                        var inboundFragment = !IsBroadcastOrMulticast(destination) && IsLocalV6(destination);

                        parsed = new ParsedPacket(
                            default,
                            payloadLength,
                            inboundFragment
                                ? TrafficDirection.Inbound
                                : TrafficDirection.Outbound);

                        return true;
                    }

                    continue;
                }

                return false;
            }

            if (nextHeader is not (6 or 17) || length < cursor + 8)
            {
                return false;
            }

            var inbound = !IsBroadcastOrMulticast(destination) && IsLocalV6(destination);
            var sourcePort = BinaryPrimitives.ReadUInt16BigEndian(span[cursor..]);
            var destinationPort = BinaryPrimitives.ReadUInt16BigEndian(span[(cursor + 2)..]);
            var flowProtocol = nextHeader == 6 ? TrafficProtocol.Tcp : TrafficProtocol.Udp;

            var local = inbound
                ? TrafficEndpoint.FromIPv6(destination, destinationPort, flowProtocol)
                : TrafficEndpoint.FromIPv6(source, sourcePort, flowProtocol);

            var hash = BuildHash(
                nextHeader,
                BinaryPrimitives.ReadUInt64LittleEndian(source),
                BinaryPrimitives.ReadUInt64LittleEndian(destination),
                sourcePort,
                destinationPort,
                payloadLength,
                BinaryPrimitives.ReadUInt64LittleEndian(source[8..]),
                nextHeader == 6
                    ? BinaryPrimitives.ReadUInt32BigEndian(span[(cursor + 4)..])
                    : BinaryPrimitives.ReadUInt16BigEndian(span[(cursor + 6)..]));

            dedupHash = hash;

            parsed = new ParsedPacket(
                new TrafficPacket(
                    local,
                    inbound ? TrafficDirection.Inbound : TrafficDirection.Outbound,
                    flowProtocol,
                    payloadLength),
                0,
                inbound ? TrafficDirection.Inbound : TrafficDirection.Outbound);

            return true;
        }

        return false;
    }

    private static ulong BuildHash(
        int protocol,
        ulong sourceA,
        ulong destinationA,
        ushort sourcePort,
        ushort destinationPort,
        int length,
        ulong extra,
        uint discriminator)
    {
        var hash = 1469598103934665603UL;

        void Mix(ulong value)
        {
            hash ^= value;
            hash *= 1099511628211UL;
        }

        Mix((ulong)protocol);
        Mix(sourceA);
        Mix(destinationA);
        Mix(sourcePort);
        Mix(destinationPort);
        Mix((ulong)length);
        Mix(extra);
        Mix(discriminator);

        return hash;
    }

    private sealed class CaptureHandle
    {
        public CaptureHandle(string deviceName, IntPtr handle, int linkType, NpcapApi api)
        {
            DeviceName = deviceName;
            Handle = handle;
            LinkType = linkType;
            Api = api;
        }

        public string DeviceName { get; }

        public IntPtr Handle { get; }

        public int LinkType { get; }

        public NpcapApi Api { get; }
    }

    private readonly record struct PcapDevice(string Name, bool IsLoopback, bool IsUp);

    [StructLayout(LayoutKind.Sequential)]
    private struct PcapIf
    {
        public IntPtr Next;
        public IntPtr Name;
        public IntPtr Description;
        public IntPtr Addresses;
        public uint Flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct BpfProgram
    {
        public uint Length;
        public IntPtr Instructions;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PcapPacketHeader
    {
        public int TimestampSeconds;
        public int TimestampMicroseconds;
        public uint CaptureLength;
        public uint OriginalLength;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PcapStat
    {
        public uint Received;
        public uint Dropped;
        public uint InterfaceDropped;
    }

    /// <summary>wpcap.dll 导出函数（libpcap ABI，cdecl）。</summary>
    private sealed class NpcapApi
    {
        internal const int DltEthernet = 1;
        internal const int DltRaw = 12;

        private const uint PcapIfLoopback = 0x00000001;
        private const uint PcapIfUp = 0x00000002;
        private const uint PcapIfRunning = 0x00000004;

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int FindAllDevsDelegate(out IntPtr devices, byte[] errbuf);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate void FreeAllDevsDelegate(IntPtr devices);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate IntPtr OpenLiveDelegate(
            [MarshalAs(UnmanagedType.LPStr)] string device,
            int snapLength,
            int promiscuous,
            int timeoutMs,
            byte[] errbuf);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int CompileDelegate(
            IntPtr handle,
            out BpfProgram program,
            [MarshalAs(UnmanagedType.LPStr)] string filter,
            int optimize,
            uint netmask);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int SetFilterDelegate(IntPtr handle, ref BpfProgram program);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate void FreeCodeDelegate(ref BpfProgram program);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int NextExDelegate(IntPtr handle, out IntPtr header, out IntPtr data);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate void CloseDelegate(IntPtr handle);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate IntPtr GetErrorDelegate(IntPtr handle);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int DataLinkDelegate(IntPtr handle);

        [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
        private delegate int StatsDelegate(IntPtr handle, ref PcapStat stats);

        private readonly FindAllDevsDelegate _findAllDevs;
        private readonly FreeAllDevsDelegate _freeAllDevs;
        private readonly OpenLiveDelegate _openLive;
        private readonly CompileDelegate _compile;
        private readonly SetFilterDelegate _setFilter;
        private readonly FreeCodeDelegate _freeCode;
        private readonly NextExDelegate _nextEx;
        private readonly CloseDelegate _close;
        private readonly GetErrorDelegate _getError;
        private readonly DataLinkDelegate _dataLink;
        private readonly StatsDelegate _stats;

        internal NpcapApi(IntPtr library)
        {
            _findAllDevs = Load<FindAllDevsDelegate>(library, "pcap_findalldevs");
            _freeAllDevs = Load<FreeAllDevsDelegate>(library, "pcap_freealldevs");
            _openLive = Load<OpenLiveDelegate>(library, "pcap_open_live");
            _compile = Load<CompileDelegate>(library, "pcap_compile");
            _setFilter = Load<SetFilterDelegate>(library, "pcap_setfilter");
            _freeCode = Load<FreeCodeDelegate>(library, "pcap_freecode");
            _nextEx = Load<NextExDelegate>(library, "pcap_next_ex");
            _close = Load<CloseDelegate>(library, "pcap_close");
            _getError = Load<GetErrorDelegate>(library, "pcap_geterr");
            _dataLink = Load<DataLinkDelegate>(library, "pcap_datalink");
            _stats = Load<StatsDelegate>(library, "pcap_stats");
        }

        internal List<PcapDevice> FindDevices(out string? error)
        {
            error = null;
            var errbuf = new byte[512];
            var devices = new List<PcapDevice>();

            if (_findAllDevs(out var head, errbuf) != 0 || head == IntPtr.Zero)
            {
                error = ReadErr(errbuf);
                return devices;
            }

            try
            {
                var current = head;

                while (current != IntPtr.Zero)
                {
                    var item = Marshal.PtrToStructure<PcapIf>(current);
                    var name = Marshal.PtrToStringAnsi(item.Name);

                    if (!string.IsNullOrEmpty(name))
                    {
                        devices.Add(new PcapDevice(
                            name,
                            (item.Flags & PcapIfLoopback) != 0,
                            (item.Flags & (PcapIfUp | PcapIfRunning)) != 0 || item.Flags == 0));
                    }

                    current = item.Next;
                }
            }
            finally
            {
                _freeAllDevs(head);
            }

            return devices;
        }

        internal IntPtr OpenLive(string device, out string? error)
        {
            var errbuf = new byte[512];
            var handle = _openLive(device, SnapLength, 0, ReadTimeoutMs, errbuf);
            error = handle == IntPtr.Zero ? ReadErr(errbuf) : null;
            return handle;
        }

        internal bool SetFilter(IntPtr handle, out string? error)
        {
            error = null;

            if (_compile(handle, out var program, BpfFilter, 1, 0xffffffff) != 0)
            {
                error = GetError(handle);
                return false;
            }

            try
            {
                if (_setFilter(handle, ref program) != 0)
                {
                    error = GetError(handle);
                    return false;
                }
            }
            finally
            {
                _freeCode(ref program);
            }

            return true;
        }

        internal int NextPacket(IntPtr handle, out IntPtr header, out IntPtr data)
            => _nextEx(handle, out header, out data);

        internal int DataLink(IntPtr handle) => _dataLink(handle);

        internal bool TryGetStats(IntPtr handle, out PcapStat stats)
        {
            stats = default;
            return _stats(handle, ref stats) == 0;
        }

        internal string GetError(IntPtr handle)
        {
            var pointer = _getError(handle);
            return pointer == IntPtr.Zero ? string.Empty : Marshal.PtrToStringAnsi(pointer) ?? string.Empty;
        }

        internal void Close(IntPtr handle)
        {
            if (handle != IntPtr.Zero)
            {
                _close(handle);
            }
        }

        private static T Load<T>(IntPtr library, string name) where T : Delegate
            => Marshal.GetDelegateForFunctionPointer<T>(NativeLibrary.GetExport(library, name));

        private static string ReadErr(byte[] buf)
        {
            var end = Array.IndexOf(buf, (byte)0);
            var length = end < 0 ? buf.Length : end;
            return System.Text.Encoding.ASCII.GetString(buf, 0, length);
        }
    }
}
