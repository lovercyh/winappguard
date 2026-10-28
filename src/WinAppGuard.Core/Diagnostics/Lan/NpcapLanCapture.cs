using System.Buffers.Binary;
using System.Net;
using System.Runtime.InteropServices;
using WinAppGuard.Core.Diagnostics.AntiScan;

namespace WinAppGuard.Core.Diagnostics.Lan;

/// <summary>
/// 4.2：ARP / DHCP 采集（独立的小会话）。
///
/// BPF：<c>arp or (udp and (port 67 or 68))</c>；snaplen 600（DHCP options）；
/// 混杂模式关闭；只解析 ARP 与 DHCP 的头部/选项，不保存报文。
/// </summary>
public sealed class NpcapLanCapture : IDisposable
{
    private const int SnapLength = 600;
    private const int ReadTimeoutMs = 100;
    private const string BpfFilter = "arp or (udp and (port 67 or 68))";

    private readonly object _gate = new();
    private readonly List<CaptureHandle> _captures = new();

    private IntPtr _library;
    private bool _running;
    private int _activeThreads;
    private long _packets;
    private long _dropped;
    private string? _lastError;

    public Action<ArpFrame>? ArpObserved { get; set; }

    public Action<DhcpMessage>? DhcpObserved { get; set; }

    public Action<string>? Log { get; set; }

    public bool IsRunning
    {
        get { lock (_gate) { return _running && Volatile.Read(ref _activeThreads) > 0; } }
    }

    public long PacketsSeen => Interlocked.Read(ref _packets);

    public long DroppedPackets
    {
        get { lock (_gate) { return _dropped; } }
    }

    public string? LastError
    {
        get { lock (_gate) { return _lastError; } }
    }

    /// <summary>当前纳入检测的网卡（描述）。</summary>
    public List<string> Adapters
    {
        get { lock (_gate) { return _captures.Select(item => item.Adapter).Distinct().ToList(); } }
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

                    var adapter = LanEnvironment.MapDeviceToAdapter(device.Name) ?? device.Description ?? device.Name;

                    if (LanEnvironment.IsExcludedDescription(adapter))
                    {
                        Log?.Invoke($"局域网检测跳过虚拟网卡：{adapter}");
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
                        Log?.Invoke($"Npcap 设置 ARP/DHCP 过滤器失败：{device.Name}（{filterError}）");
                        api.Close(handle);
                        continue;
                    }

                    _captures.Add(new CaptureHandle(adapter, handle, api.DataLink(handle), api));
                    opened++;
                }

                if (opened == 0)
                {
                    _lastError = "没有可用于局域网检测的网卡。";
                    CleanupLocked();
                    return false;
                }

                _running = true;
                Volatile.Write(ref _activeThreads, opened);

                foreach (var capture in _captures)
                {
                    var thread = new Thread(() => CaptureLoop(capture))
                    {
                        IsBackground = true,
                        Name = "WinAppGuard-Lan",
                    };

                    thread.Start();
                }

                Log?.Invoke($"局域网检测已启动：{opened} 张网卡。");
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
            Log?.Invoke("局域网检测已停止。");
        }
    }

    public void Dispose() => Stop();

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

    private void CaptureLoop(CaptureHandle capture)
    {
        var buffer = new byte[SnapLength];

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
                        _lastError = string.IsNullOrWhiteSpace(error) ? "Npcap 采集失败。" : error;
                    }

                    Log?.Invoke($"局域网采集失败：{capture.Adapter}（{error}）");
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
                    Interlocked.Increment(ref _packets);

                    Parse(buffer, length, capture.LinkType, capture.Adapter);
                }
                catch (Exception ex)
                {
                    Log?.Invoke($"局域网报文解析失败：{ex.Message}");
                }
            }
        }
        finally
        {
            Interlocked.Decrement(ref _activeThreads);
        }
    }

    private void Parse(byte[] packet, int length, int linkType, string adapter)
    {
        var span = packet.AsSpan(0, length);
        var offset = 0;
        var etherType = -1;

        if (linkType == NpcapApi.DltEthernet)
        {
            if (length < 14)
            {
                return;
            }

            etherType = (span[12] << 8) | span[13];
            offset = 14;

            while (etherType is 0x8100 or 0x88a8 or 0x9100)
            {
                if (length < offset + 4)
                {
                    return;
                }

                etherType = (span[offset + 2] << 8) | span[offset + 3];
                offset += 4;
            }
        }
        else
        {
            return;
        }

        var now = DateTime.UtcNow;

        if (etherType == 0x0806)
        {
            ParseArp(span, offset, length, adapter, now, span.Slice(6, 6));
            return;
        }

        if (etherType != 0x0800 || length < offset + 20)
        {
            return;
        }

        var ihl = (span[offset] & 0x0F) * 4;

        if ((span[offset] >> 4) != 4 || ihl < 20 || length < offset + ihl)
        {
            return;
        }

        if (span[offset + 9] != 17)
        {
            return;
        }

        var fragment = BinaryPrimitives.ReadUInt16BigEndian(span[(offset + 6)..]) & 0x1FFF;

        if (fragment != 0)
        {
            return;
        }

        var udp = offset + ihl;

        if (length < udp + 8)
        {
            return;
        }

        var sourcePort = BinaryPrimitives.ReadUInt16BigEndian(span[udp..]);
        var destinationPort = BinaryPrimitives.ReadUInt16BigEndian(span[(udp + 2)..]);

        // 只看服务器 → 客户端的 DHCP 应答。
        if (sourcePort != 67 || destinationPort != 68)
        {
            return;
        }

        ParseDhcp(span, udp + 8, length, adapter, now, span.Slice(offset + 12, 4), span.Slice(6, 6));
    }

    private void ParseArp(
        ReadOnlySpan<byte> span,
        int offset,
        int length,
        string adapter,
        DateTime now,
        ReadOnlySpan<byte> ethernetSource)
    {
        // ARP: htype(2) ptype(2) hlen(1) plen(1) op(2) sha(6) spa(4) tha(6) tpa(4)
        if (length < offset + 28)
        {
            return;
        }

        var hardwareLength = span[offset + 4];
        var protocolLength = span[offset + 5];

        if (hardwareLength != 6 || protocolLength != 4)
        {
            return;
        }

        var operation = BinaryPrimitives.ReadUInt16BigEndian(span[(offset + 6)..]);
        var senderMac = LanEnvironment.FormatMac(span.Slice(offset + 8, 6));
        var senderIp = new IPAddress(span.Slice(offset + 14, 4)).ToString();
        var targetIp = new IPAddress(span.Slice(offset + 24, 4)).ToString();

        ArpObserved?.Invoke(new ArpFrame(
            now,
            adapter,
            LanEnvironment.FormatMac(ethernetSource),
            senderMac,
            senderIp,
            targetIp,
            IsReply: operation == 2,
            IsGratuitous: string.Equals(senderIp, targetIp, StringComparison.Ordinal)));
    }

    private void ParseDhcp(
        ReadOnlySpan<byte> span,
        int offset,
        int length,
        string adapter,
        DateTime now,
        ReadOnlySpan<byte> serverAddress,
        ReadOnlySpan<byte> ethernetSource)
    {
        // BOOTP 固定头 236 字节 + magic cookie 4 字节。
        if (length < offset + 240 || span[offset] != 2)
        {
            return;
        }

        if (BinaryPrimitives.ReadUInt32BigEndian(span[(offset + 236)..]) != 0x63825363)
        {
            return;
        }

        var serverIp = new IPAddress(serverAddress).ToString();
        string? router = null;
        string? dns = null;
        var lease = 0;
        var messageType = 0;

        var cursor = offset + 240;

        while (cursor + 1 < length)
        {
            var code = span[cursor++];

            if (code == 0)
            {
                continue;
            }

            if (code == 255)
            {
                break;
            }

            if (cursor >= length)
            {
                break;
            }

            var size = span[cursor++];

            if (size == 0 || cursor + size > length)
            {
                break;
            }

            var value = span.Slice(cursor, size);

            switch (code)
            {
                case 53 when size >= 1:
                    messageType = value[0];
                    break;
                case 54 when size >= 4:
                    serverIp = new IPAddress(value[..4]).ToString();
                    break;
                case 3 when size >= 4:
                    router = new IPAddress(value[..4]).ToString();
                    break;
                case 6 when size >= 4:
                    dns = new IPAddress(value[..4]).ToString();
                    break;
                case 51 when size >= 4:
                    lease = (int)BinaryPrimitives.ReadUInt32BigEndian(value[..4]);
                    break;
            }

            cursor += size;
        }

        // 只关心 OFFER(2) / ACK(5)。
        if (messageType is not (2 or 5))
        {
            return;
        }

        DhcpObserved?.Invoke(new DhcpMessage(
            now,
            adapter,
            LanEnvironment.FormatMac(ethernetSource),
            serverIp,
            router,
            dns,
            lease,
            IsOffer: messageType == 2));
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

    private sealed class CaptureHandle
    {
        public CaptureHandle(string adapter, IntPtr handle, int linkType, NpcapApi api)
        {
            Adapter = adapter;
            Handle = handle;
            LinkType = linkType;
            Api = api;
        }

        public string Adapter { get; }

        public IntPtr Handle { get; }

        public int LinkType { get; }

        public NpcapApi Api { get; }
    }

    private readonly record struct PcapDevice(string Name, string? Description, bool IsLoopback, bool IsUp);

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

    private sealed class NpcapApi
    {
        internal const int DltEthernet = 1;

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
                    var description = item.Description == IntPtr.Zero
                        ? null
                        : Marshal.PtrToStringAnsi(item.Description);

                    if (!string.IsNullOrEmpty(name))
                    {
                        devices.Add(new PcapDevice(
                            name,
                            description,
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
