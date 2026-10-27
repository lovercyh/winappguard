using System.Diagnostics;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace WinAppGuard.Core.Diagnostics.AntiScan;

/// <summary>
/// 4.0：Npcap 入站 SYN 采集。
///
/// 只做三件事：
///   - 用 libpcap API 打开活动网卡；
///   - BPF 只保留 TCP SYN（不含 SYN-ACK）；
///   - 解析 IPv4/IPv6 + TCP 头，把入站 SYN 交给反扫描分析器。
///
/// 不读载荷、不做 DPI、不修改/注入数据包。Npcap 驱动由用户安装，本程序不随包复制驱动文件。
/// </summary>
public sealed class NpcapCapture : IDisposable
{
    private const int SnapLength = 128;
    private const int ReadTimeoutMs = 100;
    private const string BpfFilter =
        "tcp and (tcp[tcpflags] & tcp-syn) != 0 and (tcp[tcpflags] & tcp-ack) == 0";

    private readonly object _gate = new();
    private readonly List<CaptureHandle> _captures = new();
    private readonly Dictionary<string, DateTime> _dedup = new(StringComparer.Ordinal);
    private readonly HashSet<string> _localAddresses = new(StringComparer.OrdinalIgnoreCase);
    private IntPtr _library;
    private bool _running;
    private DateTime _nextLocalRefreshUtc = DateTime.MinValue;
    private long _eventsSeen;
    private int _activeThreads;
    private string? _lastError;

    public Action<InboundSyn>? SynObserved { get; set; }

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

    public long EventsSeen => Interlocked.Read(ref _eventsSeen);

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

                // 所有采集线程都退出了：关掉旧句柄和库，重新开始。
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

                    if (!api.SetSynFilter(handle, out var filterError))
                    {
                        Log?.Invoke($"Npcap 设置 SYN 过滤器失败：{device.Name}（{filterError}）");
                        api.Close(handle);
                        continue;
                    }

                    var linkType = api.DataLink(handle);
                    var capture = new CaptureHandle(device.Name, handle, linkType, api);
                    _captures.Add(capture);
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
                        Name = "WinAppGuard-AntiScan",
                    };
                    thread.Start();
                }

                Log?.Invoke($"反扫描采集已启动：{opened} 张网卡，Npcap {NpcapLocator.GetVersion(wpcapPath)}。");
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

        // 等线程退出再关句柄，避免 pcap_next_ex 访问已释放的 pcap_t。
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
            Log?.Invoke("反扫描采集已停止。");
        }
    }

    private void CaptureLoop(CaptureHandle capture)
    {
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

                    Log?.Invoke($"Npcap 采集失败：{capture.DeviceName}（{error}）");
                    break;
                }

                try
                {
                    var packetHeader = Marshal.PtrToStructure<PcapPacketHeader>(header);

                    if (packetHeader.CaptureLength == 0 || packetHeader.CaptureLength > int.MaxValue)
                    {
                        continue;
                    }

                    var length = (int)Math.Min(packetHeader.CaptureLength, 65535);
                    var packet = new byte[length];
                    Marshal.Copy(data, packet, 0, length);
                    Interlocked.Increment(ref _eventsSeen);

                    if (TryParseInboundSyn(packet, capture.LinkType, out var syn))
                    {
                        SynObserved?.Invoke(syn);
                    }
                }
                catch (Exception ex)
                {
                    Log?.Invoke($"Npcap 解析数据包失败：{ex.Message}");
                }
            }
        }
        finally
        {
            Interlocked.Decrement(ref _activeThreads);
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
        _localAddresses.Clear();

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

                    if (ip.AddressFamily is AddressFamily.InterNetwork or AddressFamily.InterNetworkV6
                        && !IPAddress.IsLoopback(ip)
                        && !ip.Equals(IPAddress.Any)
                        && !ip.Equals(IPAddress.IPv6Any))
                    {
                        _localAddresses.Add(ip.ToString());
                    }
                }
            }
        }
        catch (Exception)
        {
            // 网络接口枚举失败不影响采集；空集合时退化为只按 loopback/组播过滤。
        }
    }

    private bool TryParseInboundSyn(byte[] packet, int linkType, out InboundSyn syn)
    {
        syn = default;

        var offset = 0;
        var etherType = -1;

        if (linkType == NpcapApi.DltEthernet)
        {
            if (packet.Length < 14)
            {
                return false;
            }

            etherType = (packet[12] << 8) | packet[13];
            offset = 14;

            // 802.1Q / QinQ
            while (etherType is 0x8100 or 0x88a8 or 0x9100)
            {
                if (packet.Length < offset + 4)
                {
                    return false;
                }

                etherType = (packet[offset + 2] << 8) | packet[offset + 3];
                offset += 4;
            }
        }
        else if (linkType == NpcapApi.DltRaw)
        {
            if (packet.Length < 1)
            {
                return false;
            }

            etherType = (packet[0] >> 4) == 6 ? 0x86DD : 0x0800;
        }
        else
        {
            return false;
        }

        IPAddress source;
        IPAddress destination;
        var tcpOffset = 0;

        if (etherType == 0x0800)
        {
            if (packet.Length < offset + 20)
            {
                return false;
            }

            var ihl = (packet[offset] & 0x0f) * 4;

            if ((packet[offset] >> 4) != 4 || ihl < 20 || packet.Length < offset + ihl)
            {
                return false;
            }

            if (packet[offset + 9] != 6)
            {
                return false;
            }

            var fragment = ((packet[offset + 6] & 0x1f) << 8) | packet[offset + 7];

            if (fragment != 0)
            {
                return false;
            }

            source = new IPAddress(packet.AsSpan(offset + 12, 4));
            destination = new IPAddress(packet.AsSpan(offset + 16, 4));
            tcpOffset = offset + ihl;
        }
        else if (etherType == 0x86DD)
        {
            if (packet.Length < offset + 40 || (packet[offset] >> 4) != 6)
            {
                return false;
            }

            var nextHeader = packet[offset + 6];
            source = new IPAddress(packet.AsSpan(offset + 8, 16));
            destination = new IPAddress(packet.AsSpan(offset + 24, 16));
            tcpOffset = offset + 40;

            // 跳过常见 IPv6 扩展头，直到 TCP。
            var guard = 0;

            while (nextHeader != 6 && guard++ < 8)
            {
                if (nextHeader is 0 or 43 or 60)
                {
                    if (packet.Length < tcpOffset + 2)
                    {
                        return false;
                    }

                    var headerLength = (packet[tcpOffset + 1] + 1) * 8;
                    nextHeader = packet[tcpOffset];

                    if (headerLength < 8 || packet.Length < tcpOffset + headerLength)
                    {
                        return false;
                    }

                    tcpOffset += headerLength;
                }
                else if (nextHeader == 44)
                {
                    if (packet.Length < tcpOffset + 8)
                    {
                        return false;
                    }

                    var fragmentOffset = ((packet[tcpOffset + 2] << 8) | packet[tcpOffset + 3]) >> 3;

                    if (fragmentOffset != 0)
                    {
                        return false;
                    }

                    nextHeader = packet[tcpOffset];
                    tcpOffset += 8;
                }
                else
                {
                    return false;
                }
            }

            if (nextHeader != 6)
            {
                return false;
            }
        }
        else
        {
            return false;
        }

        if (packet.Length < tcpOffset + 20)
        {
            return false;
        }

        var tcpHeaderLength = (packet[tcpOffset + 12] >> 4) * 4;

        if (tcpHeaderLength < 20 || packet.Length < tcpOffset + tcpHeaderLength)
        {
            return false;
        }

        var flags = packet[tcpOffset + 13];

        if ((flags & 0x02) == 0 || (flags & 0x10) != 0)
        {
            return false;
        }

        if (!IsInbound(destination))
        {
            return false;
        }

        var sourcePort = (ushort)((packet[tcpOffset] << 8) | packet[tcpOffset + 1]);
        var destinationPort = (ushort)((packet[tcpOffset + 2] << 8) | packet[tcpOffset + 3]);
        var sequence = (uint)((packet[tcpOffset + 4] << 24)
                              | (packet[tcpOffset + 5] << 16)
                              | (packet[tcpOffset + 6] << 8)
                              | packet[tcpOffset + 7]);

        var dedupKey = $"{source}|{sourcePort}|{destination}|{destinationPort}|{sequence}";
        var now = DateTime.UtcNow;

        lock (_gate)
        {
            if (_dedup.TryGetValue(dedupKey, out var seen) && now - seen < TimeSpan.FromSeconds(2))
            {
                return false;
            }

            _dedup[dedupKey] = now;

            if (_dedup.Count > 4096)
            {
                foreach (var pair in _dedup.Where(pair => now - pair.Value > TimeSpan.FromSeconds(5))
                             .Select(pair => pair.Key).ToList())
                {
                    _dedup.Remove(pair);
                }
            }
        }

        syn = new InboundSyn(now, source, sourcePort, destination, destinationPort);
        return true;
    }

    private bool IsInbound(IPAddress destination)
    {
        if (IPAddress.IsLoopback(destination))
        {
            return false;
        }

        lock (_gate)
        {
            // 地址集合为空时（网络枚举失败）不因为这一项丢掉所有包。
            return _localAddresses.Count == 0 || _localAddresses.Contains(destination.ToString());
        }
    }

    public void Dispose() => Stop();

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
        public long TimestampSeconds;
        public long TimestampMicroseconds;
        public uint CaptureLength;
        public uint OriginalLength;
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
        }

        internal List<PcapDevice> FindDevices(out string? error)
        {
            error = null;
            var errbuf = new byte[512];
            var devices = new List<PcapDevice>();

            if (_findAllDevs(out var head, errbuf) != 0 || head == IntPtr.Zero)
            {
                error = ReadErr(buf: errbuf);
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

        internal bool SetSynFilter(IntPtr handle, out string? error)
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
