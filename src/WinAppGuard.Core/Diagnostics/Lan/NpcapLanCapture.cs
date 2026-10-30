using System.Buffers.Binary;
using System.Net;
using System.Runtime.InteropServices;
using WinAppGuard.Core.Diagnostics.AntiScan;

namespace WinAppGuard.Core.Diagnostics.Lan;

/// <summary>
/// 4.2 / 4.3 / 4.4：ARP / DHCP / DNS / IPv6 邻接采集（独立的小会话）。
///
/// BPF：<c>arp or (udp and (port 67 or 68 or 53)) or (ip6 proto 58) or (ip6 and udp and (port 546 or 547))</c>；
/// snaplen 600；混杂模式关闭；只解析头部/选项，不保存报文。
/// </summary>
public sealed class NpcapLanCapture : IDisposable
{
    private const int SnapLength = 600;
    private const int ReadTimeoutMs = 100;
    private const string BpfFilter =
        "arp or (udp and (port 67 or 68 or 53)) or (ip6 proto 58) or (ip6 and udp and (port 546 or 547))";

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

    public Action<DnsMessage>? DnsObserved { get; set; }

    // ---- 4.4：IPv6 邻接安全 ----

    public Action<Ipv6RaMessage>? Ipv6RaObserved { get; set; }

    public Action<Ipv6NdMessage>? Ipv6NdObserved { get; set; }

    public Action<Ipv6DhcpMessage>? Ipv6DhcpObserved { get; set; }

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

        // 4.4：IPv6 / ICMPv6 / DHCPv6。
        if (etherType == 0x86DD)
        {
            ParseIpv6(span, offset, length, adapter, now, span.Slice(6, 6));
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

        if (sourcePort == 67 && destinationPort == 68)
        {
            ParseDhcp(span, udp + 8, length, adapter, now, span.Slice(offset + 12, 4), span.Slice(6, 6));
            return;
        }

        // 4.3：DNS 请求与应答都看（源/目的端口 53）。
        if (sourcePort == 53 || destinationPort == 53)
        {
            ParseDns(
                span,
                udp + 8,
                length,
                adapter,
                now,
                span.Slice(offset + 12, 4),
                span.Slice(offset + 16, 4),
                sourcePort,
                destinationPort,
                span.Slice(6, 6));
        }
    }

    /// <summary>4.3：解析 DNS 头、问题段与 A/AAAA/CNAME，交给分析器。</summary>
    private void ParseDns(
        ReadOnlySpan<byte> span,
        int offset,
        int length,
        string adapter,
        DateTime now,
        ReadOnlySpan<byte> sourceAddress,
        ReadOnlySpan<byte> destinationAddress,
        ushort sourcePort,
        ushort destinationPort,
        ReadOnlySpan<byte> ethernetSource)
    {
        if (offset >= length)
        {
            return;
        }

        var payload = span[offset..length];

        if (TryParseDnsPayload(
                payload,
                now,
                adapter,
                sourceAddress,
                destinationAddress,
                sourcePort,
                destinationPort,
                ethernetSource,
                out var message))
        {
            DnsObserved?.Invoke(message);
        }
    }

    /// <summary>
    /// 4.3：从一段 DNS 载荷（不含 UDP 头）解析请求/应答。
    /// 公开为静态方法，便于离线自检用合成字节覆盖压缩指针等边界。
    /// </summary>
    public static bool TryParseDnsPayload(
        ReadOnlySpan<byte> payload,
        DateTime timeUtc,
        string adapter,
        ReadOnlySpan<byte> sourceAddress,
        ReadOnlySpan<byte> destinationAddress,
        ushort sourcePort,
        ushort destinationPort,
        ReadOnlySpan<byte> ethernetSource,
        out DnsMessage message)
    {
        message = default;
        var length = payload.Length;

        if (length < 12)
        {
            return false;
        }

        const int baseOffset = 0;
        var transactionId = BinaryPrimitives.ReadUInt16BigEndian(payload);
        var flags = BinaryPrimitives.ReadUInt16BigEndian(payload[2..]);
        var questionCount = BinaryPrimitives.ReadUInt16BigEndian(payload[4..]);
        var answerCount = BinaryPrimitives.ReadUInt16BigEndian(payload[6..]);
        var isResponse = (flags & 0x8000) != 0;
        var responseCode = flags & 0x000F;
        var truncated = (flags & 0x0200) != 0;

        if (questionCount is 0 or > 4 || answerCount > 64)
        {
            return false;
        }

        var cursor = 12;

        if (!TryReadDnsName(payload, cursor, length, out var questionName, out cursor, baseOffset)
            || cursor + 4 > length)
        {
            return false;
        }

        var questionType = BinaryPrimitives.ReadUInt16BigEndian(payload[cursor..]);
        cursor += 4;

        var answers = new List<DnsAnswer>(Math.Min((int)answerCount, 8));

        for (var i = 0; i < answerCount && answers.Count < 16; i++)
        {
            if (!TryReadDnsName(payload, cursor, length, out var answerName, out cursor, baseOffset)
                || cursor + 10 > length)
            {
                truncated = true;
                break;
            }

            var type = BinaryPrimitives.ReadUInt16BigEndian(payload[cursor..]);
            var ttl = BinaryPrimitives.ReadUInt32BigEndian(payload[(cursor + 4)..]);
            var dataLength = BinaryPrimitives.ReadUInt16BigEndian(payload[(cursor + 8)..]);
            cursor += 10;

            if (dataLength == 0 || cursor + dataLength > length)
            {
                truncated = true;
                break;
            }

            string? value = type switch
            {
                1 when dataLength == 4 => new IPAddress(payload.Slice(cursor, 4)).ToString(),
                28 when dataLength == 16 => new IPAddress(payload.Slice(cursor, 16)).ToString(),
                5 => TryReadDnsName(payload, cursor, length, out var cname, out _, baseOffset)
                    ? cname
                    : null,
                _ => null,
            };

            if (value is not null)
            {
                answers.Add(new DnsAnswer(answerName, type, ttl, value));
            }

            cursor += dataLength;
        }

        var clientAddress = isResponse ? destinationAddress : sourceAddress;
        var serverAddress = isResponse ? sourceAddress : destinationAddress;
        var clientPort = isResponse ? destinationPort : sourcePort;

        message = new DnsMessage(
            timeUtc,
            adapter,
            new IPAddress(clientAddress).ToString(),
            clientPort,
            new IPAddress(serverAddress).ToString(),
            isResponse,
            transactionId,
            questionName,
            questionType,
            responseCode,
            LanEnvironment.FormatMac(ethernetSource),
            answers,
            truncated);

        return true;
    }

    /// <summary>读取 DNS 名称（支持压缩指针），返回下一个字段的偏移。</summary>
    /// <param name="baseOffset">DNS 报文头在帧里的起始偏移；压缩指针相对它计算。</param>
    private static bool TryReadDnsName(
        ReadOnlySpan<byte> span,
        int offset,
        int limit,
        out string name,
        out int nextOffset,
        int baseOffset)
    {
        name = string.Empty;
        nextOffset = offset;
        var labels = new List<string>(4);
        var cursor = offset;
        var jumped = false;
        var guard = 0;

        while (cursor < limit)
        {
            var lengthByte = span[cursor];

            if (lengthByte == 0)
            {
                cursor++;

                if (!jumped)
                {
                    nextOffset = cursor;
                }

                name = labels.Count == 0 ? "." : string.Join(".", labels);
                return true;
            }

            if ((lengthByte & 0xC0) == 0xC0)
            {
                if (cursor + 1 >= limit || guard++ > 8)
                {
                    return false;
                }

                if (!jumped)
                {
                    nextOffset = cursor + 2;
                }

                // 指针值相对 DNS 报文头，而不是整帧。
                cursor = baseOffset + (((lengthByte & 0x3F) << 8) | span[cursor + 1]);
                jumped = true;
                continue;
            }

            if ((lengthByte & 0xC0) != 0 || cursor + 1 + lengthByte > limit)
            {
                return false;
            }

            labels.Add(System.Text.Encoding.ASCII.GetString(span.Slice(cursor + 1, lengthByte)));
            cursor += lengthByte + 1;

            if (!jumped)
            {
                nextOffset = cursor;
            }
        }

        return false;
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

    // ==================================================================
    // 4.4：IPv6 / ICMPv6 / DHCPv6
    // ==================================================================

    private void ParseIpv6(
        ReadOnlySpan<byte> span,
        int offset,
        int length,
        string adapter,
        DateTime now,
        ReadOnlySpan<byte> ethernetSource)
    {
        if (length < offset + 40 || (span[offset] >> 4) != 6)
        {
            return;
        }

        var payloadLength = BinaryPrimitives.ReadUInt16BigEndian(span[(offset + 4)..]);
        var nextHeader = span[offset + 6];
        var hopLimit = span[offset + 7];
        var sourceAddress = new IPAddress(span.Slice(offset + 8, 16)).ToString();
        var destinationAddress = new IPAddress(span.Slice(offset + 24, 16)).ToString();
        var sourceMac = LanEnvironment.FormatMac(ethernetSource);
        var cursor = offset + 40;
        var limit = Math.Min(length, offset + 40 + payloadLength);

        if (limit < cursor)
        {
            return;
        }

        var guard = 0;

        while (true)
        {
            if (nextHeader == 58)
            {
                ParseIcmpv6(
                    span, cursor, limit, adapter, now, sourceAddress, destinationAddress,
                    hopLimit, sourceMac);
                return;
            }

            if (nextHeader == 17)
            {
                ParseUdp6(
                    span, cursor, limit, adapter, now, sourceAddress, destinationAddress, sourceMac);
                return;
            }

            // Hop-by-Hop / Routing / Destination Options
            if (nextHeader is 0 or 43 or 60)
            {
                if (cursor + 2 > limit || guard++ > 8)
                {
                    return;
                }

                var optionLength = (span[cursor + 1] + 1) * 8;

                if (optionLength < 8 || cursor + optionLength > limit)
                {
                    return;
                }

                nextHeader = span[cursor];
                cursor += optionLength;
                continue;
            }

            // Fragment：只看首片；非首片没有上层头。
            if (nextHeader == 44)
            {
                if (cursor + 8 > limit)
                {
                    return;
                }

                var fragmentOffset = BinaryPrimitives.ReadUInt16BigEndian(span[(cursor + 2)..]) & 0xFFF8;

                if (fragmentOffset != 0)
                {
                    return;
                }

                nextHeader = span[cursor];
                cursor += 8;
                continue;
            }

            // AH
            if (nextHeader == 51)
            {
                if (cursor + 2 > limit)
                {
                    return;
                }

                var ahLength = (span[cursor + 1] + 2) * 4;

                if (cursor + ahLength > limit)
                {
                    return;
                }

                nextHeader = span[cursor];
                cursor += ahLength;
                continue;
            }

            // ESP / 其他无法解析的上层协议。
            return;
        }
    }

    private void ParseUdp6(
        ReadOnlySpan<byte> span,
        int offset,
        int length,
        string adapter,
        DateTime now,
        string sourceAddress,
        string destinationAddress,
        string? sourceMac)
    {
        if (length < offset + 8)
        {
            return;
        }

        var sourcePort = BinaryPrimitives.ReadUInt16BigEndian(span[offset..]);
        var destinationPort = BinaryPrimitives.ReadUInt16BigEndian(span[(offset + 2)..]);

        if ((sourcePort != 547 && sourcePort != 546)
            || (destinationPort != 547 && destinationPort != 546))
        {
            return;
        }

        if (TryParseDhcpv6Payload(
                span[(offset + 8)..length],
                now,
                adapter,
                sourceAddress,
                destinationAddress,
                sourcePort,
                destinationPort,
                sourceMac,
                out var message))
        {
            Ipv6DhcpObserved?.Invoke(message);
        }
    }

    private void ParseIcmpv6(
        ReadOnlySpan<byte> span,
        int offset,
        int length,
        string adapter,
        DateTime now,
        string sourceAddress,
        string destinationAddress,
        byte hopLimit,
        string? sourceMac)
    {
        if (length < offset + 4)
        {
            return;
        }

        var type = span[offset];
        var payload = span[offset..length];

        if (type == 134
            && TryParseRaPayload(
                payload, now, adapter, sourceAddress, destinationAddress, hopLimit, sourceMac,
                out var ra))
        {
            Ipv6RaObserved?.Invoke(ra);
            return;
        }

        if (type is 135 or 136 or 137
            && TryParseNdPayload(
                payload, now, adapter, sourceAddress, destinationAddress, sourceMac, out var nd))
        {
            Ipv6NdObserved?.Invoke(nd);
        }
    }

    /// <summary>4.4：解析 RA 载荷（不含 IPv6 头），供离线自检使用。</summary>
    public static bool TryParseRaPayload(
        ReadOnlySpan<byte> payload,
        DateTime timeUtc,
        string adapter,
        string sourceAddress,
        string destinationAddress,
        byte hopLimit,
        string? sourceMac,
        out Ipv6RaMessage message)
    {
        message = null!;

        if (payload.Length < 16 || payload[0] != 134)
        {
            return false;
        }

        var flags = payload[5];
        var routerLifetime = BinaryPrimitives.ReadUInt16BigEndian(payload[6..]);
        var reachableTime = BinaryPrimitives.ReadUInt32BigEndian(payload[8..]);
        var retransTimer = BinaryPrimitives.ReadUInt32BigEndian(payload[12..]);
        var prefixes = new List<Ipv6PrefixInfo>();
        var routes = new List<Ipv6RouteInfo>();
        var dnsServers = new List<string>();
        var dnsDomains = new List<string>();
        uint mtu = 0;
        var cursor = 16;

        while (cursor + 2 <= payload.Length)
        {
            var type = payload[cursor];
            var totalLength = payload[cursor + 1] * 8;

            if (totalLength < 2 || cursor + totalLength > payload.Length)
            {
                break;
            }

            var data = payload.Slice(cursor + 2, totalLength - 2);

            switch (type)
            {
                case 3 when data.Length >= 30:
                    prefixes.Add(new Ipv6PrefixInfo
                    {
                        PrefixLength = data[0],
                        OnLink = (data[1] & 0x80) != 0,
                        Autonomous = (data[1] & 0x40) != 0,
                        ValidLifetime = BinaryPrimitives.ReadUInt32BigEndian(data[2..]),
                        PreferredLifetime = BinaryPrimitives.ReadUInt32BigEndian(data[6..]),
                        Prefix = FormatPrefix(data[14..30]),
                    });
                    break;

                case 5 when data.Length >= 6:
                    mtu = BinaryPrimitives.ReadUInt32BigEndian(data[2..]);
                    break;

                case 24 when data.Length >= 6:
                    routes.Add(new Ipv6RouteInfo
                    {
                        PrefixLength = data[0],
                        RouteLifetime = BinaryPrimitives.ReadUInt32BigEndian(data[2..]),
                        Prefix = FormatPrefix(data[6..]),
                    });
                    break;

                case 25 when data.Length >= 6:
                    for (var i = 6; i + 16 <= data.Length; i += 16)
                    {
                        dnsServers.Add(new IPAddress(data.Slice(i, 16)).ToString());
                    }

                    break;

                case 31 when data.Length > 6:
                    ReadDnsNames(data[6..], dnsDomains);
                    break;
            }

            cursor += totalLength;
        }

        message = new Ipv6RaMessage
        {
            TimeUtc = timeUtc,
            Adapter = adapter,
            SourceAddress = sourceAddress,
            DestinationAddress = destinationAddress,
            SourceMac = sourceMac,
            HopLimit = hopLimit,
            Managed = (flags & 0x80) != 0,
            Other = (flags & 0x40) != 0,
            HomeAgent = (flags & 0x20) != 0,
            RouterLifetime = routerLifetime,
            ReachableTime = reachableTime,
            RetransTimer = retransTimer,
            Mtu = mtu,
            Prefixes = prefixes,
            Routes = routes,
            DnsServers = dnsServers,
            DnsDomains = dnsDomains,
        };

        return true;
    }

    /// <summary>4.4：解析 NS / NA / Redirect 载荷，供离线自检使用。</summary>
    public static bool TryParseNdPayload(
        ReadOnlySpan<byte> payload,
        DateTime timeUtc,
        string adapter,
        string sourceAddress,
        string destinationAddress,
        string? sourceMac,
        out Ipv6NdMessage message)
    {
        message = null!;

        if (payload.Length < 24)
        {
            return false;
        }

        var type = payload[0];

        if (type is not (135 or 136 or 137))
        {
            return false;
        }

        var target = new IPAddress(payload.Slice(8, 16)).ToString();
        string? targetMac = null;
        string? redirectTarget = null;
        var optionOffset = 24;

        if (type == 136)
        {
            var flags = payload[4];
            ReadLinkLayerOption(payload, optionOffset, out targetMac);

            message = new Ipv6NdMessage
            {
                TimeUtc = timeUtc,
                Adapter = adapter,
                Type = type,
                SourceAddress = sourceAddress,
                DestinationAddress = destinationAddress,
                SourceMac = sourceMac,
                TargetAddress = target,
                TargetMac = targetMac,
                Router = (flags & 0x80) != 0,
                Solicited = (flags & 0x40) != 0,
                Override = (flags & 0x20) != 0,
            };

            return true;
        }

        if (type == 137)
        {
            if (payload.Length < 40)
            {
                return false;
            }

            redirectTarget = new IPAddress(payload.Slice(24, 16)).ToString();
            optionOffset = 40;
            ReadLinkLayerOption(payload, optionOffset, out targetMac);

            message = new Ipv6NdMessage
            {
                TimeUtc = timeUtc,
                Adapter = adapter,
                Type = type,
                SourceAddress = sourceAddress,
                DestinationAddress = destinationAddress,
                SourceMac = sourceMac,
                TargetAddress = target,
                TargetMac = targetMac,
                RedirectTarget = redirectTarget,
            };

            return true;
        }

        // NS
        ReadLinkLayerOption(payload, optionOffset, out targetMac);

        message = new Ipv6NdMessage
        {
            TimeUtc = timeUtc,
            Adapter = adapter,
            Type = type,
            SourceAddress = sourceAddress,
            DestinationAddress = destinationAddress,
            SourceMac = sourceMac,
            TargetAddress = target,
            TargetMac = targetMac,
        };

        return true;
    }

    /// <summary>4.4：解析 DHCPv6 载荷（不含 UDP 头），供离线自检使用。</summary>
    public static bool TryParseDhcpv6Payload(
        ReadOnlySpan<byte> payload,
        DateTime timeUtc,
        string adapter,
        string sourceAddress,
        string destinationAddress,
        ushort sourcePort,
        ushort destinationPort,
        string? sourceMac,
        out Ipv6DhcpMessage message)
    {
        message = null!;

        if (payload.Length < 4)
        {
            return false;
        }

        string? serverId = null;
        string? clientId = null;
        var dnsServers = new List<string>();
        var domains = new List<string>();
        var iaAddresses = new List<Ipv6IaInfo>();
        var minPreferred = uint.MaxValue;
        var minValid = uint.MaxValue;
        var cursor = 4;

        while (cursor + 4 <= payload.Length)
        {
            var code = BinaryPrimitives.ReadUInt16BigEndian(payload[cursor..]);
            var length = BinaryPrimitives.ReadUInt16BigEndian(payload[(cursor + 2)..]);
            cursor += 4;

            if (cursor + length > payload.Length)
            {
                break;
            }

            var data = payload.Slice(cursor, length);

            switch (code)
            {
                case 1:
                    clientId = ToHex(data);
                    break;

                case 2:
                    serverId = ToHex(data);
                    break;

                case 23:
                    for (var i = 0; i + 16 <= data.Length; i += 16)
                    {
                        dnsServers.Add(new IPAddress(data.Slice(i, 16)).ToString());
                    }

                    break;

                case 24:
                    ReadDnsNames(data, domains);
                    break;

                case 3:
                    ParseIaNa(data, iaAddresses, ref minPreferred, ref minValid);
                    break;

                case 25:
                    ParseIaPd(data, iaAddresses, ref minPreferred, ref minValid);
                    break;
            }

            cursor += length;
        }

        message = new Ipv6DhcpMessage
        {
            TimeUtc = timeUtc,
            Adapter = adapter,
            ServerToClient = sourcePort == 547 && destinationPort == 546,
            SourceAddress = sourceAddress,
            DestinationAddress = destinationAddress,
            SourcePort = sourcePort,
            DestinationPort = destinationPort,
            SourceMac = sourceMac,
            MessageType = payload[0],
            ServerId = serverId,
            ClientId = clientId,
            DnsServers = dnsServers,
            Domains = domains,
            IaAddresses = iaAddresses,
            MinPreferredLifetime = iaAddresses.Count == 0 ? 0 : minPreferred,
            MinValidLifetime = iaAddresses.Count == 0 ? 0 : minValid,
        };

        return true;
    }

    private static void ParseIaNa(
        ReadOnlySpan<byte> data,
        List<Ipv6IaInfo> addresses,
        ref uint minPreferred,
        ref uint minValid)
    {
        if (data.Length < 12)
        {
            return;
        }

        var cursor = 12;

        while (cursor + 4 <= data.Length)
        {
            var code = BinaryPrimitives.ReadUInt16BigEndian(data[cursor..]);
            var length = BinaryPrimitives.ReadUInt16BigEndian(data[(cursor + 2)..]);
            cursor += 4;

            if (cursor + length > data.Length)
            {
                return;
            }

            if (code == 5 && length >= 24)
            {
                var preferred = BinaryPrimitives.ReadUInt32BigEndian(data[(cursor + 16)..]);
                var valid = BinaryPrimitives.ReadUInt32BigEndian(data[(cursor + 20)..]);
                addresses.Add(new Ipv6IaInfo
                {
                    Address = new IPAddress(data.Slice(cursor, 16)).ToString(),
                    PrefixLength = 128,
                    PreferredLifetime = preferred,
                    ValidLifetime = valid,
                });
                minPreferred = Math.Min(minPreferred, preferred);
                minValid = Math.Min(minValid, valid);
            }

            cursor += length;
        }
    }

    private static void ParseIaPd(
        ReadOnlySpan<byte> data,
        List<Ipv6IaInfo> addresses,
        ref uint minPreferred,
        ref uint minValid)
    {
        if (data.Length < 12)
        {
            return;
        }

        var cursor = 12;

        while (cursor + 4 <= data.Length)
        {
            var code = BinaryPrimitives.ReadUInt16BigEndian(data[cursor..]);
            var length = BinaryPrimitives.ReadUInt16BigEndian(data[(cursor + 2)..]);
            cursor += 4;

            if (cursor + length > data.Length)
            {
                return;
            }

            if (code == 26 && length >= 25)
            {
                var preferred = BinaryPrimitives.ReadUInt32BigEndian(data[cursor..]);
                var valid = BinaryPrimitives.ReadUInt32BigEndian(data[(cursor + 4)..]);
                var prefixLength = data[cursor + 8];
                addresses.Add(new Ipv6IaInfo
                {
                    Address = FormatPrefix(data.Slice(cursor + 9, 16)),
                    PrefixLength = prefixLength,
                    PreferredLifetime = preferred,
                    ValidLifetime = valid,
                });
                minPreferred = Math.Min(minPreferred, preferred);
                minValid = Math.Min(minValid, valid);
            }

            cursor += length;
        }
    }

    private static void ReadLinkLayerOption(
        ReadOnlySpan<byte> payload,
        int offset,
        out string? mac)
    {
        mac = null;
        var cursor = offset;

        while (cursor + 2 <= payload.Length)
        {
            var type = payload[cursor];
            var totalLength = payload[cursor + 1] * 8;

            if (totalLength < 2 || cursor + totalLength > payload.Length)
            {
                return;
            }

            if ((type is 1 or 2) && totalLength >= 8)
            {
                mac = LanEnvironment.FormatMac(payload.Slice(cursor + 2, 6));
                return;
            }

            cursor += totalLength;
        }
    }

    private static void ReadDnsNames(ReadOnlySpan<byte> data, List<string> names)
    {
        var cursor = 0;

        while (cursor < data.Length && names.Count < 8)
        {
            if (data[cursor] == 0)
            {
                cursor++;
                continue;
            }

            var labels = new List<string>();

            while (cursor < data.Length)
            {
                var length = data[cursor++];

                if (length == 0)
                {
                    break;
                }

                if ((length & 0xC0) != 0 || cursor + length > data.Length)
                {
                    return;
                }

                labels.Add(System.Text.Encoding.ASCII.GetString(data.Slice(cursor, length)));
                cursor += length;
            }

            if (labels.Count > 0)
            {
                names.Add(string.Join(".", labels));
            }
        }
    }

    private static string FormatPrefix(ReadOnlySpan<byte> bytes)
    {
        Span<byte> full = stackalloc byte[16];
        var count = Math.Min(bytes.Length, 16);
        bytes[..count].CopyTo(full);
        return new IPAddress(full).ToString();
    }

    private static string? ToHex(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length == 0)
        {
            return null;
        }

        return Convert.ToHexString(bytes[..Math.Min(bytes.Length, 64)]);
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
