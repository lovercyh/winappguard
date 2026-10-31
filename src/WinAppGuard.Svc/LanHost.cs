using WinAppGuard.Contracts;
using WinAppGuard.Core;
using WinAppGuard.Core.Diagnostics.AntiScan;
using WinAppGuard.Core.Diagnostics.Lan;
using WinAppGuard.Core.Wfp;

namespace WinAppGuard.Service;

/// <summary>
/// 4.2：局域网欺骗检测宿主（ARP + 虚假 DHCP）。
///
/// 采集是独立的第三份 Npcap 会话（只抓 ARP / DHCP），默认只告警。
/// 基线、信任、事件与临时阻断全部落盘；DHCP 阻断默认关闭，且只拦该服务器的 DHCP 应答。
/// </summary>
internal static class LanHost
{
    private static readonly object Gate = new();

    private static readonly TimeSpan TickInterval = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan StatsInterval = TimeSpan.FromSeconds(5);
    private static readonly TimeSpan HintsInterval = TimeSpan.FromSeconds(60);
    private static readonly TimeSpan SaveInterval = TimeSpan.FromSeconds(5);

    private static LanAnalyzer? _analyzer;
    private static DnsAnalyzer? _dnsAnalyzer;
    private static Ipv6Analyzer? _ipv6Analyzer;
    private static NpcapLanCapture? _capture;
    private static LanEventStore? _eventStore;
    private static LanEventStore? _ipv6EventStore;
    private static Ipv6BlockRegistry? _ipv6Blocks;
    private static System.Threading.Timer? _timer;
    private static bool _started;
    private static bool _dirty;
    private static bool _saving;
    private static DateTime _nextStatsUtc = DateTime.MinValue;
    private static DateTime _nextHintsUtc = DateTime.MinValue;
    private static DateTime _nextSaveUtc = DateTime.MinValue;
    private static DateTime _nextPruneUtc = DateTime.MinValue;
    private static string? _lastError;
    private static int _eventCount;
    private static int _dnsEventCount;
    private static int _ipv6EventCount;

    internal static bool Collecting
    {
        get { lock (Gate) { return _capture?.IsRunning == true; } }
    }

    internal static bool BaselineReady
    {
        get { lock (Gate) { return _analyzer?.BaselineReady == true; } }
    }

    internal static int EventCount
    {
        get { lock (Gate) { return _eventCount; } }
    }

    internal static int BlockedCount
    {
        get { lock (Gate) { return _analyzer?.Blocks.Count ?? 0; } }
    }

    internal static void Start()
    {
        LanState state = LanStateStore.Load(ServicePaths.LanStateFile);
        var analyzer = new LanAnalyzer(state, DateTime.UtcNow);
        var eventStore = new LanEventStore(ServicePaths.LanDirectory);

        analyzer.EventObserved = item => OnEvent(item);
        analyzer.StateChanged = () =>
        {
            lock (Gate)
            {
                _dirty = true;
            }
        };

        // 4.3：DNS 分析与局域网共用同一个状态文件、事件文件和采集会话。
        var dnsAnalyzer = new DnsAnalyzer(state, DateTime.UtcNow);
        dnsAnalyzer.EventObserved = item => OnEvent(item);
        dnsAnalyzer.StateChanged = () =>
        {
            lock (Gate)
            {
                _dirty = true;
            }
        };
        dnsAnalyzer.UpdateConfiguredServers(LanEnvironment.GetDnsHints());

        // 4.4：IPv6 邻接安全，独立状态/事件目录，复用同一个 Npcap 会话。
        var ipv6State = Ipv6StateStore.Load(ServicePaths.Ipv6StateFile);
        var ipv6Analyzer = new Ipv6Analyzer(ipv6State, DateTime.UtcNow);
        var ipv6EventStore = new LanEventStore(ServicePaths.Ipv6Directory);
        ipv6Analyzer.EventObserved = item => OnEvent(item);
        ipv6Analyzer.StateChanged = () =>
        {
            lock (Gate)
            {
                _dirty = true;
            }
        };
        ipv6Analyzer.SeedEvents(ipv6EventStore.ReadRecent(200));
        ipv6Analyzer.UpdateLocalAddresses(LanEnvironment.GetLocalIpv6Addresses());

        // 历史事件读回内存，重启后仍能在页面里看到。
        analyzer.SeedEvents(eventStore.ReadRecent(200));
        analyzer.UpdateGatewayHints(LanEnvironment.GetGatewayHints());
        dnsAnalyzer.UpdateGatewayBaselines(analyzer.Gateways);

        // 上次运行留下的过滤器不能直接信任：先清掉，再按状态文件恢复。
        try
        {
            var removed = LanWfp.RemoveAll();

            if (removed > 0)
            {
                ServiceLog.Operation("WAG-LAN-001", $"Removed {removed} stale DHCP block filter(s).");
            }
        }
        catch (Exception ex)
        {
            ServiceLog.Warning("WAG-LAN-002", "Failed to clean stale DHCP block filters.", ex);
        }

        // 4.4：IPv6 阻断过滤器同样不能跨重启信任：非持久过滤器不会随进程退出消失，
        // 服务崩溃时可能留下旧的阻断。先全部清掉，再由本次运行重新登记。
        try
        {
            var removed = Ipv6Wfp.RemoveAll();

            if (removed > 0)
            {
                ServiceLog.Operation("WAG-LAN-026", $"Removed {removed} stale IPv6 block filter(s).");
            }
        }
        catch (Exception ex)
        {
            ServiceLog.Warning("WAG-LAN-027", "Failed to clean stale IPv6 block filters.", ex);
        }

        // 阻断登记册只在内存里：服务重启即解除，和"临时阻断 10 分钟"的语义一致。
        var ipv6Blocks = new Ipv6BlockRegistry();

        if (!state.Settings.DhcpBlockEnabled && state.Blocks.Count > 0)
        {
            state.Blocks.Clear();
        }
        foreach (var block in state.Blocks.ToList())
        {
            try
            {
                LanWfp.Add(System.Net.IPAddress.Parse(block.ServerIp));
            }
            catch (Exception ex)
            {
                ServiceLog.Warning("WAG-LAN-003", $"Failed to restore DHCP block for {block.ServerIp}.", ex);
                state.Blocks.Remove(block);
            }
        }

        lock (Gate)
        {
            _analyzer = analyzer;
            _dnsAnalyzer = dnsAnalyzer;
            _ipv6Analyzer = ipv6Analyzer;
            _eventStore = eventStore;
            _ipv6EventStore = ipv6EventStore;
            _ipv6Blocks = ipv6Blocks;
            _started = true;
            _dirty = true;
            _eventCount = analyzer.Snapshot().Events.Count;
            _dnsEventCount = dnsAnalyzer.EventCount;
            _ipv6EventCount = ipv6Analyzer.EventCount;
            _lastError = null;
        }

        eventStore.Prune(state.Settings.RetentionDays, DateTime.UtcNow);
        ipv6EventStore.Prune(state.Settings.RetentionDays, DateTime.UtcNow);
        SaveState();
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
            "WAG-LAN-004",
            $"LAN detection started (retention={state.Settings.RetentionDays}d, " +
            $"dhcpBlock={state.Settings.DhcpBlockEnabled}, blocks={state.Blocks.Count}).");
    }

    internal static void Stop()
    {
        NpcapLanCapture? capture;

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

        SaveState();

        try
        {
            LanWfp.RemoveAll();
        }
        catch (Exception ex)
        {
            ServiceLog.Warning("WAG-LAN-005", "Failed to remove DHCP block filters on stop.", ex);
        }

        Ipv6BlockRegistry? ipv6Blocks;

        lock (Gate)
        {
            ipv6Blocks = _ipv6Blocks;
            _ipv6Blocks = null;
        }

        try
        {
            ipv6Blocks?.Dispose();
        }
        catch (Exception ex)
        {
            ServiceLog.Warning("WAG-LAN-028", "Failed to release IPv6 block filters on stop.", ex);
        }

        lock (Gate)
        {
            _analyzer = null;
            _dnsAnalyzer = null;
            _ipv6Analyzer = null;
            _eventStore = null;
            _ipv6EventStore = null;
        }

        ServiceLog.Info("WAG-LAN-006", "LAN detection stopped.");
    }

    internal static ServiceResponse Query(ServiceRequest request)
    {
        LanAnalyzer? analyzer;
        NpcapLanCapture? capture;
        LanEventStore? eventStore;

        lock (Gate)
        {
            analyzer = _analyzer;
            capture = _capture;
            eventStore = _eventStore;
        }

        if (analyzer is null)
        {
            return new ServiceResponse
            {
                Id = request.Id,
                Ok = true,
                LanStatus = new LanStatusDto
                {
                    Collecting = false,
                    BaselineReady = false,
                    NpcapVersion = NpcapLocator.GetVersion(),
                    LastError = "局域网检测未启动。",
                },
                LanEvents = new List<LanEventDto>(),
                LanGateways = new List<LanGatewayDto>(),
                LanDhcpServers = new List<LanDhcpServerDto>(),
                LanBlocks = new List<LanBlockDto>(),
                LanSettings = new LanSettingsDto(),
            };
        }

        var snapshot = analyzer.Snapshot();
        var history = eventStore?.ReadRecent(400) ?? new List<LanEvent>();

        // 内存里的是本次运行的新事件；历史从磁盘补齐，按时间倒序去重。
        // 4.3 起 DNS 事件与 ARP/DHCP 共用文件，这里先过滤，避免挤占局域网列表。
        var events = snapshot.Events
            .Where(item => !item.Kind.StartsWith("dns_", StringComparison.OrdinalIgnoreCase))
            .Concat(history.Where(item => !item.Kind.StartsWith("dns_", StringComparison.OrdinalIgnoreCase)))
            .GroupBy(item => item.Id, StringComparer.Ordinal)
            .Select(group => group.First())
            .OrderByDescending(item => item.TimeUtc)
            .Take(200)
            .ToList();

        lock (Gate)
        {
            _eventCount = events.Count;
        }

        return new ServiceResponse
        {
            Id = request.Id,
            Ok = true,
            LanStatus = new LanStatusDto
            {
                Collecting = capture?.IsRunning == true,
                Adapters = capture?.Adapters ?? new List<string>(),
                BaselineReady = snapshot.BaselineReady,
                BaselineUtc = snapshot.BaselineUtc,
                GatewayCount = snapshot.Gateways.Count,
                DhcpServerCount = snapshot.DhcpServers.Count,
                EventCount = events.Count,
                BlockedCount = snapshot.Blocks.Count,
                NpcapVersion = NpcapLocator.GetVersion(),
                LastError = capture?.LastError,
            },
            LanEvents = events.Select(ToDto).ToList(),
            LanGateways = snapshot.Gateways.Select(ToDto).ToList(),
            LanDhcpServers = snapshot.DhcpServers.Select(ToDto).ToList(),
            LanBlocks = snapshot.Blocks.Select(ToDto).ToList(),
            LanSettings = ToDto(analyzer.Settings),
        };
    }

    internal static ServiceResponse Configure(ServiceRequest request)
    {
        var dto = request.LanSettings;

        if (dto is null)
        {
            return Error(request, "缺少局域网设置。");
        }

        LanAnalyzer? analyzer;

        lock (Gate)
        {
            analyzer = _analyzer;
        }

        if (analyzer is null)
        {
            return Error(request, "局域网检测未启动。");
        }

        var wasBlockEnabled = analyzer.Settings.DhcpBlockEnabled;
        analyzer.ApplySettings(new LanSettings
        {
            RetentionDays = dto.RetentionDays,
            DhcpBlockEnabled = dto.DhcpBlockEnabled,
        });

        if (wasBlockEnabled && !dto.DhcpBlockEnabled)
        {
            ReleaseAllBlocks(analyzer);
        }

        SaveState();
        ServiceLog.Operation(
            "WAG-LAN-007",
            $"LAN detection configured (retention={dto.RetentionDays}d, dhcpBlock={dto.DhcpBlockEnabled}).");

        return Query(request);
    }

    internal static ServiceResponse Clear(ServiceRequest request)
    {
        LanAnalyzer? analyzer;
        LanEventStore? store;

        lock (Gate)
        {
            analyzer = _analyzer;
            store = _eventStore;
        }

        if (analyzer is null)
        {
            return Error(request, "局域网检测未启动。");
        }

        var released = ReleaseAllBlocks(analyzer);
        analyzer.ClearEvents();
        store?.ClearWhere(kind => !kind.StartsWith("dns_", StringComparison.OrdinalIgnoreCase));

        lock (Gate)
        {
            _eventCount = 0;
            _dirty = true;
        }

        ServiceLog.Operation(
            "WAG-LAN-008",
            $"LAN events cleared; {released} DHCP block(s) released.");

        return Query(request);
    }

    internal static ServiceResponse Trust(ServiceRequest request)
    {
        LanAnalyzer? analyzer;

        lock (Gate)
        {
            analyzer = _analyzer;
        }

        if (analyzer is null)
        {
            return Error(request, "局域网检测未启动。");
        }

        var kind = request.LanTrustKind;
        var value = request.LanTrustValue;

        if (string.IsNullOrWhiteSpace(kind) || string.IsNullOrWhiteSpace(value))
        {
            return Error(request, "缺少信任类型或目标。");
        }

        if (!analyzer.Trust(kind, value.Trim(), DateTime.UtcNow))
        {
            return Error(request, "找不到要信任的网关或 DHCP 服务器。");
        }

        SaveState();
        ServiceLog.Operation("WAG-LAN-009", $"Trusted {kind} {value}.");
        return Query(request);
    }

    internal static ServiceResponse ResetBaseline(ServiceRequest request)
    {
        LanAnalyzer? analyzer;

        lock (Gate)
        {
            analyzer = _analyzer;
        }

        if (analyzer is null)
        {
            return Error(request, "局域网检测未启动。");
        }

        analyzer.ResetBaseline(DateTime.UtcNow);
        SaveState();
        ServiceLog.Operation("WAG-LAN-010", "LAN baseline reset; learning again.");

        return Query(request);
    }

    internal static ServiceResponse Block(ServiceRequest request)
    {
        LanAnalyzer? analyzer;
        var ip = request.LanBlockServerIp;

        if (string.IsNullOrWhiteSpace(ip) || !System.Net.IPAddress.TryParse(ip.Trim(), out var address))
        {
            return Error(request, "缺少或非法的 DHCP 服务器 IP。");
        }

        lock (Gate)
        {
            analyzer = _analyzer;
        }

        if (analyzer is null)
        {
            return Error(request, "局域网检测未启动。");
        }

        if (request.LanBlockEnabled)
        {
            if (!analyzer.Settings.DhcpBlockEnabled)
            {
                return Error(request, "DHCP 阻断总开关未开启。");
            }

            try
            {
                LanWfp.Add(address);
            }
            catch (Exception ex)
            {
                ServiceLog.Warning("WAG-LAN-011", $"Failed to block DHCP server {ip}.", ex);
                return Error(request, $"阻断失败：{ex.Message}");
            }

            analyzer.AddBlock(
                address.ToString(),
                DateTime.UtcNow,
                "manual DHCP block",
                eventId: null);

            ServiceLog.Operation("WAG-LAN-012", $"DHCP server {ip} blocked for 10 minutes.");
        }
        else
        {
            try
            {
                LanWfp.Remove(address);
            }
            catch (Exception ex)
            {
                ServiceLog.Warning("WAG-LAN-013", $"Failed to unblock DHCP server {ip}.", ex);
            }

            analyzer.RemoveBlock(address.ToString());
            ServiceLog.Operation("WAG-LAN-014", $"DHCP server {ip} unblocked.");
        }

        SaveState();
        return Query(request);
    }

    internal static ServiceResponse QueryDns(ServiceRequest request)
    {
        DnsAnalyzer? dns;
        NpcapLanCapture? capture;
        LanEventStore? store;

        lock (Gate)
        {
            dns = _dnsAnalyzer;
            capture = _capture;
            store = _eventStore;
        }

        if (dns is null)
        {
            return new ServiceResponse
            {
                Id = request.Id,
                Ok = true,
                DnsSecurityStatus = new DnsSecurityStatusDto
                {
                    Collecting = false,
                    BaselineReady = false,
                    NpcapVersion = NpcapLocator.GetVersion(),
                    LastError = "DNS 安全检测未启动。",
                },
                DnsSecurityServers = new List<DnsSecurityServerDto>(),
                DnsSecurityEvents = new List<LanEventDto>(),
            };
        }

        var snapshot = dns.Snapshot();
        var history = store?.ReadRecent(200, "dns_") ?? new List<LanEvent>();

        var events = snapshot.Events
            .Concat(history)
            .GroupBy(item => item.Id, StringComparer.Ordinal)
            .Select(group => group.First())
            .OrderByDescending(item => item.TimeUtc)
            .Take(200)
            .ToList();

        lock (Gate)
        {
            _dnsEventCount = events.Count;
        }

        return new ServiceResponse
        {
            Id = request.Id,
            Ok = true,
            DnsSecurityStatus = new DnsSecurityStatusDto
            {
                Collecting = capture?.IsRunning == true,
                BaselineReady = snapshot.BaselineReady,
                BaselineUtc = snapshot.BaselineUtc,
                ConfiguredCount = snapshot.ConfiguredCount,
                EventCount = events.Count,
                NpcapVersion = NpcapLocator.GetVersion(),
                LastError = capture?.LastError,
            },
            DnsSecurityServers = snapshot.Servers.Select(ToDto).ToList(),
            DnsSecurityEvents = events.Select(ToDto).ToList(),
        };
    }

    internal static ServiceResponse ClearDns(ServiceRequest request)
    {
        DnsAnalyzer? dns;
        LanEventStore? store;

        lock (Gate)
        {
            dns = _dnsAnalyzer;
            store = _eventStore;
        }

        if (dns is null)
        {
            return Error(request, "DNS 安全检测未启动。");
        }

        dns.ClearEvents();
        store?.ClearKinds("dns_");

        lock (Gate)
        {
            _dnsEventCount = 0;
            _dirty = true;
        }

        ServiceLog.Operation("WAG-LAN-021", "DNS security events cleared.");
        return QueryDns(request);
    }

    internal static ServiceResponse TrustDns(ServiceRequest request)
    {
        DnsAnalyzer? dns;
        var address = request.DnsTrustAddress;

        if (string.IsNullOrWhiteSpace(address))
        {
            return Error(request, "缺少 DNS 服务器地址。");
        }

        lock (Gate)
        {
            dns = _dnsAnalyzer;
        }

        if (dns is null)
        {
            return Error(request, "DNS 安全检测未启动。");
        }

        if (!dns.Trust(address.Trim(), request.DnsTrustEnabled, DateTime.UtcNow))
        {
            return Error(request, "DNS 服务器地址不合法。");
        }

        SaveState();
        ServiceLog.Operation(
            "WAG-LAN-022",
            $"DNS server {address} {(request.DnsTrustEnabled ? "trusted" : "untrusted")}.");
        return QueryDns(request);
    }

    internal static ServiceResponse QueryIpv6(ServiceRequest request)
    {
        Ipv6Analyzer? ipv6;
        NpcapLanCapture? capture;
        LanEventStore? store;
        Ipv6BlockRegistry? blocks;

        lock (Gate)
        {
            ipv6 = _ipv6Analyzer;
            capture = _capture;
            store = _ipv6EventStore;
            blocks = _ipv6Blocks;
        }

        if (ipv6 is null)
        {
            return new ServiceResponse
            {
                Id = request.Id,
                Ok = true,
                Ipv6SecurityStatus = new Ipv6SecurityStatusDto
                {
                    Collecting = false,
                    BaselineReady = false,
                    NpcapVersion = NpcapLocator.GetVersion(),
                    LastError = "IPv6 邻接安全检测未启动。",
                },
                Ipv6Routers = new List<Ipv6RouterDto>(),
                Ipv6DhcpServers = new List<Ipv6DhcpServerDto>(),
                Ipv6Neighbors = new List<Ipv6NeighborDto>(),
                Ipv6SecurityEvents = new List<LanEventDto>(),
            };
        }

        var snapshot = ipv6.Snapshot();
        var history = store?.ReadRecent(200) ?? new List<LanEvent>();
        var trustedRouters = ipv6.TrustedRouters.ToHashSet(StringComparer.OrdinalIgnoreCase);
        var trustedDhcp = ipv6.TrustedDhcpServers.ToHashSet(StringComparer.OrdinalIgnoreCase);

        var events = snapshot.Events
            .Concat(history)
            .GroupBy(item => item.Id, StringComparer.Ordinal)
            .Select(group => group.First())
            .OrderByDescending(item => item.TimeUtc)
            .Take(200)
            .ToList();

        lock (Gate)
        {
            _ipv6EventCount = events.Count;
        }

        return new ServiceResponse
        {
            Id = request.Id,
            Ok = true,
            Ipv6SecurityStatus = new Ipv6SecurityStatusDto
            {
                Collecting = capture?.IsRunning == true,
                BaselineReady = snapshot.BaselineReady,
                BaselineUtc = snapshot.BaselineUtc,
                EventCount = events.Count,
                RouterCount = snapshot.Routers.Count,
                DhcpServerCount = snapshot.DhcpServers.Count,
                NeighborCount = snapshot.Neighbors.Count,
                BlockedCount = blocks?.Count ?? 0,
                NpcapVersion = NpcapLocator.GetVersion(),
                LastError = capture?.LastError,
            },
            Ipv6Routers = snapshot.Routers.Select(item => ToDto(item, trustedRouters)).ToList(),
            Ipv6DhcpServers = snapshot.DhcpServers
                .Select(item => ToDto(item, trustedDhcp, blocks))
                .ToList(),
            Ipv6Neighbors = snapshot.Neighbors.Select(ToDto).ToList(),
            Ipv6SecurityEvents = events.Select(ToDto).ToList(),
        };
    }

    internal static ServiceResponse ClearIpv6(ServiceRequest request)
    {
        Ipv6Analyzer? ipv6;
        LanEventStore? store;

        lock (Gate)
        {
            ipv6 = _ipv6Analyzer;
            store = _ipv6EventStore;
        }

        if (ipv6 is null)
        {
            return Error(request, "IPv6 邻接安全检测未启动。");
        }

        ipv6.ClearEvents();
        store?.Clear();

        lock (Gate)
        {
            _ipv6EventCount = 0;
            _dirty = true;
        }

        ServiceLog.Operation("WAG-LAN-023", "IPv6 security events cleared.");
        return QueryIpv6(request);
    }

    internal static ServiceResponse TrustIpv6(ServiceRequest request)
    {
        Ipv6Analyzer? ipv6;
        Ipv6BlockRegistry? blocks;
        var kind = request.Ipv6TrustKind;
        var value = request.Ipv6TrustValue;
        var mac = request.Ipv6TrustMac;

        if (string.IsNullOrWhiteSpace(kind) || string.IsNullOrWhiteSpace(value))
        {
            return Error(request, "缺少 IPv6 信任类型或目标。");
        }

        lock (Gate)
        {
            ipv6 = _ipv6Analyzer;
            blocks = _ipv6Blocks;
        }

        if (ipv6 is null)
        {
            return Error(request, "IPv6 邻接安全检测未启动。");
        }

        var ok = string.Equals(kind, "router", StringComparison.OrdinalIgnoreCase)
            ? ipv6.TrustRouter(value.Trim(), mac ?? string.Empty, request.Ipv6TrustEnabled, DateTime.UtcNow)
            : string.Equals(kind, "dhcpv6", StringComparison.OrdinalIgnoreCase)
                ? ipv6.TrustDhcp(value.Trim(), mac, request.Ipv6TrustEnabled, DateTime.UtcNow)
                : false;

        if (!ok)
        {
            return Error(request, "IPv6 信任目标不合法。");
        }

        // 信任一个 DHCPv6 服务器时顺手解除它的临时阻断，避免"已信任但还在拦"的矛盾状态。
        if (request.Ipv6TrustEnabled
            && string.Equals(kind, "dhcpv6", StringComparison.OrdinalIgnoreCase)
            && blocks is not null)
        {
            var server = ipv6.Snapshot().DhcpServers.FirstOrDefault(item =>
                string.Equals(item.ServerId, value.Trim(), StringComparison.OrdinalIgnoreCase));

            if (server is not null && blocks.Release(server.Address))
            {
                ServiceLog.Operation(
                    "WAG-LAN-032",
                    $"IPv6 block released for trusted DHCPv6 {server.Address}.");
            }
        }

        SaveState();
        ServiceLog.Operation(
            "WAG-LAN-024",
            $"IPv6 {kind} {value} {(request.Ipv6TrustEnabled ? "trusted" : "untrusted")}.");
        return QueryIpv6(request);
    }

    internal static ServiceResponse BlockIpv6(ServiceRequest request)
    {
        Ipv6Analyzer? ipv6;
        Ipv6BlockRegistry? blocks;
        var addressText = request.Ipv6BlockAddress;

        if (string.IsNullOrWhiteSpace(addressText)
            || !System.Net.IPAddress.TryParse(addressText.Trim(), out var address)
            || address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6)
        {
            return Error(request, "缺少或非法的 IPv6 服务器地址。");
        }

        if (System.Net.IPAddress.IsLoopback(address)
            || address.Equals(System.Net.IPAddress.IPv6Any)
            || address.IsIPv6Multicast)
        {
            return Error(request, "不能阻断回环 / 组播 / 未指定地址。");
        }

        lock (Gate)
        {
            ipv6 = _ipv6Analyzer;
            blocks = _ipv6Blocks;
        }

        if (ipv6 is null || blocks is null)
        {
            return Error(request, "IPv6 邻接安全检测未启动。");
        }

        var text = address.ToString();
        var kind = string.IsNullOrWhiteSpace(request.Ipv6BlockKind)
            ? Ipv6BlockRegistry.DhcpKind
            : request.Ipv6BlockKind.Trim().ToLowerInvariant();

        if (!request.Ipv6BlockEnabled)
        {
            if (!blocks.Release(text))
            {
                return Error(request, "该地址没有正在生效的临时阻断。");
            }

            ServiceLog.Operation("WAG-LAN-030", $"IPv6 block released for {text}.");
            return QueryIpv6(request);
        }

        if (!string.Equals(kind, Ipv6BlockRegistry.DhcpKind, StringComparison.Ordinal))
        {
            return Error(request, "RA 阻断尚未通过 POC，当前只告警。");
        }

        // 只允许阻断当前确实检测到的 DHCPv6 服务器：IPC 不能被用来封任意地址。
        var server = ipv6.Snapshot().DhcpServers.FirstOrDefault(
            item => string.Equals(item.Address, text, StringComparison.OrdinalIgnoreCase));

        if (server is null)
        {
            return Error(request, "该地址不是当前检测到的 DHCPv6 服务器。");
        }

        if (ipv6.TrustedDhcpServers.Contains(
                Ipv6TrustKeys.Dhcp(server.ServerId, server.Mac), StringComparer.OrdinalIgnoreCase))
        {
            return Error(request, "该 DHCPv6 服务器已信任；请先取消信任再阻断。");
        }

        if (!blocks.TryBlock(kind, address, request.Ipv6BlockMinutes, out var scope, out var blockError))
        {
            return Error(request, blockError);
        }

        var minutes = Math.Clamp(request.Ipv6BlockMinutes, 1, Ipv6BlockRegistry.MaxMinutes);
        ServiceLog.Operation(
            "WAG-LAN-029",
            $"IPv6 DHCPv6 block for {text} ({scope}), {minutes} min.");
        return QueryIpv6(request);
    }

    internal static ServiceResponse ResetIpv6Baseline(ServiceRequest request)
    {
        Ipv6Analyzer? ipv6;

        lock (Gate)
        {
            ipv6 = _ipv6Analyzer;
        }

        if (ipv6 is null)
        {
            return Error(request, "IPv6 邻接安全检测未启动。");
        }

        ipv6.ResetBaseline(DateTime.UtcNow);
        SaveState();
        ServiceLog.Operation("WAG-LAN-025", "IPv6 baseline reset; learning again.");
        return QueryIpv6(request);
    }

    internal static LanStatusDto GetStatus()
    {
        lock (Gate)
        {
            return new LanStatusDto
            {
                Collecting = _capture?.IsRunning == true,
                Adapters = _capture?.Adapters ?? new List<string>(),
                BaselineReady = _analyzer?.BaselineReady == true,
                EventCount = _eventCount,
                BlockedCount = _analyzer?.Blocks.Count ?? 0,
                DnsSecurityCollecting = _capture?.IsRunning == true && _dnsAnalyzer is not null,
                DnsSecurityEventCount = _dnsEventCount,
                Ipv6SecurityCollecting = _capture?.IsRunning == true && _ipv6Analyzer is not null,
                Ipv6SecurityEventCount = _ipv6EventCount,
                NpcapVersion = NpcapLocator.GetVersion(),
                LastError = _lastError ?? _capture?.LastError,
            };
        }
    }

    private static void Tick()
    {
        try
        {
            EnsureCapture();

            var now = DateTime.UtcNow;
            LanAnalyzer? analyzer;
            NpcapLanCapture? capture;
            DnsAnalyzer? dns;
            Ipv6Analyzer? ipv6;
            Ipv6BlockRegistry? ipv6Blocks;

            lock (Gate)
            {
                if (!_started)
                {
                    return;
                }

                analyzer = _analyzer;
                capture = _capture;
                dns = _dnsAnalyzer;
                ipv6 = _ipv6Analyzer;
                ipv6Blocks = _ipv6Blocks;
            }

            if (analyzer is null)
            {
                return;
            }

            // DNS 规则要用网关 MAC 判断“DNS 服务器非网关”，这里每秒同步一次副本。
            dns?.UpdateGatewayBaselines(analyzer.Gateways);

            // 没有 IPv6 流量时也要让 5 分钟基线按时结束。
            ipv6?.Tick(now);

            if (capture is not null && now >= _nextStatsUtc)
            {
                capture.RefreshStatistics();
                _nextStatsUtc = now.Add(StatsInterval);
            }

            if (now >= _nextHintsUtc)
            {
                analyzer.UpdateGatewayHints(LanEnvironment.GetGatewayHints());
                dns?.UpdateConfiguredServers(LanEnvironment.GetDnsHints());
                ipv6?.UpdateLocalAddresses(LanEnvironment.GetLocalIpv6Addresses());

                _nextHintsUtc = now.Add(HintsInterval);
            }

            // 到期的 DHCP 阻断要同时删过滤器和状态。
            var before = analyzer.Blocks;

            if (analyzer.PruneBlocks(now) > 0)
            {
                var after = analyzer.Blocks
                    .Select(item => item.ServerIp)
                    .ToHashSet(StringComparer.OrdinalIgnoreCase);

                foreach (var block in before.Where(item => !after.Contains(item.ServerIp)))
                {
                    try
                    {
                        if (System.Net.IPAddress.TryParse(block.ServerIp, out var address))
                        {
                            LanWfp.Remove(address);
                        }
                    }
                    catch (Exception)
                    {
                        // 删失败下次启动再清。
                    }
                }

                ServiceLog.Operation("WAG-LAN-015", "Expired DHCP block(s) released.");
            }

            // 4.4：到期的 IPv6 临时阻断。
            if (ipv6Blocks is not null)
            {
                var expired = ipv6Blocks.Prune(now);

                if (expired.Count > 0)
                {
                    ServiceLog.Operation(
                        "WAG-LAN-031",
                        $"Expired IPv6 block(s) released: {string.Join(", ", expired)}.");
                }
            }

            if (now >= _nextPruneUtc)
            {
                var settings = analyzer.Settings;
                _eventStore?.Prune(settings.RetentionDays, now);
                _ipv6EventStore?.Prune(settings.RetentionDays, now);
                _nextPruneUtc = now.AddHours(6);
            }

            lock (Gate)
            {
                if (_dirty && now >= _nextSaveUtc)
                {
                    _nextSaveUtc = now.Add(SaveInterval);
                    _dirty = false;
                    _saving = true;
                }
            }

            if (_saving)
            {
                SaveState();
                _saving = false;
            }
        }
        catch (Exception ex)
        {
            ServiceLog.Warning("WAG-LAN-016", "LAN detection tick failed.", ex);
        }
    }

    private static void OnEvent(LanEvent item)
    {
        LanEventStore? store;
        var isDns = item.Kind.StartsWith("dns_", StringComparison.OrdinalIgnoreCase);
        var isIpv6 = item.Kind.StartsWith("ipv6_", StringComparison.OrdinalIgnoreCase);

        lock (Gate)
        {
            store = isIpv6 ? _ipv6EventStore : _eventStore;
            _dirty = true;

            if (isIpv6)
            {
                _ipv6EventCount = Math.Min(_ipv6EventCount + 1, Ipv6Analyzer.MaxEvents);
            }
            else if (isDns)
            {
                _dnsEventCount = Math.Min(_dnsEventCount + 1, DnsAnalyzer.MaxEvents);
            }
            else
            {
                _eventCount = Math.Min(_eventCount + 1, LanAnalyzer.MaxEvents);
            }
        }

        store?.Append(item);

        ServiceLog.Operation(
            "WAG-LAN-017",
            $"LAN/DNS/IPv6 event: kind={item.Kind}, severity={item.Severity}, adapter={item.Adapter}, " +
            $"source={item.SourceMac ?? "-"}, target={item.TargetIp ?? "-"}, detail={item.Detail}");

        // 高危事件立即保存，避免服务重启丢掉关键状态（例如新服务器记录）。
        if (string.Equals(item.Severity, LanSeverity.High, StringComparison.Ordinal))
        {
            SaveState();
        }
    }

    private static void EnsureCapture()
    {
        lock (Gate)
        {
            if (!_started || _capture is { IsRunning: true })
            {
                return;
            }
        }

        if (!NpcapLocator.IsAvailable)
        {
            lock (Gate)
            {
                _lastError = "Npcap 未安装。";
            }

            return;
        }

        var analyzer = _analyzer;
        var dnsAnalyzer = _dnsAnalyzer;
        var ipv6Analyzer = _ipv6Analyzer;
        var capture = new NpcapLanCapture
        {
            ArpObserved = frame => analyzer?.ObserveArp(frame, DateTime.UtcNow),
            DhcpObserved = message => analyzer?.ObserveDhcp(message, DateTime.UtcNow),
            DnsObserved = message => dnsAnalyzer?.Observe(message, DateTime.UtcNow),
            Ipv6RaObserved = message => ipv6Analyzer?.ObserveRa(message, DateTime.UtcNow),
            Ipv6NdObserved = message => ipv6Analyzer?.ObserveNd(message, DateTime.UtcNow),
            Ipv6DhcpObserved = message => ipv6Analyzer?.ObserveDhcp(message, DateTime.UtcNow),
            Log = message => ServiceLog.Info("WAG-LAN-018", message),
        };

        if (!capture.Start())
        {
            lock (Gate)
            {
                _lastError = capture.LastError ?? "Npcap 启动失败。";
            }

            capture.Dispose();
            ServiceLog.Warning("WAG-LAN-019", $"LAN capture failed to start: {capture.LastError}");
            return;
        }

        NpcapLanCapture? previous;

        lock (Gate)
        {
            previous = _capture;
            _capture = capture;
            _lastError = null;
            _nextStatsUtc = DateTime.MinValue;
            _nextHintsUtc = DateTime.MinValue;
            _nextPruneUtc = DateTime.MinValue;
        }

        previous?.Stop();
        previous?.Dispose();

        if (analyzer is not null)
        {
            analyzer.UpdateGatewayHints(LanEnvironment.GetGatewayHints());
        }

        dnsAnalyzer?.UpdateConfiguredServers(LanEnvironment.GetDnsHints());
        ipv6Analyzer?.UpdateLocalAddresses(LanEnvironment.GetLocalIpv6Addresses());

        if (analyzer is not null)
        {
            dnsAnalyzer?.UpdateGatewayBaselines(analyzer.Gateways);
        }
    }

    private static int ReleaseAllBlocks(LanAnalyzer analyzer)
    {
        var blocks = analyzer.Blocks.ToList();

        foreach (var block in blocks)
        {
            try
            {
                if (System.Net.IPAddress.TryParse(block.ServerIp, out var address))
                {
                    LanWfp.Remove(address);
                }
            }
            catch (Exception)
            {
                // 删失败不影响状态清理。
            }

            analyzer.RemoveBlock(block.ServerIp);
        }

        return blocks.Count;
    }

    private static void SaveState()
    {
        LanAnalyzer? analyzer;
        Ipv6Analyzer? ipv6;

        lock (Gate)
        {
            analyzer = _analyzer;
            ipv6 = _ipv6Analyzer;
        }

        if (analyzer is null)
        {
            return;
        }

        try
        {
            var snapshot = analyzer.Snapshot();

            LanStateStore.Save(ServicePaths.LanStateFile, new LanState
            {
                Settings = analyzer.Settings,
                Gateways = snapshot.Gateways,
                DhcpServers = snapshot.DhcpServers,
                Blocks = snapshot.Blocks,
                BaselineReadyUtc = snapshot.BaselineUtc,
                TrustedDnsServers = _dnsAnalyzer?.TrustedServers ?? new List<string>(),
                DnsBaselineReadyUtc = _dnsAnalyzer?.BaselineUtc,
            });

            if (ipv6 is not null)
            {
                var ipv6Snapshot = ipv6.Snapshot();

                Ipv6StateStore.Save(ServicePaths.Ipv6StateFile, new Ipv6State
                {
                    BaselineReadyUtc = ipv6Snapshot.BaselineUtc,
                    Routers = ipv6Snapshot.Routers,
                    DhcpServers = ipv6Snapshot.DhcpServers,
                    Neighbors = ipv6Snapshot.Neighbors,
                    TrustedRouters = ipv6.TrustedRouters,
                    TrustedDhcpServers = ipv6.TrustedDhcpServers,
                });
            }
        }
        catch (Exception ex)
        {
            ServiceLog.Warning("WAG-LAN-020", "Failed to save LAN state.", ex);
        }
    }

    private static LanEventDto ToDto(LanEvent item) => new()
    {
        Id = item.Id,
        TimeUtc = item.TimeUtc,
        Kind = item.Kind,
        Severity = item.Severity,
        Adapter = item.Adapter,
        Detail = item.Detail,
        SourceMac = item.SourceMac,
        TargetIp = item.TargetIp,
        TargetMac = item.TargetMac,
        Blocked = item.Blocked,
    };

    private static DnsSecurityServerDto ToDto(DnsServerView item) => new()
    {
        Address = item.Address,
        Adapter = item.Adapter,
        Source = item.Source,
        Mac = item.Mac,
        Trusted = item.Trusted,
    };

    private static Ipv6RouterDto ToDto(Ipv6Router item, HashSet<string> trusted) => new()
    {
        LinkLocal = item.LinkLocal,
        Mac = item.Mac,
        Prefixes = item.Prefixes.Count == 0
            ? "—"
            : string.Join(", ", item.Prefixes.Select(prefix => $"{prefix.Prefix}/{prefix.PrefixLength}")),
        Flags = FormatIpv6Flags(item),
        Lifetime = item.RouterLifetime,
        Baseline = item.Baseline,
        Trusted = trusted.Contains(Ipv6TrustKeys.Router(item.LinkLocal, item.Mac)),
        FirstSeenUtc = item.FirstSeenUtc,
        LastSeenUtc = item.LastSeenUtc,
    };

    private static Ipv6DhcpServerDto ToDto(
        Ipv6DhcpServer item, HashSet<string> trusted, Ipv6BlockRegistry? blocks)
    {
        Ipv6BlockEntry? entry = null;
        var blocked = blocks is not null && blocks.TryGet(item.Address, out entry);

        return new Ipv6DhcpServerDto
        {
            ServerId = item.ServerId,
            Address = item.Address,
            Mac = item.Mac,
            Dns = item.DnsServers.Count == 0 ? "—" : string.Join(", ", item.DnsServers),
            Domains = item.Domains.Count == 0 ? "—" : string.Join(", ", item.Domains),
            MinLeaseSeconds = item.MinValidLifetime == 0
                ? 0
                : (int)Math.Min(item.MinValidLifetime, int.MaxValue),
            Baseline = item.Baseline,
            Trusted = trusted.Contains(Ipv6TrustKeys.Dhcp(item.ServerId, item.Mac)),
            Blocked = blocked,
            BlockExpiresUtc = blocked ? entry!.ExpiresUtc : null,
            FirstSeenUtc = item.FirstSeenUtc,
            LastSeenUtc = item.LastSeenUtc,
        };
    }

    private static Ipv6NeighborDto ToDto(Ipv6Neighbor item) => new()
    {
        Address = item.Address,
        Mac = item.Mac,
        IsRouter = item.IsRouter,
        FirstSeenUtc = item.FirstSeenUtc,
        LastSeenUtc = item.LastSeenUtc,
    };

    private static string FormatIpv6Flags(Ipv6Router item)
    {
        var flags = new List<string>();

        if (item.Managed)
        {
            flags.Add("M");
        }

        if (item.Other)
        {
            flags.Add("O");
        }

        if (item.HomeAgent)
        {
            flags.Add("H");
        }

        return flags.Count == 0 ? "—" : string.Join("/", flags);
    }

    private static LanGatewayDto ToDto(LanGateway item) => new()
    {
        Adapter = item.Adapter,
        Ip = item.Ip,
        Mac = item.Mac,
        LearnedUtc = item.LearnedUtc,
        Trusted = item.Trusted,
    };

    private static LanDhcpServerDto ToDto(LanDhcpServer item) => new()
    {
        ServerIp = item.ServerIp,
        Mac = item.Mac,
        Adapter = item.Adapter,
        Gateway = item.Gateway,
        Dns = item.Dns,
        LeaseSeconds = item.LeaseSeconds,
        FirstSeenUtc = item.FirstSeenUtc,
        Trusted = item.Trusted,
    };

    private static LanBlockDto ToDto(LanBlock item) => new()
    {
        ServerIp = item.ServerIp,
        UntilUtc = item.UntilUtc,
        Reason = item.Reason,
        EventId = item.EventId,
    };

    private static LanSettingsDto ToDto(LanSettings item) => new()
    {
        RetentionDays = item.RetentionDays,
        DhcpBlockEnabled = item.DhcpBlockEnabled,
    };

    private static ServiceResponse Error(ServiceRequest request, string message) => new()
    {
        Id = request.Id,
        Ok = false,
        Error = message,
    };
}
