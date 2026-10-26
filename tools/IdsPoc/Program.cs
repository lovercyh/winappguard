using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using WinAppGuard.Core.Diagnostics;

namespace WinAppGuard.IdsPoc;

/// <summary>
/// 3.7 阶段 1 POC：用户态 flow IDS 的可行性测量工具。
///
/// 它**不进产品**，只做三件事：
///   1. 用 ETW Kernel-Network 建立 flow 表（PID + 协议 + 远端地址/端口）；
///   2. 用 ETW DNS-Client 收集域名查询（PID + 域名 + 类型 + 结果）；
///   3. 原型验证 beaconing / 扫描 / 内网横向 / DNS 异常 / 大上传几条规则，
///      同时量 CPU、内存、事件量和 flow 表大小。
///
/// 不做抓包、不解析载荷、不阻断；所有流量都是本机/回环或用户自己触发的。
/// </summary>
internal static class Program
{
    private static int Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;

        if (args.Length == 0 || args[0] is "--help" or "-h")
        {
            PrintHelp();
            return 0;
        }

        var mode = args[0].ToLowerInvariant();

        if (mode is not ("--selftest" or "--monitor"))
        {
            Console.Error.WriteLine("未知参数。用 --help 查看用法。");
            return 1;
        }

        var seconds = 60;

        if (args.Length > 1 && int.TryParse(args[1], out var parsed) && parsed is > 0 and <= 3600)
        {
            seconds = parsed;
        }

        var elevated = new WindowsPrincipal(WindowsIdentity.GetCurrent())
            .IsInRole(WindowsBuiltInRole.Administrator);

        Console.WriteLine($"管理员 = {elevated}");

        if (!elevated)
        {
            Console.WriteLine("警告：ETW 实时会话需要管理员权限，非管理员可能启动失败。");
        }

        try
        {
            using var runner = new PocRunner();

            return mode == "--selftest"
                ? runner.RunSelfTest()
                : runner.RunMonitor(seconds);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"POC 失败：{ex.GetType().Name}: {ex.Message}");
            return 2;
        }
    }

    private static void PrintHelp()
    {
        Console.WriteLine("WinAppGuard 3.7 POC — 用户态 flow IDS");
        Console.WriteLine();
        Console.WriteLine("  WinAppGuard.IdsPoc.exe --selftest [秒数]");
        Console.WriteLine("  WinAppGuard.IdsPoc.exe --monitor [秒数]");
        Console.WriteLine();
        Console.WriteLine("--selftest  本机生成 beacon/扫描/内网横向/DNS 异常/大上传，验证规则；");
        Console.WriteLine("--monitor   只监听真实流量，用浏览器/下载跑一段时间，观察误报与 CPU。");
        Console.WriteLine();
        Console.WriteLine("需要管理员权限。只读采集，不改防火墙、不阻断任何连接。");
    }
}

internal sealed class PocRunner : IDisposable
{
    private static readonly Guid NetSessionGuid = new("3A7B1C2D-4E5F-4A6B-8C9D-0E1F2A3B4C5D");
    private static readonly Guid DnsSessionGuid = new("5B8C2D3E-6F70-4B8C-9DAE-1F2B3C4D5E6F");
    private static readonly Guid KernelNetworkGuid = new("7DD42A49-5329-4832-8DFD-43D979153A88");
    private static readonly Guid DnsClientGuid = new("1C95126E-7EEA-49A9-A3FE-A378B03DDB4D");

    private static readonly TimeSpan FlowRetention = TimeSpan.FromMinutes(30);
    private static readonly TimeSpan ScanWindow = TimeSpan.FromSeconds(60);
    private static readonly TimeSpan LateralWindow = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan DnsWindow = TimeSpan.FromMinutes(10);
    private static readonly TimeSpan BeaconWindow = TimeSpan.FromMinutes(5);

    private readonly object _gate = new();
    private readonly Dictionary<string, FlowState> _flows = new();
    private readonly List<EndpointHit> _endpoints = new();
    private readonly List<DnsObservation> _dns = new();
    private readonly List<IdsAlert> _alerts = new();
    private readonly HashSet<string> _alertKeys = new(StringComparer.Ordinal);
    private readonly long[] _events = new long[64];

    private readonly EtwRealtimeSession _net;
    private readonly EtwRealtimeSession _dnsSession;
    private readonly System.Threading.Timer _timer;

    private readonly DateTime _startedUtc = DateTime.UtcNow;
    private readonly TimeSpan _cpuStart;
    private readonly Process _self = Process.GetCurrentProcess();

    private double _peakCpu;
    private long _peakMemory;
    private int _ticks;
    private int _eventTotal;
    private int _flowPeak;

    public PocRunner()
    {
        _cpuStart = _self.TotalProcessorTime;

        _net = new EtwRealtimeSession(
            "WinAppGuard-IdsPoc-Net",
            NetSessionGuid,
            KernelNetworkGuid,
            keywords: 0x10 | 0x20,
            OnNetEvent);

        _dnsSession = new EtwRealtimeSession(
            "WinAppGuard-IdsPoc-Dns",
            DnsSessionGuid,
            DnsClientGuid,
            keywords: 0,
            OnDnsEvent);

        _timer = new System.Threading.Timer(
            _ => Tick(),
            state: null,
            dueTime: TimeSpan.FromSeconds(1),
            period: TimeSpan.FromSeconds(1));
    }

    public int RunSelfTest()
    {
        if (!StartSessions())
        {
            return 2;
        }

        Console.WriteLine();
        Console.WriteLine("===== 合成场景 =====");

        using var cancellation = new CancellationTokenSource();
        var listener = new TcpListener(IPAddress.Any, 0);
        listener.Start();
        var port = ((IPEndPoint)listener.LocalEndpoint).Port;

        _ = Task.Run(() => AcceptLoop(listener, cancellation.Token));

        try
        {
            var beaconTarget = GetLocalIPv4() ?? IPAddress.Loopback;

            Console.WriteLine($"beacon：每 5 秒连接 {beaconTarget}:{port}，共 6 次…");
            for (var i = 0; i < 6; i++)
            {
                try
                {
                    using var client = new TcpClient();
                    client.Connect(beaconTarget, port);
                    var stream = client.GetStream();
                    stream.Write(new byte[64]);
                    stream.Flush();
                }
                catch (Exception)
                {
                    // 本机测试，失败不影响规则验证。
                }

                Thread.Sleep(5000);
            }

            DumpFlowDiagnostics(beaconTarget, port);

            Console.WriteLine("scan：连接 127.0.0.2..127.0.0.16 同一端口…");
            for (var i = 2; i <= 16; i++)
            {
                TryConnect(new IPAddress(new byte[] { 127, 0, 0, (byte)i }), port, 100);
            }

            Console.WriteLine("scan：再试 15 个本机监听端口…");
            var scanListeners = new List<TcpListener>();

            try
            {
                for (var i = 0; i < 15; i++)
                {
                    var scanListener = new TcpListener(IPAddress.Loopback, 0);
                    scanListener.Start();
                    scanListeners.Add(scanListener);
                }

                foreach (var scanListener in scanListeners)
                {
                    var scanPort = ((IPEndPoint)scanListener.LocalEndpoint).Port;
                    TryConnect(IPAddress.Loopback, scanPort, 200);
                }
            }
            finally
            {
                foreach (var scanListener in scanListeners)
                {
                    scanListener.Stop();
                }
            }

            Console.WriteLine("scan：再试 127.0.0.1 上 15 个关闭端口…");
            for (var i = 0; i < 15; i++)
            {
                TryConnect(IPAddress.Loopback, 20000 + i, 100);
            }

            Console.WriteLine("lateral：在本机管理端口建监听，再连 6 个回环地址…");
            var lateralListeners = new List<TcpListener>();
            var lateralPort = 0;

            foreach (var candidate in new ushort[] { 3389, 5985, 445, 135, 139 })
            {
                try
                {
                    var lateralListener = new TcpListener(IPAddress.Any, candidate);
                    lateralListener.Start();
                    lateralListeners.Add(lateralListener);
                    lateralPort = candidate;
                    break;
                }
                catch (Exception)
                {
                    // 端口被占用，换下一个。
                }
            }

            if (lateralPort > 0)
            {
                try
                {
                    for (var i = 1; i <= 6; i++)
                    {
                        TryConnect(new IPAddress(new byte[] { 127, 0, 0, (byte)i }), lateralPort, 200);
                    }
                }
                finally
                {
                    foreach (var lateralListener in lateralListeners)
                    {
                        lateralListener.Stop();
                    }
                }
            }
            else
            {
                // 所有管理端口都被占用时，退回真实内网地址的失败尝试。
                var localAddress = GetLocalIPv4();

                if (localAddress is not null)
                {
                    var prefix = localAddress.GetAddressBytes();

                    for (var i = 1; i <= 6; i++)
                    {
                        var bytes = (byte[])prefix.Clone();
                        bytes[3] = (byte)i;
                        var target = new IPAddress(bytes);

                        foreach (var adminPort in new ushort[] { 445, 3389, 5985 })
                        {
                            TryConnect(target, adminPort, 100);
                        }
                    }
                }
            }
            Console.WriteLine("dns：查询 30 个随机长域名…");
            for (var i = 0; i < 30; i++)
            {
                var name = $"{RandomLabel(40)}.example.com";

                try
                {
                    _ = Dns.GetHostAddresses(name);
                }
                catch (Exception)
                {
                    // 预期 NXDOMAIN。
                }

                Thread.Sleep(50);
            }

            Console.WriteLine("upload：向回环发送 12 MiB…");
            try
            {
                using var client = new TcpClient();
                client.Connect(IPAddress.Loopback, port);
                var stream = client.GetStream();
                var buffer = new byte[64 * 1024];
                for (var i = 0; i < 12 * 16; i++)
                {
                    stream.Write(buffer);
                }

                stream.Flush();
            }
            catch (Exception)
            {
                // 忽略：检测结果只看告警。
            }

            Thread.Sleep(3000);
            Tick();
            PrintSummary();
        }
        finally
        {
            cancellation.Cancel();
            listener.Stop();
        }

        return 0;
    }

    public int RunMonitor(int seconds)
    {
        if (!StartSessions())
        {
            return 2;
        }

        Console.WriteLine();
        Console.WriteLine($"监听 {seconds} 秒。请在这段时间里正常浏览网页、看视频、下载文件。");
        Console.WriteLine("（不要运行扫描/beacon 脚本，否则会有人为告警。）");

        for (var i = 0; i < seconds; i++)
        {
            Thread.Sleep(1000);
        }

        Tick();
        PrintSummary();
        return 0;
    }

    private bool StartSessions()
    {
        if (!_net.Start())
        {
            Console.Error.WriteLine($"流量 ETW 会话启动失败：{_net.LastError}");
            return false;
        }

        if (!_dnsSession.Start())
        {
            Console.Error.WriteLine($"DNS ETW 会话启动失败：{_dnsSession.LastError}");
            _net.Stop();
            return false;
        }

        Console.WriteLine("ETW 会话已启动：WinAppGuard-IdsPoc-Net / WinAppGuard-IdsPoc-Dns");
        return true;
    }

    private void DumpFlowDiagnostics(IPAddress target, int port)
    {
        lock (_gate)
        {
            var related = _flows
                .Where(pair => pair.Value.RemotePort == port
                               || string.Equals(pair.Value.Remote, target.ToString(), StringComparison.OrdinalIgnoreCase))
                .Take(10)
                .ToList();

            Console.WriteLine(
                $"    [debug] 目标 {target}:{port}  相关 flow={related.Count}  " +
                $"connect={_events[12] + _events[15] + _events[28] + _events[31]}");

            foreach (var pair in related)
            {
                Console.WriteLine(
                    $"      {pair.Key}  conns={pair.Value.Connections.Count}  " +
                    $"out={pair.Value.BytesOut}  in={pair.Value.BytesIn}  " +
                    $"last={pair.Value.LastSeenUtc:HH:mm:ss.fff}");
            }
        }
    }
    private void AcceptLoop(TcpListener listener, CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            try
            {
                var client = listener.AcceptTcpClient();
                _ = Task.Run(async () =>
                {
                    using (client)
                    {
                        try
                        {
                            var stream = client.GetStream();
                            var buffer = new byte[64 * 1024];

                            while (await stream.ReadAsync(buffer, token) > 0)
                            {
                            }
                        }
                        catch (Exception)
                        {
                            // 客户端提前关闭，正常。
                        }
                    }
                });
            }
            catch (Exception)
            {
                return;
            }
        }
    }

    private static void TryConnect(IPAddress address, int port, int timeoutMs)
    {
        try
        {
            using var client = new TcpClient();
            var task = client.ConnectAsync(address, port);
            _ = task.Wait(timeoutMs);
        }
        catch (Exception)
        {
            // 连接被拒/超时都算一次连接尝试，ETW 仍会看到。
        }
    }

    private static IPAddress? GetLocalIPv4()
    {
        try
        {
            return Dns.GetHostAddresses(Dns.GetHostName())
                .FirstOrDefault(address => address.AddressFamily == AddressFamily.InterNetwork
                                           && !IPAddress.IsLoopback(address));
        }
        catch (Exception)
        {
            return null;
        }
    }

    private static string RandomLabel(int length)
    {
        const string alphabet = "abcdefghijklmnopqrstuvwxyz0123456789";
        var random = Random.Shared;
        var chars = new char[length];

        for (var i = 0; i < length; i++)
        {
            chars[i] = alphabet[random.Next(alphabet.Length)];
        }

        return new string(chars);
    }

    // ---------------- ETW 回调 ----------------

    private void OnNetEvent(IntPtr pointer)
    {
        var record = Marshal.PtrToStructure<EventRecord>(pointer);
        var id = record.EventHeader.Id;

        if (id >= _events.Length)
        {
            return;
        }

        Interlocked.Increment(ref _events[id]);
        Interlocked.Increment(ref _eventTotal);

        if (record.UserData == IntPtr.Zero || record.UserDataLength < 20)
        {
            return;
        }

        var data = record.UserData;
        var pid = Marshal.ReadInt32(data, 0);

        if (pid <= 0)
        {
            return;
        }

        var size = unchecked((uint)Marshal.ReadInt32(data, 4));
        var isV6 = id is 26 or 27 or 28 or 29 or 30 or 31 or 32 or 34 or 58 or 59;
        string remote;
        ushort remotePort;

        if (!isV6)
        {
            var address = (uint)Marshal.ReadInt32(data, 8);
            remote = new IPAddress(BitConverter.GetBytes(address)).ToString();
            remotePort = (ushort)IPAddress.NetworkToHostOrder(Marshal.ReadInt16(data, 16));
        }
        else
        {
            if (record.UserDataLength < 44)
            {
                return;
            }

            var bytes = new byte[16];
            Marshal.Copy(IntPtr.Add(data, 8), bytes, 0, 16);
            remote = new IPAddress(bytes).ToString();
            remotePort = (ushort)IPAddress.NetworkToHostOrder(Marshal.ReadInt16(data, 40));
        }

        var isTcp = id <= 34;
        var isOut = id is 10 or 26 or 42 or 58;
        var isIn = id is 11 or 27 or 43 or 59;
        var isConnect = id is 12 or 15 or 28 or 31;

        if (!isOut && !isIn && !isConnect)
        {
            return;
        }

        var protocol = isTcp ? "TCP" : "UDP";
        var key = $"{pid}|{protocol}|{remote}|{remotePort}";
        var now = DateTime.UtcNow;

        lock (_gate)
        {
            if (!_flows.TryGetValue(key, out var flow))
            {
                flow = new FlowState
                {
                    Pid = pid,
                    Protocol = protocol,
                    Remote = remote,
                    RemotePort = remotePort,
                    FirstSeenUtc = now,
                };

                _flows[key] = flow;
            }

            // 只有 TCP 的连接/接受事件才作为「扫描/beacon」的连接样本；
            // 持续数据流和 UDP 组播不算，否则浏览器/Windows 发现协议会大量误报。
            if (isConnect && isTcp)
            {
                flow.Connections.Add(now);

                if (flow.Connections.Count > 64)
                {
                    flow.Connections.RemoveAt(0);
                }

                _endpoints.Add(new EndpointHit(now, pid, remote, remotePort));
            }

            flow.LastSeenUtc = now;

            if (isOut)
            {
                flow.BytesOut += size;
            }
            else if (isIn)
            {
                flow.BytesIn += size;
            }
        }
    }

    private void OnDnsEvent(IntPtr pointer)
    {
        try
        {
            var record = Marshal.PtrToStructure<EventRecord>(pointer);
            var id = record.EventHeader.Id;

            if (id is not (3006 or 3008 or 3018 or 3020))
            {
                return;
            }

            if (!TryGetString(pointer, "QueryName", out var name) || name.Length == 0)
            {
                return;
            }

            var pid = record.EventHeader.ProcessId;

            if (pid <= 0)
            {
                return;
            }

            var type = TryGetUInt16(pointer, "QueryType", out var queryType) ? queryType : (ushort)0;
            var status = ReadDnsStatus(pointer);

            lock (_gate)
            {
                _dns.Add(new DnsObservation(DateTime.UtcNow, pid, name.Trim(), type, status));

                if (_dns.Count > 10_000)
                {
                    _dns.RemoveRange(0, 1000);
                }
            }
        }
        catch (Exception)
        {
            // ETW 回调里绝不抛异常。
        }
    }

    // ---------------- 规则 ----------------

    private void Tick()
    {
        try
        {
            Evaluate();

            var now = DateTime.UtcNow;
            var cpu = CpuPercent(_self.TotalProcessorTime - _cpuStart, now - _startedUtc);

            if (cpu > _peakCpu)
            {
                _peakCpu = cpu;
            }

            var memory = _self.WorkingSet64;

            if (memory > _peakMemory)
            {
                _peakMemory = memory;
            }

            _ticks++;

            if (_ticks % 5 == 0)
            {
                int flows;

                lock (_gate)
                {
                    flows = _flows.Count;

                    if (flows > _flowPeak)
                    {
                        _flowPeak = flows;
                    }
                }

                Console.WriteLine(
                    $"[{now - _startedUtc,3:hh\\:mm\\:ss}] 事件 {_eventTotal,7}  flows {flows,5}  " +
                    $"DNS {_dns.Count,5}  CPU {cpu,4:0.0}%  内存 {memory / 1024 / 1024,4} MB  告警 {_alerts.Count}");
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"规则评估异常：{ex.GetType().Name}: {ex.Message}");
        }
    }

    private void Evaluate()
    {
        var now = DateTime.UtcNow;

        lock (_gate)
        {
            // 清理过期数据，避免 POC 长时间跑时无限增长。
            _endpoints.RemoveAll(hit => now - hit.TimeUtc > LateralWindow);
            _dns.RemoveAll(item => now - item.TimeUtc > DnsWindow);

            foreach (var key in _flows
                         .Where(pair => now - pair.Value.LastSeenUtc > FlowRetention)
                         .Select(pair => pair.Key)
                         .ToList())
            {
                _flows.Remove(key);
            }

            EvaluateBeaconing(now);
            EvaluateScanning(now);
            EvaluateLateral(now);
            EvaluateDns(now);
            EvaluateExfiltration(now);
        }
    }

    private void EvaluateBeaconing(DateTime now)
    {
        foreach (var flow in _flows.Values)
        {
            if (flow.Protocol != "TCP" || IsNoisyEndpoint(flow.Remote, flow.RemotePort))
            {
                continue;
            }

            var times = flow.Connections
                .Where(time => now - time <= BeaconWindow)
                .ToList();

            if (times.Count < 6)
            {
                continue;
            }

            var intervals = new List<double>();

            for (var i = 1; i < times.Count; i++)
            {
                intervals.Add((times[i] - times[i - 1]).TotalSeconds);
            }

            if (intervals.Any(value => value < 5.0 || value > 300))
            {
                continue;
            }

            var mean = intervals.Average();
            var variance = intervals.Sum(value => (value - mean) * (value - mean)) / intervals.Count;
            var cv = mean > 0 ? Math.Sqrt(variance) / mean : double.MaxValue;
            var averageBytes = (flow.BytesOut + flow.BytesIn) / Math.Max(1, times.Count);

            // 正常浏览会反复连同一个 CDN；beacon 通常每次只发很少的数据。
            if (averageBytes > 256 * 1024)
            {
                continue;
            }

            if (mean is >= 5.0 and <= 300 && cv <= 0.35)
            {
                AddAlert(
                    "中",
                    "beaconing",
                    flow.Pid,
                    $"{flow.Remote}:{flow.RemotePort}",
                    $"连接 {times.Count} 次，平均间隔 {mean:0.0}s，抖动 {cv:0.00}，平均每次 {FormatBytes((ulong)averageBytes)}");
            }
        }
    }

    private void EvaluateScanning(DateTime now)
    {
        var recent = _endpoints
            .Where(hit => now - hit.TimeUtc <= ScanWindow)
            .GroupBy(hit => hit.Pid);

        foreach (var group in recent)
        {
            var hits = group.ToList();

            var vertical = hits
                .GroupBy(hit => hit.Remote)
                .Select(host => new
                {
                    Host = host.Key,
                    Ports = host.Select(hit => hit.RemotePort).Distinct().Count(),
                })
                .FirstOrDefault(item => item.Ports >= 15);

            var horizontal = hits
                .GroupBy(hit => hit.RemotePort)
                .Where(port => port.Key is not 80 and not 443)
                .Select(port => new
                {
                    Port = port.Key,
                    Hosts = port.Select(hit => hit.Remote).Distinct().Count(),
                })
                .FirstOrDefault(item => item.Hosts >= 15);

            if (vertical is null && horizontal is null)
            {
                continue;
            }

            var count = Math.Max(vertical?.Ports ?? 0, horizontal?.Hosts ?? 0);
            var evidence = vertical is not null
                ? $"同一主机 {vertical.Host} 的 {vertical.Ports} 个不同端口"
                : $"同一端口 {horizontal!.Port} 上的 {horizontal.Hosts} 台不同主机";

            AddAlert(
                count >= 30 ? "高" : "中",
                "scan",
                group.Key,
                "多个远端端点",
                $"60 秒内：{evidence}");
        }
    }

    private void EvaluateLateral(DateTime now)
    {
        var recent = _endpoints
            .Where(hit => now - hit.TimeUtc <= LateralWindow
                          && hit.RemotePort is 445 or 3389 or 5985 or 135 or 139
                          && IsPrivate(hit.Remote))
            .GroupBy(hit => hit.Pid);

        foreach (var group in recent)
        {
            var hosts = group
                .Select(hit => hit.Remote)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Count();

            if (hosts >= 3)
            {
                AddAlert(
                    "高",
                    "lateral",
                    group.Key,
                    "内网管理端口",
                    $"10 分钟内连接 {hosts} 台内网主机的 445/3389/5985 等端口");
            }
        }
    }

    private void EvaluateDns(DateTime now)
    {
        // 按「同一父域」分组：正常系统进程会查很多不同域名，
        // 但不会在同一个父域下瞬间产生几十个随机子域；DGA/tunneling 才会。
        var recent = _dns
            .Where(item => now - item.TimeUtc <= DnsWindow)
            .GroupBy(item => (item.Pid, Parent: ParentDomain(item.QueryName)));

        foreach (var group in recent)
        {
            var parent = group.Key.Parent;

            if (parent.Length == 0 || IsSystemProcess(GetProcessName(group.Key.Pid)))
            {
                continue;
            }

            var names = group
                .Select(item => item.QueryName)
                .Where(name => name.Length > 0)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            var longNames = names.Count(name => name.Length >= 40);
            var nxdomain = group.Count(item => item.Status is "NXDOMAIN" or "NO_RECORDS");
            var total = group.Count();

            if (names.Count >= 20 || longNames >= 10
                || (total >= 20 && nxdomain * 100 / total >= 70))
            {
                AddAlert(
                    "中",
                    "dns",
                    group.Key.Pid,
                    parent,
                    $"父域下唯一域名 {names.Count}，长域名 {longNames}，NXDOMAIN {nxdomain}/{total}");
            }
        }
    }
    private void EvaluateExfiltration(DateTime now)
    {
        foreach (var flow in _flows.Values)
        {
            if (now - flow.LastSeenUtc > TimeSpan.FromMinutes(5))
            {
                continue;
            }

            if (flow.BytesOut >= 10 * 1024 * 1024
                && flow.BytesOut > Math.Max(1, flow.BytesIn) * 5)
            {
                AddAlert(
                    "高",
                    "exfil",
                    flow.Pid,
                    $"{flow.Remote}:{flow.RemotePort}",
                    $"上传 {FormatBytes((ulong)flow.BytesOut)} / 下载 {FormatBytes((ulong)flow.BytesIn)}");
            }
        }
    }

    private void AddAlert(string severity, string rule, int pid, string target, string evidence)
    {
        var key = $"{rule}|{pid}|{target}";

        if (!_alertKeys.Add(key))
        {
            return;
        }

        var process = GetProcessName(pid);
        var alert = new IdsAlert(DateTime.UtcNow, severity, rule, pid, process, target, evidence);
        _alerts.Add(alert);

        Console.WriteLine();
        Console.WriteLine(
            $"  [告警/{severity}] {rule}  PID {pid}  {process}  {target}");
        Console.WriteLine($"      {evidence}");
    }

    private static string GetProcessName(int pid)
    {
        try
        {
            using var process = Process.GetProcessById(pid);
            return process.ProcessName + ".exe";
        }
        catch (Exception)
        {
            return $"PID {pid}";
        }
    }

    private static bool IsSystemProcess(string processName)
        => processName.Equals("svchost.exe", StringComparison.OrdinalIgnoreCase)
           || processName.Equals("WinAppGuardSvc.exe", StringComparison.OrdinalIgnoreCase)
           || processName.Equals("System", StringComparison.OrdinalIgnoreCase)
           || processName.Equals("services.exe", StringComparison.OrdinalIgnoreCase)
           || processName.Equals("lsass.exe", StringComparison.OrdinalIgnoreCase)
           || processName.Equals("dns.exe", StringComparison.OrdinalIgnoreCase);
    private static bool IsPrivate(string address)
    {
        if (!IPAddress.TryParse(address, out var ip)
            || ip.AddressFamily != AddressFamily.InterNetwork)
        {
            return false;
        }

        var bytes = ip.GetAddressBytes();

        return bytes[0] == 10
               || (bytes[0] == 172 && bytes[1] is >= 16 and <= 31)
               || (bytes[0] == 192 && bytes[1] == 168)
               || bytes[0] == 127;
    }

    /// <summary>组播/广播/链路本地/常见发现协议端口：不能拿来做 beaconing 判断。</summary>
    private static bool IsNoisyEndpoint(string address, ushort port)
    {
        if (port is 53 or 5353 or 5355 or 1900 or 3702 or 137 or 138)
        {
            return true;
        }

        if (!IPAddress.TryParse(address, out var ip))
        {
            return false;
        }

        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            var bytes = ip.GetAddressBytes();
            return bytes[0] is >= 224 and <= 239
                   || (bytes[0] == 255 && bytes[1] == 255 && bytes[2] == 255 && bytes[3] == 255)
                   || (bytes[0] == 169 && bytes[1] == 254);
        }

        var v6 = ip.GetAddressBytes();
        return v6[0] == 0xff || (v6[0] == 0xfe && (v6[1] & 0xc0) == 0x80);
    }

    private static string ParentDomain(string name)
    {
        var trimmed = name.Trim().TrimEnd('.');

        if (trimmed.Length == 0)
        {
            return string.Empty;
        }

        var parts = trimmed.Split('.');

        return parts.Length >= 2
            ? $"{parts[^2]}.{parts[^1]}".ToLowerInvariant()
            : trimmed.ToLowerInvariant();
    }

    private static double CpuPercent(TimeSpan cpu, TimeSpan wall)
        => wall.TotalMilliseconds <= 0
            ? 0
            : cpu.TotalMilliseconds / (wall.TotalMilliseconds * Environment.ProcessorCount) * 100;

    private static string FormatBytes(ulong bytes)
    {
        string[] units = { "B", "KB", "MB", "GB" };
        var value = (double)bytes;
        var unit = 0;

        while (value >= 1024 && unit < units.Length - 1)
        {
            value /= 1024;
            unit++;
        }

        return $"{value:0.##} {units[unit]}";
    }

    private void PrintSummary()
    {
        var elapsed = DateTime.UtcNow - _startedUtc;
        var cpu = CpuPercent(_self.TotalProcessorTime - _cpuStart, elapsed);

        int flows;

        lock (_gate)
        {
            flows = _flows.Count;

            if (flows > _flowPeak)
            {
                _flowPeak = flows;
            }
        }

        Console.WriteLine();
        Console.WriteLine("===== POC 结果 =====");
        Console.WriteLine($"时长        = {elapsed.TotalSeconds:0.0} 秒");
        Console.WriteLine($"网络事件    = {_eventTotal}");
        Console.WriteLine($"事件明细    = TCP收 {_events[11] + _events[27]}, TCP发 {_events[10] + _events[26]}, " +
                          $"连接 {_events[12] + _events[15] + _events[28] + _events[31]}, " +
                          $"UDP收 {_events[43] + _events[59]}, UDP发 {_events[42] + _events[58]}");
        Console.WriteLine($"flow 峰值   = {_flowPeak}");
        Console.WriteLine($"DNS 观察    = {_dns.Count}");
        Console.WriteLine($"CPU 平均    = {cpu:0.0}%  峰值 = {_peakCpu:0.0}%（{Environment.ProcessorCount} 核）");
        Console.WriteLine($"内存 峰值   = {_peakMemory / 1024 / 1024} MB");
        Console.WriteLine($"告警数      = {_alerts.Count}");

        if (_alerts.Count > 0)
        {
            Console.WriteLine();
            Console.WriteLine("告警列表：");

            foreach (var alert in _alerts)
            {
                Console.WriteLine(
                    $"  [{alert.Severity}] {alert.Rule}  PID {alert.Pid}  {alert.Process}  " +
                    $"{alert.Target}  {alert.Evidence}");
            }
        }

        Console.WriteLine();
        Console.WriteLine("规则命中：");

        foreach (var rule in new[] { "beaconing", "scan", "lateral", "dns", "exfil" })
        {
            var hit = _alerts.Any(alert => alert.Rule == rule);
            Console.WriteLine($"  {rule,-10} {(hit ? "命中" : "未命中")}");
        }
    }

    public void Dispose()
    {
        _timer.Dispose();
        _net.Dispose();
        _dnsSession.Dispose();
        _self.Dispose();
    }

    // ---------------- 数据模型 ----------------

    private sealed class FlowState
    {
        public int Pid;
        public string Protocol = string.Empty;
        public string Remote = string.Empty;
        public ushort RemotePort;
        public DateTime FirstSeenUtc;
        public DateTime LastSeenUtc;
        public long BytesIn;
        public long BytesOut;
        public List<DateTime> Connections = new();
    }

    private readonly record struct EndpointHit(
        DateTime TimeUtc, int Pid, string Remote, ushort RemotePort);

    private readonly record struct DnsObservation(
        DateTime TimeUtc, int Pid, string QueryName, ushort QueryType, string Status);

    private sealed record IdsAlert(
        DateTime TimeUtc,
        string Severity,
        string Rule,
        int Pid,
        string Process,
        string Target,
        string Evidence);

    // ---------------- ETW 结构 / TDH ----------------

    [StructLayout(LayoutKind.Sequential)]
    private struct EventHeader
    {
        public ushort Size;
        public ushort HeaderType;
        public ushort Flags;
        public ushort EventProperty;
        public int ThreadId;
        public int ProcessId;
        public long TimeStamp;
        public Guid ProviderId;
        public ushort Id;
        public byte Version;
        public byte Channel;
        public byte Level;
        public byte Opcode;
        public ushort Task;
        public ulong Keyword;
        public uint KernelTime;
        public uint UserTime;
        public Guid ActivityId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct EventRecord
    {
        public EventHeader EventHeader;
        public uint BufferContext;
        public ushort ExtendedDataCount;
        public ushort UserDataLength;
        public IntPtr ExtendedData;
        public IntPtr UserData;
        public IntPtr UserContext;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PropertyDataDescriptor
    {
        public IntPtr PropertyName;
        public uint ArrayIndex;
        public uint Reserved;
    }

    private static bool TryGetString(IntPtr record, string property, out string value)
    {
        value = string.Empty;

        if (!TryGetProperty(record, property, out var buffer, out var size) || size <= 0)
        {
            return false;
        }

        try
        {
            value = Marshal.PtrToStringUni(buffer) ?? string.Empty;
            return value.Length > 0;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static bool TryGetUInt16(IntPtr record, string property, out ushort value)
    {
        value = 0;

        if (!TryGetProperty(record, property, out var buffer, out var size))
        {
            return false;
        }

        try
        {
            if (size < 2)
            {
                return false;
            }

            value = unchecked((ushort)Marshal.ReadInt16(buffer));
            return true;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static bool TryGetProperty(
        IntPtr record, string property, out IntPtr buffer, out int size)
    {
        buffer = IntPtr.Zero;
        size = 0;
        var namePointer = Marshal.StringToHGlobalUni(property);

        try
        {
            var descriptor = new PropertyDataDescriptor
            {
                PropertyName = namePointer,
                ArrayIndex = 0,
            };

            var rc = TdhGetPropertySize(
                record, 0, IntPtr.Zero, 1, ref descriptor, out size);

            if (rc != 0 || size <= 0)
            {
                return false;
            }

            buffer = Marshal.AllocHGlobal(size);

            if (TdhGetProperty(
                    record, 0, IntPtr.Zero, 1, ref descriptor, size, buffer) != 0)
            {
                Marshal.FreeHGlobal(buffer);
                buffer = IntPtr.Zero;
                size = 0;
                return false;
            }

            return true;
        }
        finally
        {
            Marshal.FreeHGlobal(namePointer);
        }
    }

    private static string ReadDnsStatus(IntPtr record)
    {
        foreach (var name in new[] { "QueryStatus", "ResponseStatus" })
        {
            if (!TryGetProperty(record, name, out var buffer, out var size))
            {
                continue;
            }

            try
            {
                if (size < 4)
                {
                    continue;
                }

                return unchecked((uint)Marshal.ReadInt32(buffer)) switch
                {
                    0 => "OK",
                    9002 => "SERVFAIL",
                    9003 => "NXDOMAIN",
                    9501 => "NO_RECORDS",
                    1460 => "TIMEOUT",
                    var value => $"0x{value:X8}",
                };
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        return string.Empty;
    }

    [DllImport("tdh.dll", CharSet = CharSet.Unicode)]
    private static extern int TdhGetPropertySize(
        IntPtr eventRecord, uint tdhContextCount, IntPtr tdhContext,
        uint propertyDataCount, ref PropertyDataDescriptor propertyData, out int propertySize);

    [DllImport("tdh.dll", CharSet = CharSet.Unicode)]
    private static extern int TdhGetProperty(
        IntPtr eventRecord, uint tdhContextCount, IntPtr tdhContext,
        uint propertyDataCount, ref PropertyDataDescriptor propertyData,
        int propertySize, IntPtr buffer);
}
