using System.Collections.Concurrent;
using System.Net;
using WinAppGuard.Contracts;
using WinAppGuard.Core;
using WinAppGuard.Core.Diagnostics.AntiScan;
using WinAppGuard.Core.Wfp;

namespace WinAppGuard.Service;

/// <summary>
/// 4.0：反端口扫描宿主。
///
/// 采集：Npcap（用户安装的官方驱动）只抓入站 TCP SYN；
/// 检测：<see cref="AntiScanAnalyzer"/> 维护来源 IP 的滑动窗口；
/// 处置：高危扫描可按设置临时封禁来源 IP，封禁走 WFP 的入站 accept 层。
///
/// 边界：只检测 TCP 端口扫描；不读载荷、不做 DPI、不做 inline 阻断。
/// </summary>
internal static class AntiScanHost
{
    private static readonly object Gate = new();
    private static readonly TimeSpan TickInterval = TimeSpan.FromSeconds(5);

    private const int MaxEvents = 1000;

    private static AntiScanState _state = new();
    private static AntiScanAnalyzer _analyzer = new();
    private static NpcapCapture? _capture;
    private static System.Threading.Timer? _timer;
    private static List<AntiScanEventDto> _events = new();
    private static HashSet<string> _gatewayAddresses = new(StringComparer.OrdinalIgnoreCase);
    private static bool _started;
    private static DateTime _nextCaptureRetryUtc = DateTime.MinValue;
    private static DateTime? _lastEventUtc;
    private static string? _lastError;

    internal static bool Enabled
    {
        get { lock (Gate) { return _state.Settings.Enabled; } }
    }

    internal static bool Collecting
    {
        get { lock (Gate) { return _capture?.IsRunning == true; } }
    }

    internal static bool NpcapAvailable => NpcapLocator.IsAvailable;

    internal static int BlockedCount
    {
        get { lock (Gate) { return _state.Blocks.Count; } }
    }

    internal static void Start()
    {
        lock (Gate)
        {
            _state = AntiScanStateFile.Load(ServicePaths.AntiScanStateFile);
            _started = true;
            _events = new List<AntiScanEventDto>();
            _lastEventUtc = null;
            _lastError = null;
            RefreshGatewaysLocked();

            // 上次运行留下的过滤器可能还在；状态文件才是权威。
            try
            {
                var removed = AntiScanWfp.RemoveAll();

                if (removed > 0)
                {
                    ServiceLog.Operation(
                        "WAG-ANTISCAN-001",
                        $"Removed {removed} stale anti-scan inbound filter(s) at startup.");
                }
            }
            catch (Exception ex)
            {
                ServiceLog.Warning("WAG-ANTISCAN-002", "Failed to clean stale anti-scan filters.", ex);
            }

            PruneExpiredBlocksLocked(DateTime.UtcNow);

            foreach (var block in _state.Blocks.ToList())
            {
                if (!TryAddBlockFilter(block.Address, out var error))
                {
                    _lastError = error;
                    ServiceLog.Warning(
                        "WAG-ANTISCAN-003",
                        $"Failed to restore anti-scan block for {block.Address}: {error}");
                    _state.Blocks.Remove(block);
                }
            }
        }

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
            "WAG-ANTISCAN-004",
            $"Anti-scan started (enabled={Enabled}, npcap={NpcapLocator.FindWpcapPath() ?? "missing"}, " +
            $"autoBlock={Settings().AutoBlock}, blocks={BlockedCount}).");
    }

    internal static void Stop()
    {
        NpcapCapture? capture;

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

        // 服务停止时移除临时封禁，避免留下无人管理的过滤器；状态文件保留，下次启动恢复未到期项。
        try
        {
            AntiScanWfp.RemoveAll();
        }
        catch (Exception ex)
        {
            ServiceLog.Warning("WAG-ANTISCAN-005", "Failed to remove anti-scan filters on stop.", ex);
        }

        lock (Gate)
        {
            _events = new List<AntiScanEventDto>();
        }

        ServiceLog.Info("WAG-ANTISCAN-006", "Anti-scan stopped.");
    }

    internal static ServiceResponse Query(ServiceRequest request)
    {
        lock (Gate)
        {
            return new ServiceResponse
            {
                Id = request.Id,
                Ok = true,
                AntiScanSettings = ToDto(_state.Settings),
                AntiScanStatus = BuildStatusLocked(),
                AntiScanEvents = _events.ToList(),
                AntiScanBlocks = _state.Blocks
                    .OrderBy(block => block.BlockedUntilUtc)
                    .Select(ToDto)
                    .ToList(),
            };
        }
    }

    internal static ServiceResponse Configure(ServiceRequest request)
    {
        var dto = request.AntiScanSettings;

        if (dto is null)
        {
            return Error(request, "缺少反扫描设置。");
        }

        bool wasEnabled;
        bool nowEnabled;

        lock (Gate)
        {
            wasEnabled = _state.Settings.Enabled;
            _state.Settings.Enabled = dto.Enabled;
            _state.Settings.Sensitivity = string.Equals(
                dto.Sensitivity, "conservative", StringComparison.OrdinalIgnoreCase)
                ? "conservative"
                : "standard";
            _state.Settings.AutoBlock = dto.AutoBlock;
            _state.Settings.BlockMinutes = Math.Clamp(dto.BlockMinutes, 5, 60);
            _state.Settings.Allowlist = (dto.Allowlist ?? new List<string>())
                .Where(value => IPAddress.TryParse(value?.Trim(), out _))
                .Select(value => IPAddress.Parse(value!.Trim()).ToString())
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
            nowEnabled = _state.Settings.Enabled;

            // 界面点了「Npcap：未连接（点击重试）」或刚装完 Npcap 时会重新下发一次设置：
            // 立刻清掉退避计时，让 EnsureCapture 当场再试一次，而不是再等 30 秒。
            _nextCaptureRetryUtc = DateTime.MinValue;

            if (wasEnabled != nowEnabled)
            {
                _analyzer.Clear();

                if (!nowEnabled)
                {
                    ReleaseAllLocked();
                }
            }
        }

        SaveState();

        if (nowEnabled)
        {
            EnsureCapture();
        }
        else
        {
            StopCapture();
        }

        ServiceLog.Operation(
            "WAG-ANTISCAN-007",
            $"Anti-scan configured: enabled={nowEnabled}, sensitivity={Settings().Sensitivity}, " +
            $"autoBlock={Settings().AutoBlock}, blockMinutes={Settings().BlockMinutes}.");

        return Query(request);
    }

    internal static ServiceResponse Release(ServiceRequest request)
    {
        var address = request.AntiScanAddress;
        var released = 0;

        lock (Gate)
        {
            if (request.AntiScanReleaseAll)
            {
                released = ReleaseAllLocked();
            }
            else if (!string.IsNullOrWhiteSpace(address) && IPAddress.TryParse(address, out var parsed))
            {
                if (ReleaseLocked(parsed.ToString()))
                {
                    released = 1;
                }
            }
            else
            {
                return Error(request, "缺少或非法的 IP 地址。");
            }
        }

        SaveState();

        if (released > 0)
        {
            ServiceLog.Operation(
                "WAG-ANTISCAN-008",
                $"Released {released} anti-scan inbound block(s).");
        }

        return new ServiceResponse
        {
            Id = request.Id,
            Ok = true,
            Affected = released,
            AntiScanStatus = GetStatus(),
            AntiScanBlocks = GetBlocks(),
        };
    }

    internal static ServiceResponse Clear(ServiceRequest request)
    {
        int released;
        int events;

        lock (Gate)
        {
            released = ReleaseAllLocked();
            events = _events.Count;
            _events = new List<AntiScanEventDto>();
            _lastEventUtc = null;
            _analyzer.Clear();
        }

        SaveState();

        ServiceLog.Operation(
            "WAG-ANTISCAN-009",
            $"Anti-scan cleared ({events} event(s), {released} block(s) released).");

        return new ServiceResponse
        {
            Id = request.Id,
            Ok = true,
            Affected = released,
            AntiScanStatus = GetStatus(),
            AntiScanEvents = new List<AntiScanEventDto>(),
            AntiScanBlocks = new List<AntiScanBlockDto>(),
        };
    }

    internal static AntiScanStatusDto GetStatus()
    {
        lock (Gate)
        {
            return BuildStatusLocked();
        }
    }

    private static void Tick()
    {
        try
        {
            DateTime now;
            int expired = 0;

            lock (Gate)
            {
                if (!_started)
                {
                    return;
                }

                now = DateTime.UtcNow;
                expired = PruneExpiredBlocksLocked(now);
            }

            if (expired > 0)
            {
                SaveState();
                ServiceLog.Operation("WAG-ANTISCAN-010", $"Expired {expired} anti-scan inbound block(s).");
            }

            EnsureCapture();
        }
        catch (Exception ex)
        {
            ServiceLog.Warning("WAG-ANTISCAN-011", "Anti-scan timer failed.", ex);
        }
    }

    private static void EnsureCapture()
    {
        lock (Gate)
        {
            if (!_started || !_state.Settings.Enabled)
            {
                return;
            }

            if (_capture is { IsRunning: true })
            {
                return;
            }

            if (DateTime.UtcNow < _nextCaptureRetryUtc)
            {
                return;
            }
        }

        if (!NpcapLocator.IsAvailable)
        {
            lock (Gate)
            {
                _lastError = "Npcap 未安装。";
                _nextCaptureRetryUtc = DateTime.UtcNow.AddSeconds(30);
            }

            return;
        }

        var capture = new NpcapCapture
        {
            SynObserved = OnSyn,
            Log = message => ServiceLog.Info("WAG-ANTISCAN-012", message),
        };

        if (!capture.Start())
        {
            lock (Gate)
            {
                _lastError = capture.LastError ?? "Npcap 启动失败。";
                _nextCaptureRetryUtc = DateTime.UtcNow.AddSeconds(30);
            }

            capture.Dispose();
            ServiceLog.Warning(
                "WAG-ANTISCAN-013",
                $"Anti-scan Npcap capture failed to start: {capture.LastError}");
            return;
        }

        NpcapCapture? previous;

        lock (Gate)
        {
            previous = _capture;
            _capture = capture;
            _lastError = null;
            _nextCaptureRetryUtc = DateTime.MinValue;
        }

        previous?.Stop();
        previous?.Dispose();
    }

    private static void StopCapture()
    {
        NpcapCapture? capture;

        lock (Gate)
        {
            capture = _capture;
            _capture = null;
        }

        capture?.Stop();
        capture?.Dispose();
    }

    private static void OnSyn(InboundSyn syn)
    {
        AntiScanSettings settings;

        lock (Gate)
        {
            if (!_started || !_state.Settings.Enabled)
            {
                return;
            }

            if (IsAllowlistedLocked(syn.SourceAddress))
            {
                return;
            }

            settings = CloneSettings(_state.Settings);
        }

        var finding = _analyzer.Observe(syn, DateTime.UtcNow, settings);

        if (finding is null)
        {
            return;
        }

        HandleFinding(finding, settings);
    }

    private static void HandleFinding(AntiScanFinding finding, AntiScanSettings settings)
    {
        var eventDto = new AntiScanEventDto
        {
            Id = finding.Id,
            TimeUtc = finding.TimeUtc,
            SourceAddress = finding.SourceAddress,
            DistinctPorts = finding.DistinctPorts,
            DistinctHosts = finding.DistinctHosts,
            SynCount = finding.SynCount,
            WindowSeconds = finding.WindowSeconds,
            Severity = finding.Severity,
            Action = "alert",
        };

        var blocked = false;

        if (settings.AutoBlock
            && finding.Severity == AntiScanSeverity.High
            && !IsAllowlisted(finding.SourceAddress))
        {
            blocked = TryBlock(finding.SourceAddress, settings.BlockMinutes, finding.Id, out var error);

            if (!blocked)
            {
                ServiceLog.Warning(
                    "WAG-ANTISCAN-014",
                    $"Failed to auto-block scanner {finding.SourceAddress}: {error}");
            }
            else
            {
                eventDto.Action = "blocked";
                eventDto.BlockedUntilUtc = DateTime.UtcNow.AddMinutes(settings.BlockMinutes);
            }
        }

        lock (Gate)
        {
            _events.Insert(0, eventDto);

            if (_events.Count > MaxEvents)
            {
                _events.RemoveRange(MaxEvents, _events.Count - MaxEvents);
            }

            _lastEventUtc = eventDto.TimeUtc;
        }

        ServiceLog.Operation(
            "WAG-ANTISCAN-015",
            $"Inbound scan detected: source={finding.SourceAddress}, severity={finding.Severity}, " +
            $"ports={finding.DistinctPorts}, hosts={finding.DistinctHosts}, syn={finding.SynCount}, " +
            $"blocked={blocked}.");
    }

    private static bool TryBlock(string address, int minutes, string eventId, out string? error)
    {
        error = null;

        if (!IPAddress.TryParse(address, out var ip))
        {
            error = "非法 IP 地址。";
            return false;
        }

        lock (Gate)
        {
            var existing = _state.Blocks.FirstOrDefault(
                block => string.Equals(block.Address, address, StringComparison.OrdinalIgnoreCase));

            if (existing is null && _state.Blocks.Count >= 32)
            {
                error = "临时封禁数量已达到上限。";
                return false;
            }
        }

        try
        {
            AntiScanWfp.Add(ip);
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }

        lock (Gate)
        {
            var existing = _state.Blocks.FirstOrDefault(
                block => string.Equals(block.Address, address, StringComparison.OrdinalIgnoreCase));

            var until = DateTime.UtcNow.AddMinutes(Math.Clamp(minutes, 5, 60));

            if (existing is null)
            {
                _state.Blocks.Add(new AntiScanBlock
                {
                    Address = address,
                    BlockedUntilUtc = until,
                    Reason = "inbound port scan",
                    EventId = eventId,
                });
            }
            else
            {
                existing.BlockedUntilUtc = until;
                existing.EventId = eventId;
            }
        }

        SaveState();
        return true;
    }

    private static bool TryAddBlockFilter(string address, out string? error)
    {
        error = null;

        if (!IPAddress.TryParse(address, out var ip))
        {
            error = "非法 IP 地址。";
            return false;
        }

        try
        {
            AntiScanWfp.Add(ip);
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    private static bool ReleaseLocked(string address)
    {
        if (IPAddress.TryParse(address, out var ip))
        {
            try
            {
                AntiScanWfp.Remove(ip);
            }
            catch (Exception ex)
            {
                ServiceLog.Warning(
                    "WAG-ANTISCAN-016",
                    $"Failed to remove anti-scan filter for {address}.",
                    ex);
            }
        }

        var removed = _state.Blocks.RemoveAll(
            block => string.Equals(block.Address, address, StringComparison.OrdinalIgnoreCase));

        _analyzer.ResetSource(address);
        return removed > 0;
    }

    private static int ReleaseAllLocked()
    {
        var released = 0;

        foreach (var block in _state.Blocks.ToList())
        {
            if (ReleaseLocked(block.Address))
            {
                released++;
            }
        }

        return released;
    }

    private static int PruneExpiredBlocksLocked(DateTime now)
    {
        var expired = _state.Blocks
            .Where(block => block.BlockedUntilUtc <= now)
            .ToList();

        foreach (var block in expired)
        {
            if (IPAddress.TryParse(block.Address, out var ip))
            {
                try
                {
                    AntiScanWfp.Remove(ip);
                }
                catch (Exception)
                {
                    // 到期清理失败不影响状态；下次启动会再清。
                }
            }

            _analyzer.ResetSource(block.Address);
            _state.Blocks.Remove(block);
        }

        return expired.Count;
    }

    private static bool IsAllowlisted(IPAddress address)
    {
        lock (Gate)
        {
            return IsAllowlistedLocked(address);
        }
    }

    private static bool IsAllowlisted(string address)
        => IPAddress.TryParse(address, out var parsed) && IsAllowlisted(parsed);

    private static bool IsAllowlistedLocked(IPAddress address)
    {
        var text = address.ToString();
        return _gatewayAddresses.Contains(text)
               || _state.Settings.Allowlist.Any(
                   item => string.Equals(item, text, StringComparison.OrdinalIgnoreCase));
    }

    private static void RefreshGatewaysLocked()
    {
        _gatewayAddresses.Clear();

        try
        {
            foreach (var nic in System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != System.Net.NetworkInformation.OperationalStatus.Up)
                {
                    continue;
                }

                foreach (var gateway in nic.GetIPProperties().GatewayAddresses)
                {
                    var address = gateway.Address;

                    if (address is not null
                        && !address.Equals(IPAddress.Any)
                        && !address.Equals(IPAddress.IPv6Any))
                    {
                        _gatewayAddresses.Add(address.ToString());
                    }
                }

                foreach (var dns in nic.GetIPProperties().DnsAddresses)
                {
                    if (!dns.Equals(IPAddress.Any) && !dns.Equals(IPAddress.IPv6Any))
                    {
                        _gatewayAddresses.Add(dns.ToString());
                    }
                }
            }
        }
        catch (Exception)
        {
            // 网关枚举失败时只保留用户允许名单；不影响检测。
        }
    }

    private static AntiScanStatusDto BuildStatusLocked() => new()
    {
        Enabled = _state.Settings.Enabled,
        NpcapAvailable = NpcapLocator.IsAvailable,
        NpcapVersion = NpcapLocator.GetVersion(),
        NpcapPath = NpcapLocator.FindWpcapPath(),
        Collecting = _capture?.IsRunning == true,
        EventsSeen = _capture?.EventsSeen ?? 0,
        EventCount = _events.Count,
        BlockedCount = _state.Blocks.Count,
        AutoBlock = _state.Settings.AutoBlock,
        Sensitivity = _state.Settings.Sensitivity,
        BlockMinutes = _state.Settings.BlockMinutes,
        LastEventUtc = _lastEventUtc,
        LastError = _lastError,
    };

    private static AntiScanSettingsDto ToDto(AntiScanSettings settings) => new()
    {
        Enabled = settings.Enabled,
        Sensitivity = settings.Sensitivity,
        AutoBlock = settings.AutoBlock,
        BlockMinutes = settings.BlockMinutes,
        Allowlist = settings.Allowlist.ToList(),
    };

    private static AntiScanBlockDto ToDto(AntiScanBlock block) => new()
    {
        Address = block.Address,
        BlockedUntilUtc = block.BlockedUntilUtc,
        Reason = block.Reason,
        EventId = block.EventId,
    };

    private static AntiScanSettings CloneSettings(AntiScanSettings settings) => new()
    {
        Enabled = settings.Enabled,
        Sensitivity = settings.Sensitivity,
        AutoBlock = settings.AutoBlock,
        BlockMinutes = settings.BlockMinutes,
        Allowlist = settings.Allowlist.ToList(),
    };

    private static AntiScanSettings Settings()
    {
        lock (Gate)
        {
            return CloneSettings(_state.Settings);
        }
    }

    private static List<AntiScanBlockDto> GetBlocks()
    {
        lock (Gate)
        {
            return _state.Blocks.Select(ToDto).ToList();
        }
    }

    private static void SaveState()
    {
        AntiScanState snapshot;

        lock (Gate)
        {
            snapshot = new AntiScanState
            {
                Settings = CloneSettings(_state.Settings),
                Blocks = _state.Blocks
                    .Select(block => new AntiScanBlock
                    {
                        Address = block.Address,
                        BlockedUntilUtc = block.BlockedUntilUtc,
                        Reason = block.Reason,
                        EventId = block.EventId,
                    })
                    .ToList(),
            };
        }

        try
        {
            AntiScanStateFile.Save(ServicePaths.AntiScanStateFile, snapshot);
        }
        catch (Exception ex)
        {
            ServiceLog.Warning("WAG-ANTISCAN-017", "Failed to save anti-scan state.", ex);
        }
    }

    private static ServiceResponse Error(ServiceRequest request, string message) => new()
    {
        Id = request.Id,
        Ok = false,
        Error = message,
    };
}
