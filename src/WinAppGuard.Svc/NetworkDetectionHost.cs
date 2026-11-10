using WinAppGuard.Contracts;
using WinAppGuard.Core;
using WinAppGuard.Core.Diagnostics.NetworkDetection;

namespace WinAppGuard.Service;

/// <summary>
/// 5.0：网络被动检测宿主。
///
/// 职责边界：
///   - 只读 Suricata 的 eve.json，不解析包、不做 DPI；
///   - 只产生告警，不自动创建 WFP 过滤器；
///   - 用户手动拦截由 <see cref="NetworkBlockHost"/> 执行。
/// </summary>
internal static class NetworkDetectionHost
{
    private const int MaxAlerts = 1000;
    private static readonly TimeSpan AlertCooldown = TimeSpan.FromMinutes(30);

    private static readonly object Gate = new();
    private static readonly Dictionary<string, DateTime> LastAlertUtc =
        new(StringComparer.Ordinal);

    private static NetworkDetectionState _state = new();
    private static NetworkAlertStore? _store;
    private static EveAlertReader? _reader;
    private static List<NetworkAlert> _alerts = new();
    private static System.Threading.Timer? _pruneTimer;
    private static bool _started;
    private static string? _lastError;

    internal static bool Enabled
    {
        get { lock (Gate) { return _state.Settings.Enabled; } }
    }

    internal static string CurrentRuleProfile
    {
        get { lock (Gate) { return _state.Settings.RuleProfile; } }
    }

    internal static void Start()
    {
        lock (Gate)
        {
            _state = NetworkDetectionStateFile.Load(ServicePaths.NetworkDetectionStateFile);
            _store = new NetworkAlertStore(ServicePaths.NetworkDetectionDirectory);
            _alerts = new List<NetworkAlert>();
            LastAlertUtc.Clear();
            _lastError = null;

            try
            {
                _alerts = _store.LoadRecent(_state.Settings.RetentionDays, MaxAlerts);

                foreach (var alert in _alerts)
                {
                    if (_state.AlertStatuses.TryGetValue(alert.Id, out var status))
                    {
                        alert.Status = status;
                    }

                    // 动态 WFP 过滤器随服务重启消失，旧告警不能继续显示“已拦截”。
                    alert.BlockState = "none";
                }
            }
            catch (Exception ex)
            {
                ServiceLog.Warning("WAG-ND-020", "Failed to load network detection alerts.", ex);
            }

            _started = true;
        }

        NetworkBlockHost.Start();

        if (Enabled)
        {
            StartSuricata();
            StartReader();
        }

        lock (Gate)
        {
            _pruneTimer ??= new System.Threading.Timer(
                _ => Prune(),
                null,
                TimeSpan.FromMinutes(1),
                TimeSpan.FromMinutes(10));
        }

        ServiceLog.Info(
            "WAG-ND-021",
            $"Network detection started (enabled={Enabled}, profile={CurrentRuleProfile}, " +
            $"alerts={AlertCount()}, suricata={SuricataHost.Version ?? "未找到"}).");
    }

    internal static void Stop()
    {
        lock (Gate)
        {
            _started = false;
            _pruneTimer?.Dispose();
            _pruneTimer = null;
        }

        StopReader();
        SuricataHost.Stop();
        NetworkBlockHost.Stop();

        lock (Gate)
        {
            _alerts = new List<NetworkAlert>();
            _store = null;
            LastAlertUtc.Clear();
        }

        ServiceLog.Info("WAG-ND-022", "Network detection stopped.");
    }

    internal static ServiceResponse Query(ServiceRequest request)
    {
        lock (Gate)
        {
            return new ServiceResponse
            {
                Id = request.Id,
                Ok = true,
                NetworkAlerts = _alerts
                    .OrderByDescending(alert => alert.TimeUtc)
                    .Select(ToDto)
                    .ToList(),
                NetworkDetectionSettings = ToDto(_state.Settings),
                NetworkDetectionStatus = BuildStatusLocked(),
                NetworkBlocks = NetworkBlockHost.Snapshot()
                    .Select(ToDto)
                    .ToList(),
            };
        }
    }

    internal static ServiceResponse Configure(ServiceRequest request)
    {
        var dto = request.NetworkDetectionSettings;

        if (dto is null)
        {
            return Error(request, "缺少反网络攻击配置。");
        }

        bool enabled;
        string profile;
        List<string> categories;
        string captureDeviceId;

        var requestedCategories = (dto.EnabledRuleCategories ?? new List<string>())
            .Where(NetworkRuleCategories.IsKnown)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var requestedProfile = string.Equals(
            dto.RuleProfile, "full", StringComparison.OrdinalIgnoreCase)
            ? "full"
            : "standard";

        if (requestedCategories.Count == 0)
        {
            if (requestedProfile == "standard")
            {
                return Error(request, "至少需要启用一个规则分类。");
            }

            requestedCategories = NetworkRuleCategories.DefaultEnabled.ToList();
        }

        lock (Gate)
        {
            _state.Settings.Enabled = dto.Enabled;
            _state.Settings.Notify = dto.Notify;
            _state.Settings.RetentionDays = Math.Clamp(dto.RetentionDays, 1, 365);
            _state.Settings.RuleProfile = string.Equals(
                dto.RuleProfile, "full", StringComparison.OrdinalIgnoreCase)
                ? "full"
                : "standard";
            _state.Settings.EnabledRuleCategories = requestedCategories;
            _state.Settings.CaptureDeviceId = dto.CaptureDeviceId?.Trim() ?? string.Empty;

            enabled = _state.Settings.Enabled;
            profile = _state.Settings.RuleProfile;
            categories = requestedCategories.ToList();
            captureDeviceId = _state.Settings.CaptureDeviceId;
        }

        PersistState();

        if (enabled)
        {
            StartSuricata();
            StartReader();
            SuricataHost.Reload(profile, categories, captureDeviceId);
        }
        else
        {
            StopReader();
            SuricataHost.Stop();
        }

        ServiceLog.Operation(
            "WAG-ND-023",
            $"Network detection configured: enabled={enabled}, profile={profile}, " +
            $"capture={captureDeviceId}, " +
            $"retention={_state.Settings.RetentionDays}d, notify={_state.Settings.Notify}.");

        lock (Gate)
        {
            return new ServiceResponse
            {
                Id = request.Id,
                Ok = true,
                NetworkDetectionSettings = ToDto(_state.Settings),
                NetworkDetectionStatus = BuildStatusLocked(),
            };
        }
    }

    internal static ServiceResponse Ack(ServiceRequest request)
    {
        var id = request.NetworkAlertId;

        if (string.IsNullOrWhiteSpace(id))
        {
            return Error(request, "缺少告警 id。");
        }

        lock (Gate)
        {
            var alert = _alerts.FirstOrDefault(
                item => string.Equals(item.Id, id, StringComparison.Ordinal));

            if (alert is null)
            {
                return Error(request, "告警不存在或已被清空。");
            }

            alert.Status = "ack";
            _state.AlertStatuses[id] = "ack";
        }

        PersistState();

        return new ServiceResponse
        {
            Id = request.Id,
            Ok = true,
            NetworkDetectionStatus = BuildStatus(),
        };
    }

    /// <summary>5.8：把当前所有未读反网络攻击告警一次性标记为已读。</summary>
    internal static ServiceResponse AckAll(ServiceRequest request)
    {
        var changed = 0;

        lock (Gate)
        {
            foreach (var alert in _alerts)
            {
                if (!string.Equals(alert.Status, "new", StringComparison.Ordinal))
                {
                    continue;
                }

                alert.Status = "ack";
                _state.AlertStatuses[alert.Id] = "ack";
                changed++;
            }
        }

        PersistState();

        return new ServiceResponse
        {
            Id = request.Id,
            Ok = true,
            Affected = changed,
            NetworkDetectionStatus = BuildStatus(),
        };
    }

    internal static ServiceResponse Clear(ServiceRequest request)
    {
        int cleared;

        lock (Gate)
        {
            cleared = _alerts.Count;
            _store?.Clear();
            _alerts = new List<NetworkAlert>();
            _state.AlertStatuses.Clear();
            LastAlertUtc.Clear();
        }

        PersistState();

        ServiceLog.Operation(
            "WAG-ND-024",
            $"Network detection alerts cleared ({cleared} in memory).");

        return new ServiceResponse
        {
            Id = request.Id,
            Ok = true,
            Affected = cleared,
            NetworkDetectionStatus = BuildStatus(),
        };
    }

    internal static ServiceResponse Block(ServiceRequest request)
    {
        var kind = request.NetworkBlockKind;

        if (string.IsNullOrWhiteSpace(kind)
            || string.IsNullOrWhiteSpace(request.NetworkBlockTarget))
        {
            return Error(request, "缺少拦截范围或目标。");
        }

        string? ruleName = null;
        string? alertId = request.NetworkAlertId;

        lock (Gate)
        {
            if (!string.IsNullOrWhiteSpace(alertId))
            {
                var alert = _alerts.FirstOrDefault(
                    item => string.Equals(item.Id, alertId, StringComparison.Ordinal));

                if (alert is not null)
                {
                    ruleName = alert.Signature;
                }
            }
        }

        var response = NetworkBlockHost.Add(
            request,
            kind,
            request.NetworkBlockTarget,
            request.NetworkBlockMinutes,
            alertId,
            ruleName);

        if (response.Ok)
        {
            lock (Gate)
            {
                if (!string.IsNullOrWhiteSpace(alertId))
                {
                    var alert = _alerts.FirstOrDefault(
                        item => string.Equals(item.Id, alertId, StringComparison.Ordinal));

                    if (alert is not null)
                    {
                        alert.BlockState = "blocked";
                    }
                }
            }

            ServiceLog.Operation(
                "WAG-ND-025",
                $"User blocked network traffic: kind={kind}, target={request.NetworkBlockTarget}, " +
                $"alert={alertId ?? "-"}.");
        }

        return response;
    }

    internal static ServiceResponse Release(ServiceRequest request)
    {
        if (request.NetworkBlockReleaseAll)
        {
            var all = NetworkBlockHost.RemoveAll(request);

            if (all.Ok)
            {
                lock (Gate)
                {
                    foreach (var alert in _alerts)
                    {
                        alert.BlockState = "none";
                    }
                }
            }

            return all;
        }

        var blockId = request.NetworkBlockId;

        if (string.IsNullOrWhiteSpace(blockId))
        {
            return Error(request, "缺少拦截 id。");
        }

        var response = NetworkBlockHost.Remove(request, blockId);

        if (response.Ok)
        {
            lock (Gate)
            {
                foreach (var alert in _alerts)
                {
                    if (string.Equals(alert.Id, request.NetworkAlertId, StringComparison.Ordinal))
                    {
                        alert.BlockState = "none";
                    }
                }
            }
        }

        return response;
    }

    internal static string? GetLastError()
    {
        lock (Gate)
        {
            return _lastError;
        }
    }

    private static void StartSuricata()
    {
        string profile;
        List<string> categories;
        string captureDeviceId;

        lock (Gate)
        {
            profile = _state.Settings.RuleProfile;
            categories = _state.Settings.EnabledRuleCategories
                .Where(NetworkRuleCategories.IsKnown)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
            captureDeviceId = _state.Settings.CaptureDeviceId;
        }

        SuricataHost.Start(enabled: true, profile, categories, captureDeviceId);
    }

    private static void StartReader()
    {
        lock (Gate)
        {
            if (!_started || !_state.Settings.Enabled || _reader is not null)
            {
                return;
            }

            _reader = new EveAlertReader(
                ServicePaths.SuricataEveFile,
                OnAlert,
                message =>
                {
                    lock (Gate)
                    {
                        _lastError = message;
                    }
                });

            _reader.Start();
        }
    }

    private static void StopReader()
    {
        EveAlertReader? reader;

        lock (Gate)
        {
            reader = _reader;
            _reader = null;
        }

        reader?.Dispose();
    }

    private static void OnAlert(NetworkAlert alert)
    {
        lock (Gate)
        {
            if (!_started || !_state.Settings.Enabled)
            {
                return;
            }

            // 本机临时端口每次连接都会变，不能放进冷却键，否则同一目标会重复刷告警。
            var key = $"{alert.SignatureId}|{alert.RemoteAddress}|{alert.RemotePort}|{alert.Pid}";

            if (LastAlertUtc.TryGetValue(key, out var last)
                && DateTime.UtcNow - last < AlertCooldown)
            {
                return;
            }

            LastAlertUtc[key] = DateTime.UtcNow;

            try
            {
                _store?.Append(alert);
            }
            catch (Exception ex)
            {
                ServiceLog.Warning("WAG-ND-026", "Failed to append a network alert.", ex);
            }

            _alerts.Insert(0, alert);
            _state.AlertStatuses[alert.Id] = "new";

            if (_alerts.Count > MaxAlerts)
            {
                var excess = _alerts.Count - MaxAlerts;

                for (var i = MaxAlerts; i < _alerts.Count; i++)
                {
                    _state.AlertStatuses.Remove(_alerts[i].Id);
                }

                _alerts.RemoveRange(MaxAlerts, excess);
            }

            ServiceLog.Operation(
                "WAG-ND-027",
                $"Network alert: sig={alert.SignatureId}, severity={alert.Severity}, " +
                $"process={alert.ProcessName}, remote={alert.RemoteAddress}:{alert.RemotePort}, " +
                $"signature={alert.Signature}.");
        }

        PersistState();
    }

    private static void Prune()
    {
        NetworkAlertStore? store;
        int retention;

        lock (Gate)
        {
            store = _store;
            retention = _state.Settings.RetentionDays;
        }

        if (store is null)
        {
            return;
        }

        try
        {
            var removed = store.Prune(retention);

            lock (Gate)
            {
                var cutoff = DateTime.UtcNow.AddHours(-1);

                foreach (var key in LastAlertUtc
                             .Where(pair => pair.Value < cutoff)
                             .Select(pair => pair.Key)
                             .ToList())
                {
                    LastAlertUtc.Remove(key);
                }
            }

            if (removed > 0)
            {
                ServiceLog.Operation(
                    "WAG-ND-028",
                    $"Network alert retention pruned {removed} record(s) (retention={retention}d).");
            }
        }
        catch (Exception ex)
        {
            ServiceLog.Warning("WAG-ND-029", "Failed to prune network alerts.", ex);
        }
    }

    private static NetworkDetectionStatusDto BuildStatus()
    {
        lock (Gate)
        {
            return BuildStatusLocked();
        }
    }

    private static NetworkDetectionStatusDto BuildStatusLocked()
    {
        var blocks = NetworkBlockHost.Snapshot();

        return new NetworkDetectionStatusDto
        {
            Enabled = _state.Settings.Enabled,
            Running = SuricataHost.IsRunning,
            Collecting = _reader is not null && SuricataHost.IsRunning,
            SuricataVersion = SuricataHost.Version,
            RulesVersion = "ET Open 7.0.3",
            RuleCount = SuricataHost.RuleCount,
            RuleProfile = _state.Settings.RuleProfile,
            LastError = _lastError ?? SuricataHost.LastError,
            EventsSeen = _reader?.EventsSeen ?? 0,
            EventsLost = _reader?.EventsLost ?? 0,
            AlertsNew = _alerts.Count(alert => alert.Status == "new"),
            AlertsTotal = _alerts.Count,
            LastAlertUtc = _alerts.Count > 0 ? _alerts[0].TimeUtc : null,
            ActiveBlocks = blocks.Count,
            EvePath = ServicePaths.SuricataEveFile,
            CaptureDeviceName = SuricataHost.CaptureDeviceName,
            CaptureDeviceFallback = SuricataHost.CaptureFallback,
            CaptureDeviceNote = SuricataHost.CaptureNote,
        };
    }

    private static int AlertCount()
    {
        lock (Gate)
        {
            return _alerts.Count;
        }
    }

    private static void PersistState()
    {
        try
        {
            lock (Gate)
            {
                NetworkDetectionStateFile.Save(
                    ServicePaths.NetworkDetectionStateFile,
                    _state);
            }
        }
        catch (Exception ex)
        {
            ServiceLog.Warning("WAG-ND-030", "Failed to persist network detection state.", ex);
        }
    }

    private static NetworkAlertDto ToDto(NetworkAlert alert)
        => new()
        {
            Id = alert.Id,
            TimeUtc = alert.TimeUtc,
            SignatureId = alert.SignatureId,
            Signature = alert.Signature,
            Severity = alert.Severity,
            Category = alert.Category,
            Protocol = alert.Protocol,
            AppProto = alert.AppProto,
            LocalAddress = alert.LocalAddress,
            LocalPort = alert.LocalPort,
            RemoteAddress = alert.RemoteAddress,
            RemotePort = alert.RemotePort,
            Pid = alert.Pid,
            ProcessName = alert.ProcessName,
            ProcessPath = alert.ProcessPath,
            FlowId = alert.FlowId,
            Evidence = alert.Evidence,
            Status = alert.Status,
            BlockState = alert.BlockState,
        };

    private static NetworkDetectionSettingsDto ToDto(NetworkDetectionSettings settings)
        => new()
        {
            Enabled = settings.Enabled,
            RuleProfile = settings.RuleProfile,
            Notify = settings.Notify,
            RetentionDays = settings.RetentionDays,
            EnabledRuleCategories = settings.EnabledRuleCategories.ToList(),
            CaptureDeviceId = settings.CaptureDeviceId,
        };

    private static NetworkBlockDto ToDto(NetworkBlock block)
        => new()
        {
            Id = block.Id,
            Kind = block.Kind,
            Target = block.Target,
            RuleName = block.RuleName,
            AlertId = block.AlertId,
            CreatedUtc = block.CreatedUtc,
            ExpiresUtc = block.ExpiresUtc,
        };

    private static ServiceResponse Error(ServiceRequest request, string message)
        => new()
        {
            Id = request.Id,
            Ok = false,
            Error = message,
        };
}

