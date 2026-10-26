using WinAppGuard.Contracts;
using WinAppGuard.Core;
using WinAppGuard.Core.Diagnostics;
using WinAppGuard.Core.Diagnostics.Ids;

namespace WinAppGuard.Service;

/// <summary>
/// 3.7：用户态 Flow IDS 宿主（服务端）。
///
/// 只消费两个已有 ETW 会话的回调：
///   - <see cref="TrafficHost"/> 的流观察（连接 + 字节，只有元数据）；
///   - <see cref="DnsHost"/> 的 DNS 观察。
/// 不新开 ETW 会话；IDS 关闭时把回调摘掉，保持 3.6 的开销。
///
/// 规则分析在 <see cref="IdsAnalyzer"/>（纯内存、可离线测试）；这里负责：
///   - 启停与设置持久化；
///   - 每 5 秒评估一次；
///   - 告警落盘、确认状态、抑制表；
///   - 给 IPC 提供快照。
///
/// 边界：只检测、不阻断；告警和抑制都在本地，不上传。
/// </summary>
internal static class IdsHost
{
    private static readonly object Gate = new();

    /// <summary>内存里保留的告警条数（顺序：新 → 旧）。</summary>
    private const int MaxAlerts = 1000;

    private static IdsAnalyzer _analyzer = new();
    private static IdsAlertStore? _store;
    private static IdsState _state = new();
    private static List<IdsAlert> _alerts = new();
    private static System.Threading.Timer? _timer;
    private static bool _started;
    private static int _evaluating;
    private static int _generation;
    private static DateTime? _lastAlertUtc;

    internal static bool Enabled
    {
        get { lock (Gate) { return _state.Settings.Enabled; } }
    }

    internal static bool Collecting
    {
        get
        {
            lock (Gate)
            {
                return _started && _state.Settings.Enabled && TrafficHost.Collecting;
            }
        }
    }

    internal static void Start()
    {
        lock (Gate)
        {
            _state = IdsStateFile.Load(ServicePaths.IdsStateFile);
            _store = new IdsAlertStore(ServicePaths.IdsDirectory);
            _analyzer.Clear();

            try
            {
                _alerts = _store.LoadRecent(_state.Settings.RetentionDays, MaxAlerts);
            }
            catch (Exception ex)
            {
                // 告警文件读不了不能让服务起不来；先空着，后续写入会重试。
                _alerts = new List<IdsAlert>();
                ServiceLog.Warning("WAG-IDS-004", "Failed to load IDS alerts.", ex);
            }

            _started = true;
            _lastAlertUtc = _alerts.Count > 0 ? _alerts[0].TimeUtc : null;

            var removed = _store.Prune(_state.Settings.RetentionDays);

            if (removed > 0)
            {
                ServiceLog.Operation(
                    "WAG-IDS-009",
                    $"IDS alert retention pruned {removed} record(s) (retention={_state.Settings.RetentionDays}d).");
            }

            // 把上次运行遗留、已经不存在于告警里的确认状态清掉，避免状态文件无限增长。
            var ids = _alerts.Select(alert => alert.Id).ToHashSet(StringComparer.Ordinal);

            foreach (var key in _state.AlertStatuses.Keys.Where(key => !ids.Contains(key)).ToList())
            {
                _state.AlertStatuses.Remove(key);
            }
        }

        ApplyCapture();

        lock (Gate)
        {
            _timer ??= new System.Threading.Timer(
                _ => Tick(),
                state: null,
                dueTime: TimeSpan.FromSeconds(5),
                period: TimeSpan.FromSeconds(5));
        }

        ServiceLog.Info(
            "WAG-IDS-001",
            $"IDS started (enabled={Enabled}, sensitivity={GetSettings().Sensitivity}, " +
            $"retention={GetSettings().RetentionDays}d, alerts={AlertsCount()}).");
    }

    internal static void Stop()
    {
        bool wasEnabled;

        lock (Gate)
        {
            wasEnabled = _started && _state.Settings.Enabled;
            _started = false;
            _generation++;

            _timer?.Dispose();
            _timer = null;
        }

        // 先摘回调再停 ETW：避免停机时还有事件进入分析器。
        DetachCapture();

        lock (Gate)
        {
            _alerts = new List<IdsAlert>();
            _store = null;
            _analyzer.Clear();
        }

        ServiceLog.Info("WAG-IDS-002", $"IDS stopped (wasEnabled={wasEnabled}).");
    }

    // ---------------- 采集回调 ----------------

    private static void OnFlow(NetworkFlowObservation observation)
        => _analyzer.ObserveFlow(observation);

    private static void OnDns(DnsQueryRecord record)
        => _analyzer.ObserveDns(new NetworkDnsObservation(
            record.TimeUtc,
            record.Pid,
            record.QueryName,
            record.Status ?? string.Empty,
            record.ProcessName,
            record.ProcessPath));

    /// <summary>按当前设置挂/摘回调；只对已有 ETW 会话做 fan-out。</summary>
    private static void ApplyCapture()
    {
        bool enabled;

        lock (Gate)
        {
            enabled = _started && _state.Settings.Enabled;
        }

        if (enabled)
        {
            TrafficHost.SetFlowSink(OnFlow, capture: true);
            DnsHost.SetQuerySink(OnDns);
        }
        else
        {
            DetachCapture();
        }
    }

    private static void DetachCapture()
    {
        TrafficHost.SetFlowSink(null, capture: false);
        DnsHost.SetQuerySink(null);
    }

    // ---------------- 规则评估 ----------------

    private static void Tick()
    {
        // 评估可能超过 5 秒（进程路径解析、抑制匹配）；重叠时直接跳过这一轮。
        if (Interlocked.CompareExchange(ref _evaluating, 1, 0) != 0)
        {
            return;
        }

        try
        {
            TickCore();
        }
        finally
        {
            Interlocked.Exchange(ref _evaluating, 0);
        }
    }

    private static void TickCore()
    {
        IdsSettings settings;
        List<IdsSuppression> suppressions;
        int generation;

        lock (Gate)
        {
            if (!_started || !_state.Settings.Enabled)
            {
                return;
            }

            settings = CloneSettings(_state.Settings);
            suppressions = _state.Suppressions
                .Select(CloneSuppression)
                .ToList();
            generation = _generation;
        }

        List<IdsAlert> raised;

        try
        {
            raised = _analyzer.Evaluate(DateTime.UtcNow, settings, suppressions);
        }
        catch (Exception ex)
        {
            ServiceLog.Warning("WAG-IDS-005", "IDS rule evaluation failed.", ex);
            return;
        }

        if (raised.Count == 0)
        {
            return;
        }

        lock (Gate)
        {
            if (!_started || !_state.Settings.Enabled || generation != _generation)
            {
                return;
            }

            foreach (var alert in raised)
            {
                try
                {
                    _store?.Append(alert);
                }
                catch (Exception ex)
                {
                    ServiceLog.Warning(
                        "WAG-IDS-003",
                        $"Failed to append IDS alert {alert.RuleId}/{alert.Id} to disk.",
                        ex);
                }

                _alerts.Insert(0, alert);
                _state.AlertStatuses[alert.Id] = "new";
                _lastAlertUtc = alert.TimeUtc;

                ServiceLog.Operation(
                    "WAG-IDS-010",
                    $"IDS alert: rule={alert.RuleId}, severity={alert.Severity}, " +
                    $"pid={alert.Pid}, process={alert.ProcessName}, target={alert.Target}, " +
                    $"evidence={alert.Evidence}.");
            }

            if (_alerts.Count > MaxAlerts)
            {
                var excess = _alerts.Count - MaxAlerts;

                for (var i = MaxAlerts; i < _alerts.Count; i++)
                {
                    _state.AlertStatuses.Remove(_alerts[i].Id);
                }

                _alerts.RemoveRange(MaxAlerts, excess);
            }
        }

        PersistState();
    }

    // ---------------- IPC ----------------

    internal static ServiceResponse QueryAlerts(ServiceRequest request)
    {
        List<IdsAlertDto> alerts;
        List<IdsSuppressionDto> suppressions;
        IdsSettingsDto settings;
        IdsStatusDto status;

        lock (Gate)
        {
            alerts = _alerts
                .Select(ToDto)
                .ToList();

            suppressions = _state.Suppressions
                .Select(ToDto)
                .ToList();

            settings = ToDto(_state.Settings);
            status = BuildStatusLocked();
        }

        return new ServiceResponse
        {
            Id = request.Id,
            Ok = true,
            IdsAlerts = alerts,
            IdsSuppressions = suppressions,
            IdsSettings = settings,
            IdsStatus = status,
        };
    }

    internal static ServiceResponse Configure(ServiceRequest request)
    {
        var dto = request.IdsSettings;

        if (dto is null)
        {
            return Error(request, "缺少 IDS 设置。");
        }

        int retentionDays;

        lock (Gate)
        {
            var settings = _state.Settings;
            settings.Enabled = dto.Enabled;
            settings.Sensitivity = string.Equals(
                dto.Sensitivity, "conservative", StringComparison.OrdinalIgnoreCase)
                ? "conservative"
                : "standard";
            settings.RetentionDays = Math.Clamp(dto.RetentionDays, 1, 365);
            settings.BeaconingRule = dto.BeaconingRule;
            settings.ScanRule = dto.ScanRule;
            settings.LateralRule = dto.LateralRule;
            settings.DnsRule = dto.DnsRule;
            retentionDays = settings.RetentionDays;

            if (request.IdsRemoveSuppressionIds is { Count: > 0 } removeIds)
            {
                var set = removeIds.ToHashSet(StringComparer.Ordinal);
                _state.Suppressions.RemoveAll(item => set.Contains(item.Id));
            }

            _generation++;

            if (!settings.Enabled)
            {
                _analyzer.Clear();
            }
        }

        PersistState();
        ApplyCapture();
        PruneToRetention(retentionDays);

        ServiceLog.Operation(
            "WAG-IDS-007",
            $"IDS configured: enabled={Enabled}, sensitivity={GetSettings().Sensitivity}, " +
            $"retention={GetSettings().RetentionDays}d, " +
            $"rules=beacon:{GetSettings().BeaconingRule}/scan:{GetSettings().ScanRule}/" +
            $"lateral:{GetSettings().LateralRule}/dns:{GetSettings().DnsRule}.");

        return new ServiceResponse
        {
            Id = request.Id,
            Ok = true,
            IdsSettings = GetSettings(),
            IdsSuppressions = GetSuppressions(),
            IdsStatus = GetStatus(),
        };
    }

    internal static ServiceResponse Ack(ServiceRequest request)
    {
        var id = request.IdsAlertId;

        if (string.IsNullOrWhiteSpace(id))
        {
            return Error(request, "缺少告警 id。");
        }

        lock (Gate)
        {
            var alert = _alerts.FirstOrDefault(item => string.Equals(item.Id, id, StringComparison.Ordinal));

            if (alert is null)
            {
                return Error(request, "告警不存在或已被清空。");
            }

            _state.AlertStatuses[id] = "ack";
            alert.Status = "ack";
        }

        PersistState();

        return new ServiceResponse
        {
            Id = request.Id,
            Ok = true,
            IdsStatus = GetStatus(),
        };
    }

    internal static ServiceResponse Suppress(ServiceRequest request)
    {
        var dto = request.IdsSuppression;

        if (dto is null)
        {
            return Error(request, "缺少抑制内容。");
        }

        if (request.IdsRemoveSuppression)
        {
            if (string.IsNullOrWhiteSpace(dto.Id))
            {
                return Error(request, "缺少抑制 id。");
            }

            int removed;

            lock (Gate)
            {
                removed = _state.Suppressions.RemoveAll(
                    item => string.Equals(item.Id, dto.Id, StringComparison.Ordinal));
            }

            if (removed == 0)
            {
                return Error(request, "抑制不存在。");
            }

            PersistState();

            ServiceLog.Operation(
                "WAG-IDS-008",
                $"IDS suppression removed: {dto.Id}.");

            return new ServiceResponse
            {
                Id = request.Id,
                Ok = true,
                Affected = removed,
                IdsSuppressions = GetSuppressions(),
            };
        }

        var suppression = new IdsSuppression
        {
            Id = string.IsNullOrWhiteSpace(dto.Id) ? Guid.NewGuid().ToString("N") : dto.Id,
            RuleId = string.IsNullOrWhiteSpace(dto.RuleId) ? "*" : dto.RuleId.Trim(),
            ProcessPath = string.IsNullOrWhiteSpace(dto.ProcessPath) ? null : dto.ProcessPath.Trim(),
            ProcessName = string.IsNullOrWhiteSpace(dto.ProcessName) ? null : dto.ProcessName.Trim(),
            Target = string.IsNullOrWhiteSpace(dto.Target) ? null : dto.Target.Trim(),
            UntilUtc = dto.UntilUtc,
        };

        lock (Gate)
        {
            _state.Suppressions.Add(suppression);
        }

        PersistState();

        ServiceLog.Operation(
            "WAG-IDS-008",
            $"IDS suppression added: id={suppression.Id}, rule={suppression.RuleId}, " +
            $"process={suppression.ProcessPath ?? suppression.ProcessName ?? "*"}, " +
            $"target={suppression.Target ?? "*"}, until={suppression.UntilUtc?.ToString("O") ?? "never"}.");

        return new ServiceResponse
        {
            Id = request.Id,
            Ok = true,
            Affected = 1,
            IdsSuppressions = GetSuppressions(),
        };
    }

    internal static ServiceResponse Clear(ServiceRequest request)
    {
        int cleared;

        lock (Gate)
        {
            cleared = _alerts.Count;
            _generation++;
            _store?.Clear();
            _alerts = new List<IdsAlert>();
            _state.AlertStatuses.Clear();
            _lastAlertUtc = null;
        }

        PersistState();

        ServiceLog.Operation("WAG-IDS-006", $"IDS alerts cleared ({cleared} in memory).");

        return new ServiceResponse
        {
            Id = request.Id,
            Ok = true,
            Affected = cleared,
            IdsStatus = GetStatus(),
        };
    }

    private static void PruneToRetention(int retentionDays)
    {
        IdsAlertStore? store;

        lock (Gate)
        {
            store = _store;
        }

        if (store is null)
        {
            return;
        }

        int removed;

        try
        {
            removed = store.Prune(retentionDays);
        }
        catch (Exception ex)
        {
            ServiceLog.Warning("WAG-IDS-004", "Failed to prune IDS alerts.", ex);
            return;
        }

        if (removed <= 0)
        {
            return;
        }

        lock (Gate)
        {
            _alerts = store.LoadRecent(retentionDays, MaxAlerts);
            _lastAlertUtc = _alerts.Count > 0 ? _alerts[0].TimeUtc : null;

            var ids = _alerts.Select(alert => alert.Id).ToHashSet(StringComparer.Ordinal);

            foreach (var key in _state.AlertStatuses.Keys.Where(key => !ids.Contains(key)).ToList())
            {
                _state.AlertStatuses.Remove(key);
            }
        }

        PersistState();

        ServiceLog.Operation(
            "WAG-IDS-009",
            $"IDS alert retention applied on configure ({removed} removed, retention={retentionDays}d).");
    }

    // ---------------- 状态 / DTO ----------------

    internal static IdsStatusDto GetStatus()
    {
        lock (Gate)
        {
            return BuildStatusLocked();
        }
    }

    private static IdsStatusDto BuildStatusLocked() => new()
    {
        Enabled = _state.Settings.Enabled,
        Collecting = _started && _state.Settings.Enabled && TrafficHost.Collecting,
        Sensitivity = _state.Settings.Sensitivity,
        FlowCount = _analyzer.FlowCount,
        EventsSeen = _analyzer.EventsSeen,
        EventsLost = _analyzer.EventsLost + TrafficHost.FlowParseFailures,
        AlertsNew = _alerts.Count(alert => AlertStatus(alert.Id) == "new"),
        AlertsTotal = _alerts.Count,
        LastAlertUtc = _lastAlertUtc,
        SuppressionCount = _state.Suppressions.Count,
    };

    private static IdsSettingsDto GetSettings()
    {
        lock (Gate)
        {
            return ToDto(_state.Settings);
        }
    }

    private static List<IdsSuppressionDto> GetSuppressions()
    {
        lock (Gate)
        {
            return _state.Suppressions.Select(ToDto).ToList();
        }
    }

    private static int AlertsCount()
    {
        lock (Gate)
        {
            return _alerts.Count;
        }
    }

    private static string AlertStatus(string id)
        => _state.AlertStatuses.TryGetValue(id, out var status) ? status : "new";

    private static IdsAlertDto ToDto(IdsAlert alert) => new()
    {
        Id = alert.Id,
        TimeUtc = alert.TimeUtc,
        Severity = alert.Severity,
        RuleId = alert.RuleId,
        RuleName = alert.RuleName,
        Pid = alert.Pid,
        ProcessName = alert.ProcessName,
        ProcessPath = alert.ProcessPath,
        Target = alert.Target,
        Evidence = alert.Evidence,
        Status = AlertStatus(alert.Id),
    };

    private static IdsSuppressionDto ToDto(IdsSuppression suppression) => new()
    {
        Id = suppression.Id,
        RuleId = suppression.RuleId,
        ProcessPath = suppression.ProcessPath,
        ProcessName = suppression.ProcessName,
        Target = suppression.Target,
        UntilUtc = suppression.UntilUtc,
    };

    private static IdsSettingsDto ToDto(IdsSettings settings) => new()
    {
        Enabled = settings.Enabled,
        Sensitivity = settings.Sensitivity,
        RetentionDays = settings.RetentionDays,
        BeaconingRule = settings.BeaconingRule,
        ScanRule = settings.ScanRule,
        LateralRule = settings.LateralRule,
        DnsRule = settings.DnsRule,
    };

    private static IdsSettings CloneSettings(IdsSettings settings) => new()
    {
        Enabled = settings.Enabled,
        Sensitivity = settings.Sensitivity,
        RetentionDays = settings.RetentionDays,
        BeaconingRule = settings.BeaconingRule,
        ScanRule = settings.ScanRule,
        LateralRule = settings.LateralRule,
        DnsRule = settings.DnsRule,
    };

    private static IdsSuppression CloneSuppression(IdsSuppression suppression) => new()
    {
        Id = suppression.Id,
        RuleId = suppression.RuleId,
        ProcessPath = suppression.ProcessPath,
        ProcessName = suppression.ProcessName,
        Target = suppression.Target,
        UntilUtc = suppression.UntilUtc,
    };

    private static void PersistState()
    {
        IdsState snapshot;

        lock (Gate)
        {
            snapshot = new IdsState
            {
                Settings = CloneSettings(_state.Settings),
                Suppressions = _state.Suppressions.Select(CloneSuppression).ToList(),
                AlertStatuses = new Dictionary<string, string>(
                    _state.AlertStatuses, StringComparer.Ordinal),
            };
        }

        try
        {
            IdsStateFile.Save(ServicePaths.IdsStateFile, snapshot);
        }
        catch (Exception ex)
        {
            ServiceLog.Warning("WAG-IDS-004", "Failed to save IDS state.", ex);
        }
    }

    private static ServiceResponse Error(ServiceRequest request, string message) => new()
    {
        Id = request.Id,
        Ok = false,
        Error = message,
    };
}
