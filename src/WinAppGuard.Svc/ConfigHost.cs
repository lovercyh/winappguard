using WinAppGuard.Contracts;
using WinAppGuard.Core;
using WinAppGuard.Core.Diagnostics.Config;
using WinAppGuard.Core.Diagnostics.Lan;

namespace WinAppGuard.Service;

/// <summary>
/// 4.5：本机配置完整性宿主（hosts / 代理 / PAC / WinHTTP / DNS）。
///
/// 每 30 秒采集一次只读快照，与「上一次观察值」比较；变化才产生事件。
/// 基线用 `config/state.json` 持久化；事件写 `config/events-YYYYMMDD.jsonl`，
/// 保留期跟随 4.2 的 7/15/30 天。
///
/// 只告警，不自动回滚：hosts / 代理可能是用户或企业策略有意配置的。
/// </summary>
internal static class ConfigHost
{
    private static readonly object Gate = new();
    private static readonly TimeSpan TickInterval = TimeSpan.FromSeconds(30);

    private const int MaxEvents = 500;

    private static ConfigIntegrityAnalyzer _analyzer = new();
    private static LanEventStore? _store;
    private static System.Threading.Timer? _timer;
    private static List<LanEventDto> _events = new();
    private static List<ConfigEntry> _current = new();
    private static bool _started;
    private static DateTime _nextPruneUtc = DateTime.MinValue;
    private static string? _lastError;

    internal static int EventCount
    {
        get { lock (Gate) { return _events.Count; } }
    }

    internal static void Start()
    {
        var state = ConfigStateStore.Load(ServicePaths.ConfigStateFile);
        var analyzer = new ConfigIntegrityAnalyzer();
        analyzer.Load(state.BaselineUtc, state.Baseline, state.Observed);

        var store = new LanEventStore(ServicePaths.ConfigDirectory);

        lock (Gate)
        {
            _analyzer = analyzer;
            _store = store;
            _started = true;
            _lastError = null;
            _events = store.ReadRecent(MaxEvents).Select(ToDto).ToList();
        }

        // 启动时立刻采一次：没有基线就建立基线，有基线就检查离线期间的改动。
        Tick();

        lock (Gate)
        {
            _timer ??= new System.Threading.Timer(
                _ => Tick(),
                state: null,
                dueTime: TickInterval,
                period: TickInterval);
        }

        ServiceLog.Info(
            "WAG-CONFIG-001",
            $"Config integrity monitor started (baseline={analyzer.HasBaseline}, " +
            $"items={analyzer.BaselineCount}).");
    }

    internal static void Stop()
    {
        lock (Gate)
        {
            _started = false;
            _timer?.Dispose();
            _timer = null;
        }

        SaveState();
        ServiceLog.Info("WAG-CONFIG-002", "Config integrity monitor stopped.");
    }

    internal static ServiceResponse Query(ServiceRequest request)
    {
        lock (Gate)
        {
            var items = BuildItemsLocked();
            var changed = items.Count(item => item.Changed);

            return new ServiceResponse
            {
                Id = request.Id,
                Ok = true,
                ConfigIntegrityStatus = new ConfigIntegrityStatusDto
                {
                    BaselineReady = _analyzer.HasBaseline,
                    BaselineUtc = _analyzer.BaselineUtc,
                    ItemCount = items.Count,
                    ChangedCount = changed,
                    EventCount = _events.Count,
                    LastError = _lastError,
                },
                ConfigItems = items,
                ConfigIntegrityEvents = _events.ToList(),
            };
        }
    }

    internal static ServiceResponse Clear(ServiceRequest request)
    {
        LanEventStore? store;

        lock (Gate)
        {
            store = _store;
            _events = new List<LanEventDto>();
        }

        try
        {
            store?.Clear();
        }
        catch (Exception ex)
        {
            ServiceLog.Warning("WAG-CONFIG-003", "Failed to clear config events.", ex);
        }

        ServiceLog.Operation("WAG-CONFIG-004", "Config integrity events cleared.");
        return Query(request);
    }

    internal static ServiceResponse Rebaseline(ServiceRequest request)
    {
        List<ConfigEntry> entries;

        try
        {
            entries = ConfigCollector.Collect();
        }
        catch (Exception ex)
        {
            lock (Gate)
            {
                _lastError = ex.Message;
            }

            ServiceLog.Warning("WAG-CONFIG-005", "Failed to collect config for rebaseline.", ex);
            return Query(request);
        }

        var now = DateTime.UtcNow;

        lock (Gate)
        {
            _current = entries;
            _analyzer.SetBaseline(entries, now);
            _lastError = null;
        }

        SaveState();
        ServiceLog.Operation("WAG-CONFIG-006", $"Config baseline reset ({entries.Count} item(s)).");
        return Query(request);
    }

    private static void Tick()
    {
        try
        {
            List<ConfigEntry> entries;

            try
            {
                entries = ConfigCollector.Collect();
            }
            catch (Exception ex)
            {
                lock (Gate)
                {
                    _lastError = ex.Message;
                }

                ServiceLog.Warning("WAG-CONFIG-007", "Failed to collect local config.", ex);
                return;
            }

            var now = DateTime.UtcNow;
            List<ConfigChange> changes;

            lock (Gate)
            {
                if (!_started)
                {
                    return;
                }

                _current = entries;
                changes = _analyzer.Compare(entries, now);
                _lastError = null;
            }

            foreach (var change in changes)
            {
                RecordEvent(change, now);
            }

            if (changes.Count > 0)
            {
                SaveState();
            }

            if (now >= _nextPruneUtc)
            {
                var retention = LanHost.RetentionDays;
                _store?.Prune(retention, now);
                _nextPruneUtc = now.AddHours(6);
            }
        }
        catch (Exception ex)
        {
            ServiceLog.Warning("WAG-CONFIG-008", "Config integrity tick failed.", ex);
        }
    }

    private static void RecordEvent(ConfigChange change, DateTime now)
    {
        var item = new LanEvent
        {
            TimeUtc = now,
            Kind = change.EventKind,
            Severity = change.Severity,
            Adapter = change.Scope,
            Detail = change.Detail,
            Blocked = false,
        };

        LanEventStore? store;

        lock (Gate)
        {
            store = _store;
            _events.Insert(0, ToDto(item));

            if (_events.Count > MaxEvents)
            {
                _events.RemoveRange(MaxEvents, _events.Count - MaxEvents);
            }
        }

        store?.Append(item);

        ServiceLog.Operation(
            "WAG-CONFIG-009",
            $"Config change: kind={item.Kind}, severity={item.Severity}, scope={item.Adapter}, " +
            $"detail={item.Detail}");
    }

    private static List<ConfigItemDto> BuildItemsLocked()
    {
        var entries = _current.Count > 0
            ? _current
            : _analyzer.ExportState().Baseline;

        var items = new List<ConfigItemDto>();

        foreach (var entry in entries)
        {
            var hasBaseline = _analyzer.TryGetBaseline(entry.Kind, entry.Scope, out var baseline);

            items.Add(new ConfigItemDto
            {
                Kind = entry.Kind,
                Scope = entry.Scope,
                Current = entry.Summary,
                Baseline = hasBaseline ? baseline.Summary : string.Empty,
                BaselineExists = hasBaseline,
                Changed = hasBaseline
                          && !string.Equals(baseline.Value, entry.Value, StringComparison.Ordinal),
                Severity = ConfigKinds.SeverityOf(entry.Kind),
            });
        }

        return items
            .OrderBy(item => KindOrder(item.Kind))
            .ThenBy(item => item.Scope, StringComparer.Ordinal)
            .ToList();
    }

    private static int KindOrder(string kind) => kind switch
    {
        ConfigKinds.Hosts => 0,
        ConfigKinds.Proxy => 1,
        ConfigKinds.Pac => 2,
        ConfigKinds.WinHttp => 3,
        ConfigKinds.Policy => 4,
        ConfigKinds.Dns => 5,
        _ => 9,
    };

    private static void SaveState()
    {
        ConfigState state;

        lock (Gate)
        {
            state = _analyzer.ExportState();
        }

        try
        {
            ConfigStateStore.Save(ServicePaths.ConfigStateFile, state);
        }
        catch (Exception ex)
        {
            ServiceLog.Warning("WAG-CONFIG-010", "Failed to save config integrity state.", ex);
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
}
