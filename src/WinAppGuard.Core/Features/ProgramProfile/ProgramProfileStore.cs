using WinAppGuard.Contracts;
using WinAppGuard.Contracts.Protocol;
using WinAppGuard.Core.Storage;
using WinAppGuard.Core.Diagnostics.Processes;
using WinAppGuard.Core.Diagnostics.NetworkDetection;

namespace WinAppGuard.Core.Features.ProgramProfile;

internal sealed class ProgramProfileRecord
{
    public string Path { get; set; } = string.Empty;

    public DateTime FirstSeenUtc { get; set; }

    public DateTime LastSeenUtc { get; set; }

    public int AlertCount { get; set; }

    public string? LastServiceInstance { get; set; }

    public string? LastLolbinRule { get; set; }

    public List<string> RemoteAddresses { get; set; } = new();

    public List<int> RemotePorts { get; set; } = new();

    public List<string> Categories { get; set; } = new();
}

internal sealed class ProgramProfilesState
{
    public Dictionary<string, ProgramProfileRecord> Profiles { get; set; } =
        new(StringComparer.OrdinalIgnoreCase);
}

/// <summary>
/// 6.0：程序画像的最小可用版本。
/// 只保存进程×网络的元数据，不保存命令行原文、载荷或域名查询正文。
/// </summary>
internal sealed class ProgramProfileStore : IDisposable
{
    private readonly object _gate = new();
    private readonly JsonStateFile<ProgramProfilesState> _file;
    private ProgramProfilesState _state;
    private bool _dirty;

    internal ProgramProfileStore(string path)
    {
        _file = new JsonStateFile<ProgramProfilesState>(path, schemaVersion: 1);
        _state = _file.Load(out var error) ?? new ProgramProfilesState();

        if (error is not null)
        {
            LocalLog.Warning($"[WAG-PROFILE-001] Failed to load program profiles: {error}");
        }
    }

    internal int Count
    {
        get { lock (_gate) { return _state.Profiles.Count; } }
    }

    internal void Observe(
        string? processPath,
        string? remoteAddress,
        int remotePort,
        string? category,
        string? serviceInstance,
        string? lolbinRule)
    {
        if (string.IsNullOrWhiteSpace(processPath))
        {
            return;
        }

        var key = processPath.Trim().ToLowerInvariant();
        var now = DateTime.UtcNow;

        lock (_gate)
        {
            if (!_state.Profiles.TryGetValue(key, out var profile))
            {
                profile = new ProgramProfileRecord
                {
                    Path = processPath,
                    FirstSeenUtc = now,
                };

                _state.Profiles[key] = profile;
            }

            profile.LastSeenUtc = now;
            profile.AlertCount++;

            if (!string.IsNullOrWhiteSpace(serviceInstance))
            {
                profile.LastServiceInstance = serviceInstance;
            }

            if (!string.IsNullOrWhiteSpace(lolbinRule))
            {
                profile.LastLolbinRule = lolbinRule;
            }

            AddBounded(profile.RemoteAddresses, remoteAddress);
            AddBounded(profile.RemotePorts, remotePort);
            AddBounded(profile.Categories, category);

            _dirty = true;
        }

        // 告警频率低，直接落盘；失败不影响检测。
        Save();
    }

    internal IReadOnlyList<ProgramProfileRecord> Snapshot(int limit = 200)
    {
        lock (_gate)
        {
            return _state.Profiles.Values
                .OrderByDescending(profile => profile.LastSeenUtc)
                .Take(limit)
                .Select(Clone)
                .ToList();
        }
    }

    internal void Clear()
    {
        lock (_gate)
        {
            _state = new ProgramProfilesState();
            _dirty = true;
        }

        Save();
    }

    internal void Save()
    {
        lock (_gate)
        {
            if (!_dirty)
            {
                return;
            }

            try
            {
                _file.Save(_state);
                _dirty = false;
            }
            catch (Exception ex)
            {
                LocalLog.Warning("[WAG-PROFILE-002] Failed to save program profiles.", ex);
            }
        }
    }

    public void Dispose() => Save();

    private static void AddBounded(List<string> list, string? value)
    {
        if (string.IsNullOrWhiteSpace(value) || list.Contains(value, StringComparer.OrdinalIgnoreCase))
        {
            return;
        }

        list.Add(value);

        if (list.Count > 50)
        {
            list.RemoveAt(0);
        }
    }

    private static void AddBounded(List<int> list, int value)
    {
        if (value <= 0 || list.Contains(value))
        {
            return;
        }

        list.Add(value);

        if (list.Count > 50)
        {
            list.RemoveAt(0);
        }
    }

    private static ProgramProfileRecord Clone(ProgramProfileRecord source) => new()
    {
        Path = source.Path,
        FirstSeenUtc = source.FirstSeenUtc,
        LastSeenUtc = source.LastSeenUtc,
        AlertCount = source.AlertCount,
        LastServiceInstance = source.LastServiceInstance,
        LastLolbinRule = source.LastLolbinRule,
        RemoteAddresses = source.RemoteAddresses.ToList(),
        RemotePorts = source.RemotePorts.ToList(),
        Categories = source.Categories.ToList(),
    };
}

/// <summary>6.0：画像宿主，由服务生命周期管理。</summary>
internal static class ProgramProfileHost
{
    private static ProgramProfileStore? _store;

    internal static int Count => _store?.Count ?? 0;

    internal static void Start()
    {
        _store ??= new ProgramProfileStore(ServicePaths.ProgramProfilesFile);
    }

    internal static void Stop()
    {
        _store?.Dispose();
        _store = null;
    }

    internal static void Observe(NetworkAlert alert, ProcessAttributionResult attribution)
    {
        if (_store is null)
        {
            return;
        }

        _store.Observe(
            attribution.Path,
            alert.RemoteAddress,
            alert.RemotePort,
            NetworkRuleCategoryIndex.Resolve(alert.SignatureId),
            attribution.ServiceInstance,
            attribution.LolbinRule);
    }

    internal static void Clear() => _store?.Clear();

    internal static IReadOnlyList<ProgramProfileRecord> Snapshot(int limit = 200)
        => _store?.Snapshot(limit) ?? Array.Empty<ProgramProfileRecord>();
}
