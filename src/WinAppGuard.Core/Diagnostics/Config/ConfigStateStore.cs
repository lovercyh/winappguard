using System.Text.Json;
using WinAppGuard.Core.Storage;

namespace WinAppGuard.Core.Diagnostics.Config;

/// <summary>
/// 4.5：<c>config/state.json</c> 的读写。
///
/// 5.9 起统一走 <see cref="JsonStateFile{T}"/>：新格式带 <c>schema/data</c> 外壳，
/// 旧的无外壳 JSON（camelCase）仍可直接读取；坏文件保留 <c>.corrupt-*</c>。
/// </summary>
public static class ConfigStateStore
{
    private const int SchemaVersion = 1;

    public static ConfigState Load(string path)
        => Load(path, out _, out _);

    public static ConfigState Load(string path, out string? error)
        => Load(path, out error, out _);

    public static ConfigState Load(string path, out string? error, out bool migrated)
    {
        var state = CreateFile(path).Load(out error, out migrated);

        if (state is null)
        {
            return new ConfigState();
        }

        Normalize(state);
        return state;
    }

    public static void Save(string path, ConfigState state)
        => CreateFile(path).Save(state);

    private static JsonStateFile<ConfigState> CreateFile(string path)
        => new(path, SchemaVersion)
        {
            Migrate = JsonStateFile<ConfigState>.Deserialize,
        };

    private static void Normalize(ConfigState state)
    {
        state.Baseline = NormalizeEntries(state.Baseline);
        state.Observed = NormalizeEntries(state.Observed);
    }

    private static List<ConfigEntry> NormalizeEntries(List<ConfigEntry>? entries)
        => (entries ?? new List<ConfigEntry>())
            .Where(entry => entry is not null && ConfigKinds.IsKnown(entry.Kind))
            .GroupBy(ConfigIntegrityAnalyzer.KeyOf, StringComparer.Ordinal)
            .Select(group => group.Last())
            .ToList();
}
