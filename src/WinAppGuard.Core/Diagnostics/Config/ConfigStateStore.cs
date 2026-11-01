using System.Text;
using System.Text.Json;

namespace WinAppGuard.Core.Diagnostics.Config;

/// <summary>4.5：`config/state.json` 的读写（原子替换，坏文件回退默认值）。</summary>
public static class ConfigStateStore
{
    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    public static ConfigState Load(string path)
    {
        try
        {
            if (!File.Exists(path))
            {
                return new ConfigState();
            }

            var state = JsonSerializer.Deserialize<ConfigState>(
                File.ReadAllText(path, Encoding.UTF8), Options) ?? new ConfigState();

            state.Baseline = Normalize(state.Baseline);
            state.Observed = Normalize(state.Observed);
            return state;
        }
        catch (Exception)
        {
            return new ConfigState();
        }
    }

    public static void Save(string path, ConfigState state)
    {
        var directory = Path.GetDirectoryName(path);

        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var temporary = path + ".tmp";
        File.WriteAllText(
            temporary,
            JsonSerializer.Serialize(state, Options),
            new UTF8Encoding(false));

        File.Move(temporary, path, overwrite: true);
    }

    private static List<ConfigEntry> Normalize(List<ConfigEntry>? entries)
        => (entries ?? new List<ConfigEntry>())
            .Where(entry => entry is not null && ConfigKinds.IsKnown(entry.Kind))
            .GroupBy(ConfigIntegrityAnalyzer.KeyOf, StringComparer.Ordinal)
            .Select(group => group.Last())
            .ToList();
}
