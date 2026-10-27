using System.Net;
using System.Text;
using System.Text.Json;

namespace WinAppGuard.Core.Diagnostics.AntiScan;

/// <summary>4.0：一条尚未到期的临时入站封禁。</summary>
public sealed class AntiScanBlock
{
    public string Address { get; set; } = string.Empty;

    public DateTime BlockedUntilUtc { get; set; }

    public string Reason { get; set; } = string.Empty;

    public string? EventId { get; set; }
}

/// <summary>4.0：反扫描持久化状态。</summary>
public sealed class AntiScanState
{
    public AntiScanSettings Settings { get; set; } = new();

    public List<AntiScanBlock> Blocks { get; set; } = new();
}

/// <summary>4.0：反扫描状态文件的原子读写；坏文件回退默认值。</summary>
public static class AntiScanStateFile
{
    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
    };

    public static AntiScanState Load(string path)
    {
        try
        {
            if (!File.Exists(path))
            {
                return new AntiScanState();
            }

            var state = JsonSerializer.Deserialize<AntiScanState>(
                File.ReadAllText(path, Encoding.UTF8), Options);

            if (state is null)
            {
                return new AntiScanState();
            }

            state.Settings ??= new AntiScanSettings();
            state.Settings.BlockMinutes = Math.Clamp(state.Settings.BlockMinutes, 5, 60);

            if (!string.Equals(
                    state.Settings.Sensitivity, "conservative", StringComparison.OrdinalIgnoreCase))
            {
                state.Settings.Sensitivity = "standard";
            }
            else
            {
                state.Settings.Sensitivity = "conservative";
            }

            state.Settings.Allowlist = (state.Settings.Allowlist ?? new List<string>())
                .Where(IsValidAddress)
                .Select(item => IPAddress.Parse(item.Trim()).ToString())
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            state.Blocks = (state.Blocks ?? new List<AntiScanBlock>())
                .Where(block => block is not null && IsValidAddress(block.Address))
                .ToList();

            foreach (var block in state.Blocks)
            {
                block.Address = IPAddress.Parse(block.Address.Trim()).ToString();
                block.Reason ??= string.Empty;
            }

            return state;
        }
        catch (Exception)
        {
            return new AntiScanState();
        }
    }

    public static void Save(string path, AntiScanState state)
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

    private static bool IsValidAddress(string? value)
        => !string.IsNullOrWhiteSpace(value) && IPAddress.TryParse(value.Trim(), out _);
}
