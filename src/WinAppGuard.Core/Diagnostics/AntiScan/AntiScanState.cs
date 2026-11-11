using System.Net;
using System.Text.Json;
using WinAppGuard.Core.Storage;

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

/// <summary>
/// 4.0：反扫描状态文件。
///
/// 5.9 起统一走 <see cref="JsonStateFile{T}"/>：新格式带 <c>schema/data</c> 外壳，
/// 旧的无外壳 JSON 仍可直接读取；坏文件保留 <c>.corrupt-*</c>。
/// </summary>
public static class AntiScanStateFile
{
    private const int SchemaVersion = 1;

    public static AntiScanState Load(string path)
        => Load(path, out _, out _);

    public static AntiScanState Load(string path, out string? error)
        => Load(path, out error, out _);

    public static AntiScanState Load(string path, out string? error, out bool migrated)
    {
        var state = CreateFile(path).Load(out error, out migrated);

        if (state is null)
        {
            return new AntiScanState();
        }

        Normalize(state);
        return state;
    }

    public static void Save(string path, AntiScanState state)
        => CreateFile(path).Save(state);

    private static JsonStateFile<AntiScanState> CreateFile(string path)
        => new(path, SchemaVersion)
        {
            Migrate = JsonStateFile<AntiScanState>.Deserialize,
        };

    private static void Normalize(AntiScanState state)
    {
        state.Settings ??= new AntiScanSettings();
        state.Settings.BlockMinutes = Math.Clamp(state.Settings.BlockMinutes, 5, 60);

        // 4.5：旧文件没有 Version 字段（反序列化为 0），把新协议开关补成默认开启；
        // 用户改过之后 SaveState 会写入 Version=Current，之后不再覆盖。
        if (state.Settings.Version < AntiScanSettingsVersion.Current)
        {
            state.Settings.DetectUdp = true;
            state.Settings.DetectIcmp = true;
            state.Settings.Version = AntiScanSettingsVersion.Current;
        }

        state.Settings.Sensitivity = string.Equals(
            state.Settings.Sensitivity, "conservative", StringComparison.OrdinalIgnoreCase)
            ? "conservative"
            : "standard";

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
    }

    private static bool IsValidAddress(string? value)
        => !string.IsNullOrWhiteSpace(value) && IPAddress.TryParse(value.Trim(), out _);
}
