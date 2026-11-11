using System.Text.Json;
using WinAppGuard.Core.Storage;

namespace WinAppGuard.Core.Diagnostics.Lan;

/// <summary>
/// 4.2：<c>lan/state.json</c> 的读写。
///
/// 5.9 起统一走 <see cref="JsonStateFile{T}"/>：新格式带 <c>schema/data</c> 外壳，
/// 旧的无外壳 JSON（camelCase）仍可直接读取；坏文件保留 <c>.corrupt-*</c>。
/// </summary>
public static class LanStateStore
{
    private const int SchemaVersion = 1;

    public static LanState Load(string path)
        => Load(path, out _, out _);

    public static LanState Load(string path, out string? error)
        => Load(path, out error, out _);

    public static LanState Load(string path, out string? error, out bool migrated)
    {
        var state = CreateFile(path).Load(out error, out migrated);

        if (state is null)
        {
            return new LanState();
        }

        Normalize(state);
        return state;
    }

    public static void Save(string path, LanState state)
        => CreateFile(path).Save(state);

    public static int NormalizeRetention(int days) => days switch
    {
        15 => 15,
        30 => 30,
        _ => 7,
    };

    private static JsonStateFile<LanState> CreateFile(string path)
        => new(path, SchemaVersion)
        {
            Migrate = JsonStateFile<LanState>.Deserialize,
        };

    private static void Normalize(LanState state)
    {
        state.Settings ??= new LanSettings();
        state.Settings.RetentionDays = NormalizeRetention(state.Settings.RetentionDays);

        state.Gateways = (state.Gateways ?? new List<LanGateway>())
            .Where(item => !string.IsNullOrWhiteSpace(item.Ip) && !string.IsNullOrWhiteSpace(item.Mac))
            .GroupBy(item => $"{item.Adapter}|{item.Ip}", StringComparer.OrdinalIgnoreCase)
            .Select(group => group.First())
            .ToList();

        state.DhcpServers = (state.DhcpServers ?? new List<LanDhcpServer>())
            .Where(item => !string.IsNullOrWhiteSpace(item.ServerIp))
            .GroupBy(item => item.ServerIp, StringComparer.OrdinalIgnoreCase)
            .Select(group => group.First())
            .ToList();

        state.Blocks = (state.Blocks ?? new List<LanBlock>())
            .Where(item => !string.IsNullOrWhiteSpace(item.ServerIp) && item.UntilUtc > DateTime.UtcNow)
            .ToList();

        // 4.3：DNS 信任列表去空、去重；旧状态文件没有这一项时保持空列表。
        state.TrustedDnsServers = (state.TrustedDnsServers ?? new List<string>())
            .Where(item => !string.IsNullOrWhiteSpace(item))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();
    }
}
