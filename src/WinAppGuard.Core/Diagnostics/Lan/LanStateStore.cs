using System.Text;
using System.Text.Json;

namespace WinAppGuard.Core.Diagnostics.Lan;

/// <summary>4.2：`lan/state.json` 的读写（原子替换，坏文件回退默认值）。</summary>
public static class LanStateStore
{
    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    public static LanState Load(string path)
    {
        try
        {
            if (!File.Exists(path))
            {
                return new LanState();
            }

            var state = JsonSerializer.Deserialize<LanState>(
                File.ReadAllText(path, Encoding.UTF8), Options) ?? new LanState();

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

            return state;
        }
        catch (Exception)
        {
            return new LanState();
        }
    }

    public static void Save(string path, LanState state)
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

    public static int NormalizeRetention(int days) => days switch
    {
        15 => 15,
        30 => 30,
        _ => 7,
    };
}
