using System.Text;
using System.Text.Json;

namespace WinAppGuard.Core.Diagnostics.Lan;

/// <summary>4.4：`ipv6/state.json` 的读写（原子替换，坏文件回退默认值）。</summary>
public static class Ipv6StateStore
{
    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    public static Ipv6State Load(string path)
    {
        try
        {
            if (!File.Exists(path))
            {
                return new Ipv6State();
            }

            var state = JsonSerializer.Deserialize<Ipv6State>(
                File.ReadAllText(path, Encoding.UTF8), Options) ?? new Ipv6State();

            state.Routers = (state.Routers ?? new List<Ipv6Router>())
                .Where(item => !string.IsNullOrWhiteSpace(item.LinkLocal))
                .GroupBy(item => item.LinkLocal, StringComparer.OrdinalIgnoreCase)
                .Select(group => group.First())
                .ToList();

            state.DhcpServers = (state.DhcpServers ?? new List<Ipv6DhcpServer>())
                .Where(item => !string.IsNullOrWhiteSpace(item.ServerId))
                .GroupBy(item => item.ServerId, StringComparer.OrdinalIgnoreCase)
                .Select(group => group.First())
                .ToList();

            state.Neighbors = (state.Neighbors ?? new List<Ipv6Neighbor>())
                .Where(item => !string.IsNullOrWhiteSpace(item.Address))
                .GroupBy(item => item.Address, StringComparer.OrdinalIgnoreCase)
                .Select(group => group.First())
                .ToList();

            state.TrustedRouters = (state.TrustedRouters ?? new List<string>())
                .Where(item => !string.IsNullOrWhiteSpace(item))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            state.TrustedDhcpServers = (state.TrustedDhcpServers ?? new List<string>())
                .Where(item => !string.IsNullOrWhiteSpace(item))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            return state;
        }
        catch (Exception)
        {
            return new Ipv6State();
        }
    }

    public static void Save(string path, Ipv6State state)
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
}
