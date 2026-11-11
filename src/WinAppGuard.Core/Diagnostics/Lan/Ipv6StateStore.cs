using System.Text.Json;
using WinAppGuard.Core.Storage;

namespace WinAppGuard.Core.Diagnostics.Lan;

/// <summary>
/// 4.4：<c>ipv6/state.json</c> 的读写。
///
/// 5.9 起统一走 <see cref="JsonStateFile{T}"/>：新格式带 <c>schema/data</c> 外壳，
/// 旧的无外壳 JSON（camelCase）仍可直接读取；坏文件保留 <c>.corrupt-*</c>。
/// </summary>
public static class Ipv6StateStore
{
    private const int SchemaVersion = 1;

    public static Ipv6State Load(string path)
        => Load(path, out _, out _);

    public static Ipv6State Load(string path, out string? error)
        => Load(path, out error, out _);

    public static Ipv6State Load(string path, out string? error, out bool migrated)
    {
        var state = CreateFile(path).Load(out error, out migrated);

        if (state is null)
        {
            return new Ipv6State();
        }

        Normalize(state);
        return state;
    }

    public static void Save(string path, Ipv6State state)
        => CreateFile(path).Save(state);

    private static JsonStateFile<Ipv6State> CreateFile(string path)
        => new(path, SchemaVersion)
        {
            Migrate = JsonStateFile<Ipv6State>.Deserialize,
        };

    private static void Normalize(Ipv6State state)
    {
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
    }
}
