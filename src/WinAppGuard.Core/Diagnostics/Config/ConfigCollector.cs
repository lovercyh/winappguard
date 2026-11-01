using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using Microsoft.Win32;

namespace WinAppGuard.Core.Diagnostics.Config;

/// <summary>
/// 4.5：本机配置采集（只读）。
///
/// - hosts：`%SystemRoot%\System32\drivers\etc\hosts` 与 `hosts.ics`；
/// - WinINET 代理 / PAC：遍历 `HKEY_USERS` 下已加载的用户 hive；
/// - WinHTTP 代理：`HKLM\...\Internet Settings\Connections`；
/// - 组策略代理：`HKLM\SOFTWARE\Policies\...\Internet Settings`；
/// - DNS：物理网卡的 DNS 地址（跳过 VPN / 虚拟网卡，避免拨号时误报）。
///
/// 只读取配置值，不修改任何设置；不读进程、不读载荷。
/// </summary>
public static class ConfigCollector
{
    private static readonly string[] VirtualAdapterHints =
    {
        "VMware", "VirtualBox", "Hyper-V", "Virtual", "TAP-", "Tunnel",
        "VPN", "Loopback", "WAN Miniport", "Tailscale", "WireGuard", "ZeroTier",
    };

    public static List<ConfigEntry> Collect()
    {
        var result = new List<ConfigEntry>();

        AddIfNotNull(result, CollectHosts());
        result.AddRange(CollectUserProxies());
        AddIfNotNull(result, CollectWinHttp());
        AddIfNotNull(result, CollectPolicy());
        AddIfNotNull(result, CollectDns());

        return result;
    }

    /// <summary>hosts / hosts.ics 的规范化映射行（IP + 小写名称，已排序）。</summary>
    public static string NormalizeHosts(IEnumerable<string> lines)
    {
        var entries = new List<string>();

        foreach (var raw in lines)
        {
            var line = raw;
            var comment = line.IndexOf('#');

            if (comment >= 0)
            {
                line = line[..comment];
            }

            line = line.Trim();

            if (line.Length == 0)
            {
                continue;
            }

            var parts = line.Split((char[]?)null, StringSplitOptions.RemoveEmptyEntries);

            if (parts.Length < 2 || !IPAddress.TryParse(parts[0], out _))
            {
                continue;
            }

            var names = parts
                .Skip(1)
                .Select(name => name.ToLowerInvariant())
                .OrderBy(name => name, StringComparer.Ordinal);

            entries.Add($"{parts[0]} {string.Join(",", names)}");
        }

        entries.Sort(StringComparer.Ordinal);
        return string.Join("\n", entries);
    }

    private static ConfigEntry? CollectHosts()
    {
        var lines = new List<string>();

        foreach (var name in new[] { "hosts", "hosts.ics" })
        {
            try
            {
                var path = Path.Combine(
                    Environment.SystemDirectory, "drivers", "etc", name);

                if (File.Exists(path))
                {
                    lines.AddRange(File.ReadAllLines(path));
                }
            }
            catch (Exception)
            {
                // 读不到就当空文件；不要因为权限问题让整页不可用。
            }
        }

        var value = NormalizeHosts(lines);

        return new ConfigEntry
        {
            Kind = ConfigKinds.Hosts,
            Scope = string.Empty,
            Value = value,
            Summary = Truncate(value.Replace('\n', ';'), 240),
        };
    }

    private static IEnumerable<ConfigEntry> CollectUserProxies()
    {
        var entries = new List<ConfigEntry>();
        string[] sids;

        try
        {
            sids = Registry.Users.GetSubKeyNames();
        }
        catch (Exception)
        {
            return entries;
        }

        foreach (var sid in sids)
        {
            if (sid.EndsWith("_Classes", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            // 用 SID 作为稳定键：显示名会变，SID 不会，避免改名产生“新增配置”。
            var scope = sid;

            try
            {
                using var key = Registry.Users.OpenSubKey(
                    $@"{sid}\Software\Microsoft\Windows\CurrentVersion\Internet Settings");

                if (key is null)
                {
                    continue;
                }

                var enable = ToInt(key.GetValue("ProxyEnable"));
                var server = (key.GetValue("ProxyServer") as string ?? string.Empty).Trim();
                var autoDetect = ToInt(key.GetValue("AutoDetect"));
                var pac = (key.GetValue("AutoConfigURL") as string ?? string.Empty).Trim();

                entries.Add(new ConfigEntry
                {
                    Kind = ConfigKinds.Proxy,
                    Scope = scope,
                    Value = $"enable={enable};server={server};auto={autoDetect}",
                    Summary = $"enable={enable}; server={(server.Length == 0 ? "-" : server)}; auto={autoDetect}",
                });

                entries.Add(new ConfigEntry
                {
                    Kind = ConfigKinds.Pac,
                    Scope = scope,
                    Value = pac,
                    Summary = pac,
                });
            }
            catch (Exception)
            {
                // 单个用户 hive 读不到就跳过，不影响其他用户。
            }
        }

        return entries
            .OrderBy(entry => entry.Kind, StringComparer.Ordinal)
            .ThenBy(entry => entry.Scope, StringComparer.Ordinal);
    }

    private static ConfigEntry? CollectWinHttp()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections");

            var bytes = key?.GetValue("WinHttpSettings") as byte[];
            var value = bytes is { Length: > 0 } ? Convert.ToHexString(bytes) : string.Empty;

            return new ConfigEntry
            {
                Kind = ConfigKinds.WinHttp,
                Scope = string.Empty,
                Value = value,
                Summary = value.Length <= 48 ? value : value[..48] + "…",
            };
        }
        catch (Exception)
        {
            return null;
        }
    }

    private static ConfigEntry? CollectPolicy()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(
                @"SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings");

            if (key is null)
            {
                return new ConfigEntry
                {
                    Kind = ConfigKinds.Policy,
                    Scope = string.Empty,
                    Value = "enable=0;server=;pac=",
                    Summary = string.Empty,
                };
            }

            var enable = ToInt(key.GetValue("ProxyEnable"));
            var server = (key.GetValue("ProxyServer") as string ?? string.Empty).Trim();
            var pac = (key.GetValue("AutoConfigURL") as string ?? string.Empty).Trim();

            return new ConfigEntry
            {
                Kind = ConfigKinds.Policy,
                Scope = string.Empty,
                Value = $"enable={enable};server={server};pac={pac}",
                Summary = $"enable={enable}; server={(server.Length == 0 ? "-" : server)}; pac={(pac.Length == 0 ? "-" : pac)}",
            };
        }
        catch (Exception)
        {
            return null;
        }
    }

    private static ConfigEntry? CollectDns()
    {
        try
        {
            var servers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up
                    || nic.NetworkInterfaceType is not (NetworkInterfaceType.Ethernet
                        or NetworkInterfaceType.Wireless80211)
                    || LooksVirtual(nic.Description))
                {
                    continue;
                }

                foreach (var address in nic.GetIPProperties().DnsAddresses)
                {
                    if (address is null
                        || address.AddressFamily is not (AddressFamily.InterNetwork
                            or AddressFamily.InterNetworkV6)
                        || IPAddress.IsLoopback(address)
                        || address.Equals(IPAddress.Any)
                        || address.Equals(IPAddress.IPv6Any)
                        || address.ToString().StartsWith("fec0:", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    servers.Add(address.ToString());
                }
            }

            var value = string.Join(", ", servers.OrderBy(item => item, StringComparer.Ordinal));

            return new ConfigEntry
            {
                Kind = ConfigKinds.Dns,
                Scope = string.Empty,
                Value = value,
                Summary = value,
            };
        }
        catch (Exception)
        {
            return null;
        }
    }

    private static bool LooksVirtual(string description)
        => VirtualAdapterHints.Any(hint =>
            description.Contains(hint, StringComparison.OrdinalIgnoreCase));

    private static int ToInt(object? value) => value switch
    {
        int number => number,
        long number => (int)number,
        string text when int.TryParse(text, out var parsed) => parsed,
        _ => 0,
    };

    private static void AddIfNotNull(List<ConfigEntry> target, ConfigEntry? entry)
    {
        if (entry is not null)
        {
            target.Add(entry);
        }
    }

    private static string Truncate(string value, int max)
        => value.Length <= max ? value : value[..max] + "…";
}
