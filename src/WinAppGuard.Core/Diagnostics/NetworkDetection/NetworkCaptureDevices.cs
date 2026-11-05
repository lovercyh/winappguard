using System.Net;
using System.Net.NetworkInformation;

namespace WinAppGuard.Core.Diagnostics.NetworkDetection;

/// <summary>
/// 5.2：一块可用于 Suricata 抓包的网卡。
///
/// 只描述解析所需的信息，不直接依赖 Npcap；真正的设备名由
/// <see cref="NetworkCaptureDevices.DevicePath"/> 统一拼接。
/// </summary>
public sealed class NetworkCaptureAdapter
{
    public string Id { get; init; } = string.Empty;

    public string Name { get; init; } = string.Empty;

    public string Description { get; init; } = string.Empty;

    public NetworkInterfaceType Type { get; init; } = NetworkInterfaceType.Unknown;

    public bool IsUp { get; init; }

    public bool HasGateway { get; init; }

    public bool IsLoopback { get; init; }

    public bool IsTunnel { get; init; }

    public string DisplayName =>
        !string.IsNullOrWhiteSpace(Name)
            ? Name
            : !string.IsNullOrWhiteSpace(Description)
                ? Description
                : Id;
}

/// <summary>5.2：网卡解析结果。</summary>
public sealed class NetworkCaptureResolution
{
    public string? DevicePath { get; init; }

    public string? AdapterName { get; init; }

    /// <summary>所选网卡不可用，已回退到自动选择。</summary>
    public bool Fallback { get; init; }

    /// <summary>回退原因；正常自动选择时为 null。</summary>
    public string? Reason { get; init; }
}

/// <summary>
/// 5.2：枚举网卡、把用户选择解析成 Npcap 设备名。
///
/// 解析逻辑做成纯函数，方便自检在没有真实多网卡的环境里覆盖：
/// 空选择 → 自动；选中且可用 → 精确匹配；选中但缺失/断开 → 回退自动。
/// </summary>
public static class NetworkCaptureDevices
{
    public static string DevicePath(string id) => $@"\Device\NPF_{id}";

    /// <summary>枚举本机网卡；单个网卡读取失败不会影响其它网卡。</summary>
    public static IReadOnlyList<NetworkCaptureAdapter> Enumerate()
    {
        var adapters = new List<NetworkCaptureAdapter>();

        foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
        {
            try
            {
                if (IsAuxiliaryAdapter(nic))
                {
                    continue;
                }

                var isUp = nic.OperationalStatus == OperationalStatus.Up;
                var hasGateway = false;

                try
                {
                    hasGateway = nic.GetIPProperties().GatewayAddresses.Any(
                        gateway => gateway.Address is not null
                                   && !gateway.Address.Equals(IPAddress.Any)
                                   && !gateway.Address.Equals(IPAddress.IPv6Any));
                }
                catch (Exception)
                {
                    // 某些虚拟网卡读网关会抛异常；当作没有网关即可。
                }

                adapters.Add(new NetworkCaptureAdapter
                {
                    Id = nic.Id,
                    Name = nic.Name,
                    Description = nic.Description,
                    Type = nic.NetworkInterfaceType,
                    IsUp = isUp,
                    HasGateway = hasGateway,
                    IsLoopback = nic.NetworkInterfaceType == NetworkInterfaceType.Loopback,
                    IsTunnel = nic.NetworkInterfaceType == NetworkInterfaceType.Tunnel,
                });
            }
            catch (Exception)
            {
                // 枚举到坏网卡时跳过，不影响其它网卡。
            }
        }

        return adapters;
    }

    /// <summary>
    /// 解析监听网卡。
    ///
    /// <paramref name="selectedId"/> 为空 → 自动；
    /// 有值且存在、非回环、已连接 → 精确使用（包括 Tunnel / 虚拟网卡）；
    /// 有值但缺失 / 回环 / 断开 → 回退到自动，并给出原因。
    /// </summary>
    public static NetworkCaptureResolution Resolve(
        string? selectedId,
        IReadOnlyList<NetworkCaptureAdapter> adapters)
    {
        var id = selectedId?.Trim() ?? string.Empty;

        if (id.Length == 0)
        {
            return ResolveAutomatic(adapters, fallback: false, reason: null);
        }

        var selected = adapters.FirstOrDefault(
            adapter => string.Equals(adapter.Id, id, StringComparison.OrdinalIgnoreCase));

        if (selected is null)
        {
            return ResolveAutomatic(
                adapters,
                fallback: true,
                reason: "所选网卡不存在，已回退到自动");
        }

        if (selected.IsLoopback || selected.Type == NetworkInterfaceType.Loopback)
        {
            return ResolveAutomatic(
                adapters,
                fallback: true,
                reason: "所选网卡是回环网卡，已回退到自动");
        }

        if (!selected.IsUp)
        {
            return ResolveAutomatic(
                adapters,
                fallback: true,
                reason: "所选网卡未连接，已回退到自动");
        }

        return new NetworkCaptureResolution
        {
            DevicePath = DevicePath(selected.Id),
            AdapterName = selected.DisplayName,
            Fallback = false,
        };
    }

    private static NetworkCaptureResolution ResolveAutomatic(
        IReadOnlyList<NetworkCaptureAdapter> adapters,
        bool fallback,
        string? reason)
    {
        var candidates = adapters
            .Where(adapter => !adapter.IsLoopback
                              && adapter.Type != NetworkInterfaceType.Loopback
                              && !adapter.IsTunnel
                              && adapter.Type != NetworkInterfaceType.Tunnel)
            .ToList();

        var selected =
            candidates.FirstOrDefault(adapter => adapter.IsUp && IsCaptureType(adapter.Type) && adapter.HasGateway)
            ?? candidates.FirstOrDefault(adapter => adapter.IsUp && IsCaptureType(adapter.Type))
            ?? candidates.FirstOrDefault(adapter => adapter.IsUp);

        return selected is null
            ? new NetworkCaptureResolution
            {
                Fallback = fallback,
                Reason = reason ?? "找不到可用的网卡",
            }
            : new NetworkCaptureResolution
            {
                DevicePath = DevicePath(selected.Id),
                AdapterName = selected.DisplayName,
                Fallback = fallback,
                Reason = reason,
            };
    }

    private static bool IsCaptureType(NetworkInterfaceType type)
        => type is NetworkInterfaceType.Ethernet
            or NetworkInterfaceType.Wireless80211
            or NetworkInterfaceType.GigabitEthernet;

    /// <summary>
    /// 过滤掉 Npcap 副本、WFP/QoS 过滤驱动、WAN Miniport、Teredo/6to4 等
    /// 不可能作为抓包目标的伪适配器；只留下以太网、Wi-Fi、千兆网卡和隧道。
    /// </summary>
    private static bool IsAuxiliaryAdapter(NetworkInterface nic)
    {
        var type = nic.NetworkInterfaceType;

        if (type is not (NetworkInterfaceType.Ethernet
            or NetworkInterfaceType.Wireless80211
            or NetworkInterfaceType.GigabitEthernet
            or NetworkInterfaceType.Tunnel))
        {
            return true;
        }

        var description = nic.Description ?? string.Empty;

        return description.Contains("Npcap Packet Driver", StringComparison.OrdinalIgnoreCase)
               || description.Contains("Wi-Fi Direct Virtual Adapter", StringComparison.OrdinalIgnoreCase)
               || description.Contains("Packet Scheduler", StringComparison.OrdinalIgnoreCase)
               || description.Contains("LightWeight Filter", StringComparison.OrdinalIgnoreCase)
               || description.Contains("Filter Driver", StringComparison.OrdinalIgnoreCase)
               || description.Contains("Kernel Debug", StringComparison.OrdinalIgnoreCase)
               || description.Contains("WAN Miniport", StringComparison.OrdinalIgnoreCase)
               || description.Contains("Teredo", StringComparison.OrdinalIgnoreCase)
               || description.Contains("IP-HTTPS", StringComparison.OrdinalIgnoreCase)
               || description.Contains("6to4", StringComparison.OrdinalIgnoreCase);
    }
}
