using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;

namespace WinAppGuard.Core.Diagnostics.Lan;

/// <summary>
/// 4.2：局域网检测的网卡筛选与系统信息（网关、本机 ARP 缓存）。
///
/// 只读：不修改路由、不写 ARP 表、不调整任何系统设置。
/// </summary>
public static class LanEnvironment
{
    /// <summary>已知的虚拟网卡关键词（用排除名单，VPN 因此默认保留）。</summary>
    private static readonly string[] ExcludedKeywords =
    {
        "hyper-v", "vethernet", "vmware", "virtualbox", "wsl", "docker",
        "loopback", "bluetooth", "npcap loopback",
    };

    public static bool IsExcluded(NetworkInterface nic)
    {
        var text = $"{nic.Name} {nic.Description}";

        return ExcludedKeywords.Any(keyword => text.Contains(keyword, StringComparison.OrdinalIgnoreCase));
    }

    public static bool IsExcludedDescription(string? description)
    {
        if (string.IsNullOrWhiteSpace(description))
        {
            return false;
        }

        return ExcludedKeywords.Any(keyword => description.Contains(keyword, StringComparison.OrdinalIgnoreCase));
    }

    public static List<LanAdapterInfo> GetIncludedAdapters()
    {
        var result = new List<LanAdapterInfo>();

        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up || IsExcluded(nic))
                {
                    continue;
                }

                result.Add(new LanAdapterInfo(nic.Id, nic.Description, nic.NetworkInterfaceType.ToString()));
            }
        }
        catch (Exception)
        {
            // 枚举失败时返回空列表，由上层显示“没有可用网卡”。
        }

        return result;
    }

    /// <summary>4.3：读取每张网卡配置的 DNS 服务器（IPv4）。</summary>
    public static List<DnsServerHint> GetDnsHints()
    {
        var result = new List<DnsServerHint>();

        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up || IsExcluded(nic))
                {
                    continue;
                }

                foreach (var dns in nic.GetIPProperties().DnsAddresses)
                {
                    if (dns is null
                        || dns.AddressFamily != AddressFamily.InterNetwork
                        || dns.Equals(IPAddress.Any))
                    {
                        continue;
                    }

                    result.Add(new DnsServerHint(nic.Description, dns.ToString()));
                }
            }
        }
        catch (Exception)
        {
            // 枚举失败时视为“没有配置 DNS”，只做响应侧校验。
        }

        return result;
    }

    public static List<LanGatewayHint> GetGatewayHints()    {
        var result = new List<LanGatewayHint>();

        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up || IsExcluded(nic))
                {
                    continue;
                }

                foreach (var gateway in nic.GetIPProperties().GatewayAddresses)
                {
                    var address = gateway.Address;

                    if (address is null
                        || address.AddressFamily != AddressFamily.InterNetwork
                        || address.Equals(IPAddress.Any))
                    {
                        continue;
                    }

                    result.Add(new LanGatewayHint(nic.Description, address.ToString()));
                }
            }
        }
        catch (Exception)
        {
            // 网关枚举失败时不做基线，检测退化为“只报明显异常”。
        }

        return result;
    }

    /// <summary>把 pcap 设备名（\Device\NPF_{GUID}）映射成网卡描述；失败返回 null。</summary>
    public static string? MapDeviceToAdapter(string deviceName)
    {
        try
        {
            var open = deviceName.IndexOf('{');
            var close = deviceName.LastIndexOf('}');

            if (open < 0 || close <= open)
            {
                return null;
            }

            var guid = deviceName[open..(close + 1)];

            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (string.Equals(nic.Id, guid, StringComparison.OrdinalIgnoreCase))
                {
                    return nic.Description;
                }
            }
        }
        catch (Exception)
        {
            // 映射失败时由调用方退回设备名。
        }

        return null;
    }

    /// <summary>读取本机 IPv4 ARP 缓存里的 MAC；没有返回 false。</summary>
    public static bool TryGetArpCacheMac(string ip, out string mac)
    {
        mac = string.Empty;

        if (!IPAddress.TryParse(ip, out var address)
            || address.AddressFamily != AddressFamily.InterNetwork)
        {
            return false;
        }

        var target = AddressToUInt(address);
        var size = 0;

        try
        {
            var first = GetIpNetTable(IntPtr.Zero, ref size, false);

            if (first != ErrorInsufficientBuffer || size <= 0)
            {
                return false;
            }

            var buffer = Marshal.AllocHGlobal(size);

            try
            {
                if (GetIpNetTable(buffer, ref size, false) != 0)
                {
                    return false;
                }

                var count = Marshal.ReadInt32(buffer);
                var rowSize = Marshal.SizeOf<MibIpNetRow>();
                var pointer = IntPtr.Add(buffer, sizeof(int));

                for (var i = 0; i < count; i++)
                {
                    var row = Marshal.PtrToStructure<MibIpNetRow>(pointer);
                    pointer = IntPtr.Add(pointer, rowSize);

                    if (row.Address != target || row.PhysAddrLength is 0 or > 8)
                    {
                        continue;
                    }

                    var bytes = new byte[row.PhysAddrLength];
                    Array.Copy(row.PhysAddress, bytes, bytes.Length);
                    mac = FormatMac(bytes);
                    return true;
                }
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }
        catch (Exception)
        {
            // 读不到就当没有缓存。
        }

        return false;
    }

    public static string FormatMac(ReadOnlySpan<byte> bytes)
    {
        var builder = new System.Text.StringBuilder(bytes.Length * 3);

        for (var i = 0; i < bytes.Length; i++)
        {
            if (i > 0)
            {
                builder.Append(':');
            }

            builder.Append(bytes[i].ToString("x2"));
        }

        return builder.ToString();
    }

    private static uint AddressToUInt(IPAddress address)
    {
        var bytes = address.GetAddressBytes();
        return (uint)((bytes[0] << 24) | (bytes[1] << 16) | (bytes[2] << 8) | bytes[3]);
    }

    private const int ErrorInsufficientBuffer = 122;

    [StructLayout(LayoutKind.Sequential)]
    private struct MibIpNetRow
    {
        public uint Index;
        public uint PhysAddrLength;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] PhysAddress;

        public uint Address;
        public uint Type;
    }

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern int GetIpNetTable(IntPtr table, ref int size, [MarshalAs(UnmanagedType.Bool)] bool order);
}
