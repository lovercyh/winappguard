using System.Runtime.InteropServices;
using System.Text;

namespace WinAppGuard.Core.Audit;

/// <summary>
/// 把 WFP 事件里的**设备路径**（<c>\device\harddiskvolume3\...\a.exe</c>）
/// 转成用户看得懂的 DOS 路径（<c>C:\...\a.exe</c>）。
///
/// 映射来源就是系统自己：`QueryDosDevice("C:")` 返回 <c>\Device\HarddiskVolume3</c>。
/// 转不出来时原样返回 —— 审计宁可显示一个怪路径，也不要丢事件。
/// </summary>
internal static class DevicePathMapper
{
    private static readonly Lazy<IReadOnlyList<(string Device, string Drive)>> Mapping = new(Build);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint QueryDosDeviceW(string deviceName, StringBuilder targetPath, uint maxLength);

    internal static string ToDosPath(string? devicePath)
    {
        if (string.IsNullOrEmpty(devicePath))
        {
            return string.Empty;
        }

        if (!devicePath.StartsWith(@"\device\", StringComparison.OrdinalIgnoreCase))
        {
            return devicePath;
        }

        foreach (var (device, drive) in Mapping.Value)
        {
            if (devicePath.StartsWith(device, StringComparison.OrdinalIgnoreCase))
            {
                return drive + devicePath[device.Length..];
            }
        }

        return devicePath;
    }

    private static IReadOnlyList<(string Device, string Drive)> Build()
    {
        var result = new List<(string Device, string Drive)>();

        for (var letter = 'A'; letter <= 'Z'; letter++)
        {
            var builder = new StringBuilder(1024);
            var length = QueryDosDeviceW($"{letter}:", builder, (uint)builder.Capacity);

            if (length == 0)
            {
                continue;
            }

            var device = builder.ToString();
            if (device.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase))
            {
                result.Add((device, $"{letter}:"));
            }
        }

        // 长前缀优先，避免 "\Device\HarddiskVolume1" 抢了 "\Device\HarddiskVolume10" 的匹配。
        return result.OrderByDescending(item => item.Device.Length).ToList();
    }
}
