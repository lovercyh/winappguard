namespace WinAppGuard.Core.Wfp;

/// <summary>
/// 严格模式的**内置系统放行清单**。
///
/// ==================== 为什么必须有它 ====================
/// 2.0 的严格模式是**真白名单**：我们的 block 压得过 Windows 防火墙的 allow
/// （POC 实测），所以不显式放行的话，DNS、时间同步、Windows 更新都会被一起挡掉 ——
/// 用户看到的就是"一开严格模式整台机器上不了网"。
///
/// ==================== 里面放什么 ====================
/// 只放**联网必需、且路径稳定**的系统程序：
///   - <c>svchost.exe</c>：DNS 客户端、DHCP、时间同步、Windows 更新的服务宿主
///     （⚠️ 副作用：宿主在 svchost 里的第三方服务会被一并放行 —— 这是 Windows 的
///      进程模型决定的，不是我们能单独区分的）；
///   - <c>lsass.exe</c> / <c>services.exe</c> / <c>wininit.exe</c>：系统核心进程；
///   - Defender 的平台程序（MsMpEng / MpCmdRun / NisSrv）。
///
/// Defender 的路径带版本号（<c>Platform\&lt;版本&gt;\</c>），所以按目录枚举而不是写死；
/// 只返回**真实存在**的文件 —— 给不存在的路径取程序身份只会失败。
/// </summary>
internal static class SystemAllowList
{
    /// <summary>返回当前机器上真实存在的、需要放行的系统程序路径。</summary>
    internal static List<string> GetPaths()
    {
        var result = new List<string>();
        var system32 = Environment.SystemDirectory;

        AddIfExists(result, Path.Combine(system32, "svchost.exe"));
        AddIfExists(result, Path.Combine(system32, "lsass.exe"));
        AddIfExists(result, Path.Combine(system32, "services.exe"));
        AddIfExists(result, Path.Combine(system32, "wininit.exe"));

        try
        {
            var platformRoot = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "Microsoft",
                "Windows Defender",
                "Platform");

            if (Directory.Exists(platformRoot))
            {
                foreach (var versionDirectory in Directory.GetDirectories(platformRoot))
                {
                    AddIfExists(result, Path.Combine(versionDirectory, "MsMpEng.exe"));
                    AddIfExists(result, Path.Combine(versionDirectory, "MpCmdRun.exe"));
                    AddIfExists(result, Path.Combine(versionDirectory, "NisSrv.exe"));
                }
            }
        }
        catch (Exception)
        {
            // 读不到就算了：少放行 Defender 只会让它更新失败，不影响用户上网。
        }

        return result;
    }

    private static void AddIfExists(List<string> paths, string path)
    {
        if (File.Exists(path))
        {
            paths.Add(path);
        }
    }
}
