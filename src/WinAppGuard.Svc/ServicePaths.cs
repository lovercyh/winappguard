namespace WinAppGuard.Service;

/// <summary>服务自己的文件路径（全部在 %ProgramData% 下）。</summary>
internal static class ServicePaths
{
    internal static string DataDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "WinAppGuard");

    internal static string RuleGroupsFile => Path.Combine(DataDirectory, "rule-groups.json");
}
