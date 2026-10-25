namespace WinAppGuard.Contracts;

/// <summary>
/// 服务与界面共用的数据文件位置。
///
/// 放在 Contracts 里而不是各写一遍：界面离线时要读服务写的快照，
/// 两边必须指向**同一个**路径，不能靠"记得改两处"。
/// </summary>
public static class ServicePaths
{
    /// <summary>%ProgramData%\WinAppGuard</summary>
    public static string DataDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "WinAppGuard");

    /// <summary>规则分组（服务写，界面只读）。</summary>
    public static string RuleGroupsFile => Path.Combine(DataDirectory, "rule-groups.json");

    /// <summary>规则的权威副本（服务每次写入后更新；界面离线时读它）。</summary>
    public static string RulesSnapshotFile => Path.Combine(DataDirectory, "rules.json");

    /// <summary>审计记录目录（3.0-c 起由服务写入）。</summary>
    public static string AuditDirectory => Path.Combine(DataDirectory, "audit");

    /// <summary>审计设置（机器级；服务读写）。</summary>
    public static string AuditSettingsFile => Path.Combine(DataDirectory, "audit-settings.json");

    /// <summary>3.1 受保护模式密钥目录（SYSTEM + 所有者；其他账户无权限）。</summary>
    public static string ProtectedModeDirectory => Path.Combine(DataDirectory, "protected-mode");

    /// <summary>受保护模式配置：所有者 SID、公钥、entropy、指纹（不含私钥）。</summary>
    public static string ProtectedModeConfigFile => Path.Combine(ProtectedModeDirectory, "config.json");

    /// <summary>DPAPI 用户级加密后的私钥（服务从不读取）。</summary>
    public static string OwnerKeyFile => Path.Combine(ProtectedModeDirectory, "client-key.dpapi");

    /// <summary>
    /// 3.4：WFP 对象 DACL 迁移标记。文件内容是当前所有者 SID；
    /// 内容与配置不一致（例如 --reset-owner 换了所有者）时会重新迁移。
    /// </summary>
    public static string WfpDaclMarkerFile => Path.Combine(DataDirectory, "wfp-dacl-owner-only");
}
