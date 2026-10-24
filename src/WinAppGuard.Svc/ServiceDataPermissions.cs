using System.Security.AccessControl;
using System.Security.Principal;
using WinAppGuard.Contracts;

namespace WinAppGuard.Service;

/// <summary>
/// 让普通用户能**读取**服务的数据目录（3.0-c）。
///
/// 界面改成普通权限后，需要读：
///   - rules.json（离线规则快照）
///   - audit\*.jsonl（记录页）
///   - audit-settings.json（显示当前设置）
///
/// ProgramData 默认继承通常已经给了 Users 读权限，但不同机器/组策略可能不同，
/// 这里显式加一条只读规则（不含写入），保证功能不因 ACL 差异而坏掉。
/// </summary>
internal static class ServiceDataPermissions
{
    internal static void EnsureReadableByUsers()
    {
        try
        {
            Directory.CreateDirectory(ServicePaths.DataDirectory);

            var directory = new DirectoryInfo(ServicePaths.DataDirectory);
            var security = directory.GetAccessControl();

            var users = new SecurityIdentifier(WellKnownSidType.BuiltinUsersSid, null);

            security.AddAccessRule(new FileSystemAccessRule(
                users,
                FileSystemRights.ReadAndExecute | FileSystemRights.ListDirectory,
                InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None,
                AccessControlType.Allow));

            directory.SetAccessControl(security);
        }
        catch (Exception ex)
        {
            ServiceLog.Warning("WAG-DATA-020", "Failed to set read permissions on the data folder; the UI may not be able to read offline data.", ex);
        }
    }
}
