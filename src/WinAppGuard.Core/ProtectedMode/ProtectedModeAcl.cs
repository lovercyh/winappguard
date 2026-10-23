using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;

namespace WinAppGuard.Core.ProtectedMode;

/// <summary>
/// 受保护模式目录/文件的 ACL。
///
/// 目标：
///   - SYSTEM：完全控制；
///   - 所有者：读/写/删除（轮换密钥需要重建文件；界面日常只读）；
///   - 其他任何账户（包括 Administrators 组）：没有 ACE。
///
/// 目录关闭继承，避免 %ProgramData% 的 Users/Administrators 继承进来。
/// 管理员仍然可以夺取所有权（Windows 的固有规则），文档如实说明。
/// </summary>
internal static class ProtectedModeAcl
{
    private static readonly SecurityIdentifier SystemSid =
        new(WellKnownSidType.LocalSystemSid, null);

    internal static void ApplyToDirectory(string path, SecurityIdentifier owner)
    {
        var security = new DirectorySecurity();

        // 关闭继承：只保留下面两条 ACE。
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

        security.AddAccessRule(new FileSystemAccessRule(
            SystemSid,
            FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));

        security.AddAccessRule(new FileSystemAccessRule(
            owner,
            FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));

        new DirectoryInfo(path).SetAccessControl(security);
    }

    internal static void ApplyToFile(string path, SecurityIdentifier owner)
    {
        var security = new FileSecurity();

        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);

        security.AddAccessRule(new FileSystemAccessRule(
            SystemSid,
            FileSystemRights.FullControl,
            AccessControlType.Allow));

        // 所有者需要读（界面/自检）、写和删除（轮换/修复）。
        security.AddAccessRule(new FileSystemAccessRule(
            owner,
            FileSystemRights.Read | FileSystemRights.Write | FileSystemRights.Delete,
            AccessControlType.Allow));

        new FileInfo(path).SetAccessControl(security);
    }

    /// <summary>
    /// 以当前管理员身份接管目录/文件所有权。
    /// 只在 \-\-reset-owner / 强制卸载这类跨账户场景使用。
    /// </summary>
    internal static bool TryTakeOwnership(
        string path, SecurityIdentifier newOwner, out string? error)
    {
        error = null;

        try
        {
            if (!EnablePrivilege("SeTakeOwnershipPrivilege"))
            {
                error = "无法启用 SeTakeOwnershipPrivilege（需要管理员）。";
                return false;
            }

            var sidBytes = new byte[newOwner.BinaryLength];
            newOwner.GetBinaryForm(sidBytes, 0);

            var sidPointer = Marshal.AllocHGlobal(sidBytes.Length);

            try
            {
                Marshal.Copy(sidBytes, 0, sidPointer, sidBytes.Length);

                var result = SetNamedSecurityInfo(
                    path,
                    SeFileObject,
                    OwnerSecurityInformation,
                    sidPointer,
                    IntPtr.Zero,
                    IntPtr.Zero,
                    IntPtr.Zero);

                if (result != 0)
                {
                    error = new Win32Exception((int)result, "接管文件所有权失败").Message;
                    return false;
                }

                return true;
            }
            finally
            {
                Marshal.FreeHGlobal(sidPointer);
            }
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    private static bool EnablePrivilege(string name)
    {
        if (!OpenProcessToken(
                GetCurrentProcess(),
                TokenAdjustPrivileges | TokenQuery,
                out var token))
        {
            return false;
        }

        try
        {
            if (!LookupPrivilegeValue(null, name, out var luid))
            {
                return false;
            }

            var privileges = new TokenPrivileges
            {
                PrivilegeCount = 1,
                Luid = luid,
                Attributes = SePrivilegeEnabled,
            };

            Marshal.SetLastPInvokeError(0);

            if (!AdjustTokenPrivileges(
                    token, false, ref privileges, 0, IntPtr.Zero, IntPtr.Zero))
            {
                return false;
            }

            // 权限不存在时 AdjustTokenPrivileges 仍返回 true，要再查错误码。
            return Marshal.GetLastWin32Error() != ErrorNotAllAssigned;
        }
        finally
        {
            CloseHandle(token);
        }
    }

    private const uint SeFileObject = 1;
    private const uint OwnerSecurityInformation = 0x00000001;
    private const uint TokenAdjustPrivileges = 0x0020;
    private const uint TokenQuery = 0x0008;
    private const int SePrivilegeEnabled = 0x00000002;
    private const int ErrorNotAllAssigned = 1300;

    [StructLayout(LayoutKind.Sequential)]
    private struct Luid
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TokenPrivileges
    {
        public int PrivilegeCount;
        public Luid Luid;
        public int Attributes;
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern bool OpenProcessToken(
        IntPtr processHandle, uint desiredAccess, out IntPtr tokenHandle);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern bool LookupPrivilegeValue(
        string? systemName, string name, out Luid luid);

    [DllImport("advapi32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern bool AdjustTokenPrivileges(
        IntPtr tokenHandle,
        bool disableAllPrivileges,
        ref TokenPrivileges newState,
        int bufferLength,
        IntPtr previousState,
        IntPtr returnLength);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern uint SetNamedSecurityInfo(
        string objectName,
        uint objectType,
        uint securityInfo,
        IntPtr owner,
        IntPtr group,
        IntPtr dacl,
        IntPtr sacl);

    [DllImport("kernel32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern bool CloseHandle(IntPtr handle);
}
