using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace WinAppGuard.Setup;

/// <summary>
/// 服务对象 DACL（3.1 第 4 步）。
///
///   SYSTEM            完全控制
///   所有者 SID        完全控制（停止/配置/删除）
///   Administrators    仅查询状态 + 启动 + READ_CONTROL（不能直接 sc stop）
///   其他账户          无
///
/// 这是“提高门槛”而不是“防住铁了心的管理员”：
/// 管理员仍可通过接管所有权/改 DACL 绕过，文档如实说明。
/// </summary>
internal static class ServiceSecurity
{
    private const uint ScManagerConnect = 0x0001;
    private const uint ReadControl = 0x00020000;
    private const uint WriteDac = 0x00040000;
    private const uint DaclSecurityInformation = 0x00000004;
    private const uint SddlRevision1 = 1;

    // SERVICE_QUERY_STATUS | SERVICE_START | READ_CONTROL
    private const uint AdministratorMask = 0x20014;

    internal static bool TrySetOwnerOnlyDacl(
        string serviceName, string ownerSid, out string? error)
    {
        error = null;

        try
        {
            _ = new SecurityIdentifier(ownerSid);

            var sddl =
                $"D:(A;;GA;;;SY)(A;;GA;;;{ownerSid})(A;;0x{AdministratorMask:X};;;BA)";

            if (!ConvertStringSecurityDescriptorToSecurityDescriptor(
                    sddl, SddlRevision1, out var descriptor, out _))
            {
                error = new Win32Exception(
                    Marshal.GetLastWin32Error(), "构造服务安全描述符失败").Message;
                return false;
            }

            try
            {
                var scm = OpenSCManagerW(null, null, ScManagerConnect);

                if (scm == IntPtr.Zero)
                {
                    error = new Win32Exception(
                        Marshal.GetLastWin32Error(), "打开 SCM 失败").Message;
                    return false;
                }

                try
                {
                    var service = OpenServiceW(
                        scm, serviceName, WriteDac | ReadControl);

                    if (service == IntPtr.Zero)
                    {
                        error = new Win32Exception(
                            Marshal.GetLastWin32Error(), "打开服务（WRITE_DAC）失败").Message;
                        return false;
                    }

                    try
                    {
                        if (!SetServiceObjectSecurity(
                                service, DaclSecurityInformation, descriptor))
                        {
                            error = new Win32Exception(
                                Marshal.GetLastWin32Error(), "设置服务 DACL 失败").Message;
                            return false;
                        }

                        return true;
                    }
                    finally
                    {
                        _ = CloseServiceHandle(service);
                    }
                }
                finally
                {
                    _ = CloseServiceHandle(scm);
                }
            }
            finally
            {
                _ = LocalFree(descriptor);
            }
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern bool ConvertStringSecurityDescriptorToSecurityDescriptor(
        string stringSecurityDescriptor,
        uint stringSecurityDescriptorLength,
        out IntPtr securityDescriptor,
        out uint securityDescriptorSize);

    [DllImport("advapi32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern bool SetServiceObjectSecurity(
        IntPtr service, uint securityInformation, IntPtr securityDescriptor);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern IntPtr OpenSCManagerW(
        string? machineName, string? databaseName, uint desiredAccess);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern IntPtr OpenServiceW(
        IntPtr scm, string serviceName, uint desiredAccess);

    [DllImport("advapi32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern bool CloseServiceHandle(IntPtr handle);

    [DllImport("kernel32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern IntPtr LocalFree(IntPtr memory);
}
