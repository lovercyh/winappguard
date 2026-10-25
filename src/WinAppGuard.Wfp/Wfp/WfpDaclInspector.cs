using System.Runtime.InteropServices;
using WinAppGuard.Interop;

namespace WinAppGuard.Core.Wfp;

/// <summary>
/// 3.4：读取 WFP 子层/过滤器的安全描述符并转成 SDDL。
///
/// 只用于验收和排障，不参与规则执行。放到单独文件里，避免把 interop
/// 细节混进 WfpEngine 的创建/枚举逻辑。
/// </summary>
internal static class WfpDaclInspector
{
    /// <summary>读取本工具子层的 SDDL；失败返回 null。</summary>
    internal static string? ReadSublayer(IntPtr engineHandle)
    {
        var key = WfpNativeMethods.OurSubLayerKey;

        var rc = WfpNativeMethods.FwpmSubLayerGetSecurityInfoByKey0(
            engineHandle,
            ref key,
            WfpNativeMethods.OwnerSecurityInformation | WfpNativeMethods.DaclSecurityInformation,
            out _,
            out _,
            out _,
            out _,
            out var descriptor);

        if (rc != WfpNativeMethods.ERROR_SUCCESS || descriptor == IntPtr.Zero)
        {
            return null;
        }

        try
        {
            return ConvertToSddl(descriptor);
        }
        finally
        {
            WfpNativeMethods.FwpmFreeMemory0(ref descriptor);
        }
    }

    /// <summary>读取一条过滤器的 SDDL；失败返回 null。</summary>
    internal static string? ReadFilter(IntPtr engineHandle, Guid filterKey)
    {
        var key = filterKey;

        var rc = WfpNativeMethods.FwpmFilterGetSecurityInfoByKey0(
            engineHandle,
            ref key,
            WfpNativeMethods.OwnerSecurityInformation | WfpNativeMethods.DaclSecurityInformation,
            out _,
            out _,
            out _,
            out _,
            out var descriptor);

        if (rc != WfpNativeMethods.ERROR_SUCCESS || descriptor == IntPtr.Zero)
        {
            return null;
        }

        try
        {
            return ConvertToSddl(descriptor);
        }
        finally
        {
            WfpNativeMethods.FwpmFreeMemory0(ref descriptor);
        }
    }

    private static string? ConvertToSddl(IntPtr descriptor)
    {
        if (!ConvertSecurityDescriptorToStringSecurityDescriptorW(
                descriptor,
                SddlRevision1,
                WfpNativeMethods.OwnerSecurityInformation | WfpNativeMethods.DaclSecurityInformation,
                out var text,
                out _))
        {
            return null;
        }

        try
        {
            return Marshal.PtrToStringUni(text);
        }
        finally
        {
            Marshal.FreeHGlobal(text);
        }
    }

    private const uint SddlRevision1 = 1;

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern bool ConvertSecurityDescriptorToStringSecurityDescriptorW(
        IntPtr securityDescriptor,
        uint stringSecurityDescriptorRevision,
        uint securityInformation,
        out IntPtr stringSecurityDescriptor,
        out uint stringSecurityDescriptorLength);
}
