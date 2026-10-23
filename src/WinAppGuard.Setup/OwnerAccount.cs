using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace WinAppGuard.Setup;

/// <summary>
/// 判断“提权账户”和“当前交互登录账户”是不是同一个人。
///
/// 正常 UAC：相同；over-the-shoulder（输入了另一个管理员的凭据）：不同。
/// 3.1 默认不允许后者静默把所有者设成那个管理员，必须显式
/// --allow-owner-mismatch。
/// </summary>
internal static class OwnerAccount
{
    internal static SecurityIdentifier GetCurrentSid()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return identity.User
               ?? throw new InvalidOperationException("无法获取当前账户 SID。");
    }

    internal static string GetCurrentName()
    {
        using var identity = WindowsIdentity.GetCurrent();
        return identity.Name;
    }

    /// <summary>
    /// 当前会话的交互账户；取不到（例如服务/无会话）返回 null。
    /// </summary>
    internal static SecurityIdentifier? TryGetInteractiveSid(out string? accountName)
    {
        accountName = null;

        try
        {
            var sessionId = Process.GetCurrentProcess().SessionId;
            var user = QuerySessionString(sessionId, WtsUserName);
            var domain = QuerySessionString(sessionId, WtsDomainName);

            if (string.IsNullOrWhiteSpace(user))
            {
                return null;
            }

            accountName = string.IsNullOrWhiteSpace(domain)
                ? user
                : $"{domain}\\{user}";

            return (SecurityIdentifier)new NTAccount(accountName)
                .Translate(typeof(SecurityIdentifier));
        }
        catch (Exception)
        {
            // 取不到就跳过检测，不因此阻止安装。
            return null;
        }
    }

    private static string? QuerySessionString(int sessionId, int infoClass)
    {
        if (!WTSQuerySessionInformation(
                IntPtr.Zero, sessionId, infoClass, out var buffer, out var bytes)
            || buffer == IntPtr.Zero
            || bytes <= 1)
        {
            if (buffer != IntPtr.Zero)
            {
                WTSFreeMemory(buffer);
            }

            return null;
        }

        try
        {
            return Marshal.PtrToStringUni(buffer);
        }
        finally
        {
            WTSFreeMemory(buffer);
        }
    }

    private const int WtsUserName = 5;
    private const int WtsDomainName = 7;

    [DllImport("wtsapi32.dll", SetLastError = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern bool WTSQuerySessionInformation(
        IntPtr server, int sessionId, int infoClass,
        out IntPtr buffer, out int bytesReturned);

    [DllImport("wtsapi32.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern void WTSFreeMemory(IntPtr memory);
}
