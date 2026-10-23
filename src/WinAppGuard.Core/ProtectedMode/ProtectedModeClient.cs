using System.Security.Principal;
using WinAppGuard.Contracts;

namespace WinAppGuard.Core.ProtectedMode;

/// <summary>
/// 客户端侧受保护模式：读取已安装密钥 → 配置 ServiceClient 的签名器。
///
/// UI / Setup / 提权助手 / SelfCheck 在启动时调用一次；
/// 不是所有者时返回 false，ServiceClient 会拒绝发送任何请求。
/// </summary>
internal static class ProtectedModeClient
{
    internal static bool TryConfigureSigner(
        out string? fingerprint, out string? error)
    {
        fingerprint = null;
        error = null;

        try
        {
            var owner = WindowsIdentity.GetCurrent().User;

            if (owner is null)
            {
                error = "无法获取当前账户 SID。";
                ServiceClient.SetSigner(null);
                return false;
            }

            var store = new OwnerKeyStore(ServicePaths.ProtectedModeDirectory);
            var key = store.LoadForOwner(owner);

            // 用新的 signer 替换旧的；旧对象留给进程生命周期，避免请求进行中被释放。
            ServiceClient.SetSigner(new OwnerKeySigner(key));
            fingerprint = key.Fingerprint;
            return true;
        }
        catch (Exception ex)
        {
            ServiceClient.SetSigner(null);
            error = ex.Message;
            return false;
        }
    }
}
