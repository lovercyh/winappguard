using System.Security.Principal;
using WinAppGuard.Contracts;

namespace WinAppGuard.Core.ProtectedMode;

internal enum ProtectedModeState
{
    Ready,
    NotOwner,
    KeyUnavailable,
    NotInitialized,
    ConfigBroken,
}

internal sealed record ProtectedModeStatus(
    ProtectedModeState State,
    string? OwnerName,
    string? OwnerSid,
    string? Fingerprint,
    string? Error);

/// <summary>
/// 客户端侧受保护模式：判断当前账户处在哪一态，并给 ServiceClient 配置签名器。
///
/// 三态（外加未初始化/配置损坏）：
///   Ready          —— 所有者，密钥能解开；
///   NotOwner       —— 不是安装时的所有者，文件/管道都不允许；
///   KeyUnavailable —— 是所有者，但密钥缺失/DPAPI 解不开；
///   NotInitialized —— 还没生成密钥（3.0/安装未完成）；
///   ConfigBroken   —— 配置损坏。
///
/// UI 用 CurrentStatus 显示明确原因，而不是只说“服务离线”。
/// </summary>
internal static class ProtectedModeClient
{
    private static ProtectedModeStatus _status = new(
        ProtectedModeState.NotInitialized, null, null, null, "尚未检查受保护模式");

    internal static ProtectedModeStatus CurrentStatus => Volatile.Read(ref _status);

    internal static bool TryConfigureSigner(
        out string? fingerprint, out string? error)
    {
        fingerprint = null;
        error = null;

        var status = Evaluate();
        Volatile.Write(ref _status, status);

        if (status.State != ProtectedModeState.Ready)
        {
            ServiceClient.SetSigner(null);
            error = status.Error;
            return false;
        }

        try
        {
            var owner = WindowsIdentity.GetCurrent().User;

            if (owner is null)
            {
                throw new InvalidOperationException("无法获取当前账户 SID。");
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

            Volatile.Write(ref _status, status with
            {
                State = ProtectedModeState.KeyUnavailable,
                Error = ex.Message,
            });

            error = ex.Message;
            return false;
        }
    }

    /// <summary>
    /// 3.4：当前账户是否是安装时的所有者。
    /// 配置缺失/损坏一律视为“不是”，由调用方给出明确提示。
    /// </summary>
    internal static bool IsCurrentUserOwner()
    {
        try
        {
            var config = new OwnerKeyStore(ServicePaths.ProtectedModeDirectory).ReadConfig();
            var owner = WindowsIdentity.GetCurrent().User;

            return owner is not null
                   && string.Equals(
                       config.OwnerSid, owner.Value, StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception)
        {
            return false;
        }
    }
    internal static ProtectedModeStatus Evaluate()
    {
        var store = new OwnerKeyStore(ServicePaths.ProtectedModeDirectory);
        var owner = WindowsIdentity.GetCurrent().User;

        if (owner is null)
        {
            return new ProtectedModeStatus(
                ProtectedModeState.NotOwner, null, null, null, "无法获取当前账户 SID。");
        }

        if (store.HasFiles)
        {
            ProtectedModeConfig config;

            try
            {
                config = store.ReadConfig();
            }
            catch (UnauthorizedAccessException ex)
            {
                return new ProtectedModeStatus(
                    ProtectedModeState.NotOwner, null, null, null, ex.Message);
            }
            catch (FileNotFoundException ex)
            {
                return new ProtectedModeStatus(
                    ProtectedModeState.KeyUnavailable, null, null, null,
                    $"受保护模式文件不完整：{ex.Message}");
            }
            catch (InvalidDataException ex)
            {
                return new ProtectedModeStatus(
                    ProtectedModeState.ConfigBroken, null, null, null, ex.Message);
            }
            catch (Exception ex)
            {
                return new ProtectedModeStatus(
                    ProtectedModeState.ConfigBroken, null, null, null, ex.Message);
            }

            if (!string.Equals(
                    config.OwnerSid, owner.Value, StringComparison.OrdinalIgnoreCase))
            {
                return new ProtectedModeStatus(
                    ProtectedModeState.NotOwner,
                    config.OwnerName, config.OwnerSid, config.Fingerprint,
                    $"当前账户不是所有者（所有者：{config.OwnerName}）。");
            }

            try
            {
                using var key = store.LoadForOwner(owner);

                return new ProtectedModeStatus(
                    ProtectedModeState.Ready,
                    config.OwnerName, config.OwnerSid, key.Fingerprint, null);
            }
            catch (Exception ex)
            {
                return new ProtectedModeStatus(
                    ProtectedModeState.KeyUnavailable,
                    config.OwnerName, config.OwnerSid, config.Fingerprint, ex.Message);
            }
        }

        // 文件看起来不存在：区分“目录打不开（不是所有者）”和“真的还没生成”。
        if (Directory.Exists(store.DirectoryPath))
        {
            try
            {
                if (Directory.EnumerateFileSystemEntries(store.DirectoryPath).Any())
                {
                    return new ProtectedModeStatus(
                        ProtectedModeState.KeyUnavailable, null, null, null,
                        "受保护模式目录里有文件，但配置/私钥读不到（可能不是所有者）。");
                }
            }
            catch (Exception ex)
            {
                return new ProtectedModeStatus(
                    ProtectedModeState.NotOwner, null, null, null, ex.Message);
            }
        }

        return new ProtectedModeStatus(
            ProtectedModeState.NotInitialized, null, null, null,
            "还没有受保护模式密钥；请运行 WinAppGuardSetup.exe --repair。");
    }
}
