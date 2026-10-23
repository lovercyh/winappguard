using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;

namespace WinAppGuard.Core.ProtectedMode;

/// <summary>
/// 受保护模式的文件存储（3.1）：
///
///   protected-mode\config.json      —— 公开配置（所有者 SID / 公钥 / entropy / 指纹）
///   protected-mode\client-key.dpapi —— DPAPI 用户级加密的 ECDSA 私钥
///
/// 目录和文件都只给 SYSTEM + 所有者；其他账户（含其他管理员）没有 ACE。
/// 服务端只读 config.json，从不解密 client-key.dpapi。
/// </summary>
internal sealed class OwnerKeyStore
{
    private const uint MoveFileDelayUntilReboot = 0x4;

    internal OwnerKeyStore(string directory)
    {
        DirectoryPath = Path.GetFullPath(directory);
    }

    internal string DirectoryPath { get; }

    internal string ConfigPath => Path.Combine(DirectoryPath, "config.json");

    internal string KeyPath => Path.Combine(DirectoryPath, "client-key.dpapi");

    internal bool HasFiles => File.Exists(ConfigPath) || File.Exists(KeyPath);

    internal ProtectedModeConfig ReadConfig()
    {
        if (!File.Exists(ConfigPath))
        {
            throw new FileNotFoundException(
                $"受保护模式配置不存在：{ConfigPath}");
        }

        return ProtectedModeConfig.Load(ConfigPath);
    }

    /// <summary>读取配置并确认当前账户就是所有者，再解密私钥。</summary>
    internal OwnerKey LoadForOwner(SecurityIdentifier currentUser)
    {
        var config = ReadConfig();

        if (!string.Equals(
                config.OwnerSid, currentUser.Value, StringComparison.OrdinalIgnoreCase))
        {
            throw new UnauthorizedAccessException(
                "当前账户不是受保护模式的所有者。");
        }

        return LoadKey(config);
    }

    /// <summary>
    /// 生成全新密钥并落盘。调用方负责确保这是“首次安装”或“已明确轮换/重置”，
    /// 不要在普通修复里静默调用（会换掉所有者的钥匙）。
    /// </summary>
    internal OwnerKey Create(SecurityIdentifier owner, string ownerName)
    {
        Directory.CreateDirectory(DirectoryPath);
        ProtectedModeAcl.ApplyToDirectory(DirectoryPath, owner);

        var key = OwnerKey.Create();
        var entropy = RandomNumberGenerator.GetBytes(32);

        try
        {
            var config = new ProtectedModeConfig
            {
                Version = ProtectedModeConfig.CurrentVersion,
                OwnerSid = owner.Value,
                OwnerName = string.IsNullOrWhiteSpace(ownerName) ? owner.Value : ownerName,
                PublicKey = Convert.ToBase64String(key.PublicKey),
                Entropy = Convert.ToBase64String(entropy),
                Fingerprint = key.Fingerprint,
                CreatedUtc = DateTimeOffset.UtcNow,
            };

            var blob = key.ProtectPrivateKey(entropy);

            // 先写密钥、后写配置：中途失败时旧配置配不上新密钥，服务会失败关闭，
            // 不会出现“配置还是旧的、但拿新密钥也能通过”的情况。
            WriteAtomic(KeyPath, blob, owner);
            WriteAtomic(ConfigPath, config.ToJsonBytes(), owner);

            // 立刻用真实 DPAPI 往返验证一遍（不是只检查文件存在）。
            using var loaded = LoadForOwner(owner);

            if (!string.Equals(
                    loaded.Fingerprint, key.Fingerprint, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException("密钥落盘后指纹不一致。");
            }

            return key;
        }
        catch
        {
            key.Dispose();
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(entropy);
        }
    }

    /// <summary>全新安装前清掉旧密钥；失败就中止安装，绝不复用旧钥匙。</summary>
    internal bool TryDeleteAll(
        SecurityIdentifier currentUser, out string? error, out bool deleteScheduled)
    {
        error = null;
        deleteScheduled = false;

        if (!Directory.Exists(DirectoryPath)
            && !File.Exists(ConfigPath)
            && !File.Exists(KeyPath))
        {
            return true;
        }

        if (TryDeleteDirectory())
        {
            return true;
        }

        // 可能是上一个所有者留下的 DACL：管理员先接管所有权，再删。
        if (!ProtectedModeAcl.TryTakeOwnership(
                DirectoryPath, currentUser, out var ownerError))
        {
            error = ownerError;
            return ScheduleAndReport(error, out deleteScheduled);
        }

        try
        {
            ProtectedModeAcl.ApplyToDirectory(DirectoryPath, currentUser);
        }
        catch (Exception ex)
        {
            error = $"接管所有权后设置 ACL 失败：{ex.Message}";
            return ScheduleAndReport(error, out deleteScheduled);
        }

        if (TryDeleteDirectory())
        {
            return true;
        }

        error = "密钥目录仍被占用或拒绝访问。";
        return ScheduleAndReport(error, out deleteScheduled);
    }

    private bool ScheduleAndReport(string? reason, out bool scheduled)
    {
        // 文件被占用时登记重启删除；这是最后手段，不假装已经删干净。
        scheduled = false;

        foreach (var path in new[] { KeyPath, ConfigPath })
        {
            if (File.Exists(path))
            {
                scheduled |= MoveFileEx(path, null, MoveFileDelayUntilReboot);
            }
        }

        if (Directory.Exists(DirectoryPath))
        {
            scheduled |= MoveFileEx(
                DirectoryPath, null, MoveFileDelayUntilReboot);
        }

        if (!scheduled)
        {
            return false;
        }

        // 仍然返回 false：卸载器要如实告诉用户“重启后才会彻底删除”。
        return false;
    }

    private bool TryDeleteDirectory()
    {
        try
        {
            if (!Directory.Exists(DirectoryPath))
            {
                // 目录不在但文件残留（异常安装）：逐个删。
                if (File.Exists(ConfigPath))
                {
                    File.Delete(ConfigPath);
                }

                if (File.Exists(KeyPath))
                {
                    File.Delete(KeyPath);
                }

                return !File.Exists(ConfigPath) && !File.Exists(KeyPath);
            }

            Directory.Delete(DirectoryPath, recursive: true);
            return true;
        }
        catch (Exception)
        {
            return false;
        }
    }

    private OwnerKey LoadKey(ProtectedModeConfig config)
    {
        if (!File.Exists(KeyPath))
        {
            throw new FileNotFoundException(
                $"受保护模式私钥文件不存在：{KeyPath}");
        }

        var blob = File.ReadAllBytes(KeyPath);
        var entropy = config.GetEntropyBytes();

        try
        {
            var key = OwnerKey.Unprotect(blob, entropy);

            if (string.Equals(
                    key.Fingerprint, config.Fingerprint, StringComparison.OrdinalIgnoreCase))
            {
                return key;
            }

            key.Dispose();
            throw new InvalidDataException("私钥与配置里的公钥指纹不一致。");
        }
        finally
        {
            CryptographicOperations.ZeroMemory(entropy);
            CryptographicOperations.ZeroMemory(blob);
        }
    }

    private static void WriteAtomic(
        string path, ReadOnlySpan<byte> data, SecurityIdentifier owner)
    {
        var directory = Path.GetDirectoryName(path)
                        ?? throw new InvalidOperationException("密钥路径没有父目录。");

        Directory.CreateDirectory(directory);

        var temporary = $"{path}.tmp-{Guid.NewGuid():N}";

        try
        {
            using (var stream = new FileStream(
                       temporary, FileMode.CreateNew, FileAccess.Write, FileShare.None))
            {
                // 先设 ACL 再写内容：临时文件从第一字节起就只有 SYSTEM + 所有者可读。
                ProtectedModeAcl.ApplyToFile(temporary, owner);
                stream.Write(data);
                stream.Flush(flushToDisk: true);
            }

            File.Move(temporary, path, overwrite: true);
            ProtectedModeAcl.ApplyToFile(path, owner);
        }
        catch
        {
            try
            {
                File.Delete(temporary);
            }
            catch (Exception)
            {
                // 清理临时文件失败不掩盖原始异常。
            }

            throw;
        }
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern bool MoveFileEx(
        string existingFileName, string? newFileName, uint flags);
}
