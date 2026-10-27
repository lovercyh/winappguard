using System.Diagnostics;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace WinAppGuard.Core.Diagnostics.AntiScan;

/// <summary>
/// 4.0：随包的 Npcap 官方安装包（**未做任何修改**）。
///
/// 安装器、界面和自检共用这里的文件名、哈希和参数，避免三处各写一份后写歪：
///   - 哈希固定，防止安装包被替换；
///   - 签名者必须是 Nmap Software LLC；
///   - 参数只锁定推荐选项，不静默安装（免费版不支持 /S）。
/// </summary>
public static class NpcapInstaller
{
    /// <summary>随包文件名。</summary>
    public const string FileName = "npcap-1.90.exe";

    /// <summary>随包许可证文件名。</summary>
    public const string LicenseFileName = "Npcap-LICENSE.txt";

    /// <summary>官方 1.90 安装包的 SHA-256（发布时固定，换版本必须同步修改）。</summary>
    public const string ExpectedSha256 =
        "682B57E1C05EF375931975C9D6DED40888F4BFDF9F4B11571E654F962F1199B6";

    /// <summary>
    /// 锁定安装选项：不做 WinPcap 兼容模式、不装 loopback / 802.11 支持、驱动只允许管理员访问。
    /// </summary>
    public const string Arguments =
        "/winpcap_mode=disabled /loopback_support=disabled /dot11_support=disabled /admin_only=enforced";

    /// <summary>
    /// 校验安装包：先比对固定 SHA-256，再确认 Authenticode 签名者是 Nmap Software LLC。
    /// 完整性由固定哈希保证；签名检查只是额外一道"确实来自官方"的确认。
    /// </summary>
    public static bool Verify(string path, out string failureReason)
    {
        failureReason = string.Empty;

        try
        {
            if (!File.Exists(path))
            {
                failureReason = "找不到文件。";
                return false;
            }

            var actual = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(path)));

            if (!string.Equals(actual, ExpectedSha256, StringComparison.OrdinalIgnoreCase))
            {
                failureReason = $"SHA-256 不匹配（{actual}）。";
                return false;
            }

            // Authenticode 的 PE 签名提取目前没有 X509CertificateLoader 等价 API；
            // 这里只读取签名者 Subject，真正的完整性由上面的固定 SHA-256 保证。
#pragma warning disable SYSLIB0057
            using var certificate = X509Certificate.CreateFromSignedFile(path);
#pragma warning restore SYSLIB0057

            var subject = certificate.Subject ?? string.Empty;

            if (!subject.Contains("Nmap Software LLC", StringComparison.OrdinalIgnoreCase))
            {
                failureReason = $"签名者不是 Nmap Software LLC（{subject}）。";
                return false;
            }

            return true;
        }
        catch (Exception ex)
        {
            failureReason = ex.Message;
            return false;
        }
    }

    /// <summary>
    /// 以管理员身份启动官方安装程序（会弹一次 UAC），并等它结束。
    ///
    /// 返回安装器退出码；用户取消 UAC 时返回 <c>null</c> 且 <paramref name="error"/> 为空。
    /// </summary>
    public static int? RunElevated(string path, out string? error)
    {
        error = null;

        try
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = path,
                Arguments = Arguments,
                UseShellExecute = true,
                Verb = "runas",
                WorkingDirectory = Path.GetDirectoryName(path) ?? Environment.CurrentDirectory,
            };

            using var process = Process.Start(startInfo);

            if (process is null)
            {
                error = "无法启动安装程序。";
                return null;
            }

            process.WaitForExit();
            return process.ExitCode;
        }
        catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            // ERROR_CANCELLED：用户在 UAC 里点了"否"。
            return null;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return null;
        }
    }
}
