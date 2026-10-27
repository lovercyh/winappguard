using System.IO.Compression;
using System.Text;

namespace WinAppGuard.Setup;

/// <summary>
/// 安装器自带的载荷（3.0 发布版）：
/// `WinAppGuardSetup.exe` 末尾追加了一个 ZIP，里面是界面、服务、卸载器。
///
/// 这样用户从 Releases **只需要下载 Setup + Uninstall 两个文件**，
/// 不需要再单独下载 WinAppGuard.exe / WinAppGuardSvc.exe
/// （单独下载那两个也用不了：没有安装器就不会注册服务、不会创建快捷方式）。
///
/// 文件格式：
///   [Setup 本体][ZIP 字节][magic 8 字节 "WAGPAY01"][ZIP 长度 int64 小端]
/// 没有追加数据时（开发期直接跑 bin 里的 Setup）返回 null，回退到"读取同目录文件"。
/// </summary>
internal static class EmbeddedPayload
{
    private static readonly byte[] Magic = Encoding.ASCII.GetBytes("WAGPAY01");

    private const string UiExeName = "WinAppGuard.exe";
    private const string ServiceExeName = "WinAppGuardSvc.exe";
    private const string SetupExeName = "WinAppGuardSetup.exe";
    internal const string NpcapInstallerName = "npcap-1.90.exe";
    private const string NpcapLicenseName = "Npcap-LICENSE.txt";

    /// <summary>
    /// 提取载荷。没有载荷返回 null。
    /// </summary>
    /// <param name="targetDirectory">指定解压目录；null 表示用临时目录。</param>
    internal static string? TryExtract(string? targetDirectory = null)
    {
        var executable = Environment.ProcessPath;

        if (string.IsNullOrEmpty(executable))
        {
            return null;
        }

        try
        {
            using var stream = File.OpenRead(executable);

            if (stream.Length < 16)
            {
                return null;
            }

            Span<byte> footer = stackalloc byte[16];
            stream.Seek(stream.Length - 16, SeekOrigin.Begin);
            stream.ReadExactly(footer);

            if (!footer[..8].SequenceEqual(Magic))
            {
                return null;
            }

            var length = BitConverter.ToInt64(footer[8..]);

            if (length <= 0 || length > stream.Length - 16)
            {
                return null;
            }

            stream.Seek(stream.Length - 16 - length, SeekOrigin.Begin);

            var zipBytes = new byte[length];
            stream.ReadExactly(zipBytes);

            var directory = targetDirectory
                            ?? Path.Combine(Path.GetTempPath(), $"WinAppGuard-payload-{Guid.NewGuid():N}");

            Directory.CreateDirectory(directory);

            using var archive = new ZipArchive(new MemoryStream(zipBytes), ZipArchiveMode.Read);

            foreach (var entry in archive.Entries)
            {
                var name = Path.GetFileName(entry.FullName);

                if (name is not (UiExeName or ServiceExeName or SetupExeName
                    or NpcapInstallerName or NpcapLicenseName))
                {
                    continue;
                }

                entry.ExtractToFile(Path.Combine(directory, name), overwrite: true);
            }

            return directory;
        }
        catch (Exception ex)
        {
            // 诊断：内置载荷解不开时把原因写到临时文件（安装器是隐藏控制台，用户看不到）。
            try
            {
                File.WriteAllText(
                    Path.Combine(Path.GetTempPath(), "wag-payload-error.txt"),
                    ex.ToString());
            }
            catch (Exception)
            {
                // 连诊断文件都写不了就放弃。
            }

            return null;
        }
    }
}
