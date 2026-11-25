using System.Text;

namespace WinAppGuard.Setup;

/// <summary>
/// 5.12：安装/升级日志。写入 %ProgramData%\WinAppGuard\logs\setup-YYYYMMDD.log。
///
/// 安装器是控制台程序，用户双击时窗口可能一闪而过；把关键步骤落盘，
/// 5.12 的 --doctor 和用户反馈都能看到“到底停在哪一步”。
/// </summary>
internal static class SetupLog
{
    private static readonly object Gate = new();

    internal static string DirectoryPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "WinAppGuard",
        "logs");

    internal static void Info(string message) => Append("INFO", message);

    internal static void Warn(string message) => Append("WARN", message);

    internal static void Error(string message) => Append("ERR ", message);

    private static void Append(string level, string message)
    {
        try
        {
            lock (Gate)
            {
                Directory.CreateDirectory(DirectoryPath);

                var path = Path.Combine(
                    DirectoryPath,
                    $"setup-{DateTime.UtcNow:yyyyMMdd}.log");

                File.AppendAllText(
                    path,
                    $"{DateTime.UtcNow:O} [{level}] {message}{Environment.NewLine}",
                    new UTF8Encoding(false));
            }
        }
        catch (Exception)
        {
            // 日志失败不能影响安装。
        }
    }
}
