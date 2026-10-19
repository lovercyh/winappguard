using WinAppGuard.Core;

namespace WinAppGuard.Service;

/// <summary>
/// 服务日志：复用产品的 <see cref="LocalLog"/>，但目录指向
/// <c>%ProgramData%\WinAppGuard\logs</c> —— 服务以 SYSTEM 运行，
/// 不能往某个用户的 %LOCALAPPDATA% 里写。
/// </summary>
internal static class ServiceLog
{
    private static bool _initialized;

    internal static void Initialize()
    {
        if (_initialized)
        {
            return;
        }

        _initialized = true;

        var directory = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "WinAppGuard",
            "logs");

        LocalLog.UseDirectory(directory);

        try
        {
            Directory.CreateDirectory(directory);
        }
        catch (Exception)
        {
            // 建不了目录就让日志写入自己失败，不影响服务本身。
        }
    }

    internal static void Info(string message) => LocalLog.Info($"[服务] {message}");

    internal static void Warning(string message) => LocalLog.Warning($"[服务] {message}");

    internal static void Error(string message, Exception? exception = null)
        => LocalLog.Error($"[服务] {message}", exception);
}
