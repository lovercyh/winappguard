using WinAppGuard.Core;

namespace WinAppGuard.Service;

/// <summary>
/// 服务日志（3.3 起固定英文 + 稳定事件码）。
///
/// 为什么不再跟随界面语言：服务没有"当前界面语言"这个概念，日志又经常被
/// 远程复制给排障的人看。固定英文 + 事件码，才能用 <c>WAG-RULE-913</c>
/// 这样的字符串稳定检索，也不会因为用户切换中文/英文而改变历史日志格式。
///
/// 异常的处理方式：
///   - 只记录类型、HResult、Win32 错误码和堆栈；
///   - **不记录 <c>Exception.Message</c>** —— 系统异常的 Message 会跟随系统语言，
///     一旦写进去，"全英文日志"就破了。
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

        // 3.3：服务日志固定英文（级别名、异常描述）；界面日志不受影响。
        LocalLog.English = true;

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

    internal static void Info(string code, string message)
        => LocalLog.WriteLevel("INFO", Format(code, message));

    internal static void Warning(string code, string message, Exception? exception = null)
        => LocalLog.WriteLevel("WARN", Format(code, message) + Describe(exception));

    /// <summary>记录用户/客户端主动做的、会改动系统状态的操作。</summary>
    internal static void Operation(string code, string message)
        => LocalLog.WriteLevel("OP", Format(code, message));

    internal static void Error(string code, string message, Exception? exception = null)
        => LocalLog.WriteLevel("ERROR", Format(code, message) + Describe(exception));

    private static string Format(string code, string message) => $"[{code}] {message}";

    /// <summary>异常只写类型、HResult、Win32 错误码和堆栈，绝不写本地化的 Message。</summary>
    private static string Describe(Exception? exception)
        => exception is null ? string.Empty : LocalLog.DescribeException(exception);
}
