using System.Diagnostics;
using System.Text;

namespace WinAppGuard.Core;

/// <summary>
/// 本机日志。
///
/// ============================ 隐私约定 ============================
/// 日志**只写在本机**，绝不发送到任何地方。
/// 目录固定为 %LOCALAPPDATA%\WinAppGuard\logs，用户可以随时查看、复制或删除，
/// 界面上也提供了「打开日志目录」按钮，不需要去猜日志藏在哪。
///
/// 注意：本程序确实含有一处联网代码（IP 归属查询，见 Core/IpOwnershipLookup.cs），
/// 但**日志与它无关**：日志里的内容从不参与联网，也从不被发送出去。
/// ==================================================================
///
/// 设计原则：
///   1. **写日志失败绝不能让程序出问题** —— 所有写入都用 try/catch 包住，写不进去就放弃这一次记录；
///   2. 只记录「操作」和「错误」，不记录每次扫描的连接明细
///      （连接列表每 3 秒刷新一次，把明细写进去很快就爆了，而且没有价值）；
///   3. 按天分文件，只保留最近若干天，不让日志无限增长。
/// </summary>
public static class LocalLog
{
    /// <summary>日志保留天数。</summary>
    private const int RetentionDays = 7;

    /// <summary>日志文件名前缀。</summary>
    private const string FilePrefix = "winappguard-";

    /// <summary>多个线程同时写会把文件写坏，所有写入都走这把锁。</summary>
    private static readonly object Gate = new();

    private static readonly Lazy<string> DirectoryHolder = new(CreateLogDirectory);

    /// <summary>上次清理旧日志的日期，避免每写一行都去列一次目录。</summary>
    private static DateTime _lastCleanupDate = DateTime.MinValue;

    /// <summary>日志目录的完整路径。</summary>
    /// <summary>
    /// 日志目录的完整路径。
    ///
    /// 3.0 起服务与界面共用这一套日志代码，但**目录不同**：
    /// 服务以 SYSTEM 运行，不能往某个用户的 %LOCALAPPDATA% 里写。
    /// 服务启动时调用 <see cref="UseDirectory"/> 指向 %ProgramData%。
    /// </summary>
    public static string LogDirectory => _overrideDirectory ?? DirectoryHolder.Value;

    private static string? _overrideDirectory;

    /// <summary>
    /// 指定日志目录（只应在进程启动时调用一次）。
    /// 传 null 或空字符串表示恢复默认（%LOCALAPPDATA%\WinAppGuard\logs）。
    /// </summary>
    public static void UseDirectory(string? directory)
    {
        _overrideDirectory = string.IsNullOrWhiteSpace(directory) ? null : directory;
    }

    /// <summary>
    /// 3.3：服务日志固定英文（级别名与异常描述）。
    /// 由 <c>ServiceLog.Initialize</c> 置为 true；界面日志保持中文级别。
    /// </summary>
    public static bool English { get; set; }

    /// <summary>
    /// 3.3：按当前日志语言二选一。
    /// 界面日志跟随界面语言；服务日志固定英文（<see cref="English"/> 已由服务打开）。
    /// </summary>
    public static string Pick(string chinese, string english)
        => English ? english : chinese;

    /// <summary>记录一般信息（启动、状态同步等）。</summary>
    public static void Info(string message) => Write("信息", message);

    /// <summary>记录需要注意但不致命的情况。</summary>
    public static void Warning(string message, Exception? exception = null)
        => Write("警告", Append(message, exception));

    /// <summary>记录用户主动做的、会改动系统状态的操作（阻止、允许、开关自启等）。</summary>
    public static void Operation(string message) => Write("操作", message);

    /// <summary>记录错误。传入异常时会连同堆栈一起记下来。</summary>
    public static void Error(string message, Exception? exception = null)
        => Write("错误", Append(message, exception));

    private static string Append(string message, Exception? exception)
    {
        if (exception is null)
        {
            return message;
        }

        return English
            ? message + Environment.NewLine + DescribeException(exception)
            : $"{message}{Environment.NewLine}{exception}";
    }

    /// <summary>
    /// 异常的英文描述：只写类型、HResult、Win32 错误码和堆栈。
    /// 不写 <c>Exception.Message</c>，因为系统异常的 Message 会跟随系统语言。
    /// </summary>
    public static string DescribeException(Exception exception)
    {
        var builder = new System.Text.StringBuilder();
        Exception? current = exception;

        while (current is not null)
        {
            builder.AppendLine();
            builder.Append($"exception={current.GetType().FullName} hresult=0x{current.HResult:X8}");

            if (current is System.ComponentModel.Win32Exception win32)
            {
                builder.Append($" nativeErrorCode={win32.NativeErrorCode}");
            }

            builder.AppendLine();
            builder.Append(current.StackTrace ?? "   at <no stack trace>");
            current = current.InnerException;
        }

        return builder.ToString();
    }

    /// <summary>
    /// 在资源管理器里打开日志目录。
    /// 打不开返回 false，由界面去提示，不要在日志模块里弹框。
    /// </summary>
    public static bool OpenLogDirectory()
    {
        try
        {
            Directory.CreateDirectory(LogDirectory);
            Process.Start(new ProcessStartInfo
            {
                FileName = LogDirectory,
                UseShellExecute = true,
            });
            return true;
        }
        catch (Exception)
        {
            return false;
        }
    }

    private static string CreateLogDirectory()
    {
        var path = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            AppConstants.AppDataFolderName,
            "logs");

        try
        {
            Directory.CreateDirectory(path);
        }
        catch (Exception)
        {
            // 建不出来就返回原路径，后续写入会失败并被吞掉，不影响程序运行。
        }

        return path;
    }

    /// <summary>
    /// 3.3：按调用方给定的级别名写一行。
    /// 服务日志用英文级别（INFO / WARN / OP / ERROR），界面日志仍用中文级别。
    /// </summary>
    public static void WriteLevel(string level, string message) => Write(level, message);

    private static void Write(string level, string message)
    {
        try
        {
            if (English)
            {
                level = level switch
                {
                    "信息" => "INFO",
                    "警告" => "WARN",
                    "操作" => "OP",
                    "错误" => "ERROR",
                    _ => level,
                };
            }

            lock (Gate)
            {
                var directory = LogDirectory;
                if (string.IsNullOrEmpty(directory))
                {
                    return;
                }

                CleanupOldFilesOncePerDay(directory);

                var file = Path.Combine(directory, $"{FilePrefix}{DateTime.Now:yyyyMMdd}.log");
                var line = $"{DateTime.Now:yyyy-MM-dd HH:mm:ss.fff} [{level}] {message}{Environment.NewLine}";

                File.AppendAllText(file, line, Encoding.UTF8);
            }
        }
        catch (Exception)
        {
            // 磁盘满、权限不足、路径异常…… 任何情况下都不能因为日志影响程序本身。
        }
    }

    /// <summary>删除超过保留天数的旧日志。每天只做一次。</summary>
    private static void CleanupOldFilesOncePerDay(string directory)
    {
        var today = DateTime.Now.Date;
        if (_lastCleanupDate == today)
        {
            return;
        }

        _lastCleanupDate = today;
        var cutoff = today.AddDays(-RetentionDays);

        try
        {
            foreach (var file in Directory.EnumerateFiles(directory, FilePrefix + "*.log"))
            {
                if (File.GetLastWriteTime(file) < cutoff)
                {
                    File.Delete(file);
                }
            }
        }
        catch (Exception)
        {
            // 清理失败无所谓，下次再试。
        }
    }
}
