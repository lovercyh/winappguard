using System.Globalization;
using System.Text;

namespace WinAppGuard.Core.Audit;

/// <summary>
/// 审计记录的本地存储：按天分文件、按体积分段、按天数清理。
///
/// 为什么用"一行一条 JSON"而不是数据库：
///   - 零第三方库（项目硬线），SQLite 需要外部依赖；
///   - 追加写 + 断电最多丢最后一行，而且半行能被跳过；
///   - 文件可以直接用记事本打开核对 —— 符合本项目"可验证"的一贯做法。
///
/// 文件位置：<c>%LOCALAPPDATA%\WinAppGuard\audit\audit-yyyyMMdd-NN.jsonl</c>
/// **只写本机，永不上传**。
/// </summary>
internal sealed class AuditStore : IDisposable
{
    /// <summary>单个分段文件的上限（默认 8 MB）。</summary>
    internal const long DefaultMaxFileBytes = 8L * 1024 * 1024;

    /// <summary>默认保留天数。</summary>
    internal const int DefaultRetentionDays = 7;

    private readonly object _gate = new();
    private readonly long _maxFileBytes;
    private readonly int _retentionDays;

    private FileStream? _stream;
    private string? _currentPath;
    private long _currentBytes;

    internal AuditStore(
        string? directory = null,
        long maxFileBytes = DefaultMaxFileBytes,
        int retentionDays = DefaultRetentionDays)
    {
        DirectoryPath = directory ?? Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            AppConstants.AppDataFolderName,
            "audit");

        _maxFileBytes = maxFileBytes;
        _retentionDays = retentionDays;

        Directory.CreateDirectory(DirectoryPath);
    }

    /// <summary>审计文件所在目录。</summary>
    internal string DirectoryPath { get; }

    /// <summary>是否记录（关闭后 Append 直接返回）。</summary>
    internal bool Enabled { get; set; } = true;

    /// <summary>写入失败的次数 —— 磁盘满、权限问题等。界面可以据此提示"审计没记上"。</summary>
    internal int WriteFailures { get; private set; }

    /// <summary>追加一条记录。失败不抛异常（审计不能影响主功能），只累计 <see cref="WriteFailures"/>。</summary>
    internal void Append(AuditEvent auditEvent)
    {
        if (!Enabled)
        {
            return;
        }

        var line = auditEvent.ToJsonLine();
        var bytes = Encoding.UTF8.GetBytes(line + "\n");

        lock (_gate)
        {
            try
            {
                EnsureWriter();
                _stream!.Write(bytes, 0, bytes.Length);

                // 每条都刷盘：审计的价值在于"事后还能看到"，
                // 崩溃丢掉最后几秒的记录会让排查变成猜谜。
                _stream.Flush();
                _currentBytes += bytes.Length;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
            {
                WriteFailures++;
                DisposeWriter();
            }
        }
    }

    /// <summary>读出最近的 <paramref name="maxCount"/> 条（按时间正序）。</summary>
    internal IReadOnlyList<AuditEvent> ReadRecent(int maxCount)
    {
        lock (_gate)
        {
            var result = new List<AuditEvent>();

            foreach (var file in GetFiles())
            {
                List<string> lines;
                try
                {
                    // 必须共享读写：写入端还开着这个文件（FileShare 不匹配会直接 IOException）。
                    using var stream = new FileStream(
                        file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    using var reader = new StreamReader(stream, Encoding.UTF8);

                    lines = new List<string>();
                    while (reader.ReadLine() is { } line)
                    {
                        lines.Add(line);
                    }
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    continue;
                }

                foreach (var line in lines)
                {
                    var parsed = AuditEvent.TryParse(line);
                    if (parsed is not null)
                    {
                        result.Add(parsed);
                    }
                }
            }

            return result.Count <= maxCount
                ? result
                : result.GetRange(result.Count - maxCount, maxCount);
        }
    }

    /// <summary>删掉超过保留期的文件，返回删除个数。</summary>
    internal int PurgeExpired(DateTime nowLocal)
    {
        lock (_gate)
        {
            var cutoff = nowLocal.Date.AddDays(-(_retentionDays - 1));
            var deleted = 0;

            foreach (var file in GetFiles())
            {
                var date = TryParseDate(file);
                if (date is null || date.Value.Date >= cutoff)
                {
                    continue;
                }

                try
                {
                    if (string.Equals(file, _currentPath, StringComparison.OrdinalIgnoreCase))
                    {
                        DisposeWriter();
                    }

                    File.Delete(file);
                    deleted++;
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    // 删不掉就下一天再试，不影响使用。
                }
            }

            return deleted;
        }
    }

    /// <summary>清空全部审计记录。</summary>
    internal void Clear()
    {
        lock (_gate)
        {
            DisposeWriter();

            foreach (var file in GetFiles())
            {
                try
                {
                    File.Delete(file);
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    // 忽略：上层会重新读一次文件列表，确实还在就如实显示。
                }
            }
        }
    }

    /// <summary>当前审计目录里的文件列表（按名字排序）。自检与界面用。</summary>
    internal IReadOnlyList<string> GetFiles()
    {
        if (!Directory.Exists(DirectoryPath))
        {
            return Array.Empty<string>();
        }

        return Directory.GetFiles(DirectoryPath, "audit-*.jsonl")
            .OrderBy(path => path, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    public void Dispose() => DisposeWriter();

    // ==================================================================
    // 内部
    // ==================================================================

    private void EnsureWriter()
    {
        if (_stream is not null && _currentBytes < _maxFileBytes)
        {
            return;
        }

        DisposeWriter();

        var today = DateTime.Now.ToString("yyyyMMdd", CultureInfo.InvariantCulture);
        var segment = 1;

        while (true)
        {
            var candidate = Path.Combine(DirectoryPath, $"audit-{today}-{segment:00}.jsonl");

            if (!File.Exists(candidate))
            {
                _stream = new FileStream(
                    candidate, FileMode.Append, FileAccess.Write, FileShare.ReadWrite);
                _currentPath = candidate;
                _currentBytes = _stream.Length;
                return;
            }

            var length = new FileInfo(candidate).Length;
            if (length < _maxFileBytes)
            {
                _stream = new FileStream(
                    candidate, FileMode.Append, FileAccess.Write, FileShare.ReadWrite);
                _currentPath = candidate;
                _currentBytes = length;
                return;
            }

            segment++;
        }
    }

    private void DisposeWriter()
    {
        try
        {
            _stream?.Dispose();
        }
        catch (Exception)
        {
            // 关闭失败无关紧要。
        }

        _stream = null;
        _currentPath = null;
        _currentBytes = 0;
    }

    /// <summary>从 <c>audit-yyyyMMdd-NN.jsonl</c> 里取出日期。</summary>
    private static DateTime? TryParseDate(string path)
    {
        var name = Path.GetFileNameWithoutExtension(path);
        var parts = name.Split('-');

        return parts.Length >= 2
               && DateTime.TryParseExact(
                   parts[1], "yyyyMMdd", CultureInfo.InvariantCulture, DateTimeStyles.None, out var date)
            ? date
            : null;
    }
}
