using System.Text;
using System.Text.Json;

namespace WinAppGuard.Core.Storage;

/// <summary>
/// 5.9：事件流只有一种写法。
///
/// 文件格式保持 JSONL（一行一条），按天分段、按大小轮转、按保留期清理。
/// 坏行跳过，不让一条损坏记录拖垮整个列表。
///
/// 兼容旧版本的单文件 <c>{prefix}.jsonl</c>：
///   - 读取时和新分段文件一起读；
///   - 新记录只写入 <c>{prefix}-yyyyMMdd-NN.jsonl</c>；
///   - 提供 <c>timestampSelector</c> 时，旧文件也会按保留期裁剪。
///
/// 不要求事件继承 <c>FeatureEvent</c>：IDS 等旧 DTO 已有自己的
/// 字段和 JSON 形状，迁移时优先保证旧数据可读。
/// </summary>
public sealed class JsonlEventLog<T> where T : class
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = false,
        PropertyNameCaseInsensitive = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    private readonly object _gate = new();
    private readonly Func<T, DateTime>? _timestampSelector;

    public JsonlEventLog(
        string directory,
        string prefix,
        int retentionDays,
        long maxBytesPerFile,
        Func<T, DateTime>? timestampSelector = null)
    {
        if (string.IsNullOrWhiteSpace(directory))
        {
            throw new ArgumentException("事件目录不能为空。", nameof(directory));
        }

        if (string.IsNullOrWhiteSpace(prefix))
        {
            throw new ArgumentException("事件文件前缀不能为空。", nameof(prefix));
        }

        DirectoryPath = directory;
        Prefix = prefix;
        RetentionDays = Math.Max(1, retentionDays);
        MaxBytesPerFile = Math.Max(1, maxBytesPerFile);
        _timestampSelector = timestampSelector;
    }

    public string DirectoryPath { get; }

    public string Prefix { get; }

    public int RetentionDays { get; }

    public long MaxBytesPerFile { get; }

    public void Append(T item, DateTime? nowUtc = null)
    {
        ArgumentNullException.ThrowIfNull(item);

        lock (_gate)
        {
            Directory.CreateDirectory(DirectoryPath);

            var now = nowUtc ?? DateTime.UtcNow;
            var file = GetOrCreateWritableFile(now);
            var line = JsonSerializer.Serialize(item, JsonOptions) + Environment.NewLine;

            using var stream = new FileStream(
                file,
                FileMode.Append,
                FileAccess.Write,
                FileShare.Read,
                4096,
                FileOptions.WriteThrough);

            using var writer = new StreamWriter(stream, new UTF8Encoding(false));
            writer.Write(line);
            writer.Flush();
            stream.Flush(flushToDisk: true);
        }
    }

    /// <summary>按文件顺序读取全部事件；坏行跳过。</summary>
    public IReadOnlyList<T> ReadAll()
    {
        lock (_gate)
        {
            return ReadAllCore();
        }
    }

    public IReadOnlyList<T> ReadRecent(int limit, DateTime? nowUtc = null)
    {
        if (limit <= 0)
        {
            return Array.Empty<T>();
        }

        lock (_gate)
        {
            var values = ReadAllCore();

            return values.Count <= limit
                ? values
                : values.Skip(values.Count - limit).ToList();
        }
    }

    /// <summary>删除全部事件文件（含旧版单文件）。</summary>
    public void Clear()
    {
        lock (_gate)
        {
            foreach (var file in EnumerateFiles().ToList())
            {
                try
                {
                    File.Delete(file);
                }
                catch (Exception)
                {
                    // 删不掉就留到下一次清理。
                }
            }
        }
    }

    /// <summary>
    /// 按谓词删除事件，返回删除条数。坏行原样保留，避免误删无法解析的记录。
    /// </summary>
    public int RemoveWhere(Func<T, bool> predicate)
    {
        ArgumentNullException.ThrowIfNull(predicate);

        lock (_gate)
        {
            var removed = 0;

            foreach (var file in EnumerateFiles().ToList())
            {
                var kept = new List<string>();
                var changed = false;

                foreach (var line in ReadLines(file))
                {
                    if (string.IsNullOrWhiteSpace(line))
                    {
                        changed = true;
                        continue;
                    }

                    try
                    {
                        var item = JsonSerializer.Deserialize<T>(line, JsonOptions);

                        if (item is not null && predicate(item))
                        {
                            removed++;
                            changed = true;
                            continue;
                        }
                    }
                    catch (Exception)
                    {
                        // 解析不了的行保留，避免误删。
                    }

                    kept.Add(line);
                }

                if (!changed)
                {
                    continue;
                }

                try
                {
                    if (kept.Count == 0)
                    {
                        File.Delete(file);
                        continue;
                    }

                    var temporary = file + ".tmp";
                    File.WriteAllLines(temporary, kept, new UTF8Encoding(false));
                    File.Move(temporary, file, overwrite: true);
                }
                catch (Exception)
                {
                    // 删不掉不影响功能。
                }
            }

            return removed;
        }
    }

    public int Prune(DateTime? nowUtc = null)
        => Prune(nowUtc, retentionDays: null);

    /// <summary>
    /// 按保留期清理。过期的分段文件按文件名日期整文件删除；
    /// 其余文件（含旧版单文件）在提供 <c>timestampSelector</c> 时逐条裁剪。
    /// </summary>
    public int Prune(DateTime? nowUtc, int? retentionDays)
    {
        lock (_gate)
        {
            if (!Directory.Exists(DirectoryPath))
            {
                return 0;
            }

            var days = Math.Max(1, retentionDays ?? RetentionDays);
            var now = nowUtc ?? DateTime.UtcNow;
            var cutoffDate = now.Date.AddDays(-(days - 1));
            var deleted = 0;

            foreach (var file in EnumerateFiles().ToList())
            {
                if (!IsLegacyFile(file))
                {
                    var date = TryParseDate(file);

                    if (date is not null && date.Value.Date < cutoffDate)
                    {
                        try
                        {
                            File.Delete(file);
                            deleted++;
                        }
                        catch (Exception)
                        {
                            // 删不掉就留到下一次清理。
                        }

                        continue;
                    }
                }

                PruneFileByTimestamp(file, now.AddDays(-days));
            }

            return deleted;
        }
    }

    private IReadOnlyList<T> ReadAllCore()
    {
        if (!Directory.Exists(DirectoryPath))
        {
            return Array.Empty<T>();
        }

        var values = new List<T>();

        foreach (var file in EnumerateFiles()
                     .OrderBy(file => file, StringComparer.OrdinalIgnoreCase))
        {
            foreach (var line in ReadLines(file))
            {
                if (string.IsNullOrWhiteSpace(line))
                {
                    continue;
                }

                try
                {
                    var item = JsonSerializer.Deserialize<T>(line, JsonOptions);

                    if (item is not null)
                    {
                        values.Add(item);
                    }
                }
                catch (Exception)
                {
                    // 单行损坏跳过，保留其余记录。
                }
            }
        }

        return values;
    }

    private IEnumerable<string> EnumerateFiles()
    {
        if (!Directory.Exists(DirectoryPath))
        {
            yield break;
        }

        var legacy = Path.Combine(DirectoryPath, Prefix + ".jsonl");

        if (File.Exists(legacy))
        {
            yield return legacy;
        }

        foreach (var file in Directory.EnumerateFiles(
                     DirectoryPath,
                     Prefix + "-*.jsonl",
                     SearchOption.TopDirectoryOnly))
        {
            yield return file;
        }
    }

    private bool IsLegacyFile(string file)
        => string.Equals(
            Path.GetFileName(file),
            Prefix + ".jsonl",
            StringComparison.OrdinalIgnoreCase);

    private string GetOrCreateWritableFile(DateTime nowUtc)
    {
        var date = nowUtc.ToLocalTime().ToString("yyyyMMdd");
        var files = EnumerateFiles()
            .Where(file => !IsLegacyFile(file))
            .Where(file => Path.GetFileName(file).StartsWith(
                $"{Prefix}-{date}-", StringComparison.OrdinalIgnoreCase))
            .OrderBy(file => file, StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (files.Count > 0)
        {
            var last = files[^1];

            if (new FileInfo(last).Length < MaxBytesPerFile)
            {
                return last;
            }

            var index = ParseIndex(last) + 1;
            return Path.Combine(DirectoryPath, $"{Prefix}-{date}-{index:00}.jsonl");
        }

        return Path.Combine(DirectoryPath, $"{Prefix}-{date}-00.jsonl");
    }

    private void PruneFileByTimestamp(string file, DateTime cutoff)
    {
        if (_timestampSelector is null || !File.Exists(file))
        {
            return;
        }

        var kept = new List<string>();
        var changed = false;

        foreach (var line in ReadLines(file))
        {
            if (string.IsNullOrWhiteSpace(line))
            {
                changed = true;
                continue;
            }

            try
            {
                var item = JsonSerializer.Deserialize<T>(line, JsonOptions);

                if (item is null || _timestampSelector(item) < cutoff)
                {
                    changed = true;
                    continue;
                }

                kept.Add(line);
            }
            catch (Exception)
            {
                changed = true;
            }
        }

        if (!changed)
        {
            return;
        }

        try
        {
            if (kept.Count == 0)
            {
                File.Delete(file);
                return;
            }

            var temporary = file + ".tmp";
            File.WriteAllLines(temporary, kept, new UTF8Encoding(false));
            File.Move(temporary, file, overwrite: true);
        }
        catch (Exception)
        {
            // 裁剪失败不致命：读取时仍会按保留期过滤。
        }
    }

    private static List<string> ReadLines(string file)
    {
        var lines = new List<string>();

        try
        {
            using var stream = new FileStream(
                file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var reader = new StreamReader(stream, Encoding.UTF8);

            while (reader.ReadLine() is { } line)
            {
                lines.Add(line);
            }
        }
        catch (Exception)
        {
            // 文件正在轮转/被删除时跳过。
        }

        return lines;
    }

    private static DateTime? TryParseDate(string file)
    {
        var name = Path.GetFileNameWithoutExtension(file);
        var parts = name.Split('-');

        if (parts.Length < 2
            || !DateTime.TryParseExact(
                parts[^2],
                "yyyyMMdd",
                System.Globalization.CultureInfo.InvariantCulture,
                System.Globalization.DateTimeStyles.None,
                out var date))
        {
            return null;
        }

        return date;
    }

    private static int ParseIndex(string file)
    {
        var name = Path.GetFileNameWithoutExtension(file);
        var last = name.Split('-').LastOrDefault();

        return int.TryParse(last, out var index) ? index : 0;
    }
}
