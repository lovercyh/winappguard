using System.Text;
using System.Text.Json;
using WinAppGuard.Core.Features;

namespace WinAppGuard.Core.Storage;

/// <summary>
/// 5.9：事件流只有一种写法。
///
/// 文件格式保持 JSONL（一行一条），按天分段、按大小轮转、按保留期清理。
/// 坏行跳过，不让一条损坏记录拖垮整个列表。
/// </summary>
public sealed class JsonlEventLog<T> where T : FeatureEvent
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = false,
        PropertyNameCaseInsensitive = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    private readonly object _gate = new();

    public JsonlEventLog(
        string directory,
        string prefix,
        int retentionDays,
        long maxBytesPerFile)
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

    public IReadOnlyList<T> ReadRecent(int limit, DateTime? nowUtc = null)
    {
        if (limit <= 0)
        {
            return Array.Empty<T>();
        }

        lock (_gate)
        {
            if (!Directory.Exists(DirectoryPath))
            {
                return Array.Empty<T>();
            }

            var files = EnumerateFiles()
                .OrderBy(file => file, StringComparer.OrdinalIgnoreCase)
                .ToList();

            var values = new List<T>();

            foreach (var file in files)
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

            return values.Count <= limit
                ? values
                : values.GetRange(values.Count - limit, limit);
        }
    }

    public int Prune(DateTime? nowUtc = null)
    {
        lock (_gate)
        {
            if (!Directory.Exists(DirectoryPath))
            {
                return 0;
            }

            var now = nowUtc ?? DateTime.UtcNow;
            var cutoff = now.Date.AddDays(-(RetentionDays - 1));
            var deleted = 0;

            foreach (var file in EnumerateFiles())
            {
                var date = TryParseDate(file);

                if (date is null || date.Value.Date >= cutoff)
                {
                    continue;
                }

                try
                {
                    File.Delete(file);
                    deleted++;
                }
                catch (Exception)
                {
                    // 删不掉就留到下一次清理。
                }
            }

            return deleted;
        }
    }

    private IEnumerable<string> EnumerateFiles()
        => Directory.EnumerateFiles(
            DirectoryPath,
            Prefix + "-*.jsonl",
            SearchOption.TopDirectoryOnly);

    private string GetOrCreateWritableFile(DateTime nowUtc)
    {
        var date = nowUtc.ToLocalTime().ToString("yyyyMMdd");
        var files = EnumerateFiles()
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
