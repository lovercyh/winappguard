using System.Text;
using System.Text.Json;

namespace WinAppGuard.Core.Diagnostics.Lan;

/// <summary>
/// 4.2：事件落盘（每天一个 JSONL 文件）。
///
/// 只写事件元数据（时间 / 规则 / 级别 / 网卡 / MAC / IP / 摘要），
/// 不写任何 ARP/DHCP 报文内容。
/// </summary>
public sealed class LanEventStore
{
    private const string FilePrefix = "events-";
    private const string FileSuffix = ".jsonl";

    private static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    private readonly object _gate = new();
    private readonly string _directory;

    public LanEventStore(string directory)
    {
        _directory = directory;
    }

    public void Append(LanEvent item)
    {
        lock (_gate)
        {
            try
            {
                Directory.CreateDirectory(_directory);

                var path = Path.Combine(_directory, $"{FilePrefix}{item.TimeUtc.ToLocalTime():yyyyMMdd}{FileSuffix}");
                var line = JsonSerializer.Serialize(item, Options) + "\n";
                File.AppendAllText(path, line, new UTF8Encoding(false));
            }
            catch (Exception)
            {
                // 落盘失败不影响检测；事件仍在内存与日志里。
            }
        }
    }

    /// <summary>读取最近 <paramref name="max"/> 条（新的在前）。</summary>
    public List<LanEvent> ReadRecent(int max) => ReadRecent(max, kindPrefix: null);

    /// <summary>读取最近 N 条；kindPrefix 非空时只返回该前缀的规则。</summary>
    public List<LanEvent> ReadRecent(int max, string? kindPrefix)
    {
        var result = new List<LanEvent>(Math.Min(max, 256));

        lock (_gate)
        {
            try
            {
                if (!Directory.Exists(_directory))
                {
                    return result;
                }

                foreach (var file in Directory.GetFiles(_directory, $"{FilePrefix}*{FileSuffix}")
                             .OrderByDescending(path => path, StringComparer.OrdinalIgnoreCase))
                {
                    var lines = File.ReadAllLines(file, Encoding.UTF8);

                    for (var i = lines.Length - 1; i >= 0 && result.Count < max; i--)
                    {
                        if (string.IsNullOrWhiteSpace(lines[i]))
                        {
                            continue;
                        }

                        try
                        {
                            var item = JsonSerializer.Deserialize<LanEvent>(lines[i], Options);

                            if (item is null
                                || (kindPrefix is not null
                                    && !item.Kind.StartsWith(kindPrefix, StringComparison.OrdinalIgnoreCase)))
                            {
                                continue;
                            }

                            if (!result.Any(existing => existing.Id == item.Id))
                            {
                                result.Add(item);
                            }
                        }
                        catch (Exception)
                        {
                            // 单行坏了跳过，不影响其它事件。
                        }
                    }

                    if (result.Count >= max)
                    {
                        break;
                    }
                }
            }
            catch (Exception)
            {
                // 读不到就返回已有的。
            }
        }

        return result;
    }

    /// <summary>
    /// 4.3：只删除某个规则前缀的事件（例如 <c>dns_</c>），保留同一天的其它事件。
    /// 返回删除的条数。
    /// </summary>
    public int ClearKinds(string kindPrefix)
        => ClearWhere(kind => kind.StartsWith(kindPrefix, StringComparison.OrdinalIgnoreCase));

    /// <summary>4.3：按规则名谓词删除事件（用于“只清 DNS”或“只清非 DNS”）。</summary>
    public int ClearWhere(Func<string, bool> predicate)
    {
        var removed = 0;

        lock (_gate)
        {
            try
            {
                if (!Directory.Exists(_directory))
                {
                    return 0;
                }

                foreach (var file in Directory.GetFiles(_directory, $"{FilePrefix}*{FileSuffix}"))
                {
                    var lines = File.ReadAllLines(file, Encoding.UTF8);
                    var keep = new List<string>(lines.Length);
                    var changed = false;

                    foreach (var line in lines)
                    {
                        if (string.IsNullOrWhiteSpace(line))
                        {
                            continue;
                        }

                        LanEvent? item = null;

                        try
                        {
                            item = JsonSerializer.Deserialize<LanEvent>(line, Options);
                        }
                        catch (Exception)
                        {
                            // 坏行保留，避免误删。
                        }

                        if (item is not null && predicate(item.Kind))
                        {
                            removed++;
                            changed = true;
                            continue;
                        }

                        keep.Add(line);
                    }

                    if (!changed)
                    {
                        continue;
                    }

                    if (keep.Count == 0)
                    {
                        File.Delete(file);
                    }
                    else
                    {
                        File.WriteAllText(
                            file,
                            string.Join("\n", keep) + "\n",
                            new UTF8Encoding(false));
                    }
                }
            }
            catch (Exception)
            {
                // 删不掉不影响功能。
            }
        }

        return removed;
    }

    public void Clear()
    {
        lock (_gate)
        {
            try
            {
                if (!Directory.Exists(_directory))
                {
                    return;
                }

                foreach (var file in Directory.GetFiles(_directory, $"{FilePrefix}*{FileSuffix}"))
                {
                    File.Delete(file);
                }
            }
            catch (Exception)
            {
                // 删不掉不影响功能。
            }
        }
    }

    /// <summary>按保留期删除过期文件，返回删除数量。</summary>
    public int Prune(int retentionDays, DateTime now)
    {
        var removed = 0;
        var cutoff = now.ToLocalTime().Date.AddDays(-Math.Clamp(retentionDays, 1, 365));

        lock (_gate)
        {
            try
            {
                if (!Directory.Exists(_directory))
                {
                    return 0;
                }

                foreach (var file in Directory.GetFiles(_directory, $"{FilePrefix}*{FileSuffix}"))
                {
                    var name = Path.GetFileNameWithoutExtension(file);

                    if (!name.StartsWith(FilePrefix, StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    var dateText = name[FilePrefix.Length..];

                    if (!DateTime.TryParseExact(
                            dateText, "yyyyMMdd", null,
                            System.Globalization.DateTimeStyles.None, out var date))
                    {
                        continue;
                    }

                    if (date < cutoff)
                    {
                        File.Delete(file);
                        removed++;
                    }
                }
            }
            catch (Exception)
            {
                // 清理失败下次再试。
            }
        }

        return removed;
    }
}
