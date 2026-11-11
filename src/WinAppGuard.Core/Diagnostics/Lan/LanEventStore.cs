using WinAppGuard.Core.Storage;

namespace WinAppGuard.Core.Diagnostics.Lan;

/// <summary>
/// 4.2：事件落盘（每天一个 JSONL 文件）。
///
/// 5.9 起统一走 <see cref="JsonlEventLog{T}"/>：
///   - 旧 <c>events-yyyyMMdd.jsonl</c> 仍可读取；
///   - 新记录写入 <c>events-yyyyMMdd-NN.jsonl</c>，按大小轮转；
///   - 只写事件元数据（时间 / 规则 / 级别 / 网卡 / MAC / IP / 摘要），
///     不写任何 ARP/DHCP 报文内容。
/// </summary>
public sealed class LanEventStore
{
    private const long MaxBytesPerFile = 4 * 1024 * 1024;

    private readonly object _gate = new();
    private readonly JsonlEventLog<LanEvent> _log;

    public LanEventStore(string directory)
    {
        _log = new JsonlEventLog<LanEvent>(
            directory,
            "events",
            retentionDays: 7,
            MaxBytesPerFile);
    }

    public void Append(LanEvent item)
    {
        lock (_gate)
        {
            try
            {
                _log.Append(item);
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
        if (max <= 0)
        {
            return new List<LanEvent>();
        }

        lock (_gate)
        {
            var result = new List<LanEvent>(Math.Min(max, 256));
            var seen = new HashSet<string>(StringComparer.Ordinal);

            foreach (var item in _log.ReadAll()
                         .Where(item => kindPrefix is null
                                        || item.Kind.StartsWith(
                                            kindPrefix, StringComparison.OrdinalIgnoreCase))
                         .OrderByDescending(item => item.TimeUtc))
            {
                if (!seen.Add(item.Id))
                {
                    continue;
                }

                result.Add(item);

                if (result.Count >= max)
                {
                    break;
                }
            }

            return result;
        }
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
        ArgumentNullException.ThrowIfNull(predicate);

        lock (_gate)
        {
            return _log.RemoveWhere(item => predicate(item.Kind));
        }
    }

    public void Clear()
    {
        lock (_gate)
        {
            _log.Clear();
        }
    }

    /// <summary>按保留期删除过期文件，返回删除数量。</summary>
    public int Prune(int retentionDays, DateTime now)
    {
        lock (_gate)
        {
            return _log.Prune(now, retentionDays);
        }
    }
}
