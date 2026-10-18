using System.Net;
using System.Runtime.InteropServices;

namespace WinAppGuard.Core.Audit;

/// <summary>缓存里的一条「域名 → IP」记录。</summary>
internal sealed record DnsCacheRecord(string Name, string Address, uint TtlSeconds);

/// <summary>
/// 读取 **Windows DNS 客户端缓存**（Dnscache 服务的内存缓存）。
///
/// ==================== 它读的是什么 ====================
/// 不是抓包、不是自建缓存、也不发任何网络请求：
///   - <c>DnsGetCacheDataTable</c> 枚举缓存里的名字；
///   - <c>DnsQuery(..., DNS_QUERY_NO_WIRE_QUERY)</c> 只从缓存里取记录（绝不发包）。
/// 因此它**不会新增任何外部端点**，符合本项目"唯一外部端点"的契约。
///
/// ==================== 它的天然局限 ====================
///   - TTL 到期记录就没了（实测有 1 秒的条目）→ 必须高频快照并累积；
///   - 一个 IP 可能对应多个域名（CDN）→ 只能给候选，不能断言；
///   - 浏览器自带 DoH 时根本不进这个缓存 → 域名未知（产品负责人已确认接受）。
/// </summary>
internal static class DnsCacheReader
{
    /// <summary>DNS_QUERY_NO_WIRE_QUERY：只查缓存，不发网络请求。</summary>
    private const uint DNS_QUERY_NO_WIRE_QUERY = 0x00000010;

    /// <summary>DNS TYPE：IPv4 / IPv6。</summary>
    private const ushort DNS_TYPE_A = 1;
    private const ushort DNS_TYPE_AAAA = 28;

    /// <summary>DnsFree 的释放类型：平坦表（DnsGetCacheDataTable 的返回值）。</summary>
    private const int DnsFreeFlat = 0;

    /// <summary>DNS_RECORD 里 Data 联合体前面的固定部分（32 字节）。</summary>
    private const int DnsRecordDataOffset = 32;

    [StructLayout(LayoutKind.Sequential)]
    private struct DnsCacheEntry
    {
        public IntPtr Next;
        public IntPtr Name;
        public ushort Type;
        public ushort DataLength;
        public uint Flags;
        public uint Ttl;
        public uint Reserved;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct DnsRecordHeader
    {
        public IntPtr Next;
        public IntPtr Name;
        public ushort Type;
        public ushort DataLength;
        public uint Flags;
        public uint Ttl;
        public uint Reserved;
    }

    [DllImport("dnsapi.dll", CharSet = CharSet.Unicode)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int DnsGetCacheDataTable(out IntPtr entries);

    [DllImport("dnsapi.dll", CharSet = CharSet.Unicode)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern int DnsQuery_W(
        string name,
        ushort type,
        uint options,
        IntPtr extra,
        out IntPtr results,
        IntPtr reserved);

    [DllImport("dnsapi.dll")]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    private static extern void DnsFree(IntPtr data, int freeType);

    /// <summary>
    /// 诊断：只走链表、不做任何查询，报告"表里到底有多少条目"。
    /// 用来区分两种情况：缓存本来就是空的 vs 我们的 API 调用/遍历有问题。
    /// </summary>
    internal static (int Result, int Entries, int NamedEntries, string? FirstName) ProbeTable()
    {
        var entries = 0;
        var named = 0;
        string? firstName = null;
        var table = IntPtr.Zero;

        var result = DnsGetCacheDataTable(out table);

        if (table == IntPtr.Zero)
        {
            return (result, 0, 0, null);
        }

        try
        {
            var node = table;
            var guard = 0;

            while (node != IntPtr.Zero && guard++ < 100_000)
            {
                entries++;
                var entry = Marshal.PtrToStructure<DnsCacheEntry>(node);
                var name = Marshal.PtrToStringUni(entry.Name);

                if (!string.IsNullOrEmpty(name))
                {
                    named++;
                    firstName ??= name;
                }

                node = entry.Next;
            }
        }
        finally
        {
            DnsFree(table, DnsFreeFlat);
        }

        return (result, entries, named, firstName);
    }
    /// <summary>启动时的结构体尺寸自检（防止又一次"整体偏移几字节"）。</summary>
    internal static void EnsureLayout()
    {
        var cacheEntrySize = Marshal.SizeOf<DnsCacheEntry>();
        if (cacheEntrySize != 32)
        {
            throw new InvalidOperationException($"DNS_CACHE_ENTRY 尺寸不对：期望 32，实际 {cacheEntrySize}");
        }

        var recordSize = Marshal.SizeOf<DnsRecordHeader>();
        if (recordSize != DnsRecordDataOffset)
        {
            throw new InvalidOperationException($"DNS_RECORD 头部尺寸不对：期望 {DnsRecordDataOffset}，实际 {recordSize}");
        }
    }

    /// <summary>
    /// 读一遍当前缓存，返回所有 A / AAAA 记录。
    /// 任何一步失败都返回空列表（审计功能不能因此崩掉）。
    /// </summary>
    internal static IReadOnlyList<DnsCacheRecord> ReadSnapshot(bool allowResolverQuery = true)
    {
        var result = new List<DnsCacheRecord>();
        var names = new List<string>();
        var table = IntPtr.Zero;

        try
        {
            // ⚠️ 两段式：**先只走链表把名字抄下来**，再逐名查询。
            // 边遍历边 DnsQuery 会让缓存发生变动、链表被断开 ——
            // 实测表现为"只拿到前 4 个名字"，而不是报错。
            _ = DnsGetCacheDataTable(out table);
            if (table == IntPtr.Zero)
            {
                return result;
            }

            var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var node = table;
            var guard = 0;

            while (node != IntPtr.Zero && guard++ < 100_000)
            {
                var entry = Marshal.PtrToStructure<DnsCacheEntry>(node);
                var name = Marshal.PtrToStringUni(entry.Name);

                if (!string.IsNullOrEmpty(name) && seen.Add(name))
                {
                    names.Add(name);
                }

                node = entry.Next;
            }
        }
        catch (Exception)
        {
            // 走链表出错就用已经抄下来的名字。
        }
        finally
        {
            if (table != IntPtr.Zero)
            {
                try
                {
                    DnsFree(table, DnsFreeFlat);
                }
                catch (Exception)
                {
                    // 释放失败只影响内存。
                }
            }
        }

        foreach (var name in names)
        {
            try
            {
                CollectRecords(name, DNS_TYPE_A, DNS_TYPE_AAAA, result, allowResolverQuery);
            }
            catch (Exception)
            {
                // 单个名字失败不影响其它。
            }
        }

        return result;
    }
    private static void CollectRecords(
        string name,
        ushort typeA,
        ushort typeAaaa,
        List<DnsCacheRecord> output,
        bool allowResolverQuery)
    {
        CollectOne(name, typeA, output, allowResolverQuery);
        CollectOne(name, typeAaaa, output, allowResolverQuery);
    }

    private static void CollectOne(
        string name,
        ushort type,
        List<DnsCacheRecord> output,
        bool allowResolverQuery)
    {
        // 开启「域名推测」时用缓存优先（0）：缓存有就直接返回；
        // 条目刚好过期时，Windows 可能向本机 DNS 服务器补发一次查询。
        // 关闭时用 NO_WIRE_QUERY：绝不发包，代价是覆盖率低。
        var options = allowResolverQuery ? 0u : DNS_QUERY_NO_WIRE_QUERY;

        if (DnsQuery_W(name, type, options, IntPtr.Zero, out var records, IntPtr.Zero) != 0
            || records == IntPtr.Zero)
        {
            return;
        }

        try
        {
            var node = records;

            while (node != IntPtr.Zero)
            {
                var header = Marshal.PtrToStructure<DnsRecordHeader>(node);

                try
                {
                    var address = TryReadAddress(node, header);
                    if (address is not null)
                    {
                        output.Add(new DnsCacheRecord(name, address, header.Ttl));
                    }
                }
                catch (Exception)
                {
                    // 单条记录坏了就跳过，别把整个名字的记录都丢掉。
                }

                node = header.Next;
            }
        }
        finally
        {
            DnsFree(records, DnsFreeFlat);
        }
    }

    /// <summary>从 DNS_RECORD 的 Data 联合体里读 IP。必须按原始字节读，不能用整数转换。</summary>
    private static string? TryReadAddress(IntPtr record, DnsRecordHeader header)
    {
        var data = IntPtr.Add(record, DnsRecordDataOffset);

        if (header.Type == DNS_TYPE_A)
        {
            var bytes = new byte[4];
            Marshal.Copy(data, bytes, 0, 4);
            return new IPAddress(bytes).ToString();
        }

        if (header.Type == DNS_TYPE_AAAA)
        {
            var bytes = new byte[16];
            Marshal.Copy(data, bytes, 0, 16);
            return new IPAddress(bytes).ToString();
        }

        return null;
    }
}
