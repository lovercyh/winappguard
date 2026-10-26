using System.Runtime.InteropServices;

namespace WinAppGuard.Core.Diagnostics;

/// <summary>3.5：一条 DNS 查询记录（只含域名，不含响应内容）。</summary>
public sealed record DnsQueryRecord(
    DateTime TimeUtc,
    int Pid,
    string? ProcessPath,
    string ProcessName,
    string QueryName,
    string Status,
    int EventId);

/// <summary>
/// 3.5：用 ETW 实时会话采集 <c>Microsoft-Windows-DNS-Client</c> 的查询事件。
///
/// 为什么放 Core 而不是服务：它只依赖 Win32（advapi32 / tdh），
/// 服务和 POC 工具都能直接复用，也方便离线断言事件解析。
///
/// 边界（必须如实告知用户）：
///   - 只能看到经过 Windows DNS 客户端的查询；浏览器/应用自己做 DoH/DoT 时看不到；
///   - 命中 hosts 文件、或纯缓存且不发事件的场景可能没有记录；
///   - 部分 Windows 版本会把查询记到 DNS Client 服务（svchost）名下，无法反推真实程序；
///   - 记录保存在内存环形缓冲里（默认 2000 条），服务重启即清空；
///   - 只记域名 / PID / 结果码，不记录响应内容。
/// </summary>
public sealed class DnsEtwMonitor : IDisposable
{
    private const string SessionName = "WinAppGuard-Dns";

    /// <summary>会话 GUID（固定值；同一台机器只允许一个同名会话）。</summary>
    private static readonly Guid SessionGuid = new("7C1B3A6E-2F5D-4C9A-9B7E-3D6A1F0C8E21");

    /// <summary>Microsoft-Windows-DNS-Client。</summary>
    private static readonly Guid ProviderGuid = new("1C95126E-7EEA-49A9-A3FE-A378B03DDB4D");

    /// <summary>ETW 的 EventTrace 自身 GUID，用来跳过元数据事件。</summary>
    private static readonly Guid EventTraceGuid = new("68FDD900-4A3E-11D1-84F4-0000F80464E3");

    private const int ErrorSuccess = 0;

    private readonly object _gate = new();
    private readonly LinkedList<Entry> _records = new();

    /// <summary>(pid, 域名) → 最近一条记录，用来合并同一次查询的多个事件。</summary>
    private readonly Dictionary<string, LinkedListNode<Entry>> _recent = new(StringComparer.Ordinal);

    private readonly int _capacity;

    private EtwRealtimeSession? _session;

    /// <summary>3.7：每条新增/更新的 DNS 记录回调给 IDS；在 ETW 线程执行。</summary>
    public Action<DnsQueryRecord>? QueryObserved { get; set; }

    public DnsEtwMonitor(int capacity = 2000)
    {
        _capacity = Math.Clamp(capacity, 100, 10_000);
    }

    public bool IsRunning => _session?.IsRunning == true;

    public string? LastError => _session?.LastError;

    /// <summary>启动实时会话。失败返回 false，原因见 <see cref="LastError"/>。</summary>
    public bool Start()
    {
        lock (_gate)
        {
            if (_session is not null)
            {
                return _session.IsRunning;
            }

            var session = new EtwRealtimeSession(
                SessionName, SessionGuid, ProviderGuid, keywords: 0, OnEvent);

            if (!session.Start())
            {
                session.Dispose();
                return false;
            }

            _session = session;
            return true;
        }
    }

    /// <summary>停止会话并释放消费者线程。</summary>
    public void Stop()
    {
        EtwRealtimeSession? session;

        lock (_gate)
        {
            session = _session;
            _session = null;
        }

        session?.Dispose();
    }

    /// <summary>最近记录（新的在前）。</summary>
    public IReadOnlyList<DnsQueryRecord> Snapshot(int max = 500)
    {
        lock (_gate)
        {
            var limit = Math.Clamp(max, 1, _capacity);
            var list = new List<DnsQueryRecord>(Math.Min(limit, _records.Count));

            for (var node = _records.Last; node is not null && list.Count < limit; node = node.Previous)
            {
                list.Add(new DnsQueryRecord(
                    node.Value.TimeUtc,
                    node.Value.Pid,
                    node.Value.ProcessPath,
                    node.Value.ProcessName,
                    node.Value.QueryName,
                    node.Value.Status,
                    node.Value.EventId));
            }

            return list;
        }
    }

    /// <summary>清空内存记录（会话继续运行）。</summary>
    public void Clear()
    {
        lock (_gate)
        {
            _records.Clear();
            _recent.Clear();
        }
    }

    public void Dispose() => Stop();

    private void OnEvent(IntPtr recordPointer)
    {
        var record = EtwRealtimeSession.ReadRecord(recordPointer);

        // 实时会话通常不会收到元数据事件；仍然防御一下。
        if (record.EventHeader.ProviderId == EventTraceGuid)
        {
            return;
        }

        if (!TryGetString(recordPointer, "QueryName", out var queryName))
        {
            return;
        }

        queryName = queryName.Trim();

        if (queryName.Length == 0 || queryName.Length > 512)
        {
            return;
        }

        var status = ReadStatus(recordPointer);
        var pid = record.EventHeader.ProcessId;
        var (path, name) = ResolveProcess(pid);
        Add(pid, path, name, queryName, status, record.EventHeader.Id);
    }

    private static (string? Path, string Name) ResolveProcess(int pid)
    {
        string? path;

        try
        {
            path = ProcessResolver.TryGetImagePath(pid);
        }
        catch (Exception)
        {
            path = null;
        }

        return (path, string.IsNullOrEmpty(path) ? $"PID {pid}" : Path.GetFileName(path));
    }

    private void Add(
        int pid, string? processPath, string processName,
        string queryName, string status, int eventId)
    {
        if (pid <= 0)
        {
            return;
        }

        var now = DateTime.UtcNow;
        DnsQueryRecord? notification = null;

        lock (_gate)
        {
            var key = $"{pid}|{queryName.ToLowerInvariant()}";

            if (_recent.TryGetValue(key, out var node)
                && (now - node.Value.TimeUtc).TotalSeconds <= 2)
            {
                node.Value.TimeUtc = now;
                node.Value.EventId = eventId;

                if (status.Length > 0)
                {
                    node.Value.Status = status;
                }

                notification = ToRecord(node.Value);
            }
            else
            {
                var entry = new Entry
                {
                    TimeUtc = now,
                    Pid = pid,
                    ProcessPath = processPath,
                    ProcessName = processName,
                    QueryName = queryName,
                    Status = status,
                    EventId = eventId,
                };

                var added = _records.AddLast(entry);
                _recent[key] = added;
                notification = ToRecord(entry);

                while (_records.Count > _capacity && _records.First is { } first)
                {
                    _records.RemoveFirst();
                    _recent.Remove($"{first.Value.Pid}|{first.Value.QueryName.ToLowerInvariant()}");
                }
            }
        }

        if (notification is { } record)
        {
            QueryObserved?.Invoke(record);
        }
    }

    private static DnsQueryRecord ToRecord(Entry entry)
        => new(
            entry.TimeUtc,
            entry.Pid,
            entry.ProcessPath,
            entry.ProcessName,
            entry.QueryName,
            entry.Status,
            entry.EventId);
    // ---------------- TDH ----------------

    private static bool TryGetString(IntPtr record, string property, out string value)
    {
        value = string.Empty;

        if (!TryGetSize(record, property, out var size) || size <= 0)
        {
            return false;
        }

        var buffer = Marshal.AllocHGlobal(size);

        try
        {
            if (!TryGetProperty(record, property, size, buffer))
            {
                return false;
            }

            value = Marshal.PtrToStringUni(buffer) ?? string.Empty;
            return value.Length > 0;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static string ReadStatus(IntPtr record)
    {
        foreach (var name in new[] { "QueryStatus", "ResponseStatus" })
        {
            if (!TryGetSize(record, name, out var size) || size < 4)
            {
                continue;
            }

            var buffer = Marshal.AllocHGlobal(size);

            try
            {
                if (!TryGetProperty(record, name, size, buffer))
                {
                    continue;
                }

                return FormatStatus(unchecked((uint)Marshal.ReadInt32(buffer)));
            }
            finally
            {
                Marshal.FreeHGlobal(buffer);
            }
        }

        return string.Empty;
    }

    private static string FormatStatus(uint status)
    {
        return status switch
        {
            0 => "OK",
            9002 => "SERVFAIL",
            9003 => "NXDOMAIN",
            9501 => "NO_RECORDS",
            1460 => "TIMEOUT",
            _ => $"0x{status:X8}",
        };
    }

    private static bool TryGetSize(IntPtr record, string property, out int size)
    {
        size = 0;
        var namePointer = Marshal.StringToHGlobalUni(property);

        try
        {
            var descriptor = new PropertyDataDescriptor
            {
                PropertyName = namePointer,
                ArrayIndex = 0,
            };

            var rc = TdhGetPropertySize(
                record, 0, IntPtr.Zero, 1, ref descriptor, out size);

            return rc == ErrorSuccess;
        }
        finally
        {
            Marshal.FreeHGlobal(namePointer);
        }
    }

    private static bool TryGetProperty(IntPtr record, string property, int size, IntPtr buffer)
    {
        var namePointer = Marshal.StringToHGlobalUni(property);

        try
        {
            var descriptor = new PropertyDataDescriptor
            {
                PropertyName = namePointer,
                ArrayIndex = 0,
            };

            return TdhGetProperty(
                record, 0, IntPtr.Zero, 1, ref descriptor, size, buffer) == ErrorSuccess;
        }
        finally
        {
            Marshal.FreeHGlobal(namePointer);
        }
    }

    private sealed class Entry
    {
        public DateTime TimeUtc;
        public int Pid;
        public string? ProcessPath;
        public string ProcessName = string.Empty;
        public string QueryName = string.Empty;
        public string Status = string.Empty;
        public int EventId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PropertyDataDescriptor
    {
        public IntPtr PropertyName;
        public uint ArrayIndex;
        public uint Reserved;
    }

    [DllImport("tdh.dll", CharSet = CharSet.Unicode)]
    private static extern int TdhGetPropertySize(
        IntPtr eventRecord, uint tdhContextCount, IntPtr tdhContext,
        uint propertyDataCount, ref PropertyDataDescriptor propertyData, out int propertySize);

    [DllImport("tdh.dll", CharSet = CharSet.Unicode)]
    private static extern int TdhGetProperty(
        IntPtr eventRecord, uint tdhContextCount, IntPtr tdhContext,
        uint propertyDataCount, ref PropertyDataDescriptor propertyData,
        int propertySize, IntPtr buffer);
}
