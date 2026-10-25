using System.Runtime.InteropServices;

namespace WinAppGuard.Core.Diagnostics;

/// <summary>3.5：一条 DNS 查询记录（只含域名，不含响应内容）。</summary>
public sealed record DnsQueryRecord(DateTime TimeUtc, int Pid, string QueryName, string Status);

/// <summary>
/// 3.5：用 ETW 实时会话采集 <c>Microsoft-Windows-DNS-Client</c> 的查询事件。
///
/// 为什么放 Core 而不是服务：它只依赖 Win32（advapi32 / tdh），
/// 服务和 POC 工具都能直接复用，也方便离线断言事件解析。
///
/// 边界（必须如实告知用户）：
///   - 只能看到经过 Windows DNS 客户端的查询；浏览器/应用自己做 DoH/DoT 时看不到；
///   - 命中 hosts 文件、或纯缓存且不发事件的场景可能没有记录；
///   - 记录保存在内存环形缓冲里（默认 2000 条），服务重启即清空；
///   - 只记域名 / PID / 结果码，不记录响应 IP 内容之外的任何载荷。
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

    private const uint WnodeFlagTracedGuid = 0x00020000;
    private const uint EventTraceRealTimeMode = 0x00000100;
    private const uint ProcessTraceModeRealTime = 0x00000100;
    private const uint ProcessTraceModeEventRecord = 0x10000000;
    private const uint EventControlCodeEnableProvider = 1;
    private const uint EventTraceControlStop = 1;
    private const byte TraceLevelInformation = 4;

    private const int ErrorSuccess = 0;
    private const int ErrorInsufficientBuffer = 122;
    private const int ErrorAlreadyExists = 183;
    private const int ErrorCancelled = 1223;
    private const int ErrorWmiInstanceNotFound = 4201;

    private readonly object _gate = new();
    private readonly LinkedList<Entry> _records = new();

    /// <summary>(pid, 域名) → 最近一条记录，用来合并 3006/3008 这类同一次查询的多个事件。</summary>
    private readonly Dictionary<string, LinkedListNode<Entry>> _recent = new(StringComparer.Ordinal);

    private readonly int _capacity;

    private Thread? _thread;
    private ulong _traceHandle;
    private IntPtr _sessionProperties;
    private EventTraceLogfile _logfile;
    private EventRecordCallback? _callback;
    private bool _stopping;
    private string? _lastError;

    public DnsEtwMonitor(int capacity = 2000)
    {
        _capacity = Math.Clamp(capacity, 100, 10_000);
    }

    public bool IsRunning { get; private set; }

    public string? LastError => _lastError;

    /// <summary>启动实时会话。失败返回 false，原因见 <see cref="LastError"/>。</summary>
    public bool Start()
    {
        lock (_gate)
        {
            if (_thread is not null)
            {
                return IsRunning;
            }

            if (!TryStartSession(out var sessionError))
            {
                _lastError = $"StartTrace/EnableTrace failed: {sessionError}";
                return false;
            }

            _stopping = false;
            _callback = OnEvent;
            _logfile = new EventTraceLogfile
            {
                LoggerName = SessionName,
                ProcessTraceMode = ProcessTraceModeEventRecord | ProcessTraceModeRealTime,
                EventCallback = Marshal.GetFunctionPointerForDelegate(_callback),
            };

            _traceHandle = OpenTraceW(ref _logfile);

            if (_traceHandle == ulong.MaxValue)
            {
                var error = Marshal.GetLastWin32Error();
                _lastError = $"OpenTrace failed: {error}";
                StopSession();
                return false;
            }

            var handle = _traceHandle;
            _thread = new Thread(() => ProcessLoop(handle))
            {
                IsBackground = true,
                Name = "dns-etw",
            };

            _thread.Start();
            IsRunning = true;
            _lastError = null;

            return true;
        }
    }

    /// <summary>停止会话并释放消费者线程。</summary>
    public void Stop()
    {
        Thread? thread;
        ulong handle;

        lock (_gate)
        {
            thread = _thread;
            _thread = null;
            _stopping = true;
            IsRunning = false;
            handle = _traceHandle;
            _traceHandle = 0;
        }

        // 先停会话：ProcessTrace 会因此返回，线程才能退出。
        StopSession();

        if (thread is not null && thread != Thread.CurrentThread)
        {
            _ = thread.Join(TimeSpan.FromSeconds(3));
        }

        if (handle != 0 && handle != ulong.MaxValue)
        {
            _ = CloseTrace(handle);
        }

        FreeSessionProperties();
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
                    node.Value.QueryName,
                    node.Value.Status));
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

    // ---------------- 消费线程 ----------------

    private void ProcessLoop(ulong handle)
    {
        var result = ProcessTrace(new[] { handle }, 1, IntPtr.Zero, IntPtr.Zero);

        lock (_gate)
        {
            IsRunning = false;

            if (!_stopping
                && result != ErrorSuccess
                && result != ErrorCancelled)
            {
                _lastError = $"ProcessTrace exited: {result}";
            }
        }
    }

    private void OnEvent(IntPtr recordPointer)
    {
        try
        {
            var record = Marshal.PtrToStructure<EventRecord>(recordPointer);

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
            Add(record.EventHeader.ProcessId, queryName, status);
        }
        catch (Exception)
        {
            // ETW 回调里绝不能抛异常：那会打断整个消费线程。
        }
    }

    private void Add(int pid, string queryName, string status)
    {
        if (pid <= 0)
        {
            return;
        }

        var now = DateTime.UtcNow;

        lock (_gate)
        {
            var key = $"{pid}|{queryName.ToLowerInvariant()}";

            if (_recent.TryGetValue(key, out var node)
                && (now - node.Value.TimeUtc).TotalSeconds <= 2)
            {
                node.Value.TimeUtc = now;

                if (status.Length > 0)
                {
                    node.Value.Status = status;
                }

                return;
            }

            var entry = new Entry
            {
                TimeUtc = now,
                Pid = pid,
                QueryName = queryName,
                Status = status,
            };

            var added = _records.AddLast(entry);
            _recent[key] = added;

            while (_records.Count > _capacity && _records.First is { } first)
            {
                _records.RemoveFirst();
                _recent.Remove($"{first.Value.Pid}|{first.Value.QueryName.ToLowerInvariant()}");
            }
        }
    }

    // ---------------- 会话 ----------------

    private bool TryStartSession(out int error)
    {
        error = ErrorSuccess;

        var propertiesSize = Marshal.SizeOf<EventTraceProperties>();
        var nameBytes = (SessionName.Length + 1) * sizeof(char);
        var totalSize = propertiesSize + nameBytes;
        var buffer = Marshal.AllocHGlobal(totalSize);

        try
        {
            for (var i = 0; i < totalSize; i++)
            {
                Marshal.WriteByte(buffer, i, 0);
            }

            var properties = new EventTraceProperties
            {
                Wnode = new WnodeHeader
                {
                    BufferSize = (uint)totalSize,
                    Flags = WnodeFlagTracedGuid,
                    ClientContext = 1,
                    Guid = SessionGuid,
                },
                LogFileMode = EventTraceRealTimeMode,
                FlushTimer = 1,
                LoggerNameOffset = (uint)propertiesSize,
            };

            Marshal.StructureToPtr(properties, buffer, false);

            var name = SessionName.ToCharArray();
            Marshal.Copy(name, 0, IntPtr.Add(buffer, propertiesSize), name.Length);
            Marshal.WriteInt16(buffer, propertiesSize + name.Length * sizeof(char), 0);

            var rc = StartTraceW(out var handle, SessionName, buffer);

            if (rc == ErrorAlreadyExists)
            {
                // 服务上次崩溃可能留下同名会话：停掉再试一次。
                _ = ControlTraceW(0, SessionName, buffer, EventTraceControlStop);
                rc = StartTraceW(out handle, SessionName, buffer);
            }

            if (rc != ErrorSuccess)
            {
                error = rc;
                Marshal.FreeHGlobal(buffer);
                return false;
            }

            // 0 = 不过滤关键字；Level 4 = Informational。
            var provider = ProviderGuid;

            var enableRc = EnableTraceEx2(
                handle,
                ref provider,
                EventControlCodeEnableProvider,
                TraceLevelInformation,
                0,
                0,
                0,
                IntPtr.Zero);

            if (enableRc != ErrorSuccess)
            {
                _ = ControlTraceW(handle, SessionName, buffer, EventTraceControlStop);
                error = enableRc;
                Marshal.FreeHGlobal(buffer);
                return false;
            }

            _sessionProperties = buffer;
            return true;
        }
        catch
        {
            Marshal.FreeHGlobal(buffer);
            throw;
        }
    }

    private void StopSession()
    {
        var properties = _sessionProperties;

        if (properties != IntPtr.Zero)
        {
            _ = ControlTraceW(0, SessionName, properties, EventTraceControlStop);
        }
    }

    private void FreeSessionProperties()
    {
        IntPtr properties;

        lock (_gate)
        {
            properties = _sessionProperties;
            _sessionProperties = IntPtr.Zero;
        }

        if (properties != IntPtr.Zero)
        {
            Marshal.FreeHGlobal(properties);
        }
    }

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

    // ---------------- 内部模型 ----------------

    private sealed class Entry
    {
        public DateTime TimeUtc;
        public int Pid;
        public string QueryName = string.Empty;
        public string Status = string.Empty;
    }

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate void EventRecordCallback(IntPtr eventRecord);

    // ---------------- 结构（evntrace.h / evntcons.h）----------------

    [StructLayout(LayoutKind.Sequential)]
    private struct WnodeHeader
    {
        public uint BufferSize;
        public uint ProviderId;
        public ulong HistoricalContext;
        public ulong TimeStamp;
        public Guid Guid;
        public uint ClientContext;
        public uint Flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct EventTraceProperties
    {
        public WnodeHeader Wnode;
        public uint BufferSize;
        public uint MinimumBuffers;
        public uint MaximumBuffers;
        public uint MaximumFileSize;
        public uint LogFileMode;
        public uint FlushTimer;
        public uint EnableFlags;
        public int AgeLimit;
        public uint NumberOfBuffers;
        public uint FreeBuffers;
        public uint EventsLost;
        public uint BuffersWritten;
        public uint LogBuffersLost;
        public uint RealTimeBuffersLost;
        public IntPtr LoggerThreadId;
        public uint LogFileNameOffset;
        public uint LoggerNameOffset;
    }

    [StructLayout(LayoutKind.Sequential, Size = 0xac, CharSet = CharSet.Unicode)]
    private struct TimeZoneInformation
    {
        public uint Bias;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
        public string StandardName;

        [MarshalAs(UnmanagedType.ByValArray, ArraySubType = UnmanagedType.U2, SizeConst = 8)]
        public ushort[] StandardDate;

        public uint StandardBias;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 32)]
        public string DaylightName;

        [MarshalAs(UnmanagedType.ByValArray, ArraySubType = UnmanagedType.U2, SizeConst = 8)]
        public ushort[] DaylightDate;

        public uint DaylightBias;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct EventTraceHeader
    {
        public ushort Size;
        public ushort FieldTypeFlags;
        public byte Type;
        public byte Level;
        public ushort Version;
        public int ThreadId;
        public int ProcessId;
        public long TimeStamp;
        public Guid Guid;
        public uint KernelTime;
        public uint UserTime;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct EtwBufferContext
    {
        public byte ProcessorNumber;
        public byte Alignment;
        public ushort LoggerId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct EventTrace
    {
        public EventTraceHeader Header;
        public uint InstanceId;
        public uint ParentInstanceId;
        public Guid ParentGuid;
        public IntPtr MofData;
        public int MofLength;
        public EtwBufferContext BufferContext;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TraceLogfileHeader
    {
        public uint BufferSize;
        public uint Version;
        public uint ProviderVersion;
        public uint NumberOfProcessors;
        public long EndTime;
        public uint TimerResolution;
        public uint MaximumFileSize;
        public uint LogFileMode;
        public uint BuffersWritten;
        public uint StartBuffers;
        public uint PointerSize;
        public uint EventsLost;
        public uint CpuSpeedInMHz;
        public IntPtr LoggerName;
        public IntPtr LogFileName;
        public TimeZoneInformation TimeZone;
        public long BootTime;
        public long PerfFreq;
        public long StartTime;
        public uint ReservedFlags;
        public uint BuffersLost;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct EventTraceLogfile
    {
        [MarshalAs(UnmanagedType.LPWStr)]
        public string? LogFileName;

        [MarshalAs(UnmanagedType.LPWStr)]
        public string? LoggerName;

        public long CurrentTime;
        public uint BuffersRead;
        public uint ProcessTraceMode;
        public EventTrace CurrentEvent;
        public TraceLogfileHeader LogfileHeader;
        public IntPtr BufferCallback;
        public int BufferSize;
        public int Filled;
        public int EventsLost;
        public IntPtr EventCallback;
        public int IsKernelTrace;
        public IntPtr Context;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct EventHeader
    {
        public ushort Size;
        public ushort HeaderType;
        public ushort Flags;
        public ushort EventProperty;
        public int ThreadId;
        public int ProcessId;
        public long TimeStamp;
        public Guid ProviderId;
        public ushort Id;
        public byte Version;
        public byte Channel;
        public byte Level;
        public byte Opcode;
        public ushort Task;
        public ulong Keyword;
        public uint KernelTime;
        public uint UserTime;
        public Guid ActivityId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct EventRecord
    {
        public EventHeader EventHeader;
        public EtwBufferContext BufferContext;
        public ushort ExtendedDataCount;
        public ushort UserDataLength;
        public IntPtr ExtendedData;
        public IntPtr UserData;
        public IntPtr UserContext;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct PropertyDataDescriptor
    {
        public IntPtr PropertyName;
        public uint ArrayIndex;
        public uint Reserved;
    }

    // ---------------- P/Invoke ----------------

    [DllImport("advapi32.dll", EntryPoint = "StartTraceW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int StartTraceW(out ulong sessionHandle, string sessionName, IntPtr properties);

    [DllImport("advapi32.dll", EntryPoint = "ControlTraceW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern int ControlTraceW(
        ulong sessionHandle, string? sessionName, IntPtr properties, uint controlCode);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern int EnableTraceEx2(
        ulong traceHandle, ref Guid providerId, uint controlCode, byte level,
        ulong matchAnyKeyword, ulong matchAllKeyword, uint timeout, IntPtr enableParameters);

    [DllImport("advapi32.dll", EntryPoint = "OpenTraceW", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern ulong OpenTraceW(ref EventTraceLogfile logfile);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern int ProcessTrace(
        [In] ulong[] handleArray, uint handleCount, IntPtr startTime, IntPtr endTime);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern int CloseTrace(ulong traceHandle);

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
