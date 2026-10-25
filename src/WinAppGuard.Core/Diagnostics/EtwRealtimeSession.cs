using System.Runtime.InteropServices;

namespace WinAppGuard.Core.Diagnostics;

/// <summary>
/// 3.5：一个**只启用单个 provider** 的 ETW 实时会话。
///
/// DNS 与流量采集共用这套底层：StartTrace / EnableTraceEx2 / OpenTrace /
/// ProcessTrace / ControlTrace 的调用顺序、结构体布局和停止流程只写一次，
/// 避免两份 P/Invoke 各自踩坑。
///
/// 回调在 ETW 的消费线程上执行，<see cref="EtwRealtimeSession"/> 会吞掉异常：
/// 回调里抛异常会直接打断 ProcessTrace。
/// </summary>
public sealed class EtwRealtimeSession : IDisposable
{
    private const uint WnodeFlagTracedGuid = 0x00020000;
    private const uint EventTraceRealTimeMode = 0x00000100;
    private const uint ProcessTraceModeRealTime = 0x00000100;
    private const uint ProcessTraceModeEventRecord = 0x10000000;
    private const uint EventControlCodeEnableProvider = 1;
    private const uint EventTraceControlStop = 1;

    private const int ErrorSuccess = 0;
    private const int ErrorAlreadyExists = 183;
    private const int ErrorCancelled = 1223;

    private readonly object _gate = new();
    private readonly string _sessionName;
    private readonly Guid _sessionGuid;
    private readonly Guid _providerGuid;
    private readonly ulong _keywords;
    private readonly byte _level;
    private readonly Action<IntPtr> _onEvent;

    private Thread? _thread;
    private ulong _traceHandle;
    private IntPtr _sessionProperties;
    private EventTraceLogfile _logfile;
    private EventRecordCallback? _callback;
    private bool _stopping;

    public EtwRealtimeSession(
        string sessionName,
        Guid sessionGuid,
        Guid providerGuid,
        ulong keywords,
        Action<IntPtr> onEvent,
        byte level = 4)
    {
        _sessionName = sessionName;
        _sessionGuid = sessionGuid;
        _providerGuid = providerGuid;
        _keywords = keywords;
        _onEvent = onEvent;
        _level = level;
    }

    public bool IsRunning { get; private set; }

    public string? LastError { get; private set; }

    /// <summary>结构体大小（自检用；大小不对说明 P/Invoke 布局错了）。</summary>
    internal static (int Logfile, int EventRecord) NativeStructSizes
        => (Marshal.SizeOf<EventTraceLogfile>(), Marshal.SizeOf<EventRecord>());

    /// <summary>把 ETW 回调指针转成只读结构（内部类型只在 Core 内使用）。</summary>
    internal static EventRecord ReadRecord(IntPtr pointer)
        => Marshal.PtrToStructure<EventRecord>(pointer);

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
                LastError = $"StartTrace/EnableTrace failed: {sessionError}";
                return false;
            }

            _stopping = false;
            _callback = Dispatch;
            _logfile = new EventTraceLogfile
            {
                LoggerName = _sessionName,
                ProcessTraceMode = ProcessTraceModeEventRecord | ProcessTraceModeRealTime,
                EventCallback = Marshal.GetFunctionPointerForDelegate(_callback),
            };

            _traceHandle = OpenTraceW(ref _logfile);

            if (_traceHandle == ulong.MaxValue)
            {
                var error = Marshal.GetLastWin32Error();
                LastError = $"OpenTrace failed: {error}";
                StopSession();
                FreeSessionProperties();
                return false;
            }

            var handle = _traceHandle;
            _thread = new Thread(() => ProcessLoop(handle))
            {
                IsBackground = true,
                Name = $"etw-{_sessionName}",
            };

            _thread.Start();
            IsRunning = true;
            LastError = null;

            return true;
        }
    }

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

    public void Dispose() => Stop();

    private void Dispatch(IntPtr record)
    {
        try
        {
            _onEvent(record);
        }
        catch (Exception)
        {
            // ETW 回调里绝不能抛异常。
        }
    }

    private void ProcessLoop(ulong handle)
    {
        var result = ProcessTrace(new[] { handle }, 1, IntPtr.Zero, IntPtr.Zero);

        lock (_gate)
        {
            IsRunning = false;

            if (!_stopping && result != ErrorSuccess && result != ErrorCancelled)
            {
                LastError = $"ProcessTrace exited: {result}";
            }
        }
    }

    private bool TryStartSession(out int error)
    {
        error = ErrorSuccess;

        var propertiesSize = Marshal.SizeOf<EventTraceProperties>();
        var nameBytes = (_sessionName.Length + 1) * sizeof(char);
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
                    Guid = _sessionGuid,
                },
                LogFileMode = EventTraceRealTimeMode,
                FlushTimer = 1,
                LoggerNameOffset = (uint)propertiesSize,
            };

            Marshal.StructureToPtr(properties, buffer, false);

            var name = _sessionName.ToCharArray();
            Marshal.Copy(name, 0, IntPtr.Add(buffer, propertiesSize), name.Length);
            Marshal.WriteInt16(buffer, propertiesSize + name.Length * sizeof(char), 0);

            var rc = StartTraceW(out var handle, _sessionName, buffer);

            if (rc == ErrorAlreadyExists)
            {
                // 上次崩溃可能留下同名会话：停掉再试一次。
                _ = ControlTraceW(0, _sessionName, buffer, EventTraceControlStop);
                rc = StartTraceW(out handle, _sessionName, buffer);
            }

            if (rc != ErrorSuccess)
            {
                error = rc;
                Marshal.FreeHGlobal(buffer);
                return false;
            }

            var provider = _providerGuid;

            var enableRc = EnableTraceEx2(
                handle,
                ref provider,
                EventControlCodeEnableProvider,
                _level,
                _keywords,
                0,
                0,
                IntPtr.Zero);

            if (enableRc != ErrorSuccess)
            {
                _ = ControlTraceW(handle, _sessionName, buffer, EventTraceControlStop);
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
            _ = ControlTraceW(0, _sessionName, properties, EventTraceControlStop);
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
    internal struct EtwBufferContext
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
    internal struct EventHeader
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
    internal struct EventRecord
    {
        public EventHeader EventHeader;
        public EtwBufferContext BufferContext;
        public ushort ExtendedDataCount;
        public ushort UserDataLength;
        public IntPtr ExtendedData;
        public IntPtr UserData;
        public IntPtr UserContext;
    }

    // ---------------- P/Invoke ----------------

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    private delegate void EventRecordCallback(IntPtr eventRecord);

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
}
