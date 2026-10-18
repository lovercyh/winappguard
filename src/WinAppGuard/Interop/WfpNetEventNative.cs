using System.Runtime.InteropServices;

namespace WinAppGuard.Interop;

/// <summary>
/// WFP **网络事件**相关的结构体与函数（严格模式/审计用）。
///
/// 这些布局在 2.1 的 POC 里已经实测验证过：订阅能建、事件能收到、
/// 进程身份和远端地址都正确。这里的 <see cref="EnsureLayout"/> 把**字段偏移**
/// 也一起钉住 —— 只校验总尺寸是不够的（实测踩过：总尺寸对、地址整体偏 4 字节）。
/// </summary>
internal static class WfpNetEventNative
{
    /// <summary>FWPM_NET_EVENT_TYPE_CLASSIFY_DROP。</summary>
    internal const int EventTypeClassifyDrop = 3;

    [StructLayout(LayoutKind.Sequential)]
    internal struct FwpmNetEventSubscription
    {
        public IntPtr EnumTemplate;
        public uint Flags;
        public Guid SessionKey;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ByteArray6
    {
        public byte B0, B1, B2, B3, B4, B5;
    }

    /// <summary>头结构体里那段"保留"的联合体（48 字节）。</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct NetEventReservedUnion
    {
        public ByteArray6 R2;
        public ByteArray6 R3;
        public uint R4;
        public uint R5;
        public ushort R6;
        public uint R7;
        public uint R8;
        public ushort R9;
        public ulong R10;
    }

    /// <summary>FWP_AF + 联合体（56 字节，前面有 4 字节对齐填充）。</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct NetEventTail
    {
        public int Reserved1;
        public NetEventReservedUnion Union;
    }

    /// <summary>
    /// 地址联合体：16 字节、对齐 **4**。
    /// ⚠️ 不能用 ulong 字段 —— .NET 会把对齐算成 8，整个地址/端口区偏移 4 字节。
    /// </summary>
    [StructLayout(LayoutKind.Sequential, Size = 16)]
    internal struct AddrUnion
    {
        public uint V4;
        public uint Padding1;
        public uint Padding2;
        public uint Padding3;
    }

    /// <summary>FWPM_NET_EVENT_HEADER1（144 字节）。</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct FwpmNetEventHeader1
    {
        public long TimeStamp;
        public uint Flags;
        public int IpVersion;
        public byte IpProtocol;
        public AddrUnion LocalAddr;
        public AddrUnion RemoteAddr;
        public ushort LocalPort;
        public ushort RemotePort;
        public uint ScopeId;
        public WfpNativeMethods.FwpByteBlob AppId;
        public IntPtr UserId;
        public NetEventTail Tail;
    }

    /// <summary>FWPM_NET_EVENT1（160 字节）。</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct FwpmNetEvent1
    {
        public FwpmNetEventHeader1 Header;
        public int Type;
        public IntPtr EventData;
    }

    [UnmanagedFunctionPointer(CallingConvention.Winapi)]
    internal delegate void NetEventCallback(IntPtr context, IntPtr eventPtr);

    [DllImport("fwpuclnt.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    internal static extern uint FwpmNetEventSubscribe0(
        IntPtr engineHandle,
        ref FwpmNetEventSubscription subscription,
        NetEventCallback callback,
        IntPtr context,
        out IntPtr subscriptionHandle);

    [DllImport("fwpuclnt.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    internal static extern uint FwpmNetEventUnsubscribe0(IntPtr engineHandle, IntPtr subscriptionHandle);

    internal static void EnsureLayout()
    {
        Check<FwpmNetEventSubscription>(32, "FWPM_NET_EVENT_SUBSCRIPTION0");
        Check<NetEventReservedUnion>(48, "net-event reserved union");
        Check<NetEventTail>(56, "net-event tail");
        Check<FwpmNetEventHeader1>(144, "FWPM_NET_EVENT_HEADER1");
        Check<FwpmNetEvent1>(160, "FWPM_NET_EVENT1");

        CheckOffset<FwpmNetEventHeader1>(20, nameof(FwpmNetEventHeader1.LocalAddr));
        CheckOffset<FwpmNetEventHeader1>(36, nameof(FwpmNetEventHeader1.RemoteAddr));
        CheckOffset<FwpmNetEventHeader1>(52, nameof(FwpmNetEventHeader1.LocalPort));
        CheckOffset<FwpmNetEventHeader1>(54, nameof(FwpmNetEventHeader1.RemotePort));
        CheckOffset<FwpmNetEventHeader1>(56, nameof(FwpmNetEventHeader1.ScopeId));
        CheckOffset<FwpmNetEventHeader1>(64, nameof(FwpmNetEventHeader1.AppId));
        CheckOffset<FwpmNetEventHeader1>(80, nameof(FwpmNetEventHeader1.UserId));
        CheckOffset<FwpmNetEventHeader1>(88, nameof(FwpmNetEventHeader1.Tail));

        CheckOffset<FwpmNetEvent1>(144, nameof(FwpmNetEvent1.Type));
    }

    private static void Check<T>(int expected, string name) where T : struct
    {
        var actual = Marshal.SizeOf<T>();
        if (actual != expected)
        {
            throw new InvalidOperationException($"{name} 尺寸不对：期望 {expected}，实际 {actual}");
        }
    }

    private static void CheckOffset<T>(int expected, string fieldName) where T : struct
    {
        var actual = Marshal.OffsetOf<T>(fieldName).ToInt32();
        if (actual != expected)
        {
            throw new InvalidOperationException(
                $"{typeof(T).Name}.{fieldName} 偏移不对：期望 {expected}，实际 {actual}");
        }
    }
}
