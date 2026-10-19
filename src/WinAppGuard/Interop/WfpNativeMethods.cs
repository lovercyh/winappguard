using System.Runtime.InteropServices;

namespace WinAppGuard.Interop;

/// <summary>
/// WFP（Windows Filtering Platform）的 P/Invoke 声明与结构体。
///
/// ==================== 为什么单独一个文件 ====================
/// <see cref="NativeMethods"/> 里原来只有三类调用（TCP 表、进程路径、控制台），
/// 一眼就能审计完。WFP 这一套体量大、结构体多，混进去会把那份清单冲淡，
/// 所以单独成一个文件。审计时这两份文件合起来就是程序调用的**全部**系统接口。
///
/// ==================== 两个必须写死的实测结论 ====================
/// 1. <c>providerData</c> 字段是 <c>FWP_BYTE_BLOB</c> **结构体本身**（16 字节），
///    不是指针。写成 <c>IntPtr</c> 会让后面所有字段错位 8 字节，
///    BFE 会报 <c>FWP_E_INVALID_ENUMERATOR (0x8032001D)</c>（"枚举器无效"）——
///    这个错误信息完全指不到真正的原因，实测踩过一次。
/// 2. <c>action.type</c> 必须带 <c>FWP_ACTION_FLAG_TERMINATING (0x1000)</c>。
///    只写 <c>FWP_ACTION_BLOCK (0x1)</c> 会被拒绝，
///    报 <c>0x80320024</c>（"该操作类型不是筛选器允许的操作类型"）。
///    证据：系统自带过滤器的 <c>action.type</c> 是 <c>0x00001002</c>（PERMIT|TERMINATING）。
///
/// 结构体尺寸在 <see cref="EnsureLayout"/> 里做运行期校验：布局一旦不对，
/// 宁可启动时就明确报错，也不要等到某次过滤器添加失败才去猜。
///
/// 每个 P/Invoke 都标了 <c>DefaultDllImportSearchPaths(System32)</c>：
/// 明确只从系统目录加载 fwpuclnt.dll，避免被当前目录里的同名 DLL 劫持。
/// </summary>
internal static class WfpNativeMethods
{
    // ---------------- 常量 ----------------

    /// <summary>RPC_C_AUTHN_WINNT：用当前登录凭据与 BFE 认证。</summary>
    internal const uint RPC_C_AUTHN_WINNT = 10;

    /// <summary>FWPM_SESSION_FLAG_DYNAMIC：动态会话 —— 会话一结束，其中新建的对象自动消失。</summary>
    internal const uint FWPM_SESSION_FLAG_DYNAMIC = 0x00000001;

    /// <summary>FWPM_SUBLAYER_FLAG_PERSISTENT：子层持久化（重启后仍在）。</summary>
    internal const uint FWPM_SUBLAYER_FLAG_PERSISTENT = 0x00000001;

    /// <summary>FWPM_FILTER_FLAG_PERSISTENT：过滤器持久化（重启后仍在，实测有效）。</summary>
    internal const uint FWPM_FILTER_FLAG_PERSISTENT = 0x00000001;

    /// <summary>FWP_ACTION_BLOCK | FWP_ACTION_FLAG_TERMINATING。单独用 0x1 会被拒绝。</summary>
    internal const uint FWP_ACTION_BLOCK = 0x00001001;

    /// <summary>FWP_ACTION_PERMIT | FWP_ACTION_FLAG_TERMINATING。</summary>
    internal const uint FWP_ACTION_PERMIT = 0x00001002;

    /// <summary>FWP_MATCH_EQUAL。</summary>
    internal const uint FWP_MATCH_EQUAL = 0;

    /// <summary>FWP_MATCH_RANGE（端口范围用）。</summary>
    internal const uint FWP_MATCH_RANGE = 5;

    /// <summary>FWP_RANGE_TYPE（端口范围条件值的类型）。</summary>
    internal const uint FWP_RANGE_TYPE = 0x102;


    /// <summary>FWP_EMPTY：让 BFE 自己算权重。</summary>
    internal const uint FWP_EMPTY = 0;

    /// <summary>FWP_UINT8。</summary>
    internal const uint FWP_UINT8 = 1;

    /// <summary>FWP_UINT16（端口号用）。</summary>
    internal const uint FWP_UINT16 = 2;

    /// <summary>FWP_UINT32。</summary>
    internal const uint FWP_UINT32 = 3;

    /// <summary>FWP_UINT64。</summary>
    internal const uint FWP_UINT64 = 4;

    /// <summary>FWP_BYTE_BLOB_TYPE。</summary>
    internal const uint FWP_BYTE_BLOB_TYPE = 12;

    /// <summary>FWP_BYTE_ARRAY16_TYPE（IPv6 地址条件用）。数值来自 SDK 的 fwptypes.h。</summary>
    internal const uint FWP_BYTE_ARRAY16_TYPE = 11;

    // ---------------- 错误码 ----------------

    /// <summary>成功。</summary>
    internal const uint ERROR_SUCCESS = 0;

    /// <summary>FWP_E_FILTER_NOT_FOUND：过滤器不存在。</summary>
    internal const uint FWP_E_FILTER_NOT_FOUND = 0x80320003;

    /// <summary>FWP_E_SUBLAYER_NOT_FOUND：子层不存在。</summary>
    internal const uint FWP_E_SUBLAYER_NOT_FOUND = 0x80320007;

    /// <summary>FWP_E_ALREADY_EXISTS：同 GUID 的对象已经存在（重复创建时出现，通常可以当成功处理）。</summary>
    internal const uint FWP_E_ALREADY_EXISTS = 0x80320009;

    /// <summary>FWP_E_IN_USE：还有别的对象引用它，删不掉（必须先删光该子层下的过滤器）。</summary>
    internal const uint FWP_E_IN_USE = 0x8032000A;

    // ---------------- 固定 GUID ----------------
    //
    // ⚠️ 这里的每一个 GUID 都必须从官方文档逐字核对，不能凭记忆。
    //    POC 阶段把 FWPM_CONDITION_IP_PROTOCOL 写错过，BFE 报的是
    //    FWP_E_CONDITION_NOT_FOUND (0x80320002)，同样指不到真正原因。
    //    目前只放进**已在虚拟机里实测通过**的层和条件；要用到新的条件时，
    //    先核文档、再实测，然后才加到这里。

    /// <summary>
    /// 本程序的子层 GUID。
    ///
    /// ★ 这个值一旦发布就**永远不能再改**：它相当于本程序在系统里的身份，
    ///   改了之后就找不到之前留下的过滤器（<c>--recover</c> 也就失效了）。
    /// </summary>
    internal static readonly Guid OurSubLayerKey = new("6b1f0d2a-8e34-4c77-9f5b-2a7d3c8e1b60");

    /// <summary>FWPM_LAYER_ALE_AUTH_CONNECT_V4：IPv4 出站连接"授权"层。</summary>
    internal static readonly Guid LayerAleAuthConnectV4 = new("c38d57d1-05a7-4c33-904f-7fbceee60e82");

    /// <summary>
    /// FWPM_LAYER_ALE_AUTH_CONNECT_V6：IPv6 出站连接"授权"层。
    ///
    /// ★ 为什么必须有这一层：WFP 的层是按 IP 协议族分开的。
    ///   只挂 V4 的 block，程序走 IPv6 就绕过去了 —— 门只关了一半。
    ///   GUID 取自官方头文件 fwpmu.h 的 DEFINE_GUID（4a72393b-319f-44bc-84c3-ba54dcb3b6b4），
    ///   并由 --wfp-rule-test 在虚拟机里真加一条过滤器来验证：GUID 错的话
    ///   FwpmFilterAdd0 会直接报"层不存在"。
    /// </summary>
    internal static readonly Guid LayerAleAuthConnectV6 = new("4a72393b-319f-44bc-84c3-ba54dcb3b6b4");

    /// <summary>FWPM_CONDITION_ALE_APP_ID：按程序身份（可执行文件路径）匹配。</summary>
    internal static readonly Guid ConditionAleAppId = new("d78e1e87-8644-4ea5-9437-d809ecefc971");

    /// <summary>
    /// FWPM_CONDITION_IP_REMOTE_ADDRESS：按远端 IP 匹配。
    ///
    /// ★ GUID 取自 Windows SDK 的 <c>um\fwpmu.h</c>（不是凭记忆）：
    ///   <c>C:\Program Files (x86)\Windows Kits\10\Include\&lt;版本&gt;\um\fwpmu.h</c>。
    /// 值类型：IPv4 用 FWP_UINT32（**主机序**），IPv6 用 FWP_BYTE_ARRAY16。
    /// </summary>
    internal static readonly Guid ConditionIpRemoteAddress = new("b235ae9a-1d64-49b8-a44c-5ff3d9095045");

    /// <summary>FWPM_CONDITION_IP_PROTOCOL：IP 协议号（TCP=6 / UDP=17）。值类型：FWP_UINT8。</summary>
    internal static readonly Guid ConditionIpProtocol = new("3971ef2b-623e-4f9a-8cb1-6e79b806b9a7");

    /// <summary>FWPM_CONDITION_IP_REMOTE_PORT：远端端口。值类型：FWP_UINT16；范围用 FWP_RANGE。</summary>
    internal static readonly Guid ConditionIpRemotePort = new("c35a604d-d22b-4e1a-91b4-68f674ee674b");

    /// <summary>
    /// FWPM_CONDITION_CURRENT_PROFILE_ID：当前网络类别（域 / 专用 / 公用）。值类型：FWP_UINT32。
    /// 数值与 <c>NLM_NETWORK_CATEGORY</c> 一致：0=公用、1=专用、2=域。
    /// </summary>
    internal static readonly Guid ConditionCurrentProfileId = new("ab3033c9-c0e3-4759-937d-5758c65d4ae3");

    /// <summary>
    /// 子层权重。WFP 在**不同子层之间**先比子层权重（数值大的优先）。
    ///
    /// 实测：0xFFFF 时，本程序子层里的 block 能压过 Windows 防火墙自己
    /// （FWPM_SUBLAYER_MPSSVC_WF）的 allow 规则。
    /// </summary>
    internal const ushort OurSubLayerWeight = 0xFFFF;

    // ---------------- 结构体 ----------------

    /// <summary>FWP_BYTE_BLOB。</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct FwpByteBlob
    {
        public uint Size;
        public IntPtr Data;
    }

    /// <summary>FWPM_DISPLAY_DATA0。name 是必填字段。</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct FwpmDisplayData
    {
        public IntPtr Name;
        public IntPtr Description;
    }

    /// <summary>FWPM_SESSION0。</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct FwpmSession
    {
        public Guid SessionKey;
        public FwpmDisplayData DisplayData;
        public uint Flags;
        public uint TxnWaitTimeoutInMSec;
        public uint ProcessId;
        public IntPtr Sid;
        public IntPtr Username;
        public int KernelMode;
    }

    /// <summary>FWPM_SUBLAYER0。</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct FwpmSubLayer
    {
        public Guid SubLayerKey;
        public FwpmDisplayData DisplayData;
        public uint Flags;
        public IntPtr ProviderKey;

        // ⚠️ 结构体本身（16 字节），不是指针 —— 见文件头说明。
        public FwpByteBlob ProviderData;

        public ushort Weight;
    }

    /// <summary>FWP_VALUE0。</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct FwpValue
    {
        public uint Type;
        public IntPtr Value;
    }

    /// <summary>FWP_CONDITION_VALUE0。</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct FwpConditionValue
    {
        public uint Type;
        public IntPtr Value;
    }


    /// <summary>FWP_RANGE0：端口范围匹配用。</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct FwpRange
    {
        public FwpValue Low;
        public FwpValue High;
    }

    /// <summary>FWPM_FILTER_CONDITION0。</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct FwpmFilterCondition
    {
        public Guid FieldKey;
        public uint MatchType;
        public FwpConditionValue ConditionValue;
    }

    /// <summary>FWPM_ACTION0。</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct FwpmAction
    {
        public uint Type;
        public Guid FilterType;
    }

    /// <summary>FWPM_FILTER0。</summary>
    [StructLayout(LayoutKind.Sequential)]
    internal struct FwpmFilter
    {
        public Guid FilterKey;
        public FwpmDisplayData DisplayData;
        public uint Flags;
        public IntPtr ProviderKey;

        // ⚠️ 结构体本身（16 字节），不是指针 —— 见文件头说明。
        public FwpByteBlob ProviderData;

        public Guid LayerKey;
        public Guid SubLayerKey;
        public FwpValue Weight;
        public uint NumFilterConditions;
        public IntPtr FilterCondition;
        public FwpmAction Action;
        public Guid ProviderContextKey;
        public IntPtr Reserved;
        public ulong FilterId;
        public FwpValue EffectiveWeight;
    }

    // ---------------- P/Invoke ----------------

    [DllImport("fwpuclnt.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    internal static extern uint FwpmEngineOpen0(
        [MarshalAs(UnmanagedType.LPWStr)] string? serverName,
        uint authnService,
        IntPtr authIdentity,
        ref FwpmSession session,
        out IntPtr engineHandle);

    [DllImport("fwpuclnt.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    internal static extern uint FwpmEngineClose0(IntPtr engineHandle);

    [DllImport("fwpuclnt.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    internal static extern uint FwpmSubLayerAdd0(
        IntPtr engineHandle,
        ref FwpmSubLayer subLayer,
        IntPtr securityDescriptor);

    [DllImport("fwpuclnt.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    internal static extern uint FwpmSubLayerDeleteByKey0(IntPtr engineHandle, ref Guid key);

    [DllImport("fwpuclnt.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    internal static extern uint FwpmSubLayerGetByKey0(
        IntPtr engineHandle,
        ref Guid key,
        out IntPtr subLayer);

    [DllImport("fwpuclnt.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    internal static extern uint FwpmFilterAdd0(
        IntPtr engineHandle,
        ref FwpmFilter filter,
        IntPtr securityDescriptor,
        out ulong id);

    [DllImport("fwpuclnt.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    internal static extern uint FwpmFilterDeleteByKey0(IntPtr engineHandle, ref Guid key);

    [DllImport("fwpuclnt.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    internal static extern uint FwpmFilterCreateEnumHandle0(
        IntPtr engineHandle,
        IntPtr enumTemplate,
        out IntPtr enumHandle);

    [DllImport("fwpuclnt.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    internal static extern uint FwpmFilterEnum0(
        IntPtr engineHandle,
        IntPtr enumHandle,
        uint numEntriesRequested,
        out IntPtr entries,
        out uint numEntriesReturned);

    [DllImport("fwpuclnt.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    internal static extern uint FwpmFilterDestroyEnumHandle0(IntPtr engineHandle, IntPtr enumHandle);

    [DllImport("fwpuclnt.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    internal static extern uint FwpmGetAppIdFromFileName0(
        [MarshalAs(UnmanagedType.LPWStr)] string fileName,
        out IntPtr appId);

    [DllImport("fwpuclnt.dll", ExactSpelling = true)]
    [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
    internal static extern void FwpmFreeMemory0(ref IntPtr p);

    // ---------------- 辅助 ----------------

    /// <summary>把 WFP 错误码变成「人能看懂的一句话」，用于日志和界面提示。</summary>
    internal static string DescribeError(uint code)
    {
        if (code == ERROR_SUCCESS)
        {
            return "成功";
        }

        var message = Marshal.GetExceptionForHR(unchecked((int)code))?.Message ?? "未知错误";
        return $"0x{code:X8}（{message.Trim()}）";
    }

    /// <summary>
    /// 校验结构体尺寸。
    ///
    /// 这些数字对应 x64 上的官方定义，任何一个不对都说明字段类型写错了
    /// （典型错误就是把 <c>FWP_BYTE_BLOB</c> 写成指针，整体少 8 字节）。
    /// 与其让 BFE 用一条误导性的错误码拒绝请求，不如在这里直接说清楚。
    /// </summary>
    internal static void EnsureLayout()
    {
        CheckLayout<FwpmFilter>(200, "FWPM_FILTER0");
        CheckLayout<FwpmSubLayer>(72, "FWPM_SUBLAYER0");
        CheckLayout<FwpmFilterCondition>(40, "FWPM_FILTER_CONDITION0");

        // FWPM_ACTION0 = FWP_ACTION_TYPE(4) + union{GUID}(16) = 20 字节。
        // ⚠️ GUID 在 Windows 上的对齐是 4，不是 8 —— 所以不会填充到 24。
        //    （这里最初就写错过一次，被 EnsureLayout 自己抓了出来。）
        CheckLayout<FwpmAction>(20, "FWPM_ACTION0");

        CheckLayout<FwpmSession>(72, "FWPM_SESSION0");
        CheckLayout<FwpValue>(16, "FWP_VALUE0");
        CheckLayout<FwpConditionValue>(16, "FWP_CONDITION_VALUE0");
        CheckLayout<FwpValue>(16, "FWP_VALUE0");
        CheckLayout<FwpRange>(32, "FWP_RANGE0");
        CheckLayout<FwpByteBlob>(16, "FWP_BYTE_BLOB");
    }

    private static void CheckLayout<T>(int expected, string name) where T : struct
    {
        var actual = Marshal.SizeOf<T>();
        if (actual != expected)
        {
            throw new InvalidOperationException(
                $"{name} 的结构体尺寸不对：期望 {expected} 字节，实际 {actual} 字节。" +
                "这可能是某个字段的类型写错了（例如把结构体写成指针），" +
                "也可能是这里记录的期望值本身算错了。两种都要对照官方定义核对。");
        }
    }
}
