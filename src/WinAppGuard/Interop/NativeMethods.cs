using System.Runtime.InteropServices;
using System.Text;

namespace WinAppGuard.Interop;

/// <summary>
/// Win32 API 声明。
///
/// 本程序与系统底层打交道的地方只有两类：
///   1. 读取 TCP 连接表（iphlpapi.dll）；
///   2. 查询进程的可执行文件路径（kernel32.dll）。
///
/// 所有 P/Invoke 全部集中在这一个文件，目的是方便安全审计——
/// 想知道程序到底调用了哪些系统接口，只看这里就够了。
/// </summary>
internal static class NativeMethods
{
    // ---------------- 地址族 ----------------

    /// <summary>IPv4。</summary>
    internal const int AF_INET = 2;

    /// <summary>IPv6。</summary>
    internal const int AF_INET6 = 23;

    // ---------------- TCP 表类型 ----------------

    /// <summary>所有 TCP 连接，并且带所属进程 PID。</summary>
    internal const int TCP_TABLE_OWNER_PID_ALL = 5;

    // ---------------- 返回码 ----------------

    internal const int NO_ERROR = 0;
    internal const int ERROR_INSUFFICIENT_BUFFER = 122;

    // ---------------- 进程访问权限 ----------------

    /// <summary>
    /// 查询进程信息所需的最小权限。
    /// 相比 PROCESS_ALL_ACCESS，这个权限更容易读取到受保护进程的路径。
    /// </summary>
    internal const uint PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

    /// <summary>
    /// 获取 TCP 连接表。
    ///
    /// 标准调用方式分两步：
    ///   第一次传 pTcpTable = IntPtr.Zero，函数返回 ERROR_INSUFFICIENT_BUFFER，
    ///   并把需要的缓冲区字节数写入 pdwSize；
    ///   按该大小分配内存后再次调用，才真正拿到数据。
    /// </summary>
    [DllImport("iphlpapi.dll", SetLastError = true)]
    internal static extern uint GetExtendedTcpTable(
        IntPtr pTcpTable,
        ref int pdwSize,
        [MarshalAs(UnmanagedType.Bool)] bool bOrder,
        int ulAf,
        int tableClass,
        int reserved);

    /// <summary>打开进程，取得句柄。</summary>
    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern IntPtr OpenProcess(
        uint dwDesiredAccess,
        [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle,
        int dwProcessId);

    /// <summary>关闭句柄。忘记调用会泄漏内核句柄，长时间运行会耗尽。</summary>
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CloseHandle(IntPtr hObject);

    // ---------------- 单实例用的窗口消息 ----------------

    /// <summary>HWND_BROADCAST：把消息发给本会话里所有的顶层窗口。</summary>
    internal static readonly IntPtr HWND_BROADCAST = new(0xFFFF);

    /// <summary>
    /// 注册一个自定义窗口消息，返回它的编号。
    ///
    /// 用 RegisterWindowMessage 而不是自己挑一个数字，是为了避免和系统消息撞号：
    /// 系统会保证同一个字符串在所有进程里得到同一个编号。
    /// </summary>
    [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode, ExactSpelling = true)]
    internal static extern uint RegisterWindowMessageW(string lpString);

    /// <summary>把消息投递到窗口的消息队列（不等待处理）。</summary>
    [DllImport("user32.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool PostMessageW(IntPtr hWnd, uint msg, IntPtr wParam, IntPtr lParam);

    /// <summary>
    /// 查询指定进程可执行文件的完整路径。
    ///
    /// 必须使用 W（Unicode）版本，否则中文路径会变成乱码。
    /// </summary>
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool QueryFullProcessImageNameW(
        IntPtr hProcess,
        int dwFlags,
        StringBuilder lpExeName,
        ref int lpdwSize);
}

/// <summary>
/// IPv4 TCP 连接表中的一行（含所属进程 PID）。
/// 对应 Win32 的 MIB_TCPROW_OWNER_PID，字段顺序必须完全一致。
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct MibTcpRowOwnerPid
{
    /// <summary>连接状态，取值见 <see cref="WinAppGuard.Models.TcpState"/>。</summary>
    public uint State;

    /// <summary>本地地址，网络字节序。</summary>
    public uint LocalAddr;

    /// <summary>本地端口，网络字节序，数值存放在低 16 位。</summary>
    public uint LocalPort;

    /// <summary>远程地址，网络字节序。</summary>
    public uint RemoteAddr;

    /// <summary>远程端口，网络字节序，数值存放在低 16 位。</summary>
    public uint RemotePort;

    /// <summary>拥有该连接的进程 PID。</summary>
    public uint OwningPid;
}

/// <summary>
/// IPv6 TCP 连接表中的一行（含所属进程 PID）。
/// 对应 Win32 的 MIB_TCP6ROW_OWNER_PID，字段顺序必须完全一致。
/// 注意：IPv6 行的字段顺序与 IPv4 不同，地址在前、状态在后。
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct MibTcp6RowOwnerPid
{
    /// <summary>本地地址，16 字节，网络字节序。</summary>
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
    public byte[] LocalAddr;

    /// <summary>本地地址的作用域 ID，仅链路本地地址有意义。</summary>
    public uint LocalScopeId;

    /// <summary>本地端口，网络字节序，数值存放在低 16 位。</summary>
    public uint LocalPort;

    /// <summary>远程地址，16 字节，网络字节序。</summary>
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
    public byte[] RemoteAddr;

    /// <summary>远程地址的作用域 ID。</summary>
    public uint RemoteScopeId;

    /// <summary>远程端口，网络字节序，数值存放在低 16 位。</summary>
    public uint RemotePort;

    /// <summary>连接状态，取值见 <see cref="WinAppGuard.Models.TcpState"/>。</summary>
    public uint State;

    /// <summary>拥有该连接的进程 PID。</summary>
    public uint OwningPid;
}
