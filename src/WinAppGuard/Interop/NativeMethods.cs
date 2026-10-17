using System.Runtime.InteropServices;
using System.Text;

namespace WinAppGuard.Interop;

/// <summary>
/// Win32 API 声明。
///
/// 本程序与系统底层打交道的地方只有三类：
///   1. 读取 TCP 连接表（iphlpapi.dll）；
///   2. 查询进程的可执行文件路径（kernel32.dll）；
///   3. 图形界面模式启动时释放掉控制台窗口（kernel32.dll）。
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

    // ---------------- 控制台（图形界面模式要收掉它） ----------------

    /// <summary>
    /// 释放当前进程的控制台。
    ///
    /// 为什么需要它：本程序是**控制台子系统**的 exe（这样命令行模式才能同步输出、
    /// 退出码才对），但图形界面模式不需要那个黑框 —— 启动时立刻调它把控制台收掉。
    ///
    /// 代价：控制台窗口在进程启动到这一行之间是可见的。实测稳态约 0.5 秒；
    /// 发布后第一次运行因为杀毒软件要扫这个 49MB 的新文件，可能几秒到十几秒。
    ///
    /// 没有控制台时它返回 false —— 忽略即可。
    /// </summary>
    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool FreeConsole();

    // ---------------- 数字签名验证 ----------------

    /// <summary>
    /// 验证 PE 文件的数字签名（Authenticode）。
    ///
    /// 返回值是 HRESULT：0 表示签名有效且受信任，其它值是具体的失败原因
    /// （没有签名、证书链不受信任、文件被改过、证书过期/被吊销等）。
    ///
    /// 注意：这个函数**可能会联网**（去 CA 服务器查证书吊销列表）。
    /// 是否联网由 WINTRUST_DATA.dwProvFlags 控制，详见 DigitalSignature.cs。
    /// </summary>
    [DllImport("wintrust.dll", SetLastError = true, ExactSpelling = true)]
    internal static extern int WinVerifyTrust(IntPtr hwnd, ref Guid pgActionID, ref WinTrustData pWVTData);

    // ---------------- 目录签名（catalog）验证 ----------------
    //
    // Windows 有**两套**签名机制：
    //   内嵌签名 —— 存在 exe 自己的证书表里，主要给第三方软件用；
    //   目录签名 —— 存在 C:\Windows\System32\CatRoot\ 的 .cat 文件里，
    //              大量 Windows 系统文件只有这种（exe 里什么都没有）。
    //
    // 只查内嵌签名会导致 notepad.exe / cmd.exe 这类系统文件被误报成「未签名」。
    // 下面这几个函数就是用来补上目录签名这条路径的。

    /// <summary>
    /// 打开目录签名管理上下文。
    /// 哈希算法传 "SHA256"（不要用已废弃的 SHA-1 版本）。
    /// </summary>
    [DllImport("wintrust.dll", SetLastError = true, ExactSpelling = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CryptCATAdminAcquireContext2(
        out IntPtr phCatAdmin,
        IntPtr pgSubsystem,
        string pwszHashAlgorithm,
        IntPtr pStrongHashPolicy,
        int dwFlags);

    /// <summary>
    /// 计算文件的哈希（目录签名靠这个哈希去索引）。
    /// 第一次传 pbHash = null 拿所需长度，第二次才真正取哈希。
    /// </summary>
    [DllImport("wintrust.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CryptCATAdminCalcHashFromFileHandle2(
        IntPtr hCatAdmin,
        IntPtr hFile,
        ref int pcbHash,
        byte[]? pbHash,
        int dwFlags);

    /// <summary>
    /// 按文件哈希找包含它的目录。
    /// **返回 IntPtr.Zero 表示没有目录收录这个文件**，也就是「没有目录签名」。
    /// </summary>
    [DllImport("wintrust.dll", SetLastError = true, ExactSpelling = true)]
    internal static extern IntPtr CryptCATAdminEnumCatalogFromHash(
        IntPtr hCatAdmin,
        byte[] pbHash,
        int cbHash,
        int dwFlags,
        ref IntPtr phPrevCatInfo);

    /// <summary>取出目录文件的完整路径（后面要用它去验证）。</summary>
    [DllImport("wintrust.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CryptCATCatalogInfoFromContext(
        IntPtr hCatInfo,
        ref CatalogInfo psCatInfo,
        int dwFlags);

    /// <summary>释放目录上下文。</summary>
    [DllImport("wintrust.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CryptCATAdminReleaseCatalogContext(IntPtr hCatAdmin, IntPtr hCatInfo, int dwFlags);

    /// <summary>释放目录签名管理上下文。</summary>
    [DllImport("wintrust.dll", SetLastError = true, ExactSpelling = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool CryptCATAdminReleaseContext(IntPtr hCatAdmin, int dwFlags);

    // ---------------- 从验证状态里取签名者 ----------------
    //
    // WinVerifyTrust 只告诉你「信不信任」，不告诉你「谁签的」。
    // 下面三个辅助函数能顺着它返回的状态句柄把签名者证书挖出来。
    // 好处是**内嵌签名和目录签名都能用同一套代码取名字**。

    /// <summary>从 WinVerifyTrust 的状态句柄取提供程序数据。</summary>
    [DllImport("wintrust.dll", ExactSpelling = true)]
    internal static extern IntPtr WTHelperProvDataFromStateData(IntPtr hStateData);

    /// <summary>从提供程序数据里取签名者。</summary>
    [DllImport("wintrust.dll", ExactSpelling = true)]
    internal static extern IntPtr WTHelperGetProvSignerFromChain(
        IntPtr pProvData,
        int dwIdx,
        [MarshalAs(UnmanagedType.Bool)] bool fCounterSigner,
        int dwIdx2);

    /// <summary>从签名者里取证书（含 pCert 指针）。</summary>
    [DllImport("wintrust.dll", ExactSpelling = true)]
    internal static extern IntPtr WTHelperGetProvCertFromChain(IntPtr pSgnr, int dwIdx);
}

/// <summary>CATALOG_INFO：目录签名上下文里取出来的目录文件路径。</summary>
[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
internal struct CatalogInfo
{
    /// <summary>结构体大小，必须自己填。</summary>
    public int cbStruct;

    /// <summary>目录文件（.cat）的完整路径，最大 MAX_PATH。</summary>
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
    public string CatalogFile;
}

/// <summary>
/// CRYPT_PROVIDER_CERT 的**前缀**。
///
/// 我们只读 cbStruct 和 pCert 这两个字段，后面的字段用不到，
/// 所以这里只声明前缀 —— 结构体只会被我们「指向并读前几个字段」，
/// 不参与分配，因此不需要完整定义。
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct CryptProviderCert
{
    /// <summary>结构体大小。</summary>
    public int cbStruct;

    /// <summary>指向 CERT_CONTEXT 的指针。</summary>
    public IntPtr pCert;
}

/// <summary>
/// CERT_CONTEXT：证书上下文。同样只声明我们需要的字段。
/// 用它取出证书的编码字节，交给 X509CertificateLoader 解析。
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct CertContext
{
    /// <summary>证书编码类型。</summary>
    public int dwCertEncodingType;

    /// <summary>指向证书编码字节的指针。</summary>
    public IntPtr pbCertEncoded;

    /// <summary>证书编码字节数。</summary>
    public int cbCertEncoded;

    /// <summary>证书信息，用不到。</summary>
    public IntPtr pCertInfo;

    /// <summary>证书存储句柄，用不到。</summary>
    public IntPtr hCertStore;
}

/// <summary>
/// WINTRUST_FILE_INFO：告诉 WinVerifyTrust 要验证哪个文件。
/// 字段顺序必须与 Win32 完全一致。
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct WinTrustFileInfo
{
    /// <summary>结构体大小，必须自己填。</summary>
    public int cbStruct;

    /// <summary>要验证的文件完整路径。</summary>
    [MarshalAs(UnmanagedType.LPWStr)]
    public string FilePath;

    /// <summary>已打开的文件句柄；用路径时传 IntPtr.Zero。</summary>
    public IntPtr hFile;

    /// <summary>已知主题的 GUID；不用时传 IntPtr.Zero。</summary>
    public IntPtr pgKnownSubject;
}

/// <summary>
/// WINTRUST_DATA：WinVerifyTrust 的主参数结构。
/// 字段顺序必须与 Win32 完全一致，改顺序会读到垃圾数据。
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct WinTrustData
{
    /// <summary>结构体大小，必须自己填。</summary>
    public int cbStruct;

    public IntPtr pPolicyCallbackData;
    public IntPtr pSIPClientData;

    /// <summary>界面选项。2 = WTD_UI_NONE（不弹任何对话框）。</summary>
    public int dwUIChoice;

    /// <summary>已废弃的吊销检查字段，用 dwProvFlags 代替。填 0。</summary>
    public int fdwRevocationChecks;

    /// <summary>要验证的对象类型。1 = WTD_CHOICE_FILE（一个文件）。</summary>
    public int dwUnionChoice;

    /// <summary>指向 WinTrustFileInfo 的指针。</summary>
    public IntPtr pFile;

    /// <summary>1 = WTD_STATEACTION_VERIFY（开始验证），2 = WTD_STATEACTION_CLOSE（释放状态）。</summary>
    public int dwStateAction;

    /// <summary>由系统填写，调用方不要动。</summary>
    public IntPtr hWVTStateData;

    public IntPtr pwszURLReference;

    /// <summary>提供程序标志位：控制是否联网查吊销列表等，见 DigitalSignature.cs。</summary>
    public int dwProvFlags;

    public int dwUIContext;
}

/// <summary>
/// WINTRUST_CATALOG_INFO：验证**目录签名**时用这个结构，替代 WinTrustFileInfo。
/// 字段顺序必须与 Win32 完全一致。
/// </summary>
[StructLayout(LayoutKind.Sequential)]
internal struct WinTrustCatalogInfo
{
    /// <summary>结构体大小，必须自己填。</summary>
    public int cbStruct;

    /// <summary>目录版本号，填 0。</summary>
    public int dwCatalogVersion;

    /// <summary>目录文件（.cat）的完整路径。</summary>
    [MarshalAs(UnmanagedType.LPWStr)]
    public string CatalogFilePath;

    /// <summary>
    /// 成员标签：文件哈希的**十六进制大写字符串**，不带分隔符。
    /// 目录签名就是靠这个把「文件」和「签名」对应起来的。
    /// </summary>
    [MarshalAs(UnmanagedType.LPWStr)]
    public string MemberTag;

    /// <summary>被签名的文件完整路径。</summary>
    [MarshalAs(UnmanagedType.LPWStr)]
    public string MemberFilePath;

    /// <summary>被签名文件的句柄。</summary>
    public IntPtr hMemberFile;

    /// <summary>我们算出来的文件哈希字节。</summary>
    public IntPtr CalculatedFileHash;

    /// <summary>哈希字节数。</summary>
    public int cbCalculatedFileHash;

    /// <summary>目录上下文，填 IntPtr.Zero。</summary>
    public IntPtr CatalogContext;

    /// <summary>目录签名管理上下文（CryptCATAdminAcquireContext2 得到的那个）。</summary>
    public IntPtr hCatAdmin;
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
