using System.Net;
using System.Net.Sockets;
using WinAppGuard.Localization;

namespace WinAppGuard.Models;

/// <summary>
/// 一条 TCP 连接。
///
/// 数据由 <see cref="WinAppGuard.Core.ConnectionScanner"/> 填充，界面只读取本类型，
/// 不直接接触 Win32 结构体，这样界面代码和底层解析代码互不牵连。
///
/// 带 Text 后缀的属性是给 DataGridView 直接绑定的显示文本，
/// 放在这里而不是写在界面里，是为了让「数据怎么显示」这件事只有一处定义。
/// </summary>
public sealed class TcpConnectionItem
{
    /// <summary>所属进程 PID。</summary>
    public required int Pid { get; init; }

    /// <summary>程序名，例如 chrome.exe。拿不到路径时会退化成「PID 1234」。</summary>
    public required string ProcessName { get; set; }

    /// <summary>可执行文件完整路径。拿不到时为空字符串。</summary>
    public required string ProcessPath { get; set; }

    /// <summary>协议版本，取值 "IPv4" 或 "IPv6"。</summary>
    public required string Protocol { get; init; }

    /// <summary>本地端口。</summary>
    public required ushort LocalPort { get; init; }

    /// <summary>远程 IP 地址。</summary>
    public required IPAddress RemoteAddress { get; init; }

    /// <summary>远程端口。</summary>
    public required ushort RemotePort { get; init; }

    /// <summary>连接状态。</summary>
    public required TcpState State { get; init; }

    // ------------------------------------------------------------------
    // 以下属性不属于扫描结果本身，而是界面在扫描之后补充的展示状态
    // ------------------------------------------------------------------

    /// <summary>
    /// 该程序当前是否已被本工具阻止联网。
    /// 由界面在扫描完成后根据防火墙规则填充，扫描器本身不设置这个值。
    /// </summary>
    public bool IsBlocked { get; set; }

    /// <summary>
    /// 该文件的数字签名检查结果。
    /// 由界面在后台线程填充（检查很慢，要算文件哈希、验证证书链），扫描器本身不设置这个值。
    /// </summary>
    public SignatureInfo Signature { get; set; } = SignatureInfo.None;

    /// <summary>
    /// 该连接远程地址的归属信息（国家/地区、运营商 AS）。
    /// 由界面在后台查好后填充，扫描器本身不设置这个值。
    /// 功能关闭时保持 <see cref="IpOwnershipInfo.None"/>，界面据此完全不显示归属。
    /// </summary>
    public IpOwnershipInfo IpOwnership { get; set; } = IpOwnershipInfo.None;

    /// <summary>
    /// 该程序在「严格模式」白名单里的状态。
    /// 由界面在扫描完成后根据防火墙规则填充，扫描器本身不设置这个值。
    /// </summary>
    public WhitelistState Whitelist { get; set; } = WhitelistState.NotApplicable;

    /// <summary>
    /// 「放行」列的显示文本。
    ///
    /// 三档的原因见 <see cref="WhitelistState"/>：严格模式挡不住"别人早就放行过"的程序，
    /// 所以「已放行」必须区分来源，不能含糊成一句"已放行"。
    ///
    /// 文本刻意写短（列宽有限，后面还有一列数字签名），**完整含义放在悬停提示里**
    /// （见 MainForm 的 BuildWhitelistTooltip）—— 不能因为放不下就省掉信息。
    /// </summary>
    public string WhitelistText => Whitelist switch
    {
        WhitelistState.Ours => Localizer.T("已放行·本工具"),
        WhitelistState.OtherSource => Localizer.T("已放行·其它来源"),
        WhitelistState.NotWhitelisted => Localizer.T("未放行"),
        _ => "—",
    };

    /// <summary>
    /// 阻止状态的显示文本。
    /// 拿不到路径的连接无法被阻止，显示为破折号而不是「未阻止」，避免误导。
    /// </summary>
    public string BlockStateText =>
        string.IsNullOrEmpty(ProcessPath) ? "—" : Localizer.T(IsBlocked ? "已阻止" : "未阻止");

    /// <summary>
    /// 3.5：服务代查到路径后回填名称与路径。
    /// </summary>
    public void ApplyResolvedPath(string path)
    {
        ProcessPath = path;
        ProcessName = Path.GetFileName(path);
    }

    // ------------------------------------------------------------------
    // 3.5：每程序流量（服务端按程序聚合，界面按 PID 匹配到每一行）
    // ------------------------------------------------------------------

    /// <summary>本次服务运行以来的 TCP 上传字节数（近似值）。</summary>
    public long TrafficBytesOut { get; private set; }

    /// <summary>本次服务运行以来的 TCP 下载字节数（近似值）。</summary>
    public long TrafficBytesIn { get; private set; }

    /// <summary>是否拿到了该程序的流量数据（拿不到时显示破折号，不显示 0）。</summary>
    public bool HasTrafficData { get; private set; }

    /// <summary>上传列的显示文本。</summary>
    public string TrafficOutText => HasTrafficData ? FormatTrafficBytes(TrafficBytesOut) : "—";

    /// <summary>下载列的显示文本。</summary>
    public string TrafficInText => HasTrafficData ? FormatTrafficBytes(TrafficBytesIn) : "—";

    /// <summary>总计列的显示文本。</summary>
    public string TrafficTotalText =>
        HasTrafficData ? FormatTrafficBytes(TrafficBytesOut + TrafficBytesIn) : "—";

    /// <summary>流量列的悬停提示：把「近似值」的限制写清楚。</summary>
    public string TrafficTooltip => Localizer.T("本次运行累计，仅统计 TCP；短连接和 UDP 可能漏计。");

    /// <summary>3.5：把服务返回的该程序累计流量填到这一行。</summary>
    public void ApplyTraffic(long bytesOut, long bytesIn)
    {
        TrafficBytesOut = Math.Max(0, bytesOut);
        TrafficBytesIn = Math.Max(0, bytesIn);
        HasTrafficData = true;
    }

    /// <summary>
    /// 字节数 → 人话。**纯函数**，自检直接断言边界（1023 B / 1024 B / 1.5 MB）。
    /// 小于 1 KB 显示整数 B；更大的单位保留一位小数，避免列宽被长小数撑爆。
    /// </summary>
    public static string FormatTrafficBytes(long bytes)
    {
        if (bytes <= 0)
        {
            return "0 B";
        }

        string[] units = { "B", "KB", "MB", "GB", "TB" };
        var value = (double)bytes;
        var unit = 0;

        while (value >= 1024 && unit < units.Length - 1)
        {
            value /= 1024;
            unit++;
        }

        return unit == 0
            ? $"{bytes} B"
            : $"{value:0.#} {units[unit]}";
    }

    /// <summary>
    /// 数字签名列的显示文本。
    ///
    /// 签名的短名字直接显示出来（例如「Google LLC」），这样扫一眼就能看出
    /// 一个陌生程序到底是谁签的。完整结论放在悬停提示里。
    /// </summary>
    public string SignatureText => Signature.State switch
    {
        SignatureState.Valid => string.IsNullOrEmpty(Signature.SignerName)
            ? Localizer.T("已签名")
            : Signature.SignerName,
        SignatureState.Unsigned => Localizer.T("未签名"),
        SignatureState.Tampered => Localizer.T("签名无效"),
        SignatureState.Untrusted => Localizer.T("不受信任"),
        SignatureState.CertificateProblem => Localizer.T("证书异常"),
        SignatureState.Error => Localizer.T("检查失败"),

        // 还没检查：有路径说明马上会有结果，留空；没路径就永远不会有结果。
        _ => string.IsNullOrEmpty(ProcessPath) ? "—" : string.Empty,
    };

    /// <summary>数字签名列的悬停提示，显示完整结论。</summary>
    public string SignatureTooltip => Signature.Detail;

    /// <summary>
    /// 「远程 IP」列的悬停提示，显示该地址的归属（国家/地区、运营商 AS）。
    ///
    /// 没有归属信息时返回空字符串，界面据此完全不挂提示 ——
    /// 这样「还没查」和「查了没数据」在观感上是分得开的。
    /// </summary>
    public string IpOwnershipTooltip => IpOwnership.TooltipText;

    // ------------------------------------------------------------------
    // 以下为界面显示用属性
    // ------------------------------------------------------------------

    /// <summary>
    /// 程序路径的显示文本。
    /// 取不到路径是正常现象（System 进程、已退出进程、受保护进程），不要当成错误。
    /// </summary>
    public string ProcessPathText => string.IsNullOrEmpty(ProcessPath) ? Localizer.T("（无法获取）") : ProcessPath;

    /// <summary>本地端口的显示文本。</summary>
    public string LocalPortText => LocalPort == 0 ? "-" : LocalPort.ToString();

    /// <summary>远程 IP 的显示文本。IPv6 加方括号，避免和端口号看混。</summary>
    public string RemoteAddressText =>
        RemoteAddress.AddressFamily == AddressFamily.InterNetworkV6
            ? $"[{RemoteAddress}]"
            : RemoteAddress.ToString();

    /// <summary>远程端口的显示文本。监听状态没有对端，显示为 -。</summary>
    public string RemotePortText => RemotePort == 0 ? "-" : RemotePort.ToString();

    /// <summary>连接状态的显示文本。</summary>
    public string StateText => State switch
    {
        TcpState.Closed => Localizer.T("已关闭"),
        TcpState.Listen => Localizer.T("监听中"),
        TcpState.SynSent => Localizer.T("同步已发送"),
        TcpState.SynReceived => Localizer.T("同步已接收"),
        TcpState.Established => Localizer.T("已建立"),
        TcpState.FinWait1 => "FIN-WAIT-1",
        TcpState.FinWait2 => "FIN-WAIT-2",
        TcpState.CloseWait => Localizer.T("关闭等待"),
        TcpState.Closing => Localizer.T("正在关闭"),
        TcpState.LastAck => Localizer.T("最后确认"),
        TcpState.TimeWait => Localizer.T("时间等待"),
        TcpState.DeleteTcb => Localizer.T("已删除"),
        _ => Localizer.F("未知({0})", (int)State),
    };
}
