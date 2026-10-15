namespace WinAppGuard.Models;

/// <summary>
/// TCP 连接状态。
///
/// 枚举值和 Windows 的 MIB_TCP_STATE 完全一致，不能随意改动，
/// 否则会把「已建立」误判成别的状态。
/// </summary>
public enum TcpState : uint
{
    /// <summary>已关闭。</summary>
    Closed = 1,

    /// <summary>正在监听本地端口（还没有对端）。</summary>
    Listen = 2,

    /// <summary>已发出连接请求，等待对方回应。</summary>
    SynSent = 3,

    /// <summary>已收到对方的连接请求。</summary>
    SynReceived = 4,

    /// <summary>连接已建立，正在传输数据。这就是「正在联网」。</summary>
    Established = 5,

    /// <summary>主动关闭的第一步。</summary>
    FinWait1 = 6,

    /// <summary>主动关闭的第二步。</summary>
    FinWait2 = 7,

    /// <summary>对方已请求关闭，本机尚未关闭。</summary>
    CloseWait = 8,

    /// <summary>双方同时关闭中。</summary>
    Closing = 9,

    /// <summary>等待最后一个确认。</summary>
    LastAck = 10,

    /// <summary>连接已结束，等待系统回收，短时间内仍会出现在连接表里。</summary>
    TimeWait = 11,

    /// <summary>连接控制块即将删除。</summary>
    DeleteTcb = 12,
}
