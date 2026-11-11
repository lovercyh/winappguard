namespace WinAppGuard.Contracts;

/// <summary>
/// 5.9：跨进程/跨层统一错误码。
///
/// 现有命令的错误信息是写死的中文句子，脚本只能靠字符串判断。
/// 新代码改为返回 ErrorCode，由 UI / CLI 负责本地化。
/// 旧的 ServiceRequest/ServiceResponse 暂时保留，协议 v3 在 5.10 切换。
/// </summary>
public enum ErrorCode
{
    None = 0,

    /// <summary>需要管理员权限。</summary>
    Unauthorized = 1,

    /// <summary>不是所有者，或签名密钥不可用。</summary>
    NotOwner = 2,

    /// <summary>参数缺失或格式不正确。</summary>
    InvalidArgument = 3,

    /// <summary>目标不存在（规则、告警、记录等）。</summary>
    NotFound = 4,

    /// <summary>与当前状态冲突（重复、上限、正在运行等）。</summary>
    Conflict = 5,

    /// <summary>服务或子系统不可用。</summary>
    Unavailable = 6,

    /// <summary>操作超时。</summary>
    Timeout = 7,

    /// <summary>未分类的内部错误。</summary>
    Internal = 8,
}
