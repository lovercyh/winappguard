namespace WinAppGuard.Core;

/// <summary>
/// 受保护的进程名单（**只限制「阻止」，不限制「允许」**）。
///
/// 这是本工具最重要的一道安全护栏：拦住这些进程会让 Windows 本身出问题，
/// 严重时会导致系统无法正常使用甚至断网。所以**把检查做在防火墙底层**，
/// 而不是界面层——放在界面层的话，将来任何别的调用路径都能绕过去。
///
/// 名单只包含「拦了会出大事」的进程，不是「不建议拦」的进程。
///
/// ⚠ **这道护栏只管「阻止」**：这些进程**可以**被放行。
/// 理由有两条，缺一不可：
///   1. 放行永远不会把用户锁在外面 —— 危险只存在于"拦掉"这个方向；
///   2. 严格模式**必须**能放行本程序自己（否则它自己连 IP 归属都查不了），
///      也必须能放行用户主动想放行的系统关键进程。
/// 调用方通过 <c>FirewallManager.ValidateProgramPath</c> 的 <c>forBlocking</c> 参数
/// 决定要不要执行这道检查。
/// </summary>
public static class ProtectedProcesses
{
    /// <summary>
    /// 受保护的进程文件名。
    ///
    /// svchost.exe 需要特别说明：它承载了 Windows 的大量系统服务
    /// （DNS 客户端、DHCP、Windows 更新、时间同步等），单独拦掉它
    /// 会让整台机器的网络出现难以排查的异常，所以必须保护。
    /// </summary>
    private static readonly HashSet<string> ProtectedNames = new(StringComparer.OrdinalIgnoreCase)
    {
        // ---- Windows 内核与核心进程 ----
        "system",                       // PID 4，内核本身
        "system idle process",          // PID 0
        "registry",                     // 注册表进程
        "memory compression",           // 内存压缩
        "smss.exe",                     // 会话管理器
        "csrss.exe",                    // 客户端/服务器运行时
        "wininit.exe",                  // Windows 启动初始化
        "winlogon.exe",                 // 登录进程
        "services.exe",                 // 服务控制管理器
        "lsass.exe",                    // 本地安全认证（拦了会无法登录）
        "svchost.exe",                  // 大量系统服务的宿主
        "dwm.exe",                      // 桌面窗口管理器
        "audiodg.exe",                  // 音频设备图

        // ---- 安全软件 ----
        // 拦掉它们会让杀毒/防护功能异常，属于「用户多半不想真的拦掉」的范畴。
        "MsMpEng.exe",                  // Microsoft Defender 反恶意软件引擎
        "NisSrv.exe",                   // Microsoft Defender 网络检查服务
        "SecurityHealthService.exe",    // Windows 安全中心
    };

    /// <summary>
    /// 受保护的进程文件名清单（只读）。
    /// 界面可以据此把**「阻止」**相关的按钮和菜单项置灰 —— 但**不要**把「允许」也置灰。
    /// </summary>
    public static IReadOnlyCollection<string> ProtectedFileNames => ProtectedNames;

    /// <summary>
    /// 判断某个程序是否**不允许被阻止**。
    ///
    /// 注意措辞：这不是「不允许建任何规则」—— 放行这些进程是允许的（见类型注释）。
    /// 调用方只应在**创建阻止规则**时使用本方法的结果。
    /// </summary>
    /// <param name="programPath">程序的完整路径。</param>
    /// <param name="reason">被拒绝的原因，供界面提示用户。</param>
    /// <returns>受保护返回 true。</returns>
    public static bool IsProtected(string programPath, out string reason)
    {
        reason = string.Empty;

        if (string.IsNullOrWhiteSpace(programPath))
        {
            return false;
        }

        // 1) 自我保护。
        //    如果不拦这一条，用户点一次「阻止」就能把 WinAppGuard 自己封死，
        //    之后就再也打不开界面去解除拦截了。
        var selfPath = Environment.ProcessPath;
        if (!string.IsNullOrEmpty(selfPath) &&
            string.Equals(selfPath, programPath, StringComparison.OrdinalIgnoreCase))
        {
            reason = "这是 WinAppGuard 自身。拦掉它你就无法再用界面解除任何拦截了。";
            return true;
        }

        // 2) 系统关键进程。
        var fileName = Path.GetFileName(programPath);
        if (ProtectedNames.Contains(fileName))
        {
            reason = $"{fileName} 是 Windows 的关键进程。拦掉它可能导致系统异常、无法登录或整台机器断网。";
            return true;
        }

        return false;
    }
}
