namespace WinAppGuard.Core;

/// <summary>
/// 系统开机时刻。
///
/// 为什么要它：「阻断到下次重启」需要判断**这台机器这次开机是什么时候**，
/// 而不是「程序这次启动是什么时候」（用户可能中途才打开程序）。
///
/// 实现：`Environment.TickCount64` 是**开机以来的毫秒数**（托管 API，
/// 不需要新增任何 P/Invoke）。用「现在 − 开机时长」就能推出开机时刻。
/// 同一次开机期间这个值是稳定的；重启之后会跳到一个新的时刻。
///
/// 已知的精度限制（如实写在文档里，不假装没有）：
///   - 从休眠恢复、或系统时钟被大幅校准，都可能让推算值漂移；
///   - 所以判断「是否重启过」时用的是**5 分钟容差**（见
///     <see cref="WinAppGuard.Models.RuleExpiry.BootTimeTolerance"/>），
///     宁可偶尔提前解除，也不要让规则卡住不动。
/// </summary>
public static class SystemUptime
{
    /// <summary>当前这次开机的时刻（UTC）。</summary>
    public static DateTime BootTimeUtc
        => DateTime.UtcNow - TimeSpan.FromMilliseconds(Environment.TickCount64);
}
