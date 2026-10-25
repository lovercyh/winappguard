using WinAppGuard.Core;

namespace WinAppGuard.Service;

/// <summary>
/// 3.5：「临时锁网」= 定时严格模式。
///
/// 它不新建一套 WFP 对象，而是**复用严格模式的动态会话**，只多记一个到期时间：
///   - 到点由服务主动撤销（见 <see cref="RuleHandlers.ExpireLockdownIfDue"/>）；
///   - 服务停止 / 崩溃时，动态会话随进程消失，网络自动恢复；
///   - 不落盘：服务重启后不会「自动恢复锁网」，避免用户不知道网络为什么断了。
///
/// 到期检查不在这里起线程：服务已经有串行化的规则锁（<see cref="RuleHandlers.Gate"/>），
/// 定时器在锁内调用 <see cref="TryExpireIfDue"/>，就不会和规则写入同时碰 WFP。
/// </summary>
internal static class LockdownHost
{
    /// <summary>最短 1 分钟。</summary>
    internal const int MinSeconds = 60;

    /// <summary>最长 24 小时。</summary>
    internal const int MaxSeconds = 24 * 60 * 60;

    private static readonly object Gate = new();

    private static DateTime? _expiresUtc;

    internal static bool IsActive
    {
        get { lock (Gate) { return _expiresUtc is not null; } }
    }

    internal static DateTime? ExpiresUtc
    {
        get { lock (Gate) { return _expiresUtc; } }
    }

    internal static int RemainingSeconds
    {
        get
        {
            lock (Gate)
            {
                if (_expiresUtc is not { } expires)
                {
                    return 0;
                }

                var remaining = (expires - DateTime.UtcNow).TotalSeconds;
                return remaining <= 0 ? 0 : (int)Math.Ceiling(remaining);
            }
        }
    }

    /// <summary>
    /// 开始临时锁网。调用方已经持有 <see cref="RuleHandlers.Gate"/>，
    /// 并且会先确认严格模式当前未开启。
    /// </summary>
    internal static StrictModeChangeResult Enable(int seconds)
    {
        if (seconds < MinSeconds || seconds > MaxSeconds)
        {
            return new StrictModeChangeResult(
                false,
                $"临时锁网时长必须在 {MinSeconds}～{MaxSeconds} 秒之间。");
        }

        lock (Gate)
        {
            if (_expiresUtc is not null)
            {
                return new StrictModeChangeResult(false, "临时锁网已经在进行中。");
            }
        }

        // 手动严格模式已经开着时不接管：否则到点会把用户自己开的会话关掉。
        if (StrictModeHost.IsEnabled)
        {
            return new StrictModeChangeResult(false, "严格模式已经开启，无需临时锁网。");
        }

        var result = StrictModeHost.Enable();

        if (!result.Success)
        {
            return result;
        }

        lock (Gate)
        {
            _expiresUtc = DateTime.UtcNow.AddSeconds(seconds);
        }

        ServiceLog.Info("WAG-STRICT-006", $"Timed lockdown enabled: {seconds} seconds.");

        return new StrictModeChangeResult(
            true,
            $"临时锁网已开启：{Describe(seconds)}后自动恢复联网。");
    }

    /// <summary>手动关闭严格模式时清掉到期时间，避免到点又执行一次撤销。</summary>
    internal static void Cancel(string code, string reason)
    {
        lock (Gate)
        {
            if (_expiresUtc is null)
            {
                return;
            }

            _expiresUtc = null;
            ServiceLog.Info(code, reason);
        }
    }

    /// <summary>未到返回 false；到期则清空状态并返回 true（由调用方在规则锁内撤销会话）。</summary>
    internal static bool TryExpireIfDue(out DateTime expiresUtc)
    {
        lock (Gate)
        {
            if (_expiresUtc is not { } expires || DateTime.UtcNow < expires)
            {
                expiresUtc = default;
                return false;
            }

            expiresUtc = expires;
            _expiresUtc = null;
            return true;
        }
    }

    /// <summary>撤销失败时重新挂一个短期到期，让定时器继续重试，而不是留下永久断网。</summary>
    internal static void RetryLater(TimeSpan delay)
    {
        lock (Gate)
        {
            _expiresUtc = DateTime.UtcNow.Add(delay);
        }

        ServiceLog.Warning(
            "WAG-STRICT-009",
            $"Timed lockdown revocation failed; retrying in {delay.TotalSeconds:0} seconds.");
    }

    /// <summary>服务停止：只清状态，会话本身由 <see cref="StrictModeHost.Shutdown"/> 撤销。</summary>
    internal static void Shutdown()
    {
        lock (Gate)
        {
            _expiresUtc = null;
        }
    }

    private static string Describe(int seconds)
    {
        if (seconds % 3600 == 0)
        {
            return $"{seconds / 3600} 小时";
        }

        if (seconds % 60 == 0)
        {
            return $"{seconds / 60} 分钟";
        }

        return $"{seconds} 秒";
    }
}
