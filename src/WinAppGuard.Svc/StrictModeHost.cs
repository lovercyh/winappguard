using WinAppGuard.Core;

namespace WinAppGuard.Service;

/// <summary>
/// 严格模式宿主（3.0-c）：**动态会话活在服务进程里**。
///
/// 为什么必须归服务：
///   - 会话是"进程级"的（WFP 动态会话 + 过滤器），进程一结束 BFE 就自动撤销。
///     放在界面里，关掉界面 = 保护消失，而用户以为它还在；
///   - 放在服务里，关掉界面保护仍在；服务被停/崩溃 = 立即撤销（安全方向，
///     不会留下"谁都上不了网且没人能关"的死局）。
///
/// 所有方法都在 <see cref="RuleHandlers"/> 的串行锁里调用，这里再加一把
/// 自己的锁只是为了防止将来有人绕过规则命令直接调。
/// </summary>
internal static class StrictModeHost
{
    private static readonly object Gate = new();

    /// <summary>界面 exe（服务代界面放行，否则严格模式下界面查不了 IP 归属）。</summary>
    private static readonly string UiPath =
        Path.Combine(AppContext.BaseDirectory, "WinAppGuard.exe");

    internal static bool IsEnabled
    {
        get
        {
            lock (Gate)
            {
                return StrictModeManager.IsEnabled;
            }
        }
    }

    internal static int PermittedCount
    {
        get
        {
            lock (Gate)
            {
                return StrictModeManager.PermittedPrograms.Count;
            }
        }
    }

    internal static StrictModeChangeResult Enable()
    {
        lock (Gate)
        {
            var extras = new List<string>();

            if (File.Exists(UiPath))
            {
                extras.Add(UiPath);
            }

            var result = StrictModeManager.Enable(extras);

            ServiceLog.Info("WAG-STRICT-001", $"Strict mode enable: {(result.Success ? "ok" : "failed")}.");
            return result;
        }
    }

    internal static StrictModeChangeResult Disable()
    {
        lock (Gate)
        {
            var result = StrictModeManager.Disable();
            ServiceLog.Info("WAG-STRICT-002", $"Strict mode disable: {(result.Success ? "ok" : "failed")}.");
            return result;
        }
    }

    /// <summary>白名单变化后重建会话（没开严格模式时什么都不做）。</summary>
    internal static void RefreshIfEnabled()
    {
        lock (Gate)
        {
            var result = StrictModeManager.RefreshIfEnabled();

            if (result is not null)
            {
                ServiceLog.Info("WAG-STRICT-003", $"Strict mode session rebuilt after allowlist change: {(result.Success ? "ok" : "failed")}.");
            }
        }
    }

    /// <summary>从 1.x 升级的兜底：还原被改过的全局默认出站动作。</summary>
    internal static StrictModeRecoveryResult RecoverLegacy(string settingsPath)
    {
        lock (Gate)
        {
            var result = StrictModeManager.RecoverIfLeftOn(settingsPath);

            if (result.WasLeftOn)
            {
                ServiceLog.Warning("WAG-STRICT-004", $"Legacy 1.x strict-mode state handled: restored={result.Restored}.");
            }

            return result;
        }
    }

    /// <summary>服务停止时主动撤销会话（崩溃时 BFE 会自动撤销）。</summary>
    internal static void Shutdown()
    {
        lock (Gate)
        {
            if (StrictModeManager.IsEnabled)
            {
                _ = StrictModeManager.Disable();
                ServiceLog.Info("WAG-STRICT-005", "Strict mode session revoked because the service is stopping.");
            }
        }
    }
}
