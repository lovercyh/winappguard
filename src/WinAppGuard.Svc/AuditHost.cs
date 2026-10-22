using WinAppGuard.Contracts;
using WinAppGuard.Core.Audit;

namespace WinAppGuard.Service;

/// <summary>
/// 审计宿主（3.0-c）：采集与落盘都在服务里。
///
/// 为什么搬进来：
///   - 关掉界面后记录还必须继续（这是"记录"这个功能的全部意义）；
///   - 采集要读 WFP 拦截事件、连接表，服务本来就有 SYSTEM 权限；
///   - 记录文件写到 %ProgramData%，不再随用户目录散落。
///
/// 界面只通过 IPC 改设置 / 清空，以及**只读**这些文件。
/// </summary>
internal static class AuditHost
{
    private static readonly object Gate = new();
    private static readonly string SettingsPath = ServicePaths.AuditSettingsFile;

    private static AuditSettings _settings = AuditSettingsFile.Read(SettingsPath);
    private static AuditService? _service;

    internal static bool Collecting
    {
        get
        {
            lock (Gate)
            {
                return _service is not null;
            }
        }
    }

    internal static int EventsWritten
    {
        get
        {
            lock (Gate)
            {
                return _service?.EventsWritten ?? 0;
            }
        }
    }

    internal static AuditSettings Snapshot()
    {
        lock (Gate)
        {
            return _settings.Clone();
        }
    }

    /// <summary>服务启动时调用（设置里开着就开采集）。</summary>
    internal static void StartIfEnabled()
    {
        lock (Gate)
        {
            StartCore();
        }
    }

    /// <summary>服务停止时调用。</summary>
    internal static void Stop()
    {
        lock (Gate)
        {
            StopCore();
        }
    }

    /// <summary>修改设置：落盘 + 重启采集（保留期/域名开关是构造参数，必须重建）。</summary>
    internal static AuditSettings Apply(AuditSettings updated)
    {
        lock (Gate)
        {
            updated.Normalize();
            _settings = updated;

            try
            {
                AuditSettingsFile.Write(SettingsPath, _settings);
            }
            catch (Exception ex)
            {
                ServiceLog.Warning($"保存审计设置失败：{ex.Message}");
            }

            StopCore();
            StartCore();

            return _settings.Clone();
        }
    }

    /// <summary>清空记录：先停采集，删完再恢复（否则文件被占着删不掉）。</summary>
    internal static int Clear()
    {
        lock (Gate)
        {
            StopCore();

            try
            {
                using var store = new AuditStore(ServicePaths.AuditDirectory);
                var deleted = store.Clear();
                ServiceLog.Info($"记录：用户清空记录，删除 {deleted} 个文件");
                return deleted;
            }
            finally
            {
                StartCore();
            }
        }
    }

    private static void StartCore()
    {
        if (_service is not null || !_settings.Enabled)
        {
            return;
        }

        try
        {
            var service = new AuditService(
                ServicePaths.AuditDirectory,
                pollSeconds: 3,
                retentionDays: _settings.RetentionDays,
                allowDomainLookup: _settings.DomainLookup);

            service.Start();
            _service = service;

            ServiceLog.Info(
                $"记录：已开始采集（保留 {_settings.RetentionDays} 天，" +
                $"域名推测{(_settings.DomainLookup ? "开" : "关")}）。");
        }
        catch (Exception ex)
        {
            _service = null;
            ServiceLog.Warning($"启动审计采集失败：{ex.Message}");
        }
    }

    private static void StopCore()
    {
        if (_service is null)
        {
            return;
        }

        try
        {
            _service.Dispose();
        }
        catch (Exception ex)
        {
            ServiceLog.Warning($"停止审计采集时出错：{ex.Message}");
        }

        _service = null;
        ServiceLog.Info("记录：已停止采集。");
    }
}
