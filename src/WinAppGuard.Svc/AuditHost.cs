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
                ServiceLog.Warning("WAG-AUDIT-020", "Failed to save audit settings.", ex);
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
                ServiceLog.Operation("WAG-AUDIT-010", $"Audit records cleared by user: {deleted} files deleted.");
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

            ServiceLog.Info("WAG-AUDIT-001", $"Audit capture started (retention {_settings.RetentionDays} days, domain lookup {(_settings.DomainLookup ? "on" : "off")}).");
        }
        catch (Exception ex)
        {
            _service = null;
            ServiceLog.Warning("WAG-AUDIT-030", "Failed to start audit capture.", ex);
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
            ServiceLog.Warning("WAG-AUDIT-031", "Error while stopping audit capture.", ex);
        }

        _service = null;
        ServiceLog.Info("WAG-AUDIT-032", "Audit capture stopped.");
    }
}
