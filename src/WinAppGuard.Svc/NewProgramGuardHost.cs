using WinAppGuard.Contracts;
using WinAppGuard.Core;
using WinAppGuard.Core.Wfp;
using WinAppGuard.Interop;

namespace WinAppGuard.Service;

/// <summary>
/// 5.8：新程序默认阻止的临时隔离。
///
/// 这是**唯一**允许界面在没有 UAC 的情况下创建 WFP 过滤器的路径，
/// 因此边界写死：
///   - 只创建动态会话里的程序级阻止过滤器，不写持久规则；
///   - 只接受 .exe 完整路径，复用 FirewallManager.ValidateProgramPath；
///   - 受保护进程（本程序、系统关键进程）直接拒绝；
///   - 只在本功能开启且用户正在处理新程序弹窗时调用；
///   - 服务停止/重启时动态会话自动清空。
///
/// 这不是“内核 callout”：检测到新程序时第一条连接可能已经建立，
/// 这里只能阻止它后续的出站连接。
/// </summary>
internal static class NewProgramGuardHost
{
    private const int MaxBlocked = 200;
    private const string DisplayName = "AppGuard_NewProgramGuard";

    private static readonly object Gate = new();
    private static readonly Dictionary<string, Guid[]> Blocked =
        new(StringComparer.OrdinalIgnoreCase);

    private static WfpEngine? _engine;

    internal static void Start()
    {
        lock (Gate)
        {
            StopLocked();

            try
            {
                _engine = WfpEngine.Open(dynamicSession: true);
                _engine.EnsureSublayer(persistent: false);
            }
            catch (Exception ex)
            {
                _engine?.Dispose();
                _engine = null;
                ServiceLog.Warning(
                    "WAG-GUARD-001",
                    "Failed to open the WFP session for new-program quarantine.",
                    ex);
            }
        }
    }

    internal static void Stop()
    {
        lock (Gate)
        {
            StopLocked();
        }
    }

    internal static ServiceResponse Block(ServiceRequest request)
    {
        var rawPath = request.Value;

        string fullPath;

        try
        {
            fullPath = FirewallManager.ValidateProgramPath(rawPath ?? string.Empty, forBlocking: true);
        }
        catch (Exception ex)
        {
            return Error(request, ex.Message);
        }

        lock (Gate)
        {
            if (_engine is null)
            {
                return Error(request, "临时阻止会话不可用，未创建阻止过滤器。");
            }

            if (Blocked.Count >= MaxBlocked)
            {
                return Error(request, $"临时阻止已达上限 {MaxBlocked} 条。");
            }

            if (Blocked.ContainsKey(fullPath))
            {
                return new ServiceResponse
                {
                    Id = request.Id,
                    Ok = true,
                    Affected = 0,
                };
            }

            var keys = new List<Guid>(WfpRuleStore.OutboundLayers.Length);

            try
            {
                foreach (var layer in WfpRuleStore.OutboundLayers)
                {
                    var key = WfpEngine.BuildFilterKey($"newprogram|{fullPath}|{layer}");

                    _engine.TryDeleteFilter(key);
                    _engine.AddAppIdFilter(
                        key,
                        DisplayName,
                        $"newprogram|{fullPath}",
                        fullPath,
                        layer,
                        WfpNativeMethods.FWP_ACTION_BLOCK,
                        WfpRuleStore.WeightBlock,
                        persistent: false);

                    keys.Add(key);
                }
            }
            catch (Exception ex)
            {
                foreach (var key in keys)
                {
                    try
                    {
                        _engine.TryDeleteFilter(key);
                    }
                    catch (Exception)
                    {
                        // 动态会话关闭时会一起清掉。
                    }
                }

                ServiceLog.Warning(
                    "WAG-GUARD-002",
                    $"Failed to create a temporary new-program block for {fullPath}.",
                    ex);

                return Error(request, $"创建临时阻止失败：{ex.Message}");
            }

            Blocked[fullPath] = keys.ToArray();
        }

        ServiceLog.Operation(
            "WAG-GUARD-003",
            $"Temporary new-program block created: {fullPath}");

        return new ServiceResponse
        {
            Id = request.Id,
            Ok = true,
            Affected = 1,
        };
    }

    internal static ServiceResponse Release(ServiceRequest request)
    {
        var path = request.Value?.Trim();

        if (string.IsNullOrEmpty(path))
        {
            return Error(request, "缺少程序路径。");
        }

        try
        {
            path = Path.GetFullPath(path);
        }
        catch (Exception)
        {
            // 文件已经被删除时仍然允许释放：下面按原字符串查字典。
        }

        lock (Gate)
        {
            if (!Blocked.TryGetValue(path, out var keys))
            {
                return new ServiceResponse
                {
                    Id = request.Id,
                    Ok = true,
                    Affected = 0,
                };
            }

            foreach (var key in keys)
            {
                try
                {
                    _engine?.TryDeleteFilter(key);
                }
                catch (Exception ex)
                {
                    ServiceLog.Warning(
                        "WAG-GUARD-004",
                        $"Failed to delete a temporary new-program block filter for {path}.",
                        ex);
                }
            }

            Blocked.Remove(path);
        }

        ServiceLog.Operation(
            "WAG-GUARD-005",
            $"Temporary new-program block released: {path}");

        return new ServiceResponse
        {
            Id = request.Id,
            Ok = true,
            Affected = 1,
        };
    }

    private static void StopLocked()
    {
        foreach (var pair in Blocked.ToList())
        {
            foreach (var key in pair.Value)
            {
                try
                {
                    _engine?.TryDeleteFilter(key);
                }
                catch (Exception)
                {
                    // 动态会话关闭时自动清掉。
                }
            }
        }

        Blocked.Clear();

        _engine?.Dispose();
        _engine = null;
    }

    private static ServiceResponse Error(ServiceRequest request, string message)
        => new()
        {
            Id = request.Id,
            Ok = false,
            Error = message,
        };
}
