using System.Net;
using System.Net.Sockets;
using WinAppGuard.Contracts;
using WinAppGuard.Core.Diagnostics.NetworkDetection;
using WinAppGuard.Core.Wfp;
using WinAppGuard.Interop;

namespace WinAppGuard.Service;

/// <summary>
/// 5.0：用户手动触发的 WFP 出站阻断。
///
/// 与规则命中完全解耦：告警本身不会调用这里，只有用户在界面上确认
/// “拦截”之后才会创建过滤器。所有过滤器都在动态会话里，服务停止/
/// 重启自动消失，避免留下无法解释的永久规则。
/// </summary>
internal static class NetworkBlockHost
{
    private const string DescriptionPrefix = "AppGuard|1|NetworkDetectionBlock|";
    private const int MaxBlocks = 200;

    private static readonly object Gate = new();
    private static readonly List<NetworkBlock> Blocks = new();

    private static WfpEngine? _engine;
    private static System.Threading.Timer? _timer;

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
                ServiceLog.Warning("WAG-ND-010", "Failed to open the WFP session for network blocks.", ex);
            }

            _timer = new System.Threading.Timer(
                _ => Expire(),
                null,
                TimeSpan.FromSeconds(30),
                TimeSpan.FromSeconds(30));
        }
    }

    internal static void Stop()
    {
        lock (Gate)
        {
            StopLocked();
        }
    }

    internal static IReadOnlyList<NetworkBlock> Snapshot()
    {
        lock (Gate)
        {
            return Blocks
                .OrderBy(block => block.ExpiresUtc)
                .ToList();
        }
    }

    internal static ServiceResponse Add(
        ServiceRequest request,
        string kind,
        string target,
        int minutes,
        string? alertId,
        string? ruleName)
    {
        var duration = Math.Clamp(minutes, 1, 60);

        lock (Gate)
        {
            if (_engine is null)
            {
                return Error(request, "WFP 会话不可用，无法创建拦截。");
            }

            if (Blocks.Count >= MaxBlocks)
            {
                return Error(request, $"活动拦截已达上限 {MaxBlocks} 条，请先释放一些。");
            }

            if (!TryParseTarget(kind, target, out var parsed, out var error))
            {
                return Error(request, error);
            }

            if (!IsAllowedAddress(parsed.RemoteAddress))
            {
                return Error(request, "拒绝拦截 loopback / 组播 / 未指定地址。");
            }

            var existing = Blocks.FirstOrDefault(
                block => string.Equals(block.Kind, kind, StringComparison.OrdinalIgnoreCase)
                    && string.Equals(block.Target, target, StringComparison.OrdinalIgnoreCase));

            if (existing is not null)
            {
                existing.ExpiresUtc = DateTime.UtcNow.AddMinutes(duration);
                return new ServiceResponse
                {
                    Id = request.Id,
                    Ok = true,
                    NetworkBlocks = SnapshotLocked(),
                };
            }

            var block = new NetworkBlock
            {
                Kind = kind,
                Target = target,
                AlertId = alertId,
                RuleName = ruleName,
                CreatedUtc = DateTime.UtcNow,
                ExpiresUtc = DateTime.UtcNow.AddMinutes(duration),
                FilterKey = WfpEngine.BuildFilterKey($"netdetect|{kind}|{target}|{Guid.NewGuid():N}"),
            };

            try
            {
                _engine.AddTransportOutboundFilter(
                    block.FilterKey,
                    $"{AppConstants.RulePrefix}NDBlock_{block.Id}",
                    $"{DescriptionPrefix}{block.Id}|{kind}|{target}",
                    parsed.RemoteAddress,
                    parsed.RemotePort is { } remotePortValue ? (ushort)remotePortValue : null,
                    parsed.LocalAddress,
                    parsed.LocalPort is { } localPortValue ? (ushort)localPortValue : null,
                    parsed.Protocol,
                    WfpNativeMethods.FWP_ACTION_BLOCK,
                    WfpRuleStore.WeightBlock,
                    persistent: false);
            }
            catch (Exception ex)
            {
                ServiceLog.Warning("WAG-ND-011", "Failed to add a network block filter.", ex);
                return Error(request, $"创建拦截失败：{ex.Message}");
            }

            Blocks.Add(block);

            ServiceLog.Operation(
                "WAG-ND-012",
                $"Manual network block: id={block.Id}, kind={kind}, target={target}, " +
                $"minutes={duration}, alert={alertId ?? "-"};");

            return new ServiceResponse
            {
                Id = request.Id,
                Ok = true,
                NetworkBlocks = SnapshotLocked(),
            };
        }
    }

    internal static ServiceResponse Remove(ServiceRequest request, string blockId)
    {
        lock (Gate)
        {
            var block = Blocks.FirstOrDefault(
                item => string.Equals(item.Id, blockId, StringComparison.Ordinal));

            if (block is null)
            {
                return Error(request, "拦截不存在或已到期。");
            }

            RemoveLocked(block);

            return new ServiceResponse
            {
                Id = request.Id,
                Ok = true,
                Affected = 1,
                NetworkBlocks = SnapshotLocked(),
            };
        }
    }

    internal static ServiceResponse RemoveAll(ServiceRequest request)
    {
        lock (Gate)
        {
            var removed = Blocks.Count;

            foreach (var block in Blocks.ToList())
            {
                RemoveLocked(block);
            }

            ServiceLog.Operation(
                "WAG-ND-013",
                $"Released all manual network blocks ({removed}).");

            return new ServiceResponse
            {
                Id = request.Id,
                Ok = true,
                Affected = removed,
                NetworkBlocks = SnapshotLocked(),
            };
        }
    }

    private static void Expire()
    {
        lock (Gate)
        {
            var now = DateTime.UtcNow;
            var expired = Blocks.Where(block => block.ExpiresUtc <= now).ToList();

            foreach (var block in expired)
            {
                RemoveLocked(block);
            }

            if (expired.Count > 0)
            {
                ServiceLog.Operation(
                    "WAG-ND-014",
                    $"Expired {expired.Count} manual network block(s).");
            }
        }
    }

    private static void RemoveLocked(NetworkBlock block)
    {
        try
        {
            _engine?.TryDeleteFilter(block.FilterKey);
        }
        catch (Exception ex)
        {
            ServiceLog.Warning("WAG-ND-015", "Failed to delete a network block filter.", ex);
        }

        Blocks.Remove(block);
    }

    private static void StopLocked()
    {
        _timer?.Dispose();
        _timer = null;

        foreach (var block in Blocks.ToList())
        {
            try
            {
                _engine?.TryDeleteFilter(block.FilterKey);
            }
            catch (Exception)
            {
                // 动态会话关闭时也会自动删除。
            }
        }

        Blocks.Clear();

        _engine?.Dispose();
        _engine = null;
    }

    private static List<NetworkBlockDto> SnapshotLocked()
        => Blocks
            .OrderBy(block => block.ExpiresUtc)
            .Select(block => new NetworkBlockDto
            {
                Id = block.Id,
                Kind = block.Kind,
                Target = block.Target,
                RuleName = block.RuleName,
                AlertId = block.AlertId,
                CreatedUtc = block.CreatedUtc,
                ExpiresUtc = block.ExpiresUtc,
            })
            .ToList();

    private static bool TryParseTarget(
        string kind,
        string target,
        out ParsedTarget parsed,
        out string error)
    {
        parsed = default;
        error = string.Empty;

        try
        {
            switch (kind)
            {
                case "ip":
                {
                    if (!IPAddress.TryParse(target, out var address))
                    {
                        error = "IP 地址格式不正确。";
                        return false;
                    }

                    parsed = new ParsedTarget(address, null, null, null, null);
                    return true;
                }

                case "ip-port":
                {
                    var parts = target.Split('|', StringSplitOptions.TrimEntries);
                    if (parts.Length < 2
                        || !IPAddress.TryParse(parts[0], out var address)
                        || !ushort.TryParse(parts[1], out var port)
                        || port == 0)
                    {
                        error = "IP:端口格式不正确，应为 IP|端口|TCP/UDP。";
                        return false;
                    }

                    var protocol = parts.Length >= 3 ? ParseProtocol(parts[2]) : null;
                    parsed = new ParsedTarget(address, port, null, null, protocol);
                    return true;
                }

                case "connection":
                {
                    var parts = target.Split('|', StringSplitOptions.TrimEntries);
                    if (parts.Length < 5
                        || !IPAddress.TryParse(parts[1], out var localAddress)
                        || !ushort.TryParse(parts[2], out var localPort)
                        || !IPAddress.TryParse(parts[3], out var remoteAddress)
                        || !ushort.TryParse(parts[4], out var remotePort))
                    {
                        error = "五元组格式不正确，应为 协议|本机IP|本机端口|远端IP|远端端口。";
                        return false;
                    }

                    var protocol = ParseProtocol(parts[0]);
                    if (protocol is null)
                    {
                        error = "协议只支持 TCP / UDP。";
                        return false;
                    }

                    parsed = new ParsedTarget(
                        remoteAddress, remotePort, localAddress, localPort, protocol);
                    return true;
                }

                default:
                    error = "5.0 只支持 ip / ip-port / connection 三种拦截范围。";
                    return false;
            }
        }
        catch (Exception)
        {
            error = "拦截目标解析失败。";
            return false;
        }
    }

    private static byte? ParseProtocol(string text)
        => text.Trim().ToUpperInvariant() switch
        {
            "TCP" => 6,
            "UDP" => 17,
            _ => null,
        };

    private static bool IsAllowedAddress(IPAddress address)
    {
        if (IPAddress.IsLoopback(address)
            || address.Equals(IPAddress.Any)
            || address.Equals(IPAddress.IPv6Any)
            || address.Equals(IPAddress.IPv6None)
            || address.IsIPv6Multicast
            || address.IsIPv6LinkLocal)
        {
            return false;
        }

        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            var bytes = address.GetAddressBytes();
            return bytes[0] != 0 && bytes[0] < 224;
        }

        return true;
    }

    private static ServiceResponse Error(ServiceRequest request, string message)
        => new()
        {
            Id = request.Id,
            Ok = false,
            Error = message,
        };

    private readonly record struct ParsedTarget(
        IPAddress RemoteAddress,
        int? RemotePort,
        IPAddress? LocalAddress,
        int? LocalPort,
        byte? Protocol);
}
