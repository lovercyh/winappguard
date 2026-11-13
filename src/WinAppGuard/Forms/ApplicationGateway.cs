using WinAppGuard.Contracts;
using WinAppGuard.Contracts.Protocol;
using WinAppGuard.Core;

namespace WinAppGuard.Forms;

/// <summary>5.10：一次网关调用的结果；UI 用它区分成功、失败和取消。</summary>
internal enum GatewayFailure
{
    None = 0,
    Offline = 1,
    Timeout = 2,
    Unauthorized = 3,
    VersionMismatch = 4,
    Error = 5,
}

internal sealed record GatewayResult(
    ServiceResponse? Response,
    string? Error,
    bool Cancelled,
    GatewayFailure Failure = GatewayFailure.None)
{
    internal bool Ok => Response is { Ok: true };
}

/// <summary>
/// 5.10：界面访问服务端的唯一入口。
///
/// 读刷新和写命令都通过异步方法执行，避免 UI 线程等待 IPC；
/// 底层仍复用 v3/v2 客户端，协议细节不泄漏到页面。
/// </summary>
internal interface IApplicationGateway
{
    bool IsRunningAsAdmin { get; }

    ServiceResponse? TryRequest(ServiceRequest request, TimeSpan timeout, out string? error);

    ServiceResponse? TryElevatedRequest(ServiceRequest request, out string? error);

    ServiceStatus? TryGetStatus(TimeSpan timeout);

    QueryView? TryQuery(ServiceRequest request, TimeSpan timeout, out string? error);

    TrafficView? TryTraffic(ServiceRequest request, TimeSpan timeout, out string? error);

    Task<GatewayResult> TryRequestAsync(
        ServiceRequest request,
        TimeSpan timeout,
        CancellationToken cancellationToken);

    Task<GatewayResult> TryElevatedRequestAsync(
        ServiceRequest request,
        CancellationToken cancellationToken);

    Task<ServiceStatus?> TryGetStatusAsync(
        TimeSpan timeout,
        CancellationToken cancellationToken);
}

/// <summary>5.10：生产实现，直接包装现有 IPC 客户端；协议仍是 v3（可回退 v2）。</summary>
internal sealed class ServiceApplicationGateway : IApplicationGateway
{
    public bool IsRunningAsAdmin => AdminHelper.IsRunningAsAdmin();

    public ServiceResponse? TryRequest(
        ServiceRequest request, TimeSpan timeout, out string? error)
        => ServiceClient.TryRequest(request, timeout, out error);

    public ServiceResponse? TryElevatedRequest(ServiceRequest request, out string? error)
        => ElevatedClient.TryRequest(request, out error);

    public ServiceStatus? TryGetStatus(TimeSpan timeout)
        => ServiceClient.TryGetStatus(timeout);

    public QueryView? TryQuery(
        ServiceRequest request, TimeSpan timeout, out string? error)
    {
        var response = ServiceClient.TryRequest(request, timeout, out error);

        if (response is null)
        {
            return null;
        }

        if (!response.Ok)
        {
            error = response.Error ?? error ?? "查询失败。";
            return null;
        }

        return LegacyPayloadAdapter.CreateResponse(
            request.Command, response, 0, null) as QueryView;
    }

    public TrafficView? TryTraffic(
        ServiceRequest request, TimeSpan timeout, out string? error)
    {
        var response = ServiceClient.TryRequest(request, timeout, out error);

        if (response is null || !response.Ok)
        {
            error ??= response?.Error ?? "查询失败。";
            return null;
        }

        return LegacyPayloadAdapter.CreateResponse(
            request.Command, response, 0, null) as TrafficView;
    }

    public async Task<GatewayResult> TryRequestAsync(
        ServiceRequest request,
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        if (cancellationToken.IsCancellationRequested)
        {
            return new GatewayResult(null, null, Cancelled: true);
        }

        try
        {
            return await Task.Run(
                () =>
                {
                    var response = ServiceClient.TryRequest(request, timeout, out var error);
                    return Classify(new GatewayResult(response, error, Cancelled: false));
                },
                cancellationToken).ConfigureAwait(true);
        }
        catch (OperationCanceledException)
        {
            return new GatewayResult(null, null, Cancelled: true);
        }
    }

    public async Task<GatewayResult> TryElevatedRequestAsync(
        ServiceRequest request,
        CancellationToken cancellationToken)
    {
        if (cancellationToken.IsCancellationRequested)
        {
            return new GatewayResult(null, null, Cancelled: true);
        }

        try
        {
            return await Task.Run(
                () =>
                {
                    var response = ElevatedClient.TryRequest(request, out var error);
                    return Classify(new GatewayResult(response, error, Cancelled: false));
                },
                cancellationToken).ConfigureAwait(true);
        }
        catch (OperationCanceledException)
        {
            return new GatewayResult(null, null, Cancelled: true);
        }
    }

    public async Task<ServiceStatus?> TryGetStatusAsync(
        TimeSpan timeout,
        CancellationToken cancellationToken)
    {
        if (cancellationToken.IsCancellationRequested)
        {
            return null;
        }

        try
        {
            return await Task.Run(
                () => ServiceClient.TryGetStatus(timeout),
                cancellationToken).ConfigureAwait(true);
        }
        catch (OperationCanceledException)
        {
            return null;
        }
    }

    private static GatewayResult Classify(GatewayResult result)
    {
        if (result.Cancelled)
        {
            return result with { Failure = GatewayFailure.Offline };
        }

        if (result.Ok)
        {
            return result with { Failure = GatewayFailure.None };
        }

        var code = result.Response?.ErrorCode;
        var error = result.Error ?? result.Response?.Error ?? string.Empty;

        if (string.Equals(code, "NotElevated", StringComparison.Ordinal)
            || string.Equals(code, "NotOwner", StringComparison.Ordinal)
            || error.Contains("签名密钥", StringComparison.Ordinal)
            || error.Contains("认证失败", StringComparison.Ordinal)
            || error.Contains("管理员权限", StringComparison.Ordinal))
        {
            return result with { Failure = GatewayFailure.Unauthorized };
        }

        if (string.Equals(code, "VersionMismatch", StringComparison.Ordinal)
            || error.Contains("协议", StringComparison.Ordinal)
            || error.Contains("版本", StringComparison.Ordinal))
        {
            return result with { Failure = GatewayFailure.VersionMismatch };
        }

        if (error.Contains("Timeout", StringComparison.OrdinalIgnoreCase)
            || error.Contains("超时", StringComparison.Ordinal))
        {
            return result with { Failure = GatewayFailure.Timeout };
        }

        if (result.Response is null
            && (error.Contains("管道", StringComparison.Ordinal)
                || error.Contains("v4", StringComparison.OrdinalIgnoreCase)
                || error.Contains("连接", StringComparison.Ordinal)
                || error.Contains("Offline", StringComparison.OrdinalIgnoreCase)))
        {
            return result with { Failure = GatewayFailure.Offline };
        }

        return result with { Failure = GatewayFailure.Error };
    }
}
