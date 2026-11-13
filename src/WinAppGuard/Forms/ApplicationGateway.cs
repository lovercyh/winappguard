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
    ResponsePayload? Payload,
    string? Error,
    bool Cancelled,
    GatewayFailure Failure = GatewayFailure.None)
{
    internal bool Ok => Payload is { Ok: true };

    internal T? As<T>()
        where T : ResponsePayload
        => Payload as T;
}

/// <summary>
/// 5.10：界面访问服务端的唯一入口。
///
/// 读刷新和写命令都通过异步方法执行，避免 UI 线程等待 IPC；
/// 协议细节不泄漏到页面：查询返回强类型视图，写命令返回 <see cref="ResponsePayload"/>。
/// </summary>
internal interface IApplicationGateway
{
    bool IsRunningAsAdmin { get; }

    ResponsePayload? TryRequest(ServiceRequest request, TimeSpan timeout, out string? error);

    ResponsePayload? TryElevatedRequest(ServiceRequest request, out string? error);

    ServiceStatus? TryGetStatus(TimeSpan timeout);

    QueryView? TryQuery(ServiceRequest request, TimeSpan timeout, out string? error);

    TrafficView? TryTraffic(ServiceRequest request, TimeSpan timeout, out string? error);

    RulesView? TryRules(ServiceRequest request, TimeSpan timeout, out string? error);

    AllowTargetsView? TryAllowTargets(ServiceRequest request, TimeSpan timeout, out string? error);

    ProcessPathsView? TryProcessPaths(ServiceRequest request, TimeSpan timeout, out string? error);

    FilterMapView? TryFilterMap(ServiceRequest request, TimeSpan timeout, out string? error);

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

/// <summary>5.10：生产实现，直接包装 v4 IPC 客户端。</summary>
internal sealed class ServiceApplicationGateway : IApplicationGateway
{
    public bool IsRunningAsAdmin => AdminHelper.IsRunningAsAdmin();

    public ResponsePayload? TryRequest(
        ServiceRequest request, TimeSpan timeout, out string? error)
        => ServiceClient.TryRequest(request, timeout, out error);

    public ResponsePayload? TryElevatedRequest(ServiceRequest request, out string? error)
        => ElevatedClient.TryRequest(request, out error);

    public ServiceStatus? TryGetStatus(TimeSpan timeout)
        => ServiceClient.TryGetStatus(timeout);

    public QueryView? TryQuery(
        ServiceRequest request, TimeSpan timeout, out string? error)
        => ServiceClient.TryRequestAs<QueryView>(request, timeout, out error);

    public TrafficView? TryTraffic(
        ServiceRequest request, TimeSpan timeout, out string? error)
        => ServiceClient.TryRequestAs<TrafficView>(request, timeout, out error);

    public RulesView? TryRules(
        ServiceRequest request, TimeSpan timeout, out string? error)
        => ServiceClient.TryRequestAs<RulesView>(request, timeout, out error);

    public AllowTargetsView? TryAllowTargets(
        ServiceRequest request, TimeSpan timeout, out string? error)
        => ServiceClient.TryRequestAs<AllowTargetsView>(request, timeout, out error);

    public ProcessPathsView? TryProcessPaths(
        ServiceRequest request, TimeSpan timeout, out string? error)
        => ServiceClient.TryRequestAs<ProcessPathsView>(request, timeout, out error);

    public FilterMapView? TryFilterMap(
        ServiceRequest request, TimeSpan timeout, out string? error)
        => ServiceClient.TryRequestAs<FilterMapView>(request, timeout, out error);

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

        var code = result.Payload?.ErrorCode;
        var error = result.Error ?? result.Payload?.Error ?? string.Empty;

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

        if (result.Payload is null
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
