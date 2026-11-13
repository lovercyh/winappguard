using WinAppGuard.Contracts;
using WinAppGuard.Core;

namespace WinAppGuard.Forms;

/// <summary>5.10：一次网关调用的结果；UI 用它区分成功、失败和取消。</summary>
internal sealed record GatewayResult(
    ServiceResponse? Response,
    string? Error,
    bool Cancelled)
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
                    return new GatewayResult(response, error, Cancelled: false);
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
                    return new GatewayResult(response, error, Cancelled: false);
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
}
