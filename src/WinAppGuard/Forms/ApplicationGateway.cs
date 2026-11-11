using WinAppGuard.Contracts;
using WinAppGuard.Core;

namespace WinAppGuard.Forms;

/// <summary>
/// 5.9：界面访问服务端的唯一入口。
///
/// 页面不再直接调用 <see cref="ServiceClient"/> / <see cref="ElevatedClient"/>：
///   - 只读/告警命令走 <see cref="TryRequest"/>；
///   - 需要提权的写命令走 <see cref="TryElevatedRequest"/>；
///   - 是否已提权由 <see cref="IsRunningAsAdmin"/> 统一判断。
///
/// 这样后续换协议、加超时、加诊断或做 UI 自检时，只需要替换一个实现。
/// </summary>
internal interface IApplicationGateway
{
    bool IsRunningAsAdmin { get; }

    ServiceResponse? TryRequest(ServiceRequest request, TimeSpan timeout, out string? error);

    ServiceResponse? TryElevatedRequest(ServiceRequest request, out string? error);

    ServiceStatus? TryGetStatus(TimeSpan timeout);
}

/// <summary>5.9：生产实现，直接包装现有 IPC 客户端；协议仍是 v2。</summary>
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
}
