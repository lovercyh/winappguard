using System.IO.Pipes;

namespace WinAppGuard.Contracts;

/// <summary>
/// 界面侧的 IPC 客户端。
///
/// 刻意做成"失败就返回 null"而不是抛异常：服务没装、没起、被停，
/// 都是**正常状态**，界面要能据此显示「离线模式」，而不是弹一堆错误。
/// </summary>
public static class ServiceClient
{
    /// <summary>
    /// 查询服务状态。
    /// </summary>
    /// <returns>拿到状态返回它；连不上 / 超时 / 协议不匹配返回 null。</returns>
    public static ServiceStatus? TryGetStatus(TimeSpan timeout)
    {
        var response = TryRequest(
            new ServiceRequest { Command = ServiceProtocol.Commands.Status },
            timeout);

        return response is { Ok: true } ? response.Status : null;
    }

    /// <summary>发一条请求并等响应；失败返回 null。</summary>
    public static ServiceResponse? TryRequest(ServiceRequest request, TimeSpan timeout)
    {
        try
        {
            using var cancellation = new CancellationTokenSource(timeout);
            using var pipe = new NamedPipeClientStream(
                ".", ServiceProtocol.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);

            pipe.Connect((int)Math.Max(1, timeout.TotalMilliseconds));
            PipeCodec.WriteAsync(pipe, request, cancellation.Token).GetAwaiter().GetResult();
            return PipeCodec.ReadAsync<ServiceResponse>(pipe, cancellation.Token)
                .GetAwaiter().GetResult();
        }
        catch (Exception)
        {
            return null;
        }
    }

    /// <summary>服务是否在运行（只要 status 能通就算）。</summary>
    public static bool IsRunning(TimeSpan timeout) => TryGetStatus(timeout) is not null;
}
