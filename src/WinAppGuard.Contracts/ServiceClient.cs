using System.IO.Pipes;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using WinAppGuard.Contracts.Protocol;

namespace WinAppGuard.Contracts;

/// <summary>
/// 界面侧的 IPC 客户端（3.1 协议 v2）。
///
/// 每条请求先取 nonce，再对 <c>nonce || 请求 JSON</c> 签名：
/// 没配置签名密钥（不是所有者 / DPAPI 解不开）就发不出去。
/// 连接失败仍按“正常离线”返回 null，不抛异常。
/// </summary>
public static class ServiceClient
{
    private static IServiceSigner? _signer;

    /// <summary>当前进程的签名能力；null = 没有可用密钥。</summary>
    public static bool HasSigner => Volatile.Read(ref _signer) is not null;

    /// <summary>当前签名器（自检里用于恢复现场）。</summary>
    public static IServiceSigner? CurrentSigner => Volatile.Read(ref _signer);

    /// <summary>
    /// 设置签名器。3.1 的 UI / 安装器 / 提权助手在启动时调用一次；
    /// 传 null 表示当前账户没有可用密钥。
    /// </summary>
    public static void SetSigner(IServiceSigner? signer)
        => Volatile.Write(ref _signer, signer);

    public static ServiceStatus? TryGetStatus(TimeSpan timeout)
    {
        var response = TryRequestAs<StatusView>(
            new ServiceRequest { Command = ServiceProtocol.Commands.Status },
            timeout);

        return response is { Ok: true } ? response.Status : null;
    }

    public static ResponsePayload? TryRequest(ServiceRequest request, TimeSpan timeout)
        => TryRequest(request, timeout, out _);

    /// <summary>
    /// 发一条请求并等响应；失败返回 null，并通过 <paramref name="error"/>
    /// 给出**真实原因**（没有密钥 / 连接被拒 / 找不到管道 / 超时 / 认证失败）。
    /// </summary>
    public static ResponsePayload? TryRequest(
        ServiceRequest request, TimeSpan timeout, out string? error)
    {
        var signer = Volatile.Read(ref _signer);

        if (signer is null)
        {
            error = "未配置签名密钥（当前账户不是所有者，或密钥不可用）。";
            return null;
        }

        return ServiceSession.TrySend(request, timeout, signer, out error);
    }

    /// <summary>发一条请求，并断言响应是 <typeparamref name="T"/>。</summary>
    public static T? TryRequestAs<T>(
        ServiceRequest request, TimeSpan timeout, out string? error)
        where T : ResponsePayload
    {
        var payload = TryRequest(request, timeout, out error);

        if (payload is null)
        {
            return null;
        }

        if (payload is T typed)
        {
            return typed;
        }

        // 失败时服务端可能只返回 ErrorView：把真实原因带回调用方，
        // 不要用“类型不匹配”掩盖业务错误。
        error = payload.Ok
            ? $"服务返回了 {payload.GetType().Name}，但客户端期望 {typeof(T).Name}。"
            : payload.Error ?? $"服务返回了 {payload.GetType().Name}，但客户端期望 {typeof(T).Name}。";
        return null;
    }

    public static T? TryRequestAs<T>(ServiceRequest request, TimeSpan timeout)
        where T : ResponsePayload
        => TryRequestAs<T>(request, timeout, out _);


    /// <summary>服务是否在运行（只要签名后的 status 能通就算）。</summary>
    public static bool IsRunning(TimeSpan timeout) => TryGetStatus(timeout) is not null;
}
