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
        var response = TryRequest(
            new ServiceRequest { Command = ServiceProtocol.Commands.Status },
            timeout);

        return response is { Ok: true } ? response.Status : null;
    }

    public static ServiceResponse? TryRequest(ServiceRequest request, TimeSpan timeout)
        => TryRequest(request, timeout, out _);

    /// <summary>
    /// 发一条请求并等响应；失败返回 null，并通过 <paramref name="error"/>
    /// 给出**真实原因**（没有密钥 / 连接被拒 / 找不到管道 / 超时 / 认证失败）。
    /// </summary>
    public static ServiceResponse? TryRequest(
        ServiceRequest request, TimeSpan timeout, out string? error)
    {
        var signer = Volatile.Read(ref _signer);

        if (signer is null)
        {
            error = "未配置签名密钥（当前账户不是所有者，或密钥不可用）。";
            return null;
        }

        var response = TryRequestV3(request, timeout, signer, out error);
        return response;
    }

    private static ServiceResponse? TryRequestV3(
        ServiceRequest request,
        TimeSpan timeout,
        IServiceSigner signer,
        out string? error)
    {
        error = null;

        try
        {
            using var cancellation = new CancellationTokenSource(timeout);
            using var pipe = new NamedPipeClientStream(
                ".", ServiceProtocol.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);

            try
            {
                pipe.Connect((int)Math.Max(1, Math.Min(250, timeout.TotalMilliseconds)));
            }
            catch (Exception ex) when (ex is TimeoutException or IOException or UnauthorizedAccessException)
            {
                error = $"v3 管道不可用：{ex.GetType().Name}";
                return null;
            }

            if (!ServerIdentity.IsExpectedServer(
                    pipe.SafePipeHandle.DangerousGetHandle(), out var identityError))
            {
                error = $"检测到异常的服务端：{identityError}";
                return null;
            }

            var clientNonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

            PipeCodec.WriteAsync(pipe, new ProtocolMessage
            {
                Type = "hello",
                V = ServiceProtocol.Version,
                ClientNonce = clientNonce,
            }, cancellation.Token).GetAwaiter().GetResult();

            var challenge = PipeCodec.ReadAsync<ProtocolMessage>(pipe, cancellation.Token)
                .GetAwaiter().GetResult();

            if (challenge is null
                || !string.Equals(challenge.Type, "challenge", StringComparison.Ordinal)
                || string.IsNullOrWhiteSpace(challenge.ServerNonce)
                || string.IsNullOrWhiteSpace(challenge.SessionId))
            {
                error = $"v3 握手失败：{challenge?.Message ?? "服务没有返回 challenge"}";
                return null;
            }

            var authBytes = Encoding.UTF8.GetBytes(
                $"{challenge.ServerNonce}|{clientNonce}|{challenge.SessionId}");

            PipeCodec.WriteAsync(pipe, new ProtocolMessage
            {
                Type = "auth",
                V = ServiceProtocol.Version,
                SessionId = challenge.SessionId,
                Signature = Convert.ToBase64String(signer.Sign(authBytes)),
            }, cancellation.Token).GetAwaiter().GetResult();

            var welcome = PipeCodec.ReadAsync<ProtocolMessage>(pipe, cancellation.Token)
                .GetAwaiter().GetResult();

            if (welcome is null
                || !string.Equals(welcome.Type, "welcome", StringComparison.Ordinal))
            {
                error = $"v3 认证失败：{welcome?.Message ?? "服务没有返回 welcome"}";
                return null;
            }

            var frame = new ProtocolMessage
            {
                Type = "request",
                V = ServiceProtocol.Version,
                Id = request.Id,
                Seq = 1,
                Command = request.Command,
                Payload = JsonSerializer.SerializeToElement(request, ServiceProtocol.JsonOptions),
            };

            var canonical = ProtocolSigning.CanonicalBytes(frame);
            var nonceBytes = Encoding.UTF8.GetBytes(challenge.ServerNonce);
            var signed = new byte[nonceBytes.Length + canonical.Length];
            Buffer.BlockCopy(nonceBytes, 0, signed, 0, nonceBytes.Length);
            Buffer.BlockCopy(canonical, 0, signed, nonceBytes.Length, canonical.Length);
            frame.Signature = Convert.ToBase64String(signer.Sign(signed));

            PipeCodec.WriteAsync(pipe, frame, cancellation.Token)
                .GetAwaiter().GetResult();

            var reply = PipeCodec.ReadAsync<ProtocolMessage>(pipe, cancellation.Token)
                .GetAwaiter().GetResult();

            if (reply is null)
            {
                error = "服务没有返回 v3 响应。";
                return null;
            }

            if (string.Equals(reply.Type, "error", StringComparison.Ordinal))
            {
                error = reply.Message ?? reply.ErrorCode ?? "v3 请求失败。";
                return null;
            }

            if (reply.Data is null)
            {
                error = "v3 响应缺少 data。";
                return null;
            }

            var response = reply.Data.Value.Deserialize<ServiceResponse>(
                ServiceProtocol.JsonOptions);

            if (response is null)
            {
                error = "v3 响应 data 无法解析。";
                return null;
            }

            response.Ok = reply.Ok ?? response.Ok;
            response.Error ??= reply.Message;
            response.ErrorCode ??= reply.ErrorCode;

            return response;
        }
        catch (Exception ex)
        {
            error = $"{ex.GetType().Name}: {ex.Message}";
            return null;
        }
    }


    /// <summary>服务是否在运行（只要签名后的 status 能通就算）。</summary>
    public static bool IsRunning(TimeSpan timeout) => TryGetStatus(timeout) is not null;
}
