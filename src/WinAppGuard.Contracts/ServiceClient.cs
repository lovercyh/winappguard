using System.IO.Pipes;
using System.Text.Json;

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
        error = null;

        var signer = Volatile.Read(ref _signer);

        if (signer is null)
        {
            error = "未配置签名密钥（当前账户不是所有者，或密钥不可用）。";
            return null;
        }

        try
        {
            using var cancellation = new CancellationTokenSource(timeout);
            using var pipe = new NamedPipeClientStream(
                ".", ServiceProtocol.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);

            pipe.Connect((int)Math.Max(1, timeout.TotalMilliseconds));

            // 1) 取 nonce（只有这条免签）。
            var challenge = new ServiceRequest
            {
                Command = ServiceProtocol.Commands.AuthChallenge,
            };

            PipeCodec.WriteAsync(pipe, challenge, cancellation.Token)
                .GetAwaiter().GetResult();

            var challengeResponse = PipeCodec
                .ReadAsync<ServiceResponse>(pipe, cancellation.Token)
                .GetAwaiter().GetResult();

            if (challengeResponse is not { Ok: true }
                || string.IsNullOrWhiteSpace(challengeResponse.Nonce))
            {
                error = $"认证挑战失败：{challengeResponse?.Error ?? "服务没有返回 nonce"}";
                return null;
            }

            byte[] nonce;

            try
            {
                nonce = Convert.FromBase64String(challengeResponse.Nonce);
            }
            catch (FormatException)
            {
                error = "服务返回的 nonce 不是合法 Base64。";
                return null;
            }

            if (nonce.Length != 32)
            {
                error = $"服务返回的 nonce 长度是 {nonce.Length}，期望 32。";
                return null;
            }

            // 2) 对 nonce || 原始请求字节签名，再发签名封套。
            var payload = JsonSerializer.SerializeToUtf8Bytes(
                request, ServiceProtocol.JsonOptions);

            var signed = new byte[nonce.Length + payload.Length];
            Buffer.BlockCopy(nonce, 0, signed, 0, nonce.Length);
            Buffer.BlockCopy(payload, 0, signed, nonce.Length, payload.Length);

            var signature = signer.Sign(signed);

            PipeCodec.WriteSignedAsync(
                    pipe, signature, payload, cancellation.Token)
                .GetAwaiter().GetResult();

            return PipeCodec.ReadAsync<ServiceResponse>(pipe, cancellation.Token)
                .GetAwaiter().GetResult();
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
