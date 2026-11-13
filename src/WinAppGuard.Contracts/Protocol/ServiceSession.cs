using System.IO.Pipes;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace WinAppGuard.Contracts.Protocol;

/// <summary>
/// 5.11：单连接会话。首次请求完成握手，后续请求复用同一管道。
///
/// 每个线程保留一个会话；连接失效时自动重连一次。
/// 不共享跨线程连接，避免 UI 线程和后台刷新互相阻塞。
/// </summary>
internal sealed class ServiceSession : IDisposable
{
    private static readonly TimeSpan SessionLifetime = TimeSpan.FromMinutes(4);

    [ThreadStatic]
    private static ServiceSession? _current;

    private readonly IServiceSigner _signer;
    private NamedPipeClientStream? _pipe;
    private string? _serverNonce;
    private long _seq;
    private DateTime _expiresUtc;

    private ServiceSession(IServiceSigner signer)
    {
        _signer = signer;
    }

    internal static ServiceResponse? TryRequest(
        ServiceRequest request,
        TimeSpan timeout,
        IServiceSigner signer,
        out string? error)
    {
        error = null;
        var session = _current;

        if (session is null
            || session._pipe is null
            || !session._pipe.IsConnected
            || DateTime.UtcNow >= session._expiresUtc)
        {
            session?.Dispose();
            session = new ServiceSession(signer);
            _current = session;

            if (!session.Connect(timeout, out error))
            {
                session.Dispose();
                _current = null;
                return null;
            }
        }

        var response = session.Send(request, timeout, out error);

        if (response is not null)
        {
            return response;
        }

        // 连接可能已被服务端关闭：重连一次再试。
        session.Dispose();
        _current = null;
        var retry = new ServiceSession(signer);

        if (!retry.Connect(timeout, out error))
        {
            retry.Dispose();
            return null;
        }

        _current = retry;
        response = retry.Send(request, timeout, out error);

        if (response is null)
        {
            retry.Dispose();
            _current = null;
        }

        return response;
    }

    private bool Connect(TimeSpan timeout, out string? error)
    {
        error = null;

        try
        {
            using var cancellation = new CancellationTokenSource(timeout);
            _pipe = new NamedPipeClientStream(
                ".", ServiceProtocol.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);
            _pipe.Connect((int)Math.Max(1, Math.Min(250, timeout.TotalMilliseconds)));

            if (!ServerIdentity.IsExpectedServer(
                    _pipe.SafePipeHandle.DangerousGetHandle(), out var identityError))
            {
                error = $"检测到异常的服务端：{identityError}";
                return false;
            }

            var clientNonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));

            PipeCodec.WriteAsync(_pipe, new ProtocolMessage
            {
                Type = "hello",
                V = ServiceProtocol.Version,
                ClientNonce = clientNonce,
            }, cancellation.Token).GetAwaiter().GetResult();

            var challenge = PipeCodec.ReadAsync<ProtocolMessage>(_pipe, cancellation.Token)
                .GetAwaiter().GetResult();

            if (challenge is null
                || !string.Equals(challenge.Type, "challenge", StringComparison.Ordinal)
                || string.IsNullOrWhiteSpace(challenge.ServerNonce)
                || string.IsNullOrWhiteSpace(challenge.SessionId))
            {
                error = $"v4 握手失败：{challenge?.Message ?? "服务没有返回 challenge"}";
                return false;
            }

            var authBytes = Encoding.UTF8.GetBytes(
                $"{challenge.ServerNonce}|{clientNonce}|{challenge.SessionId}");

            PipeCodec.WriteAsync(_pipe, new ProtocolMessage
            {
                Type = "auth",
                V = ServiceProtocol.Version,
                SessionId = challenge.SessionId,
                Signature = Convert.ToBase64String(_signer.Sign(authBytes)),
            }, cancellation.Token).GetAwaiter().GetResult();

            var welcome = PipeCodec.ReadAsync<ProtocolMessage>(_pipe, cancellation.Token)
                .GetAwaiter().GetResult();

            if (welcome is null
                || !string.Equals(welcome.Type, "welcome", StringComparison.Ordinal))
            {
                error = $"v4 认证失败：{welcome?.Message ?? "服务没有返回 welcome"}";
                return false;
            }

            _serverNonce = challenge.ServerNonce;
            _seq = 0;
            _expiresUtc = DateTime.UtcNow + SessionLifetime;
            return true;
        }
        catch (Exception ex)
        {
            error = $"{ex.GetType().Name}: {ex.Message}";
            return false;
        }
    }

    private ServiceResponse? Send(
        ServiceRequest request,
        TimeSpan timeout,
        out string? error)
    {
        error = null;

        if (_pipe is null || _serverNonce is null)
        {
            error = "会话没有连接。";
            return null;
        }

        try
        {
            using var cancellation = new CancellationTokenSource(timeout);
            var frame = new ProtocolMessage
            {
                Type = "request",
                V = ServiceProtocol.Version,
                Id = request.Id,
                Seq = ++_seq,
                Command = request.Command,
                Payload = LegacyPayloadAdapter.CreateRequestPayload(
                    request.Command, request),
            };

            var canonical = ProtocolSigning.CanonicalBytes(frame);
            var nonceBytes = Encoding.UTF8.GetBytes(_serverNonce);
            var signed = new byte[nonceBytes.Length + canonical.Length];
            Buffer.BlockCopy(nonceBytes, 0, signed, 0, nonceBytes.Length);
            Buffer.BlockCopy(canonical, 0, signed, nonceBytes.Length, canonical.Length);
            frame.Signature = Convert.ToBase64String(_signer.Sign(signed));

            PipeCodec.WriteAsync(_pipe, frame, cancellation.Token)
                .GetAwaiter().GetResult();

            var reply = PipeCodec.ReadAsync<ProtocolMessage>(_pipe, cancellation.Token)
                .GetAwaiter().GetResult();

            if (reply is null)
            {
                error = "服务没有返回 v4 响应。";
                return null;
            }

            if (string.Equals(reply.Type, "error", StringComparison.Ordinal))
            {
                error = reply.Message ?? reply.ErrorCode ?? "v4 请求失败。";
                return null;
            }

            if (reply.Data is null)
            {
                error = "v4 响应缺少 data。";
                return null;
            }

            var response = LegacyPayloadAdapter.ToResponse(reply.Data.Value);
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

    public void Dispose()
    {
        try
        {
            _pipe?.Dispose();
        }
        catch (Exception)
        {
            // 忽略关闭异常。
        }

        _pipe = null;
        _serverNonce = null;
    }
}
