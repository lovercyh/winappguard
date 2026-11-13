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

    /// <summary>
    /// 发一条 v4 请求并返回**强类型**响应载荷；失败返回 null 并通过
    /// <paramref name="error"/> 给出原因。连接失效时重连一次。
    /// </summary>
    internal static ResponsePayload? TrySend(
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

        var payload = session.Send(request, timeout, out error, out var retryable);

        if (payload is not null)
        {
            return payload;
        }

        // 只有传输层失败才重试；服务端已经给出业务响应时不能重放写命令。
        if (!retryable)
        {
            return null;
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
        payload = retry.Send(request, timeout, out error, out _);

        if (payload is null)
        {
            retry.Dispose();
            _current = null;
        }

        return payload;
    }

    private bool Connect(TimeSpan timeout, out string? error)
    {
        error = null;

        try
        {
            using var cancellation = new CancellationTokenSource(timeout);
            _pipe = new NamedPipeClientStream(
                ".", ServiceProtocol.PipeName, PipeDirection.InOut, PipeOptions.Asynchronous);

            try
            {
                _pipe.Connect((int)Math.Max(1, Math.Min(1000, timeout.TotalMilliseconds)));
            }
            catch (Exception ex) when (ex is TimeoutException or IOException or UnauthorizedAccessException)
            {
                // v4 管道不存在时，区分“服务没装/没启动”和“旧版 v3 服务还在跑”。
                // 后者是 5.11 硬切换后的常见现场：界面已经升级，服务还没有。
                error = LegacyServicePresent()
                    ? $"检测到旧版防护服务（{ServiceProtocol.LegacyPipeName}）。"
                      + "当前界面是 5.11 / 协议 v4，请以管理员身份运行 "
                      + "WinAppGuardSetup.exe --install 升级服务。"
                    : $"{ex.GetType().Name}: {ex.Message}";
                return false;
            }

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

    private static readonly object LegacyGate = new();
    private static DateTime _legacyCheckedUtc = DateTime.MinValue;
    private static bool _legacyPresent;

    /// <summary>
    /// 本机是否还有 5.10/v3 的控制管道。
    ///
    /// 结果缓存 10 秒：状态刷新很频繁，不能每次都去碰旧服务的管道。
    /// 优先枚举 <c>\\.\pipe\</c>；枚举被拒绝时才做一次短连接探测（不发送任何帧）。
    /// </summary>
    private static bool LegacyServicePresent()
    {
        lock (LegacyGate)
        {
            if (DateTime.UtcNow - _legacyCheckedUtc < TimeSpan.FromSeconds(10))
            {
                return _legacyPresent;
            }

            _legacyCheckedUtc = DateTime.UtcNow;
            _legacyPresent = DetectLegacyService();
            return _legacyPresent;
        }
    }

    private static bool DetectLegacyService()
    {
        try
        {
            return Directory
                .GetFiles(@"\\.\pipe\")
                .Any(path => path.EndsWith(
                    ServiceProtocol.LegacyPipeName, StringComparison.OrdinalIgnoreCase));
        }
        catch (Exception)
        {
            // 有些环境不允许枚举管道目录，退回一次短连接。
        }

        try
        {
            using var probe = new NamedPipeClientStream(
                ".", ServiceProtocol.LegacyPipeName,
                PipeDirection.InOut, PipeOptions.None);
            probe.Connect(80);
            return true;
        }
        catch (Exception)
        {
            return false;
        }
    }

    private ResponsePayload? Send(
        ServiceRequest request,
        TimeSpan timeout,
        out string? error,
        out bool retryable)
    {
        error = null;
        retryable = false;

        if (_pipe is null || _serverNonce is null)
        {
            error = "会话没有连接。";
            retryable = true;
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
                Payload = CreateRequestPayload(request.Command, request),
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
                retryable = true;
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

            var type = PayloadCatalog.ResponseTypeFor(request.Command);
            var payload = reply.Data.Value.Deserialize(type, ServiceProtocol.JsonOptions)
                as ResponsePayload;

            if (payload is null)
            {
                error = $"v4 响应载荷不是 {type.Name}。";
                return null;
            }

            if (reply.Ok is { } ok)
            {
                payload.Ok = ok;
            }

            payload.Error ??= reply.Message;
            payload.ErrorCode ??= reply.ErrorCode;

            if (reply.Revision is { } revision)
            {
                payload.Revision = revision;
            }

            return payload;
        }
        catch (Exception ex)
        {
            error = $"{ex.GetType().Name}: {ex.Message}";
            retryable = true;
            return null;
        }
    }

    /// <summary>
    /// 把请求收敛成该命令声明的 v4 请求载荷；未知字段不会上线。
    /// </summary>
    private static JsonElement CreateRequestPayload(string command, ServiceRequest request)
    {
        var type = PayloadCatalog.RequestTypeFor(command);
        var element = JsonSerializer.SerializeToElement(request, ServiceProtocol.JsonOptions);
        var typed = element.Deserialize(type, ServiceProtocol.JsonOptions);

        return JsonSerializer.SerializeToElement(
            typed, type, ServiceProtocol.JsonOptions);
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
