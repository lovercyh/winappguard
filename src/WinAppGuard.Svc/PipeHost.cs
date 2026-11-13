using System.IO.Pipes;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using WinAppGuard.Contracts;
using WinAppGuard.Contracts.Protocol;
using WinAppGuard.Core;
using WinAppGuard.Core.ProtectedMode;

namespace WinAppGuard.Service;

/// <summary>
/// 5.11：控制管道监听与 v4 会话循环。
///
/// 只负责“连接、握手、逐帧验签、把请求交给 <see cref="ControlServer"/>”；
/// 命令分发、状态构建和规则处理仍在 ControlServer，避免这层变成第二个业务中心。
/// </summary>
internal sealed class PipeHost : IDisposable
{
    private readonly CancellationTokenSource _cancellation = new();
    private Thread? _thread;
    private bool _loggedReady;

    internal bool IsListening => _thread is { IsAlive: true };

    internal void Start()
    {
        if (ControlServer.CurrentProtectedMode is null || ControlServer.HasRouter is false)
        {
            throw new InvalidOperationException(
                "受保护模式或命令目录不可用，控制管道已禁用。");
        }

        _thread = new Thread(Loop)
        {
            IsBackground = true,
            Name = "ipc-server",
        };

        _thread.Start();
    }

    internal void Stop()
    {
        try
        {
            _cancellation.Cancel();
        }
        catch (ObjectDisposedException)
        {
            return;
        }

        _thread?.Join(3000);
        _thread = null;
    }

    public void Dispose()
    {
        Stop();

        try
        {
            _cancellation.Dispose();
        }
        catch (ObjectDisposedException)
        {
            // 已释放。
        }
    }

    private void Loop()
    {
        while (!_cancellation.IsCancellationRequested)
        {
            try
            {
                // 用 NamedPipeServerStreamAcl.Create：安全描述符在**创建时**就生效，
                // 不存在"先建默认管道再收紧"的竞态；也不需要手工 SetSecurityInfo
                // （后者在非管理员下会直接 ACCESS_DENIED，实测）。
                using var pipe = CreateOwnerOnlyPipe();

                if (!_loggedReady)
                {
                    _loggedReady = true;
                    ServiceLog.Info("WAG-IPC-002", "Named pipe created (ACL: SYSTEM + owner only).");
                }

                pipe.WaitForConnectionAsync(_cancellation.Token).GetAwaiter().GetResult();

                if (_cancellation.IsCancellationRequested)
                {
                    break;
                }

                HandleClient(pipe, _cancellation.Token);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (ObjectDisposedException)
            {
                break;
            }
            catch (Exception ex)
            {
                ServiceLog.Error("WAG-IPC-003", "IPC connection handling failed.", ex);
                Thread.Sleep(200);
            }
        }
    }

    private void HandleClient(NamedPipeServerStream pipe, CancellationToken serverToken)
    {
        var protectedMode = ControlServer.CurrentProtectedMode;

        if (protectedMode is null)
        {
            return;
        }

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(serverToken);
        timeout.CancelAfter(TimeSpan.FromSeconds(5));

        if (!ClientAuth.TryGetElevation(
                pipe, out var elevated, out var clientPid,
                out var clientSid, out var clientPath, out var reason))
        {
            ServiceLog.Warning("WAG-IPC-004", $"Rejected IPC connection (pid={clientPid}); client identity could not be verified.");
            TryWrite(pipe, new ProtocolMessage
            {
                Type = "error",
                V = ServiceProtocol.Version,
                Ok = false,
                ErrorCode = nameof(ProtocolErrorCode.NotOwner),
                Message = reason,
            }, timeout.Token);
            return;
        }

        ProtocolMessage? hello;

        try
        {
            hello = PipeCodec.ReadAsync<ProtocolMessage>(pipe, timeout.Token)
                .GetAwaiter().GetResult();
        }
        catch (OperationCanceledException)
        {
            ServiceLog.Warning("WAG-IPC-005", "IPC v4 hello timed out.");
            return;
        }
        catch (Exception ex)
        {
            ServiceLog.Warning("WAG-IPC-006", "IPC v4 hello was malformed.", ex);
            return;
        }

        if (hello is null
            || !string.Equals(hello.Type, "hello", StringComparison.Ordinal)
            || string.IsNullOrWhiteSpace(hello.ClientNonce))
        {
            RejectProtocol(pipe, timeout.Token, ProtocolErrorCode.VersionMismatch, "协议握手无效。");
            return;
        }

        if (hello.V != ServiceProtocol.Version)
        {
            RejectProtocol(pipe, timeout.Token, ProtocolErrorCode.VersionMismatch, "协议版本不匹配。");
            return;
        }

        var serverNonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
        var sessionId = Guid.NewGuid().ToString("N");
        var capacities = new[] { "v4", "modules", "revision" };

        TryWrite(pipe, new ProtocolMessage
        {
            Type = "challenge",
            V = ServiceProtocol.Version,
            SessionId = sessionId,
            ServerNonce = serverNonce,
            ServerTimeUtc = DateTime.UtcNow,
            ToolVersion = ControlServer.VersionText,
            Protocol = ServiceProtocol.Version,
            Capabilities = capacities,
            MaxFrameBytes = ServiceProtocol.MaxMessageBytes,
        }, timeout.Token);

        ProtocolMessage? auth;

        try
        {
            auth = PipeCodec.ReadAsync<ProtocolMessage>(pipe, timeout.Token)
                .GetAwaiter().GetResult();
        }
        catch (OperationCanceledException)
        {
            ServiceLog.Warning("WAG-IPC-008", "IPC v4 auth timed out.");
            return;
        }
        catch (Exception ex)
        {
            ServiceLog.Warning("WAG-IPC-009", "IPC v4 auth was malformed.", ex);
            return;
        }

        if (auth is null
            || !string.Equals(auth.Type, "auth", StringComparison.Ordinal)
            || !string.Equals(auth.SessionId, sessionId, StringComparison.Ordinal)
            || string.IsNullOrWhiteSpace(auth.Signature))
        {
            RejectProtocol(pipe, timeout.Token, ProtocolErrorCode.NotOwner, "认证失败。");
            return;
        }

        var authBytes = Encoding.UTF8.GetBytes(
            $"{serverNonce}|{hello.ClientNonce}|{sessionId}");

        byte[] authSignature;

        try
        {
            authSignature = Convert.FromBase64String(auth.Signature);
        }
        catch (FormatException)
        {
            RejectProtocol(pipe, timeout.Token, ProtocolErrorCode.NotOwner, "认证失败。");
            return;
        }

        if (!OwnerKey.Verify(
                protectedMode.GetPublicKeyBytes(), authBytes, authSignature))
        {
            var rejected = ControlServer.RecordAuthRejection();
            ServiceLog.Warning(
                "WAG-AUTH-003",
                $"Rejected IPC v4 auth: invalid signature (pid={clientPid}, sid={clientSid ?? "?"}, path={clientPath ?? "?"}, total rejected={rejected}).");
            RejectProtocol(pipe, timeout.Token, ProtocolErrorCode.NotOwner, "认证失败。");
            return;
        }

        TryWrite(pipe, new ProtocolMessage
        {
            Type = "welcome",
            V = ServiceProtocol.Version,
            SessionId = sessionId,
            ExpiresUtc = DateTime.UtcNow.AddMinutes(5),
            Protocol = ServiceProtocol.Version,
        }, timeout.Token);

        timeout.CancelAfter(TimeSpan.FromSeconds(30));

        var expectedSeq = 1L;
        var sessionExpiresUtc = DateTime.UtcNow.AddMinutes(5);
        var nonceBytes = Encoding.UTF8.GetBytes(serverNonce);
        var rateWindowStartUtc = DateTime.UtcNow;
        var requestCountInWindow = 0;

        while (!serverToken.IsCancellationRequested)
        {
            timeout.CancelAfter(TimeSpan.FromSeconds(30));
            var now = DateTime.UtcNow;

            if (now - rateWindowStartUtc >= TimeSpan.FromSeconds(1))
            {
                rateWindowStartUtc = now;
                requestCountInWindow = 0;
            }

            if (++requestCountInWindow > 50)
            {
                RejectProtocol(pipe, timeout.Token, ProtocolErrorCode.RateLimited, "请求过于频繁。");
                break;
            }

            ProtocolMessage? frame;

            try
            {
                frame = PipeCodec.ReadAsync<ProtocolMessage>(pipe, timeout.Token)
                    .GetAwaiter().GetResult();
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                ServiceLog.Warning("WAG-IPC-010", "IPC v4 request was malformed.", ex);
                break;
            }

            if (frame is null)
            {
                break;
            }

            if (!string.Equals(frame.Type, "request", StringComparison.Ordinal)
                || frame.Seq != expectedSeq
                || string.IsNullOrWhiteSpace(frame.Command)
                || frame.Payload is null)
            {
                RejectProtocol(pipe, timeout.Token, ProtocolErrorCode.InvalidArgument, "请求帧无效。");
                break;
            }

            if (DateTime.UtcNow > sessionExpiresUtc)
            {
                RejectProtocol(pipe, timeout.Token, ProtocolErrorCode.Timeout, "会话已过期。");
                break;
            }

            if (string.IsNullOrWhiteSpace(frame.Signature))
            {
                RejectProtocol(pipe, timeout.Token, ProtocolErrorCode.NotOwner, "请求缺少签名。");
                break;
            }

            var canonical = ProtocolSigning.CanonicalBytes(frame);
            var signed = new byte[nonceBytes.Length + canonical.Length];
            Buffer.BlockCopy(nonceBytes, 0, signed, 0, nonceBytes.Length);
            Buffer.BlockCopy(canonical, 0, signed, nonceBytes.Length, canonical.Length);

            byte[] requestSignature;

            try
            {
                requestSignature = Convert.FromBase64String(frame.Signature);
            }
            catch (FormatException)
            {
                RejectProtocol(pipe, timeout.Token, ProtocolErrorCode.NotOwner, "请求签名无效。");
                break;
            }

            if (!OwnerKey.Verify(
                    protectedMode.GetPublicKeyBytes(), signed, requestSignature))
            {
                RejectProtocol(pipe, timeout.Token, ProtocolErrorCode.NotOwner, "请求签名无效。");
                break;
            }

            ServiceRequest request;

            try
            {
                request = frame.Payload.Value.Deserialize<ServiceRequest>(
                    ServiceProtocol.JsonOptions) ?? new ServiceRequest();
            }
            catch (Exception ex)
            {
                ServiceLog.Warning("WAG-IPC-011", "IPC v4 request payload was invalid.", ex);
                RejectProtocol(pipe, timeout.Token, ProtocolErrorCode.InvalidArgument, "请求载荷无效。");
                break;
            }

            request.Id = frame.Id ?? request.Id;
            request.Command = frame.Command;
            request.ProtocolVersion = ServiceProtocol.Version;

            if (request.Command.StartsWith("write.", StringComparison.OrdinalIgnoreCase))
            {
                ServiceLog.Operation(
                    "WAG-IPC-012",
                    $"IPC v4 write operation: pid={clientPid}, sid={clientSid ?? "?"}, path={clientPath ?? "?"}, command={request.Command}.");
            }

            var response = ControlServer.DispatchRequest(request, elevated, clientPid);
            response.Revision = ControlServer.RuleRevision;
            response.RevisionEpoch = ControlServer.RuleRevisionEpoch;

            TryWrite(pipe, new ProtocolMessage
            {
                Type = "response",
                V = ServiceProtocol.Version,
                Seq = frame.Seq,
                Ok = response.Ok,
                ErrorCode = response.ErrorCode
                    ?? (response.Ok ? nameof(ProtocolErrorCode.None) : nameof(ProtocolErrorCode.Internal)),
                Message = response.Error,
                Revision = ControlServer.RuleRevision,
                Data = JsonSerializer.SerializeToElement(
                    response,
                    response.GetType(),
                    ServiceProtocol.JsonOptions),
            }, timeout.Token);

            expectedSeq++;
        }
    }

    private static void RejectProtocol(
        NamedPipeServerStream pipe,
        CancellationToken token,
        ProtocolErrorCode code,
        string message)
    {
        TryWrite(pipe, new ProtocolMessage
        {
            Type = "error",
            V = ServiceProtocol.Version,
            Ok = false,
            ErrorCode = code.ToString(),
            Message = message,
        }, token);
    }

    private static void TryWrite<T>(
        NamedPipeServerStream pipe, T response, CancellationToken token)
    {
        try
        {
            PipeCodec.WriteAsync(pipe, response, token).GetAwaiter().GetResult();
        }
        catch (Exception ex)
        {
            ServiceLog.Warning("WAG-IPC-015", "Failed to write the IPC response.", ex);
        }
    }

    /// <summary>
    /// 创建一条只有 SYSTEM 与**所有者 SID** 能连接的命名管道。
    /// 安全描述符在建管道时生效，避免"先建后收紧"的窗口。
    /// </summary>
    private static NamedPipeServerStream CreateOwnerOnlyPipe()
    {
        var protectedMode = ControlServer.CurrentProtectedMode
            ?? throw new InvalidOperationException("受保护模式不可用。");

        var security = new PipeSecurity();

        security.AddAccessRule(new PipeAccessRule(
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
            PipeAccessRights.FullControl,
            AccessControlType.Allow));

        security.AddAccessRule(new PipeAccessRule(
            protectedMode.GetOwnerSid(),
            PipeAccessRights.FullControl,
            AccessControlType.Allow));

        return NamedPipeServerStreamAcl.Create(
            ServiceProtocol.PipeName,
            PipeDirection.InOut,
            maxNumberOfServerInstances: 4,
            PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous,
            inBufferSize: 0,
            outBufferSize: 0,
            pipeSecurity: security);
    }
}
