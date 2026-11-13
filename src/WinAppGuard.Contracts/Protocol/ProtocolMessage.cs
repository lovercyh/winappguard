using System.Text.Json;

namespace WinAppGuard.Contracts.Protocol;

/// <summary>
/// 5.10：协议 v3 的单一帧模型。
///
/// 握手、认证、请求、响应都复用同一条长度前缀 JSON 帧；用 <see cref="Type"/>
/// 区分。这样不用为每种帧维护一套读写逻辑。
/// </summary>
public sealed class ProtocolMessage
{
    public string Type { get; set; } = string.Empty;

    public int V { get; set; } = ServiceProtocol.Version;

    public string? Id { get; set; }

    public long Seq { get; set; }

    public string? Command { get; set; }

    public JsonElement? Payload { get; set; }

    public string? ClientNonce { get; set; }

    public string? ServerNonce { get; set; }

    public string? SessionId { get; set; }

    public string? Signature { get; set; }

    public DateTime? ServerTimeUtc { get; set; }

    public DateTime? ExpiresUtc { get; set; }

    public string? ToolVersion { get; set; }

    public int Protocol { get; set; }

    public string[]? Capabilities { get; set; }

    public long? MaxFrameBytes { get; set; }

    public bool? Ok { get; set; }

    public string? ErrorCode { get; set; }

    public string? Message { get; set; }

    public long? Revision { get; set; }

    public JsonElement? Data { get; set; }
}

/// <summary>5.10：v3 错误码。数值只在 v3 使用，不复用 v2 的 ErrorCode 数值。</summary>
public enum ProtocolErrorCode
{
    None = 0,
    UnknownCommand = 1,
    VersionMismatch = 2,
    NotElevated = 3,
    NotOwner = 4,
    InvalidArgument = 5,
    NotFound = 6,
    Conflict = 7,
    Busy = 8,
    TooLarge = 9,
    RateLimited = 10,
    Unavailable = 11,
    Timeout = 12,
    Internal = 13,
}

/// <summary>5.10：v3 签名使用的规范字节。签名不包含 Signature 自身。</summary>
public static class ProtocolSigning
{
    public static byte[] CanonicalBytes(ProtocolMessage message)
    {
        var saved = message.Signature;
        message.Signature = null;

        try
        {
            return System.Text.Json.JsonSerializer.SerializeToUtf8Bytes(
                message, ServiceProtocol.JsonOptions);
        }
        finally
        {
            message.Signature = saved;
        }
    }
}
