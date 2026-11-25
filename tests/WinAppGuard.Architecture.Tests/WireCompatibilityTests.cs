using System.Text.Json;
using WinAppGuard.Contracts;
using WinAppGuard.Contracts.Protocol;

namespace WinAppGuard.Architecture.Tests;

/// <summary>
/// 5.12：线上 JSON 省略 null，但签名规范字节必须保持 5.11.1 的形状。
/// 否则 5.12 客户端与 5.11.1 服务端会对同一帧算出不同签名。
/// </summary>
public sealed class WireCompatibilityTests
{
    [Fact]
    public void WireJsonOmitsNullFields()
    {
        var frame = new ProtocolMessage
        {
            Type = "request",
            V = ServiceProtocol.Version,
            Id = "id",
            Seq = 1,
            Command = ServiceProtocol.Commands.Status,
            Payload = JsonSerializer.SerializeToElement(
                new ServiceRequest { Command = ServiceProtocol.Commands.Status },
                ServiceProtocol.JsonOptions),
        };

        var json = JsonSerializer.Serialize(frame, ServiceProtocol.JsonOptions);

        Assert.DoesNotContain("\"serverNonce\":", json, StringComparison.Ordinal);
        Assert.DoesNotContain("\"signature\":", json, StringComparison.Ordinal);
        Assert.Contains("\"command\":\"status\"", json, StringComparison.Ordinal);
    }

    [Fact]
    public void CanonicalBytesAreStableAcrossWireRoundTrip()
    {
        var original = new ProtocolMessage
        {
            Type = "request",
            V = ServiceProtocol.Version,
            Id = "id",
            Seq = 7,
            Command = ServiceProtocol.Commands.ListRules,
            Payload = JsonSerializer.SerializeToElement(
                new ServiceRequest
                {
                    Command = ServiceProtocol.Commands.ListRules,
                    Value = "demo",
                },
                ServiceProtocol.JsonOptions),
        };

        var expected = ProtocolSigning.CanonicalBytes(original);

        var wire = JsonSerializer.SerializeToUtf8Bytes(
            original, ServiceProtocol.JsonOptions);
        var parsed = JsonSerializer.Deserialize<ProtocolMessage>(
            wire, ServiceProtocol.JsonOptions);

        Assert.NotNull(parsed);

        var actual = ProtocolSigning.CanonicalBytes(parsed!);

        Assert.Equal(expected, actual);
    }

    [Fact]
    public void OldStyleFrameWithExplicitNullsStillVerifies()
    {
        // 5.11.1 的线上帧会显式带 null；5.12 解析后必须算出相同规范字节。
        var frame = new ProtocolMessage
        {
            Type = "request",
            V = ServiceProtocol.Version,
            Id = "id",
            Seq = 1,
            Command = ServiceProtocol.Commands.Status,
            Payload = JsonSerializer.SerializeToElement(
                new ServiceRequest { Command = ServiceProtocol.Commands.Status },
                ServiceProtocol.CanonicalJsonOptions),
        };

        var expected = ProtocolSigning.CanonicalBytes(frame);
        var oldStyle = JsonSerializer.SerializeToUtf8Bytes(
            frame, ServiceProtocol.CanonicalJsonOptions);
        var parsed = JsonSerializer.Deserialize<ProtocolMessage>(
            oldStyle, ServiceProtocol.JsonOptions);

        Assert.NotNull(parsed);
        Assert.Equal(expected, ProtocolSigning.CanonicalBytes(parsed!));
    }
}
