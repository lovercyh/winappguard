using System.Text.Json;
using WinAppGuard.Contracts;
using WinAppGuard.Contracts.Protocol;

namespace WinAppGuard.Architecture.Tests;

public sealed class ProtocolMessageTests
{
    [Fact]
    public async Task FrameRoundTripsThroughPipeCodec()
    {
        var request = new ProtocolMessage
        {
            Type = "request",
            V = ServiceProtocol.Version,
            Id = "abc",
            Seq = 7,
            Command = ServiceProtocol.Commands.Ping,
            Payload = JsonSerializer.SerializeToElement(
                new ServiceRequest { Command = ServiceProtocol.Commands.Ping },
                ServiceProtocol.JsonOptions),
        };

        using var stream = new MemoryStream();
        await PipeCodec.WriteAsync(stream, request, CancellationToken.None);
        stream.Position = 0;

        var read = await PipeCodec.ReadAsync<ProtocolMessage>(
            stream, CancellationToken.None);

        Assert.NotNull(read);
        Assert.Equal("request", read!.Type);
        Assert.Equal(7, read.Seq);
        Assert.Equal(ServiceProtocol.Commands.Ping, read.Command);
        Assert.NotNull(read.Payload);
    }

    [Fact]
    public void CanonicalBytesIgnoreSignature()
    {
        var unsigned = new ProtocolMessage
        {
            Type = "request",
            V = ServiceProtocol.Version,
            Id = "abc",
            Seq = 1,
            Command = ServiceProtocol.Commands.Ping,
            Payload = JsonSerializer.SerializeToElement(
                new ServiceRequest { Command = ServiceProtocol.Commands.Ping },
                ServiceProtocol.JsonOptions),
        };

        var canonical = ProtocolSigning.CanonicalBytes(unsigned);

        unsigned.Signature = "signature-value";

        Assert.Equal(canonical, ProtocolSigning.CanonicalBytes(unsigned));
    }

    [Fact]
    public void CanonicalBytesSurviveJsonRoundTripAndSignatureVerification()
    {
        var frame = new ProtocolMessage
        {
            Type = "request",
            V = ServiceProtocol.Version,
            Id = "abc",
            Seq = 7,
            Command = ServiceProtocol.Commands.Ping,
            Payload = JsonSerializer.SerializeToElement(
                new ServiceRequest { Command = ServiceProtocol.Commands.Ping },
                ServiceProtocol.JsonOptions),
        };

        var canonical = ProtocolSigning.CanonicalBytes(frame);
        var json = JsonSerializer.SerializeToUtf8Bytes(frame, ServiceProtocol.JsonOptions);
        var received = JsonSerializer.Deserialize<ProtocolMessage>(
            json, ServiceProtocol.JsonOptions);

        Assert.NotNull(received);

        var receivedCanonical = ProtocolSigning.CanonicalBytes(received!);

        using var key = System.Security.Cryptography.ECDsa.Create(
            System.Security.Cryptography.ECCurve.NamedCurves.nistP256);
        var signature = key.SignData(canonical, System.Security.Cryptography.HashAlgorithmName.SHA256);

        Assert.True(key.VerifyData(
            receivedCanonical,
            signature,
            System.Security.Cryptography.HashAlgorithmName.SHA256));
    }

    [Fact]
    public void ProtocolVersionIsFourAndPipeIsV4()
    {
        Assert.Equal(4, ServiceProtocol.Version);
        Assert.Equal("WinAppGuard.Control.v4", ServiceProtocol.PipeName);
    }
}
