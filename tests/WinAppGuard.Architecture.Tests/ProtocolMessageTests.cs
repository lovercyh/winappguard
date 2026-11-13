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
    public void ProtocolVersionIsThreeAndPipeIsV3()
    {
        Assert.Equal(3, ServiceProtocol.Version);
        Assert.Equal("WinAppGuard.Control.v3", ServiceProtocol.PipeName);
    }
}
