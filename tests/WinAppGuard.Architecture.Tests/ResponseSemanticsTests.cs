using System.Text.Json;
using WinAppGuard.Contracts;
using WinAppGuard.Contracts.Protocol;
using WinAppGuard.Service;

namespace WinAppGuard.Architecture.Tests;

/// <summary>
/// 5.11：写命令与失败语义。响应不再有万能结果类，
/// 每条命令都必须落到具体载荷类型上，并且 Ok / Error / Affected 能原样往返。
/// </summary>
public sealed class ResponseSemanticsTests
{
    [Fact]
    public void SuccessfulPayloadDefaultsToOk()
    {
        var write = new WriteResult { Affected = 2 };

        Assert.True(write.Ok);
        Assert.Equal(2, write.Affected);
    }

    [Fact]
    public void ErrorViewRoundTripsFailureCode()
    {
        var view = new ErrorView
        {
            Ok = false,
            Error = "规则名不存在。",
            ErrorCode = nameof(ProtocolErrorCode.InvalidArgument),
        };

        var element = JsonSerializer.SerializeToElement(
            view, view.GetType(), ServiceProtocol.JsonOptions);
        var back = element.Deserialize<ErrorView>(ServiceProtocol.JsonOptions);

        Assert.NotNull(back);
        Assert.False(back!.Ok);
        Assert.Equal("规则名不存在。", back.Error);
        Assert.Equal(nameof(ProtocolErrorCode.InvalidArgument), back.ErrorCode);
    }

    [Fact]
    public void EveryResponseTypeRoundTripsEnvelopeFields()
    {
        foreach (var type in PayloadCatalog.ResponseTypes)
        {
            var payload = (ResponsePayload)Activator.CreateInstance(type)!;
            payload.Ok = false;
            payload.Error = "失败";
            payload.ErrorCode = nameof(ProtocolErrorCode.Internal);
            payload.Affected = 5;
            payload.Revision = 9;
            payload.RevisionEpoch = "epoch";

            var element = JsonSerializer.SerializeToElement(
                payload, type, ServiceProtocol.JsonOptions);
            var back = element.Deserialize(type, ServiceProtocol.JsonOptions)
                as ResponsePayload;

            Assert.NotNull(back);
            Assert.Equal(type, back!.GetType());
            Assert.False(back.Ok);
            Assert.Equal("失败", back.Error);
            Assert.Equal(nameof(ProtocolErrorCode.Internal), back.ErrorCode);
            Assert.Equal(5, back.Affected);
            Assert.Equal(9, back.Revision);
            Assert.Equal("epoch", back.RevisionEpoch);
        }
    }

    [Fact]
    public void EveryCommandMapsToConcreteResponsePayload()
    {
        foreach (var command in CommandPolicyTable.DeclaredCommands())
        {
            var type = PayloadCatalog.ResponseTypeFor(command);

            Assert.False(type.IsAbstract, command);
            Assert.NotEqual(typeof(ErrorView), type);
            Assert.True(
                typeof(ResponsePayload).IsAssignableFrom(type),
                command);
        }
    }

    [Fact]
    public void ClientRefusesToSendWithoutSigner()
    {
        var previous = ServiceClient.CurrentSigner;

        try
        {
            ServiceClient.SetSigner(null);

            var response = ServiceClient.TryRequest(
                new ServiceRequest { Command = ServiceProtocol.Commands.Status },
                TimeSpan.FromSeconds(1),
                out var error);

            Assert.Null(response);
            Assert.NotNull(error);
            Assert.Contains("签名密钥", error, StringComparison.Ordinal);
        }
        finally
        {
            ServiceClient.SetSigner(previous);
        }
    }

    [Fact]
    public void WriteCommandsDoNotExposeFeatureCollections()
    {
        // 写命令只带 Affected / Message，不再回传整套检测数据。
        var properties = typeof(WriteResult)
            .GetProperties()
            .Select(property => property.Name)
            .ToHashSet(StringComparer.Ordinal);

        Assert.Contains(nameof(WriteResult.Affected), properties);
        Assert.DoesNotContain("IdsAlerts", properties);
        Assert.DoesNotContain("NetworkAlerts", properties);
        Assert.DoesNotContain("AntiScanEvents", properties);
        Assert.DoesNotContain("LanEvents", properties);
        Assert.DoesNotContain("Ipv6Routers", properties);
        Assert.DoesNotContain("ConfigItems", properties);
        Assert.DoesNotContain("NameSources", properties);
        Assert.DoesNotContain("DnsRecords", properties);
        Assert.DoesNotContain("Traffic", properties);
    }
}
