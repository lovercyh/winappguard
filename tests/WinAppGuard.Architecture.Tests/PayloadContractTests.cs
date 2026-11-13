using System.Text.Json;
using WinAppGuard.Contracts;
using WinAppGuard.Contracts.Protocol;

namespace WinAppGuard.Architecture.Tests;

/// <summary>
/// 5.11：v4 载荷契约。每条命令都必须有明确的请求/响应类型，
/// 响应一旦被序列化就必须能按同一类型还原。
/// </summary>
public sealed class PayloadContractTests
{
    [Fact]
    public void EveryDeclaredCommandHasTypedPayloads()
    {
        foreach (var command in CommandPolicyTable.DeclaredCommands())
        {
            var requestType = PayloadCatalog.RequestTypeFor(command);
            var responseType = PayloadCatalog.ResponseTypeFor(command);

            Assert.True(
                typeof(RequestPayload).IsAssignableFrom(requestType),
                $"{command} 的请求载荷不是 RequestPayload：{requestType.Name}");

            Assert.True(
                typeof(ResponsePayload).IsAssignableFrom(responseType),
                $"{command} 的响应载荷不是 ResponsePayload：{responseType.Name}");
        }
    }

    [Theory]
    [InlineData(ServiceProtocol.Commands.Status, typeof(StatusView))]
    [InlineData(ServiceProtocol.Commands.ListRules, typeof(RulesView))]
    [InlineData(ServiceProtocol.Commands.FilterMap, typeof(FilterMapView))]
    [InlineData(ServiceProtocol.Commands.AllowTargets, typeof(AllowTargetsView))]
    [InlineData(ServiceProtocol.Commands.QueryProcessPaths, typeof(ProcessPathsView))]
    [InlineData(ServiceProtocol.Commands.QueryTraffic, typeof(TrafficView))]
    [InlineData(ServiceProtocol.Commands.ConfigureTraffic, typeof(TrafficView))]
    [InlineData(ServiceProtocol.Commands.ClearTraffic, typeof(TrafficView))]
    [InlineData(ServiceProtocol.Commands.StrictEnable, typeof(StatusView))]
    [InlineData(ServiceProtocol.Commands.AuditClear, typeof(StatusView))]
    [InlineData(ServiceProtocol.Commands.QueryIdsAlerts, typeof(QueryView))]
    [InlineData(ServiceProtocol.Commands.QueryLan, typeof(QueryView))]
    [InlineData(ServiceProtocol.Commands.IdsConfigure, typeof(QueryView))]
    [InlineData(ServiceProtocol.Commands.AddProgramRule, typeof(WriteResult))]
    public void ResponseTypeMatchesCommandFamily(string command, Type expected)
        => Assert.Equal(expected, PayloadCatalog.ResponseTypeFor(command));

    [Fact]
    public void ResponseCatalogIsClosedOverDeclaredTypes()
    {
        var known = PayloadCatalog.ResponseTypes.ToHashSet();

        foreach (var command in CommandPolicyTable.DeclaredCommands())
        {
            Assert.Contains(PayloadCatalog.ResponseTypeFor(command), known);
        }
    }

    [Fact]
    public void QueryViewRoundTripsTypedFeatureData()
    {
        var query = new QueryView
        {
            Ok = true,
            Revision = 7,
            RevisionEpoch = "epoch",
            IdsAlerts = new List<IdsAlertDto>
            {
                new() { Id = "a1", RuleId = "beaconing" },
            },
            Ipv6Routers = new List<Ipv6RouterDto>
            {
                new() { LinkLocal = "fe80::1" },
            },
            NameSources = new List<NameSourceDto>
            {
                new() { Address = "192.0.2.1" },
            },
            TrafficStartedUtc = new DateTime(2026, 1, 2, 3, 4, 5, DateTimeKind.Utc),
        };

        var element = JsonSerializer.SerializeToElement(
            query, query.GetType(), ServiceProtocol.JsonOptions);
        var back = element.Deserialize(
            PayloadCatalog.ResponseTypeFor(ServiceProtocol.Commands.QueryIdsAlerts),
            ServiceProtocol.JsonOptions) as QueryView;

        Assert.NotNull(back);
        Assert.True(back!.Ok);
        Assert.Equal(7, back.Revision);
        Assert.Equal("epoch", back.RevisionEpoch);
        Assert.Single(back.IdsAlerts!);
        Assert.Equal("a1", back.IdsAlerts![0].Id);
        Assert.Single(back.Ipv6Routers!);
        Assert.Single(back.NameSources!);
        Assert.Equal(query.TrafficStartedUtc, back.TrafficStartedUtc);
    }

    [Fact]
    public void WriteResultRoundTripsFailureMetadata()
    {
        var result = new WriteResult
        {
            Ok = false,
            Error = "规则名不存在。",
            ErrorCode = nameof(ProtocolErrorCode.InvalidArgument),
            Affected = 3,
            Message = "detail",
        };

        var element = JsonSerializer.SerializeToElement(
            result, result.GetType(), ServiceProtocol.JsonOptions);
        var back = element.Deserialize(
            PayloadCatalog.ResponseTypeFor(ServiceProtocol.Commands.DeleteRule),
            ServiceProtocol.JsonOptions) as WriteResult;

        Assert.NotNull(back);
        Assert.False(back!.Ok);
        Assert.Equal("规则名不存在。", back.Error);
        Assert.Equal(nameof(ProtocolErrorCode.InvalidArgument), back.ErrorCode);
        Assert.Equal(3, back.Affected);
        Assert.Equal("detail", back.Message);
    }

    [Fact]
    public void RequestPayloadDropsFieldsNotDeclaredForCommand()
    {
        var request = new ServiceRequest
        {
            Id = "id",
            Command = ServiceProtocol.Commands.AddProgramRule,
            Value = @"C:\demo.exe",
            Action = "block",
            TrafficPaused = true,
        };

        var type = PayloadCatalog.RequestTypeFor(ServiceProtocol.Commands.AddProgramRule);
        var element = JsonSerializer.SerializeToElement(request, ServiceProtocol.JsonOptions);
        var typed = element.Deserialize(type, ServiceProtocol.JsonOptions);
        var payload = JsonSerializer.SerializeToElement(
            typed, type, ServiceProtocol.JsonOptions);

        Assert.Equal("C:\\demo.exe", payload.GetProperty("value").GetString());
        Assert.Equal("block", payload.GetProperty("action").GetString());
        Assert.False(payload.TryGetProperty("trafficPaused", out _));
        Assert.False(payload.TryGetProperty("command", out _));
    }
}
