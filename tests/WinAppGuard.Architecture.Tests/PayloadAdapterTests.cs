using System.Text.Json;
using WinAppGuard.Contracts;
using WinAppGuard.Contracts.Protocol;

namespace WinAppGuard.Architecture.Tests;

public sealed class PayloadAdapterTests
{
    [Fact]
    public void EveryCommandSurvivesRequestAndResponseAdapter()
    {
        foreach (var command in CommandPolicyTable.DeclaredCommands())
        {
            var request = new ServiceRequest
            {
                Id = "id",
                Command = command,
            };

            var payload = LegacyPayloadAdapter.CreateRequestPayload(command, request);
            var back = LegacyPayloadAdapter.ToRequest(command, "id", payload);

            Assert.Equal(command, back.Command);
            Assert.Equal("id", back.Id);
            Assert.Equal(ServiceProtocol.Version, back.ProtocolVersion);

            var response = new ServiceResponse
            {
                Id = "id",
                Ok = true,
                Affected = 1,
                Status = new ServiceStatus
                {
                    ServiceVersion = "test",
                    ProtocolVersion = ServiceProtocol.Version,
                },
            };

            var typed = LegacyPayloadAdapter.CreateResponse(
                command, response, 1, "epoch");
            var element = JsonSerializer.SerializeToElement(
                typed, typed.GetType(), ServiceProtocol.JsonOptions);
            var legacy = LegacyPayloadAdapter.ToResponse(element);

            Assert.True(legacy.Ok, command);
            Assert.Equal("id", legacy.Id);
        }
    }
}
