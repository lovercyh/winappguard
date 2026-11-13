using WinAppGuard.Contracts;
using WinAppGuard.Contracts.Protocol;

namespace WinAppGuard.Architecture.Tests;

public sealed class PayloadCatalogTests
{
    [Fact]
    public void EveryDeclaredCommandHasRequestAndResponsePayload()
    {
        var commands = CommandPolicyTable.DeclaredCommands();

        Assert.NotEmpty(commands);

        foreach (var command in commands)
        {
            var request = PayloadCatalog.RequestTypeFor(command);
            var response = PayloadCatalog.ResponseTypeFor(command);

            Assert.True(typeof(RequestPayload).IsAssignableFrom(request));
            Assert.True(typeof(ResponsePayload).IsAssignableFrom(response));
        }
    }

    [Fact]
    public void CatalogHasTwentyTwoRequestAndNineResponseTypes()
    {
        Assert.Equal(22, PayloadCatalog.RequestTypes.Count);
        Assert.Equal(9, PayloadCatalog.ResponseTypes.Count);
        Assert.Equal(
            22,
            PayloadCatalog.RequestTypes.Distinct().Count());
        Assert.Equal(
            9,
            PayloadCatalog.ResponseTypes.Distinct().Count());
    }

    [Fact]
    public void UnknownCommandIsNotMappedToReadPayload()
    {
        Assert.Throws<InvalidOperationException>(
            () => PayloadCatalog.RequestTypeFor("not.a.real.command"));
    }
}
