using WinAppGuard.Contracts;
using WinAppGuard.Service;

namespace WinAppGuard.Architecture.Tests;

public sealed class CommandRouterTests
{
    [Fact]
    public void ServiceCatalogRegistersEveryDeclaredCommandExactlyOnce()
    {
        var router = ServiceCatalog.CreateRouter();
        var declared = CommandPolicyTable.DeclaredCommands();

        Assert.Equal(declared.Count, router.Handlers.Count);
        Assert.Equal(
            declared.OrderBy(command => command, StringComparer.Ordinal),
            router.Handlers
                .Select(handler => handler.Command)
                .OrderBy(command => command, StringComparer.Ordinal));
    }

    [Fact]
    public void ServiceCatalogHandlersHaveModuleAndPolicy()
    {
        var router = ServiceCatalog.CreateRouter();

        foreach (var handler in router.Handlers)
        {
            Assert.False(string.IsNullOrWhiteSpace(handler.Module));
            Assert.True(CommandPolicyTable.TryGet(handler.Command, out _));
        }
    }

    [Fact]
    public void ServiceCatalogKeepsNewProgramGuardInItsOwnModuleAndPolicy()
    {
        var router = ServiceCatalog.CreateRouter();

        var guardHandlers = router.Handlers
            .Where(handler => CommandPolicyTable.Get(handler.Command) == CommandPolicy.OwnerTemporaryWfp)
            .ToList();

        Assert.Equal(2, guardHandlers.Count);
        Assert.All(guardHandlers, handler => Assert.Equal("new-program-guard", handler.Module));
    }

    [Fact]
    public void ServiceCatalogGroupsCommandsByFeature()
    {
        var router = ServiceCatalog.CreateRouter();

        Assert.Equal("ids", ModuleOf(router, ServiceProtocol.Commands.QueryIdsAlerts));
        Assert.Equal("ids", ModuleOf(router, ServiceProtocol.Commands.AlertIdsAck));
        Assert.Equal("network-detection", ModuleOf(router, ServiceProtocol.Commands.QueryNetworkDetection));
        Assert.Equal("lan", ModuleOf(router, ServiceProtocol.Commands.QueryLan));
        Assert.Equal("lan", ModuleOf(router, ServiceProtocol.Commands.QueryNameResolution));
        Assert.Equal("rules", ModuleOf(router, ServiceProtocol.Commands.ListRules));
        Assert.Equal("system", ModuleOf(router, ServiceProtocol.Commands.Status));
    }

    [Fact]
    public void DuplicateRegistrationFails()
    {
        var router = new CommandRouter();
        router.Register(new DelegateCommandHandler(
            ServiceProtocol.Commands.Ping,
            "one",
            context => new ActionResult { Id = context.Request.Id }));

        var error = Assert.Throws<InvalidOperationException>(() =>
            router.Register(new DelegateCommandHandler(
                ServiceProtocol.Commands.Ping,
                "two",
                context => new ActionResult { Id = context.Request.Id })));

        Assert.Contains(ServiceProtocol.Commands.Ping, error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void MissingRegistrationFailsValidation()
    {
        var missing = ServiceProtocol.Commands.QueryIdsAlerts;
        var router = new CommandRouter();

        foreach (var command in CommandPolicyTable.DeclaredCommands().Where(command => command != missing))
        {
            router.Register(new DelegateCommandHandler(
                command,
                "test",
                context => new ActionResult { Id = context.Request.Id }));
        }

        var error = Assert.Throws<InvalidOperationException>(router.Validate);

        Assert.Contains(missing, error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void UndeclaredRegistrationFailsValidation()
    {
        var router = new CommandRouter();

        foreach (var command in CommandPolicyTable.DeclaredCommands())
        {
            router.Register(new DelegateCommandHandler(
                command,
                "test",
                context => new ActionResult { Id = context.Request.Id }));
        }

        router.Register(new DelegateCommandHandler(
            "write.not-declared",
            "test",
            context => new ActionResult { Id = context.Request.Id }));

        var error = Assert.Throws<InvalidOperationException>(router.Validate);

        Assert.Contains("write.not-declared", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void UnknownCommandIsNotDispatched()
    {
        var router = new CommandRouter();

        var response = router.Dispatch(new CommandContext(
            new ServiceRequest { Id = "1", Command = "not.a.real.command" },
            Elevated: false,
            ClientPid: 1));

        Assert.False(response.Ok);
        Assert.Contains("未知命令", response.Error, StringComparison.Ordinal);
    }

    [Fact]
    public void PolicyGuardRejectsUnknownCommandBeforeRouting()
    {
        var response = CommandPolicyGuard.Check(
            new ServiceRequest { Id = "1", Command = "not.a.real.command" },
            elevated: true,
            clientPid: 1);

        Assert.NotNull(response);
        Assert.False(response!.Ok);
    }

    [Fact]
    public void AuthChallengeCannotBeDispatchedAsNormalCommand()
    {
        var router = ServiceCatalog.CreateRouter();

        var response = router.Dispatch(new CommandContext(
            new ServiceRequest { Id = "1", Command = ServiceProtocol.Commands.AuthChallenge },
            Elevated: false,
            ClientPid: 1));

        Assert.False(response.Ok);
        Assert.Contains("第一条命令", response.Error, StringComparison.Ordinal);
    }

    private static string ModuleOf(CommandRouter router, string command)
        => Assert.Single(router.Handlers, handler => handler.Command == command).Module;
}
