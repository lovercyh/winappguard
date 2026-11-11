using System.Reflection;
using WinAppGuard.Contracts;

namespace WinAppGuard.Architecture.Tests;

public sealed class CommandPolicyTests
{
    [Fact]
    public void EveryDeclaredCommandHasPolicy()
    {
        var commands = DeclaredCommands();

        Assert.NotEmpty(commands);

        foreach (var command in commands)
        {
            Assert.True(
                CommandPolicyTable.TryGet(command, out _),
                $"命令没有声明策略：{command}");
        }
    }

    [Fact]
    public void WriteCommandsAreWritePolicy()
    {
        foreach (var command in DeclaredCommands()
                     .Where(command => command.StartsWith("write.", StringComparison.OrdinalIgnoreCase)))
        {
            Assert.Equal(CommandPolicy.Write, CommandPolicyTable.Get(command));
        }
    }

    [Fact]
    public void AlertCommandsAreAlertMetadata()
    {
        foreach (var command in DeclaredCommands()
                     .Where(command => command.StartsWith("alert.", StringComparison.OrdinalIgnoreCase)))
        {
            Assert.Equal(CommandPolicy.AlertMetadata, CommandPolicyTable.Get(command));
        }
    }

    [Fact]
    public void OnlyNewProgramGuardCommandsUseOwnerTemporaryWfp()
    {
        var commands = DeclaredCommands()
            .Where(command => CommandPolicyTable.Get(command) == CommandPolicy.OwnerTemporaryWfp)
            .OrderBy(command => command, StringComparer.Ordinal)
            .ToArray();

        Assert.Equal(
            new[]
            {
                ServiceProtocol.Commands.GuardNewProgramBlock,
                ServiceProtocol.Commands.GuardNewProgramRelease,
            },
            commands);
    }

    [Fact]
    public void UnknownCommandIsNotSilentlyRead()
    {
        Assert.False(CommandPolicyTable.TryGet("not.a.real.command", out _));
        Assert.Throws<InvalidOperationException>(
            () => CommandPolicyTable.Get("not.a.real.command"));
    }

    private static IReadOnlyList<string> DeclaredCommands()
        => typeof(ServiceProtocol.Commands)
            .GetFields(BindingFlags.Public | BindingFlags.Static)
            .Where(field => field.IsLiteral && field.FieldType == typeof(string))
            .Select(field => (string?)field.GetRawConstantValue())
            .Where(command => !string.IsNullOrWhiteSpace(command))
            .Select(command => command!)
            .Distinct(StringComparer.Ordinal)
            .ToList();
}
