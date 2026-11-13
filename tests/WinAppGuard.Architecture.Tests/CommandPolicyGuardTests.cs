using WinAppGuard.Contracts;
using WinAppGuard.Service;

namespace WinAppGuard.Architecture.Tests;

/// <summary>
/// 5.9：命令权限行为必须和 5.8 一致。
/// 这些测试只调用策略守卫，不执行 Handler、不启动服务、不碰 WFP。
/// </summary>
public sealed class CommandPolicyGuardTests
{
    [Fact]
    public void WriteCommandWithoutElevationIsRejected()
    {
        var response = Check(ServiceProtocol.Commands.AddProgramRule, elevated: false);

        Assert.NotNull(response);
        Assert.False(response!.Ok);
        Assert.Contains("管理员权限", response.Error, StringComparison.Ordinal);
    }

    [Fact]
    public void WriteCommandWithElevationIsAllowed()
    {
        Assert.Null(Check(ServiceProtocol.Commands.AddProgramRule, elevated: true));
    }

    [Fact]
    public void AlertMetadataWithoutElevationIsAllowed()
    {
        Assert.Null(Check(ServiceProtocol.Commands.AlertIdsAck, elevated: false));
    }

    [Fact]
    public void NewProgramGuardWithoutElevationIsAllowed()
    {
        Assert.Null(Check(ServiceProtocol.Commands.GuardNewProgramBlock, elevated: false));
        Assert.Null(Check(ServiceProtocol.Commands.GuardNewProgramRelease, elevated: false));
    }

    [Fact]
    public void PermanentAlertSuppressionWithoutElevationIsRejected()
    {
        var request = new ServiceRequest
        {
            Command = ServiceProtocol.Commands.AlertIdsSuppress,
            IdsSuppression = new IdsSuppressionDto { UntilUtc = null },
            IdsRemoveSuppression = false,
        };

        var response = CommandPolicyGuard.Check(request, elevated: false, clientPid: 1);

        Assert.NotNull(response);
        Assert.False(response!.Ok);
        Assert.Contains("永久不再提醒", response.Error, StringComparison.Ordinal);
    }

    [Fact]
    public void TemporaryAlertSuppressionWithoutElevationIsAllowed()
    {
        var request = new ServiceRequest
        {
            Command = ServiceProtocol.Commands.AlertIdsSuppress,
            IdsSuppression = new IdsSuppressionDto
            {
                UntilUtc = DateTime.UtcNow.AddHours(1),
            },
            IdsRemoveSuppression = false,
        };

        Assert.Null(CommandPolicyGuard.Check(request, elevated: false, clientPid: 1));
    }

    [Fact]
    public void RemovingAlertSuppressionWithoutElevationIsAllowed()
    {
        var request = new ServiceRequest
        {
            Command = ServiceProtocol.Commands.AlertIdsSuppress,
            IdsSuppression = new IdsSuppressionDto { UntilUtc = null },
            IdsRemoveSuppression = true,
        };

        Assert.Null(CommandPolicyGuard.Check(request, elevated: false, clientPid: 1));
    }

    private static ActionResult? Check(string command, bool elevated)
        => CommandPolicyGuard.Check(
            new ServiceRequest { Id = "1", Command = command },
            elevated,
            clientPid: 1);
}
