namespace WinAppGuard.Contracts.Protocol;

/// <summary>
/// 5.11：76 条命令 → 22 个请求载荷 / 6 个响应载荷的唯一映射。
///
/// 这里只做类型映射；真正的字段适配由 <c>LegacyPayloadAdapter</c> 完成。
/// </summary>
public static class PayloadCatalog
{
    public static Type RequestTypeFor(string command) => command switch
    {
        ServiceProtocol.Commands.Status or ServiceProtocol.Commands.Ping
            or ServiceProtocol.Commands.AuthCheck or ServiceProtocol.Commands.AuthChallenge
            or ServiceProtocol.Commands.FilterMap or ServiceProtocol.Commands.AllowTargets
            or ServiceProtocol.Commands.QueryDns or ServiceProtocol.Commands.QueryIdsAlerts
            or ServiceProtocol.Commands.QueryNetworkDetection
            or ServiceProtocol.Commands.QueryAntiScan
            or ServiceProtocol.Commands.QueryLan
            or ServiceProtocol.Commands.QueryDnsSecurity
            or ServiceProtocol.Commands.QueryIpv6Security
            or ServiceProtocol.Commands.QueryConfigIntegrity
            or ServiceProtocol.Commands.QueryNameResolution
            or ServiceProtocol.Commands.QueryTraffic
            or ServiceProtocol.Commands.PurgeExpiredRules
            => typeof(EmptyPayload),

        ServiceProtocol.Commands.ListRules
            => typeof(RulesQuery),

        ServiceProtocol.Commands.AddProgramRule or ServiceProtocol.Commands.AddIpRule
            => typeof(RuleAdd),

        ServiceProtocol.Commands.DeleteRule
            => typeof(RuleDelete),

        ServiceProtocol.Commands.DeleteRulesForProgram
            => typeof(RuleDeleteForProgram),

        ServiceProtocol.Commands.ClearBlocklist or ServiceProtocol.Commands.ClearWhitelist
            or ServiceProtocol.Commands.ClearAllRules
            => typeof(RuleClear),

        ServiceProtocol.Commands.SetGroup
            => typeof(RuleSetGroup),

        ServiceProtocol.Commands.ImportRules or ServiceProtocol.Commands.ImportGroups
            => typeof(RuleImport),

        ServiceProtocol.Commands.StrictEnable or ServiceProtocol.Commands.StrictDisable
            or ServiceProtocol.Commands.StrictRefresh or ServiceProtocol.Commands.StrictRecoverLegacy
            or ServiceProtocol.Commands.StrictLockdown
            => typeof(StrictCommand),

        ServiceProtocol.Commands.QueryProcessPaths
            => typeof(PidsQuery),

        ServiceProtocol.Commands.AuditConfigure or ServiceProtocol.Commands.AuditClear
            => typeof(AuditSettings),

        ServiceProtocol.Commands.ConfigureTraffic
            => typeof(TrafficConfig),

        ServiceProtocol.Commands.IdsConfigure or ServiceProtocol.Commands.IdsAck
            or ServiceProtocol.Commands.IdsSuppress or ServiceProtocol.Commands.IdsClear
            or ServiceProtocol.Commands.AlertIdsAck or ServiceProtocol.Commands.AlertIdsAckAll
            or ServiceProtocol.Commands.AlertIdsSuppress or ServiceProtocol.Commands.AlertIdsClear
            => typeof(IdsSettings),

        ServiceProtocol.Commands.NetworkDetectionConfigure
            or ServiceProtocol.Commands.NetworkDetectionAck
            or ServiceProtocol.Commands.NetworkDetectionClear
            or ServiceProtocol.Commands.NetworkDetectionBlock
            or ServiceProtocol.Commands.NetworkDetectionRelease
            or ServiceProtocol.Commands.NetworkDetectionReleaseAll
            or ServiceProtocol.Commands.AlertNetworkAck
            or ServiceProtocol.Commands.AlertNetworkAckAll
            or ServiceProtocol.Commands.AlertNetworkClear
            => typeof(NetworkSettings),

        ServiceProtocol.Commands.GuardNewProgramBlock
            or ServiceProtocol.Commands.GuardNewProgramRelease
            => typeof(GuardDecision),

        ServiceProtocol.Commands.ConfigureAntiScan
            or ServiceProtocol.Commands.ReleaseAntiScanBlock
            or ServiceProtocol.Commands.ClearAntiScan
            => typeof(AntiScanSettings),

        ServiceProtocol.Commands.ConfigureLan or ServiceProtocol.Commands.ClearLan
            or ServiceProtocol.Commands.TrustLan or ServiceProtocol.Commands.BlockLanDhcp
            or ServiceProtocol.Commands.ResetLanBaseline
            => typeof(LanSettings),

        ServiceProtocol.Commands.TrustDnsServer
            => typeof(DnsTrust),

        ServiceProtocol.Commands.TrustIpv6 or ServiceProtocol.Commands.BlockIpv6
            or ServiceProtocol.Commands.ResetIpv6Baseline
            => typeof(Ipv6Trust),

        ServiceProtocol.Commands.BlockNameSource
            => typeof(NameBlock),

        ServiceProtocol.Commands.ClearTraffic or ServiceProtocol.Commands.ClearDns
            or ServiceProtocol.Commands.ClearDnsSecurity
            or ServiceProtocol.Commands.ClearIpv6Security
            or ServiceProtocol.Commands.ClearConfigIntegrity
            or ServiceProtocol.Commands.ClearNameResolution
            => typeof(ClearOnly),

        ServiceProtocol.Commands.RebaselineConfigIntegrity
            => typeof(Rebaseline),

        _ => throw new InvalidOperationException($"命令没有声明 v4 请求载荷：{command}"),
    };

    public static Type ResponseTypeFor(string command) => command switch
    {
        ServiceProtocol.Commands.Status or ServiceProtocol.Commands.Ping
            => typeof(StatusView),

        ServiceProtocol.Commands.ListRules
            => typeof(RulesView),

        ServiceProtocol.Commands.QueryProcessPaths
            => typeof(ProcessPathsView),

        ServiceProtocol.Commands.QueryTraffic
            => typeof(TrafficView),

        _ when command.StartsWith("query.", StringComparison.OrdinalIgnoreCase)
            => typeof(QueryView),

        _ => typeof(WriteResult),
    };

    public static IReadOnlyList<Type> RequestTypes { get; } = new[]
    {
        typeof(EmptyPayload), typeof(RulesQuery), typeof(RuleAdd), typeof(RuleDelete),
        typeof(RuleDeleteForProgram), typeof(RuleClear), typeof(RuleImport),
        typeof(RuleSetGroup), typeof(StrictCommand), typeof(PidsQuery),
        typeof(AuditSettings), typeof(TrafficConfig), typeof(IdsSettings),
        typeof(NetworkSettings), typeof(GuardDecision), typeof(AntiScanSettings),
        typeof(LanSettings), typeof(DnsTrust), typeof(Ipv6Trust), typeof(NameBlock),
        typeof(ClearOnly), typeof(Rebaseline),
    };

    public static IReadOnlyList<Type> ResponseTypes { get; } = new[]
    {
        typeof(QueryView), typeof(WriteResult), typeof(StatusView),
        typeof(RulesView), typeof(ProcessPathsView), typeof(TrafficView),
    };
}
