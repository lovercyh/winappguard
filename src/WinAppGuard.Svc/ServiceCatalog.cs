using WinAppGuard.Contracts;

namespace WinAppGuard.Service;

/// <summary>
/// 5.9：服务端命令目录。
///
/// 这是“命令 → Handler”的唯一注册点；<see cref="ControlServer.Dispatch"/> 不再保留大 switch。
/// 启动时会调用 <see cref="CommandRouter.Validate"/>：
///   - 协议声明的每条命令必须恰好注册一次；
///   - 不允许注册协议外命令；
///   - 每条命令必须有显式权限策略；
///   - 只有 5.8 的新程序提醒命令可以使用 OwnerTemporaryWfp。
///
/// 协议仍是 v2：这里只改服务内部的分发方式，不改请求/响应结构。
/// </summary>
internal static class ServiceCatalog
{
    private const string SystemModule = "system";
    private const string RulesModule = "rules";
    private const string TrafficModule = "traffic";
    private const string DnsModule = "dns";
    private const string NetworkDetectionModule = "network-detection";
    private const string IdsModule = "ids";
    private const string NewProgramGuardModule = "new-program-guard";
    private const string AntiScanModule = "antiscan";
    private const string LanModule = "lan";
    private const string ConfigIntegrityModule = "config-integrity";

    internal static CommandRouter CreateRouter()
    {
        var router = new CommandRouter();

        // ---------------------------------------------------------------- system
        Route(router, ServiceProtocol.Commands.Ping, SystemModule, context => StatusResponse(context.Request));
        Route(router, ServiceProtocol.Commands.Status, SystemModule, context => StatusResponse(context.Request));

        // auth.challenge 是握手命令，由连接循环在 Dispatch 之前单独处理（且免签名）。
        // 这里仍然登记一个防御性 Handler：万一它作为普通请求到达，明确拒绝，
        // 而不是让它落进“未知命令”或被别的模块误处理。
        Route(router, ServiceProtocol.Commands.AuthChallenge, SystemModule, context => new ActionResult
        {
            Id = context.Request.Id,
            Ok = false,
            Error = "auth.challenge 只能作为连接后的第一条命令。",
        });

        Route(router, ServiceProtocol.Commands.AuthCheck, SystemModule, context =>
        {
            ServiceLog.Info(
                "WAG-AUTH-004",
                $"Auth probe: pid={context.ClientPid}, elevated={context.Elevated}.");

            return new ActionResult
            {
                Id = context.Request.Id,
                Ok = context.Elevated,
                Error = context.Elevated ? null : "当前客户端未提权。",
            };
        });

        Route(
            router,
            ServiceProtocol.Commands.QueryProcessPaths,
            SystemModule,
            context => ControlServer.ResolveProcessPaths(context.Request));

        // ----------------------------------------------------------------- rules
        // 规则/严格模式/审计写入全部交给同一个 RuleHandlers 实例，
        // 保证和启动迁移、定时清理、篡改检测共用同一把锁和同一份快照。
        foreach (var command in new[]
                 {
                     ServiceProtocol.Commands.ListRules,
                     ServiceProtocol.Commands.FilterMap,
                     ServiceProtocol.Commands.AllowTargets,
                     ServiceProtocol.Commands.ImportGroups,
                     ServiceProtocol.Commands.AddProgramRule,
                     ServiceProtocol.Commands.AddIpRule,
                     ServiceProtocol.Commands.DeleteRule,
                     ServiceProtocol.Commands.DeleteRulesForProgram,
                     ServiceProtocol.Commands.ClearBlocklist,
                     ServiceProtocol.Commands.ClearWhitelist,
                     ServiceProtocol.Commands.ClearAllRules,
                     ServiceProtocol.Commands.SetGroup,
                     ServiceProtocol.Commands.ImportRules,
                     ServiceProtocol.Commands.PurgeExpiredRules,
                     ServiceProtocol.Commands.StrictEnable,
                     ServiceProtocol.Commands.StrictDisable,
                     ServiceProtocol.Commands.StrictRefresh,
                     ServiceProtocol.Commands.StrictRecoverLegacy,
                     ServiceProtocol.Commands.StrictLockdown,
                     ServiceProtocol.Commands.AuditConfigure,
                     ServiceProtocol.Commands.AuditClear,
                 })
        {
            Route(
                router,
                command,
                RulesModule,
                context => ControlServer.HandleRuleCommand(context.Request));
        }

        // --------------------------------------------------------------- traffic
        Route(
            router,
            ServiceProtocol.Commands.QueryTraffic,
            TrafficModule,
            context => TrafficCaptureHost.Query(context.Request));

        Route(
            router,
            ServiceProtocol.Commands.ClearTraffic,
            TrafficModule,
            context => TrafficCaptureHost.Clear(context.Request));

        Route(
            router,
            ServiceProtocol.Commands.ConfigureTraffic,
            TrafficModule,
            context => TrafficCaptureHost.Configure(context.Request));

        // ------------------------------------------------------------------- DNS
        Route(router, ServiceProtocol.Commands.QueryDns, DnsModule, context => new ActionResult
        {
            Id = context.Request.Id,
            Ok = true,
            DnsRecords = DnsHost.Snapshot(500),
        });

        Route(router, ServiceProtocol.Commands.ClearDns, DnsModule, context => new ActionResult
        {
            Id = context.Request.Id,
            Ok = true,
            Affected = DnsHost.Clear(),
        });

        // ----------------------------------------------------- network detection
        Route(
            router,
            ServiceProtocol.Commands.QueryNetworkDetection,
            NetworkDetectionModule,
            context => NetworkDetectionHost.Query(context.Request));

        Route(
            router,
            ServiceProtocol.Commands.NetworkDetectionConfigure,
            NetworkDetectionModule,
            context => NetworkDetectionHost.Configure(context.Request));

        Route(
            router,
            ServiceProtocol.Commands.NetworkDetectionAck,
            NetworkDetectionModule,
            context => NetworkDetectionHost.Ack(context.Request));

        Route(
            router,
            ServiceProtocol.Commands.NetworkDetectionClear,
            NetworkDetectionModule,
            context => NetworkDetectionHost.Clear(context.Request));

        Route(
            router,
            ServiceProtocol.Commands.NetworkDetectionBlock,
            NetworkDetectionModule,
            context => NetworkDetectionHost.Block(context.Request));

        Route(
            router,
            ServiceProtocol.Commands.NetworkDetectionRelease,
            NetworkDetectionModule,
            context => NetworkDetectionHost.Release(context.Request));

        Route(
            router,
            ServiceProtocol.Commands.NetworkDetectionReleaseAll,
            NetworkDetectionModule,
            context => NetworkDetectionHost.Release(context.Request));

        // ------------------------------------------------------------------- IDS
        Route(
            router,
            ServiceProtocol.Commands.QueryIdsAlerts,
            IdsModule,
            context => IdsHost.QueryAlerts(context.Request));

        Route(
            router,
            ServiceProtocol.Commands.IdsConfigure,
            IdsModule,
            context => IdsHost.Configure(context.Request));

        Route(
            router,
            ServiceProtocol.Commands.IdsAck,
            IdsModule,
            context => IdsHost.Ack(context.Request));

        Route(
            router,
            ServiceProtocol.Commands.IdsSuppress,
            IdsModule,
            context => IdsHost.Suppress(context.Request));

        Route(
            router,
            ServiceProtocol.Commands.IdsClear,
            IdsModule,
            context => IdsHost.Clear(context.Request));

        // 5.2：告警元数据命令，允许所有者免提权；是否允许永久不再提醒仍由
        // CommandPolicyGuard 按请求内容判断。
        Route(
            router,
            ServiceProtocol.Commands.AlertIdsAck,
            IdsModule,
            context => IdsHost.Ack(context.Request));

        Route(
            router,
            ServiceProtocol.Commands.AlertIdsAckAll,
            IdsModule,
            context => IdsHost.AckAll(context.Request));

        Route(
            router,
            ServiceProtocol.Commands.AlertIdsSuppress,
            IdsModule,
            context => IdsHost.Suppress(context.Request));

        Route(
            router,
            ServiceProtocol.Commands.AlertIdsClear,
            IdsModule,
            context => IdsHost.Clear(context.Request));

        Route(
            router,
            ServiceProtocol.Commands.AlertNetworkAck,
            NetworkDetectionModule,
            context => NetworkDetectionHost.Ack(context.Request));

        Route(
            router,
            ServiceProtocol.Commands.AlertNetworkAckAll,
            NetworkDetectionModule,
            context => NetworkDetectionHost.AckAll(context.Request));

        Route(
            router,
            ServiceProtocol.Commands.AlertNetworkClear,
            NetworkDetectionModule,
            context => NetworkDetectionHost.Clear(context.Request));

        // ------------------------------------------------------ new program guard
        // 5.8：这两条是独立权限策略，不能并入 Read / Write / Alert。
        Route(
            router,
            ServiceProtocol.Commands.GuardNewProgramBlock,
            NewProgramGuardModule,
            context => NewProgramGuardHost.Block(context.Request));

        Route(
            router,
            ServiceProtocol.Commands.GuardNewProgramRelease,
            NewProgramGuardModule,
            context => NewProgramGuardHost.Release(context.Request));

        // --------------------------------------------------------------- antiscan
        Route(
            router,
            ServiceProtocol.Commands.QueryAntiScan,
            AntiScanModule,
            context => AntiScanHost.Query(context.Request));

        Route(
            router,
            ServiceProtocol.Commands.ConfigureAntiScan,
            AntiScanModule,
            context => AntiScanHost.Configure(context.Request));

        Route(
            router,
            ServiceProtocol.Commands.ReleaseAntiScanBlock,
            AntiScanModule,
            context => AntiScanHost.Release(context.Request));

        Route(
            router,
            ServiceProtocol.Commands.ClearAntiScan,
            AntiScanModule,
            context => AntiScanHost.Clear(context.Request));

        // ------------------------------------------------------------------- LAN
        // 4.2：局域网。
        Route(
            router,
            ServiceProtocol.Commands.QueryLan,
            LanModule,
            context => LanHost.Query(context.Request));

        Route(
            router,
            ServiceProtocol.Commands.ConfigureLan,
            LanModule,
            context => LanHost.Configure(context.Request));

        Route(
            router,
            ServiceProtocol.Commands.ClearLan,
            LanModule,
            context => LanHost.Clear(context.Request));

        Route(
            router,
            ServiceProtocol.Commands.TrustLan,
            LanModule,
            context => LanHost.Trust(context.Request));

        Route(
            router,
            ServiceProtocol.Commands.BlockLanDhcp,
            LanModule,
            context => LanHost.Block(context.Request));

        Route(
            router,
            ServiceProtocol.Commands.ResetLanBaseline,
            LanModule,
            context => LanHost.ResetBaseline(context.Request));

        // 4.5：局域网名称解析。查询与 LAN 查询共用同一份数据。
        Route(
            router,
            ServiceProtocol.Commands.QueryNameResolution,
            LanModule,
            context => LanHost.Query(context.Request));

        Route(
            router,
            ServiceProtocol.Commands.ClearNameResolution,
            LanModule,
            context => LanHost.ClearName(context.Request));

        Route(
            router,
            ServiceProtocol.Commands.BlockNameSource,
            LanModule,
            context => LanHost.BlockName(context.Request));

        // 4.3：DNS 安全。
        Route(
            router,
            ServiceProtocol.Commands.QueryDnsSecurity,
            LanModule,
            context => LanHost.QueryDns(context.Request));

        Route(
            router,
            ServiceProtocol.Commands.ClearDnsSecurity,
            LanModule,
            context => LanHost.ClearDns(context.Request));

        Route(
            router,
            ServiceProtocol.Commands.TrustDnsServer,
            LanModule,
            context => LanHost.TrustDns(context.Request));

        // 4.4：IPv6 邻接安全。
        Route(
            router,
            ServiceProtocol.Commands.QueryIpv6Security,
            LanModule,
            context => LanHost.QueryIpv6(context.Request));

        Route(
            router,
            ServiceProtocol.Commands.ClearIpv6Security,
            LanModule,
            context => LanHost.ClearIpv6(context.Request));

        Route(
            router,
            ServiceProtocol.Commands.TrustIpv6,
            LanModule,
            context => LanHost.TrustIpv6(context.Request));

        Route(
            router,
            ServiceProtocol.Commands.BlockIpv6,
            LanModule,
            context => LanHost.BlockIpv6(context.Request));

        Route(
            router,
            ServiceProtocol.Commands.ResetIpv6Baseline,
            LanModule,
            context => LanHost.ResetIpv6Baseline(context.Request));

        // ------------------------------------------------------ config integrity
        Route(
            router,
            ServiceProtocol.Commands.QueryConfigIntegrity,
            ConfigIntegrityModule,
            context => ConfigHost.Query(context.Request));

        Route(
            router,
            ServiceProtocol.Commands.ClearConfigIntegrity,
            ConfigIntegrityModule,
            context => ConfigHost.Clear(context.Request));

        Route(
            router,
            ServiceProtocol.Commands.RebaselineConfigIntegrity,
            ConfigIntegrityModule,
            context => ConfigHost.Rebaseline(context.Request));

        router.Validate();

        return router;
    }

    private static ActionResult StatusResponse(ServiceRequest request)
        => new()
        {
            Id = request.Id,
            Ok = true,
            Status = ControlServer.BuildStatus(),
        };

    private static void Route(
        CommandRouter router,
        string command,
        string module,
        Func<CommandContext, ActionResult> handler)
        => router.Register(new DelegateCommandHandler(command, module, handler));
}
