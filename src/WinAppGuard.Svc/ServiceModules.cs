namespace WinAppGuard.Service;

/// <summary>
/// 5.9：服务的 12 个模块。
///
/// 14 个 Host 收敛为 12 个生命周期模块：
///   - LockdownHost / StrictModeHost 并入 rules；
///   - SuricataHost / NetworkBlockHost 并入 network-detection；
///   - 其余检测 Host 各自一个模块；
///   - 控制管道作为最后一个模块启动，客户端不会在依赖模块就绪前连进来。
/// </summary>
internal static class ServiceModules
{
    internal static IReadOnlyList<IServiceModule> Create(ControlServer server)
        => new IServiceModule[]
        {
            new DelegateServiceModule(
                "rules",
                order: 10,
                restartable: false,
                start: server.StartRuleServices,
                stop: server.StopRuleServices,
                detail: ControlServer.RulesHealth),

            new DelegateServiceModule(
                "audit",
                order: 20,
                restartable: true,
                start: AuditHost.StartIfEnabled,
                stop: AuditHost.Stop,
                detail: () => AuditHost.Collecting ? "collecting" : "disabled"),

            new DelegateServiceModule(
                "traffic",
                order: 30,
                restartable: false,
                start: TrafficHost.Start,
                stop: TrafficHost.Stop,
                detail: () => TrafficHost.Collecting ? "collecting" : "idle"),

            new DelegateServiceModule(
                "traffic-capture",
                order: 40,
                restartable: false,
                start: TrafficCaptureHost.Start,
                stop: TrafficCaptureHost.Stop,
                detail: () => TrafficCaptureHost.Collecting ? "collecting" : "idle"),

            new DelegateServiceModule(
                "dns",
                order: 50,
                restartable: false,
                start: DnsHost.Start,
                stop: DnsHost.Stop,
                detail: () => DnsHost.Collecting ? "collecting" : "idle"),

            new DelegateServiceModule(
                "ids",
                order: 60,
                restartable: false,
                start: IdsHost.Start,
                stop: IdsHost.Stop,
                detail: () => IdsHost.Enabled ? "enabled" : "disabled"),

            new DelegateServiceModule(
                "antiscan",
                order: 70,
                restartable: false,
                start: AntiScanHost.Start,
                stop: AntiScanHost.Stop,
                detail: () => AntiScanHost.Collecting ? "collecting" : "idle"),

            new DelegateServiceModule(
                "lan",
                order: 80,
                restartable: false,
                start: LanHost.Start,
                stop: LanHost.Stop,
                detail: () => LanHost.Collecting ? "collecting" : "idle"),

            new DelegateServiceModule(
                "config-integrity",
                order: 90,
                restartable: true,
                start: ConfigHost.Start,
                stop: ConfigHost.Stop,
                detail: () => "monitoring"),

            new DelegateServiceModule(
                "network-detection",
                order: 100,
                restartable: false,
                start: NetworkDetectionHost.Start,
                stop: NetworkDetectionHost.Stop,
                detail: () => NetworkDetectionHost.Enabled ? "enabled" : "disabled"),

            new DelegateServiceModule(
                "new-program-guard",
                order: 110,
                restartable: true,
                start: NewProgramGuardHost.Start,
                stop: NewProgramGuardHost.Stop,
                detail: () => "ready"),

            new DelegateServiceModule(
                "control-plane",
                order: 120,
                restartable: false,
                start: server.StartControlPlane,
                stop: server.StopControlPlane,
                detail: server.ControlPlaneHealth),
        };
}
