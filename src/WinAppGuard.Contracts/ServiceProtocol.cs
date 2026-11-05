using System.Text.Json;

namespace WinAppGuard.Contracts;

/// <summary>
/// 服务与界面之间的 IPC 约定。
///
/// 命名管道名带 <c>v2</c>：协议不兼容时**换一个管道**，而不是在同一管道里猜版本 ——
/// 这样旧界面连不上新服务时会立刻失败并给出明确提示，而不是发出一条被误解的指令。
/// </summary>
public static class ServiceProtocol
{
    /// <summary>管道名（不带 <c>\\.\pipe\</c> 前缀）。</summary>
    public const string PipeName = "WinAppGuard.Control.v2";

    /// <summary>协议版本。任何不兼容的字段变化都要 +1。</summary>
    public const int Version = 2;

    /// <summary>单条消息上限（64 KB）。正常请求只有几百字节。</summary>
    /// <summary>
    /// 单条消息上限（4 MB）。
    ///
    /// 3.0-b 起 <c>write.rules.import</c> 会把整份规则文件交给服务，而规则文件本身
    /// 允许到 2 MB（见 <c>RuleExport.MaxBytes</c>），64 KB 会直接把正常导入挡掉。
    /// 读取方向的规则列表（几千条）同样可能超过 64 KB。
    /// </summary>
    public const int MaxMessageBytes = 4 * 1024 * 1024;

    /// <summary>ECDSA P-256 DER 签名上限（实际 64 字节左右）。</summary>
    public const int MaxSignatureBytes = 256;

    /// <summary>服务显示名（安装/卸载、SCM 里看到的名字）。</summary>
    public const string ServiceName = "WinAppGuardSvc";

    /// <summary>服务显示名（给人看的）。</summary>
    public const string ServiceDisplayName = "WinAppGuard 防护服务";

    /// <summary>服务描述。</summary>
    public const string ServiceDescription = "维护 WinAppGuard 的 WFP 规则与审计记录。停掉它不会删除已有规则。";

    /// <summary>请求里的命令名（v1 只有只读命令）。</summary>
    public static class Commands
    {
        /// <summary>3.1 协议 v2：获取一次性 nonce（只有这条命令免签）。</summary>
        public const string AuthChallenge = "auth.challenge";

        public const string Status = "status";
        public const string Ping = "ping";

        /// <summary>鉴权探针：不做任何事，只回答"当前客户端是否已提权"。</summary>
        public const string AuthCheck = "auth.check";

        // ---- 3.0-b：规则只读 ----

        /// <summary>列出全部规则（程序 + IP + 白名单）。</summary>
        public const string ListRules = "rules.list";

        /// <summary>过滤器 id → 规则名（记录页用）。</summary>
        public const string FilterMap = "rules.filterMap";

        // ---- 3.0-b：规则写入（必须提权；服务端会再校验一遍）----

        public const string AddProgramRule = "write.rules.addProgram";
        public const string AddIpRule = "write.rules.addIp";
        public const string DeleteRule = "write.rules.delete";
        public const string DeleteRulesForProgram = "write.rules.deleteForProgram";
        public const string ClearBlocklist = "write.rules.clearBlocklist";
        public const string ClearWhitelist = "write.rules.clearWhitelist";

        /// <summary>删除本工具创建的全部规则（CLI --unblock-all）。</summary>
        public const string ClearAllRules = "write.rules.clearAll";
        public const string SetGroup = "write.rules.setGroup";
        public const string ImportRules = "write.rules.import";

        /// <summary>清理已到期的临时规则（服务端定时/界面启动时调用）。</summary>
        public const string PurgeExpiredRules = "write.rules.purgeExpired";

        /// <summary>把界面本地（旧版本）的分组文件内容交给服务保存。</summary>
        public const string ImportGroups = "write.groups.import";

        // ---- 3.0-c：严格模式（会话由服务持有）----

        /// <summary>本工具白名单 + 其它来源允许规则（替界面读，界面不再碰 WFP）。</summary>
        public const string AllowTargets = "rules.allowTargets";

        public const string StrictEnable = "write.strict.enable";
        public const string StrictDisable = "write.strict.disable";

        /// <summary>白名单变化后重建严格模式会话（服务写规则时会自动调用，界面一般不用）。</summary>
        public const string StrictRefresh = "write.strict.refresh";

        /// <summary>1.x 升级兜底：按界面传来的设置文件路径还原全局默认出站。</summary>
        public const string StrictRecoverLegacy = "write.strict.recoverLegacy";

        /// <summary>
        /// 3.5：临时锁网（定时严格模式）。复用严格模式的动态会话，
        /// 只额外记录一个到期时间，到点由服务主动撤销。
        /// </summary>
        public const string StrictLockdown = "write.strict.lockdown";

        // ---- 3.0-c：审计（采集在服务，界面只读）----

        /// <summary>修改机器级审计设置（开关 / 域名推测 / 保留期）。</summary>
        public const string AuditConfigure = "write.audit.configure";

        /// <summary>3.5：批量查询 PID 对应的可执行文件路径（服务以 SYSTEM 运行，能读到界面读不到的进程）。</summary>
        public const string QueryProcessPaths = "query.process.paths";

        /// <summary>3.5：每程序流量快照（本次服务运行以来，TCP + UDP 网络事件）。</summary>
        public const string QueryTraffic = "query.traffic";

        /// <summary>3.6：清空本次运行的流量计数并重置统计起点。</summary>
        public const string ClearTraffic = "write.traffic.clear";

        /// <summary>4.1：暂停 / 继续精确流量统计（只对本次运行有效）。</summary>
        public const string ConfigureTraffic = "write.traffic.configure";

        /// <summary>3.5：最近的 DNS 查询记录（内存环形缓冲）。</summary>
        public const string QueryDns = "query.dns";

        /// <summary>3.5：清空 DNS 内存记录（服务继续采集）。</summary>
        public const string ClearDns = "write.dns.clear";

        // ---- 3.7：用户态 Flow IDS（只检测、不阻断）----

        /// <summary>3.7：读取最近的 IDS 告警（只读）。</summary>
        // ---- 5.0 网络被动检测（Suricata / ET Open） ----

        /// <summary>5.0：读取网络检测告警、状态、配置、活动拦截（只读）。</summary>
        public const string QueryNetworkDetection = "query.network-detection";

        /// <summary>5.0：修改网络检测开关、证据保留。</summary>
        public const string NetworkDetectionConfigure = "write.network-detection.configure";

        /// <summary>5.0：确认一条网络检测告警。</summary>
        public const string NetworkDetectionAck = "write.network-detection.ack";

        /// <summary>5.0：清空网络检测告警。</summary>
        public const string NetworkDetectionClear = "write.network-detection.clear";

        /// <summary>5.0：用户手动拦截，WFP 动态过滤器执行。</summary>
        public const string NetworkDetectionBlock = "write.network-detection.block";

        /// <summary>5.0：释放一个手动拦截。</summary>
        public const string NetworkDetectionRelease = "write.network-detection.release";

        /// <summary>5.0：释放全部手动拦截。</summary>
        public const string NetworkDetectionReleaseAll = "write.network-detection.release-all";

        public const string QueryIdsAlerts = "query.ids.alerts";

        /// <summary>3.7：修改 IDS 开关、规则、敏感度和保留期（写，需提权）。</summary>
        public const string IdsConfigure = "write.ids.configure";

        /// <summary>3.7：确认一条告警（写，需提权）。</summary>
        public const string IdsAck = "write.ids.ack";

        /// <summary>3.7：新增或取消一条抑制（写，需提权）。</summary>
        public const string IdsSuppress = "write.ids.suppress";

        /// <summary>3.7：清空告警（写，需提权）。</summary>
        public const string IdsClear = "write.ids.clear";

        // ---- 5.2：告警元数据（只改已读 / 不再提醒 / 告警历史，不改 WFP / 设置）----
        //
        // 这些命令仍然要求管道身份认证（SYSTEM + 所有者 SID + ECDSA 签名），
        // 但不要求管理员提权。命名刻意不用 write. 前缀，避免和“系统变更必须提权”混淆。

        /// <summary>5.2：标记一条 IDS 告警为已读。</summary>
        public const string AlertIdsAck = "alert.ids.ack";

        /// <summary>5.2：新增或取消一条“同类告警不再提醒”。</summary>
        public const string AlertIdsSuppress = "alert.ids.suppress";

        /// <summary>5.2：清空 IDS 告警历史。</summary>
        public const string AlertIdsClear = "alert.ids.clear";

        /// <summary>5.2：标记一条反网络攻击告警为已读。</summary>
        public const string AlertNetworkAck = "alert.network.ack";

        /// <summary>5.2：清空反网络攻击告警历史。</summary>
        public const string AlertNetworkClear = "alert.network.clear";

        // ---- 4.0：反端口扫描与临时 IP 封禁 ----

        /// <summary>4.0：读取反扫描状态、事件、临时封禁和设置（只读）。</summary>
        public const string QueryAntiScan = "query.antiscan";

        /// <summary>4.0：修改反扫描开关、敏感度、自动封禁与 TTL（写，需提权）。</summary>
        public const string ConfigureAntiScan = "write.antiscan.configure";

        /// <summary>4.0：解除一个来源 IP 的临时封禁（写，需提权）。</summary>
        public const string ReleaseAntiScanBlock = "write.antiscan.release";

        /// <summary>4.0：清空扫描事件并解除全部临时封禁（写，需提权）。</summary>
        public const string ClearAntiScan = "write.antiscan.clear";

        // ---- 4.2：局域网欺骗检测 ----

        /// <summary>4.2：读取局域网状态、事件、网关、DHCP 服务器与阻断（只读）。</summary>
        public const string QueryLan = "query.lan";

        /// <summary>4.2：修改保留期与 DHCP 阻断总开关（写，需提权）。</summary>
        public const string ConfigureLan = "write.lan.configure";

        /// <summary>4.2：清空事件并解除全部 DHCP 阻断（写，需提权）。</summary>
        public const string ClearLan = "write.lan.clear";

        /// <summary>4.2：信任当前网关 MAC / DHCP 服务器（写，需提权）。</summary>
        public const string TrustLan = "write.lan.trust";

        /// <summary>4.2：临时阻断 / 解除某个 DHCP 服务器（写，需提权）。</summary>
        public const string BlockLanDhcp = "write.lan.block";

        /// <summary>4.2：清空基线并重新学习（写，需提权）。</summary>
        public const string ResetLanBaseline = "write.lan.reset-baseline";

        // ---- 4.3：DNS 安全 ----

        /// <summary>4.3：读取 DNS 安全状态、服务器与事件（只读）。</summary>
        public const string QueryDnsSecurity = "query.dns-security";

        /// <summary>4.3：只清空 DNS 安全事件（写，需提权）。</summary>
        public const string ClearDnsSecurity = "write.dns-security.clear";

        /// <summary>4.3：信任 / 取消信任某个 DNS 服务器（写，需提权）。</summary>
        public const string TrustDnsServer = "write.dns-security.trust";

        // ---- 4.4：IPv6 邻接安全 ----

        /// <summary>4.4：读取 IPv6 邻接安全状态、端点与事件（只读）。</summary>
        public const string QueryIpv6Security = "query.ipv6-security";

        /// <summary>4.4：只清空 IPv6 邻接安全事件（写，需提权）。</summary>
        public const string ClearIpv6Security = "write.ipv6-security.clear";

        /// <summary>4.4：信任 / 取消信任路由器或 DHCPv6 服务器（写，需提权）。</summary>
        public const string TrustIpv6 = "write.ipv6-security.trust";

        /// <summary>4.4：清空 IPv6 基线并重新学习（写，需提权）。</summary>
        public const string ResetIpv6Baseline = "write.ipv6-security.reset-baseline";

        /// <summary>4.4：临时阻断 / 解除某个 IPv6 路由器或 DHCPv6 服务器（写，需提权）。</summary>
        public const string BlockIpv6 = "write.ipv6-security.block";

        // ---- 4.5：本机配置完整性 ----

        /// <summary>4.5：读取本机配置监控状态、监控项与事件（只读）。</summary>
        public const string QueryConfigIntegrity = "query.config-integrity";

        /// <summary>4.5：只清空本机配置事件（写，需提权）。</summary>
        public const string ClearConfigIntegrity = "write.config-integrity.clear";

        /// <summary>4.5：重新采集配置基线（写，需提权）。</summary>
        public const string RebaselineConfigIntegrity = "write.config-integrity.rebaseline";

        // ---- 4.5：局域网名称解析 ----

        /// <summary>4.5：读取 LLMNR/NBNS/mDNS 来源、状态与事件（只读）。</summary>
        public const string QueryNameResolution = "query.name-resolution";

        /// <summary>4.5：只清空名称解析事件（写，需提权）。</summary>
        public const string ClearNameResolution = "write.name-resolution.clear";

        /// <summary>4.5：临时阻断 / 解除某个名称解析来源（写，需提权）。</summary>
        public const string BlockNameSource = "write.name-resolution.block";

        /// <summary>清空全部审计记录（服务先停采集，删完再恢复）。</summary>
        public const string AuditClear = "write.audit.clear";
    }

    /// <summary>
    /// 5.2：只改告警元数据、不需要管理员提权的命令。
    ///
    /// 这里用精确匹配，不用前缀匹配 —— 避免以后有人把新命令随手加进
    /// <c>alert.</c> 前缀就被默认为免提权。
    /// </summary>
    public static bool IsAlertCommand(string command)
        => command is Commands.AlertIdsAck
            or Commands.AlertIdsSuppress
            or Commands.AlertIdsClear
            or Commands.AlertNetworkAck
            or Commands.AlertNetworkClear;

    /// <summary>
    /// 5.2：永久“同类告警不再提醒”会长期改变检测可见性，即使走 alert.* 也要求提权。
    /// 删除已有项、1 小时 / 24 小时都不算。
    /// </summary>
    public static bool IsPermanentAlertSuppression(ServiceRequest request)
        => string.Equals(
               request.Command,
               Commands.AlertIdsSuppress,
               StringComparison.Ordinal)
           && !request.IdsRemoveSuppression
           && request.IdsSuppression is { UntilUtc: null };

    /// <summary>JSON 序列化选项（双方必须一致）。</summary>
    public static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
    };
}
