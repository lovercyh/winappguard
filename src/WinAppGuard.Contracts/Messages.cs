namespace WinAppGuard.Contracts;

/// <summary>一条 IPC 请求。</summary>
public sealed class ServiceRequest
{
    /// <summary>请求 id（服务原样回传，便于客户端匹配）。</summary>
    public string Id { get; set; } = Guid.NewGuid().ToString("N");

    /// <summary>命令名，见 <see cref="ServiceProtocol.Commands"/>。</summary>
    public string Command { get; set; } = string.Empty;

    /// <summary>客户端协议版本。</summary>
    public int ProtocolVersion { get; set; } = ServiceProtocol.Version;

    // ---- 3.0-b：规则命令的参数 ----

    /// <summary>程序完整路径，或 IP 地址。</summary>
    public string? Value { get; set; }

    /// <summary>block / allow。</summary>
    public string? Action { get; set; }

    /// <summary>到期标记（与规则说明里的格式一致；空 = 永久）。</summary>
    public string? Expiry { get; set; }

    /// <summary>作用范围标记（协议/端口；空 = 不限）。</summary>
    public string? Scope { get; set; }

    /// <summary>分组名（空 = 未分组）。</summary>
    public string? Group { get; set; }

    /// <summary>规则名（删除时用）。</summary>
    public string? RuleName { get; set; }

    /// <summary>导入文件内容 / 分组文件内容。</summary>
    public string? Json { get; set; }

    /// <summary>清理到期规则时：本次是否是"刚登录"（决定「直到下次重启」类规则是否到期）。</summary>
    public bool FreshLogonSession { get; set; }

    // ---- 3.0-c：审计设置（null = 不改这一项）----

    public bool? AuditEnabled { get; set; }

    public bool? AuditDomainLookup { get; set; }

    public int? AuditRetentionDays { get; set; }

    /// <summary>3.5：批量查询路径的 PID 列表（最多 64 个）。</summary>
    public List<int>? Pids { get; set; }

    /// <summary>3.5：临时锁网的持续时间（秒）。由服务端再做一次范围校验。</summary>
    public int? LockdownSeconds { get; set; }

    // ---- 3.7：IDS ----

    /// <summary>修改 IDS 设置（null = 不改）。</summary>
    public IdsSettingsDto? IdsSettings { get; set; }

    /// <summary>要确认的告警 id。</summary>
    public string? IdsAlertId { get; set; }

    /// <summary>要新增的抑制；<see cref="IdsRemoveSuppression"/> 为 true 时按 <see cref="IdsSuppressionDto.Id"/> 删除。</summary>
    public IdsSuppressionDto? IdsSuppression { get; set; }

    /// <summary>true = 取消抑制，false = 新增抑制。</summary>
    public bool IdsRemoveSuppression { get; set; }

    /// <summary>3.7：随设置一起批量取消的抑制 id（界面保存设置时用，避免多次 UAC）。</summary>
    public List<string>? IdsRemoveSuppressionIds { get; set; }
}

/// <summary>一条 IPC 响应。</summary>
public sealed class ServiceResponse
{
    public string Id { get; set; } = string.Empty;

    public bool Ok { get; set; }

    /// <summary>失败原因（只在 <see cref="Ok"/> 为 false 时非空）。</summary>
    public string? Error { get; set; }

    /// <summary>3.1：auth.challenge 返回的 32 字节 nonce（Base64）。</summary>
    public string? Nonce { get; set; }

    /// <summary>服务状态（status 命令返回）。</summary>
    public ServiceStatus? Status { get; set; }

    /// <summary>规则列表（rules.list 返回）。</summary>
    public List<RuleDto>? Rules { get; set; }

    /// <summary>过滤器 id → 规则名（rules.filterMap 返回，键是十进制字符串）。</summary>
    public Dictionary<string, string>? FilterMap { get; set; }

    /// <summary>本次操作影响的条数（删除 / 导入等）。</summary>
    public int Affected { get; set; }

    // ---- 3.0-c ----

    /// <summary>本工具的白名单程序（rules.allowTargets）。</summary>
    public List<string>? Programs { get; set; }

    /// <summary>系统 / 其它软件放行的程序（rules.allowTargets）。</summary>
    public List<string>? OtherPrograms { get; set; }

    /// <summary>不限程序的允许规则条数（rules.allowTargets）。</summary>
    public int ProgramlessRuleCount { get; set; }

    /// <summary>给人看的一句话（严格模式开关的结果说明）。</summary>
    public string? Message { get; set; }

    /// <summary>3.5：会话中 PID 对应的路径。</summary>
    public List<ProcessPathDto>? ProcessPaths { get; set; }

    /// <summary>3.5：每程序流量快照（按本次运行累计）。</summary>
    public List<TrafficDto>? Traffic { get; set; }

    /// <summary>
    /// 3.6：本次流量统计的起点（UTC）。服务重启或执行清空后更新；
    /// 旧服务不返回时为 null，界面显示「未知」。
    /// </summary>
    public DateTime? TrafficStartedUtc { get; set; }

    /// <summary>3.5：最近的 DNS 查询记录。</summary>
    public List<DnsDto>? DnsRecords { get; set; }

    // ---- 3.7：IDS ----

    /// <summary>最近的 IDS 告警（按时间倒序）。</summary>
    public List<IdsAlertDto>? IdsAlerts { get; set; }

    /// <summary>当前抑制列表。</summary>
    public List<IdsSuppressionDto>? IdsSuppressions { get; set; }

    /// <summary>当前 IDS 设置。</summary>
    public IdsSettingsDto? IdsSettings { get; set; }

    /// <summary>IDS 运行状态。</summary>
    public IdsStatusDto? IdsStatus { get; set; }
}

/// <summary>
/// 3.5：一条 DNS 查询记录。
///
/// 只有域名、PID、时间和结果码；**不记录**查询响应里的 IP 列表之外的任何内容，
/// 更不记录 URL/HTTPS 路径。DoH/DoT 不经过系统 DNS 客户端，采不到。
/// </summary>
public sealed class DnsDto
{
    /// <summary>查询时间（UTC）。</summary>
    public DateTime TimeUtc { get; set; }

    /// <summary>发起查询的进程 PID。</summary>
    public int Pid { get; set; }

    /// <summary>进程完整路径；服务拿不到时为 null。</summary>
    public string? ProcessPath { get; set; }

    /// <summary>显示名（文件名，或「PID 123」）。</summary>
    public string ProcessName { get; set; } = string.Empty;

    /// <summary>查询的域名。</summary>
    public string QueryName { get; set; } = string.Empty;

    /// <summary>结果码（OK / NXDOMAIN / 0x...）；未完成时为空。</summary>
    public string? Status { get; set; }

    /// <summary>ETW 事件 ID（诊断用；3006 = 发起，3008 = 完成）。</summary>
    public int EventId { get; set; }
}

/// <summary>
/// 3.7：一条 IDS 告警。
///
/// 只有连接元数据与统计证据；**不含**载荷、URL、HTTPS 内容。
/// 级别和状态都是稳定英文标记，界面负责翻译。
/// </summary>
public sealed class IdsAlertDto
{
    public string Id { get; set; } = string.Empty;

    public DateTime TimeUtc { get; set; }

    /// <summary>low / medium / high。</summary>
    public string Severity { get; set; } = "medium";

    /// <summary>beaconing / scan / lateral / dns。</summary>
    public string RuleId { get; set; } = string.Empty;

    public string RuleName { get; set; } = string.Empty;

    public int Pid { get; set; }

    public string ProcessName { get; set; } = string.Empty;

    public string? ProcessPath { get; set; }

    /// <summary>远端 IP:端口、主机、端口或父域。</summary>
    public string Target { get; set; } = string.Empty;

    /// <summary>数值型证据摘要（英文/数字，不写中文）。</summary>
    public string Evidence { get; set; } = string.Empty;

    /// <summary>new / ack / ignored。</summary>
    public string Status { get; set; } = "new";
}

/// <summary>3.7：IDS 设置。</summary>
public sealed class IdsSettingsDto
{
    public bool Enabled { get; set; } = true;

    /// <summary>standard / conservative。</summary>
    public string Sensitivity { get; set; } = "standard";

    /// <summary>告警保留天数。</summary>
    public int RetentionDays { get; set; } = 30;

    public bool BeaconingRule { get; set; } = true;

    public bool ScanRule { get; set; } = true;

    public bool LateralRule { get; set; } = true;

    public bool DnsRule { get; set; } = true;
}

/// <summary>3.7：一条抑制。</summary>
public sealed class IdsSuppressionDto
{
    public string Id { get; set; } = string.Empty;

    /// <summary>规则 id，或 * 表示全部规则。</summary>
    public string RuleId { get; set; } = "*";

    public string? ProcessPath { get; set; }

    public string? ProcessName { get; set; }

    public string? Target { get; set; }

    /// <summary>到期时间（UTC）；null = 永久。</summary>
    public DateTime? UntilUtc { get; set; }
}

/// <summary>3.7：IDS 运行状态（诊断与验收用）。</summary>
public sealed class IdsStatusDto
{
    public bool Enabled { get; set; }

    public bool Collecting { get; set; }

    public string Sensitivity { get; set; } = "standard";

    public int FlowCount { get; set; }

    public long EventsSeen { get; set; }

    /// <summary>被淘汰/解析失败的事件数；0 表示没观察到丢失。</summary>
    public long EventsLost { get; set; }

    public int AlertsNew { get; set; }

    public int AlertsTotal { get; set; }

    public DateTime? LastAlertUtc { get; set; }

    public int SuppressionCount { get; set; }
}

/// <summary>
/// 3.5：一个程序（或一个拿不到路径的 PID）本次服务运行以来的 TCP 流量。
///
/// 只统计 TCP，且是「服务看到连接之后」的字节数：短连接、UDP、已被系统
/// 回收的连接都可能漏计。界面必须把这条限制写出来，不能把它当精确账单。
/// </summary>
public sealed class TrafficDto
{
    /// <summary>聚合键：程序完整路径（小写），或 <c>pid:123</c>。</summary>
    public string Key { get; set; } = string.Empty;

    /// <summary>程序完整路径；拿不到时为 null。</summary>
    public string? Path { get; set; }

    /// <summary>显示名（文件名或「PID 123」）。</summary>
    public string Name { get; set; } = string.Empty;

    /// <summary>路径是否真的解析到了（false 表示这是 PID 兜底项）。</summary>
    public bool IsPathKnown { get; set; }

    /// <summary>这些字节属于哪些 PID（界面按 PID 匹配当前连接）。</summary>
    public List<int>? Pids { get; set; }

    /// <summary>下载字节数（TCP 数据字节）。</summary>
    public long BytesIn { get; set; }

    /// <summary>上传字节数（TCP 数据字节）。</summary>
    public long BytesOut { get; set; }

    /// <summary>最后一次统计到流量的时间（UTC）。</summary>
    public DateTime LastSeenUtc { get; set; }
}

/// <summary>一条规则的 IPC 表示（与界面表格字段对应）。</summary>
public sealed class RuleDto
{
    public string Name { get; set; } = string.Empty;

    /// <summary>program / ip。</summary>
    public string Kind { get; set; } = "program";

    /// <summary>程序路径，或 IP。</summary>
    public string Value { get; set; } = string.Empty;

    /// <summary>block / allow。</summary>
    public string Action { get; set; } = "block";

    /// <summary>到期标记（空 = 永久）。</summary>
    public string Expiry { get; set; } = string.Empty;

    /// <summary>作用范围标记（空 = 不限）。</summary>
    public string Scope { get; set; } = string.Empty;

    public string Group { get; set; } = string.Empty;

    public bool Enabled { get; set; } = true;
}

/// <summary>3.5：一个 PID 的路径解析结果。路径为 null 表示进程已退出或无法读取。</summary>
public sealed class ProcessPathDto
{
    public int Pid { get; set; }

    public string? Path { get; set; }

    /// <summary>英文错误码（not_found / access_denied / invalid_pid），界面负责翻译。</summary>
    public string? Error { get; set; }
}

/// <summary>服务状态快照（v1）。</summary>
public sealed class ServiceStatus
{
    public string ServiceVersion { get; set; } = "0.0.0";

    public int ProtocolVersion { get; set; } = ServiceProtocol.Version;

    /// <summary>本工具的子层是否还在。</summary>
    public bool SublayerPresent { get; set; }

    /// <summary>阻止类规则数量（程序 + IP）。</summary>
    public int BlockRuleCount { get; set; }

    /// <summary>允许类规则数量（白名单）。</summary>
    public int AllowRuleCount { get; set; }

    /// <summary>封禁 IP 规则数量。</summary>
    public int IpRuleCount { get; set; }

    /// <summary>严格模式是否正在生效（3.0-c 起由服务持有；3.0-a 恒为 false）。</summary>
    public bool StrictModeActive { get; set; }

    /// <summary>严格模式当前放行的程序数量（3.0-c）。</summary>
    public int StrictModePermittedCount { get; set; }

    // ---- 3.5：临时锁网 ----

    /// <summary>
    /// 当前严格模式是否由「临时锁网」建立。
    /// 手动开启严格模式时为 false —— 两种状态不能混在一起，否则界面会显示错的倒计时。
    /// </summary>
    public bool StrictModeLockdownActive { get; set; }

    /// <summary>临时锁网到期时间（UTC）；未锁网为 null。</summary>
    public DateTime? StrictModeLockdownExpiresUtc { get; set; }

    /// <summary>临时锁网剩余秒数（0 = 未锁网）。服务端算，界面不要自己猜。</summary>
    public int StrictModeLockdownRemainingSeconds { get; set; }

    /// <summary>审计开关（机器级设置）。</summary>
    public bool AuditEnabled { get; set; }

    /// <summary>审计采集是否真的在跑（服务实际状态）。</summary>
    public bool AuditCollecting { get; set; }

    /// <summary>3.5：流量采集是否在跑（ETW 会话不可用时为 false）。</summary>
    public bool TrafficCollecting { get; set; }

    /// <summary>3.5：本次服务运行解析到的网络数据事件数（诊断/验收用）。</summary>
    public long TrafficEventsSeen { get; set; }

    /// <summary>3.5：DNS ETW 采集是否在跑（启动失败/被系统停止时为 false）。</summary>
    public bool DnsCollecting { get; set; }

    // ---- 3.7：IDS ----

    /// <summary>IDS 是否在设置里开启。</summary>
    public bool IdsEnabled { get; set; }

    /// <summary>IDS 实际是否在采集（ETW 回调已挂上）。</summary>
    public bool IdsCollecting { get; set; }

    /// <summary>未确认的告警数。</summary>
    public int IdsAlertsNew { get; set; }

    /// <summary>当前内存里的 flow 数。</summary>
    public int IdsFlowCount { get; set; }

    /// <summary>IDS 观察到的网络事件数。</summary>
    public long IdsEventsSeen { get; set; }

    /// <summary>审计设置：域名推测。</summary>
    public bool AuditDomainLookup { get; set; }

    /// <summary>审计设置：保留天数。</summary>
    public int AuditRetentionDays { get; set; }

    /// <summary>本次服务运行以来写入的记录条数。</summary>
    public int AuditEventsWritten { get; set; }

    // ---- 3.0-c：篡改防护 ----

    /// <summary>本次服务运行以来自动重建的规则条数（外部删除导致）。</summary>
    public int TamperRebuiltCount { get; set; }

    /// <summary>最近一次检测到规则被外部删除的时间（UTC）。</summary>
    public DateTime? LastTamperUtc { get; set; }

    /// <summary>服务启动以来自动解除的到期规则总数。</summary>
    public int ExpiredPurgedCount { get; set; }

    /// <summary>最近一次自动解除的程序路径（最多 20 条）。</summary>
    public List<string>? LastPurgedPrograms { get; set; }

    // ---- 3.1：受保护模式 ----

    /// <summary>服务是否成功加载了受保护模式配置（失败关闭时为 false）。</summary>
    public bool ProtectedMode { get; set; }

    /// <summary>所有者显示名（只读展示）。</summary>
    public string? ProtectedModeOwner { get; set; }

    /// <summary>所有者 SID。</summary>
    public string? ProtectedModeOwnerSid { get; set; }

    /// <summary>服务正在使用的公钥指纹（完整 64 位十六进制）。</summary>
    public string? ProtectedModeFingerprint { get; set; }

    /// <summary>本次服务运行以来签名验证失败的次数。</summary>
    public int AuthRejectedCount { get; set; }
}
