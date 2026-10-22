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
}

/// <summary>一条 IPC 响应。</summary>
public sealed class ServiceResponse
{
    public string Id { get; set; } = string.Empty;

    public bool Ok { get; set; }

    /// <summary>失败原因（只在 <see cref="Ok"/> 为 false 时非空）。</summary>
    public string? Error { get; set; }

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

    /// <summary>审计开关（机器级设置）。</summary>
    public bool AuditEnabled { get; set; }

    /// <summary>审计采集是否真的在跑（服务实际状态）。</summary>
    public bool AuditCollecting { get; set; }

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
}
