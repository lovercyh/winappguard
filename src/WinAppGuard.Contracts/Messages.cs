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
}
