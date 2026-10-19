using System.Text.Json;

namespace WinAppGuard.Contracts;

/// <summary>
/// 服务与界面之间的 IPC 约定。
///
/// 命名管道名带 <c>v1</c>：协议不兼容时**换一个管道**，而不是在同一管道里猜版本 ——
/// 这样旧界面连不上新服务时会立刻失败并给出明确提示，而不是发出一条被误解的指令。
/// </summary>
public static class ServiceProtocol
{
    /// <summary>管道名（不带 <c>\\.\pipe\</c> 前缀）。</summary>
    public const string PipeName = "WinAppGuard.Control.v1";

    /// <summary>协议版本。任何不兼容的字段变化都要 +1。</summary>
    public const int Version = 1;

    /// <summary>单条消息上限（64 KB）。正常请求只有几百字节。</summary>
    public const int MaxMessageBytes = 64 * 1024;

    /// <summary>服务显示名（安装/卸载、SCM 里看到的名字）。</summary>
    public const string ServiceName = "WinAppGuardSvc";

    /// <summary>服务显示名（给人看的）。</summary>
    public const string ServiceDisplayName = "WinAppGuard 防护服务";

    /// <summary>服务描述。</summary>
    public const string ServiceDescription = "维护 WinAppGuard 的 WFP 规则与审计记录。停掉它不会删除已有规则。";

    /// <summary>请求里的命令名（v1 只有只读命令）。</summary>
    public static class Commands
    {
        public const string Status = "status";
        public const string Ping = "ping";
    }

    /// <summary>JSON 序列化选项（双方必须一致）。</summary>
    public static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
    };
}
