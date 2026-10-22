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
    /// <summary>
    /// 单条消息上限（4 MB）。
    ///
    /// 3.0-b 起 <c>write.rules.import</c> 会把整份规则文件交给服务，而规则文件本身
    /// 允许到 2 MB（见 <c>RuleExport.MaxBytes</c>），64 KB 会直接把正常导入挡掉。
    /// 读取方向的规则列表（几千条）同样可能超过 64 KB。
    /// </summary>
    public const int MaxMessageBytes = 4 * 1024 * 1024;

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

        // ---- 3.0-c：审计（采集在服务，界面只读）----

        /// <summary>修改机器级审计设置（开关 / 域名推测 / 保留期）。</summary>
        public const string AuditConfigure = "write.audit.configure";

        /// <summary>清空全部审计记录（服务先停采集，删完再恢复）。</summary>
        public const string AuditClear = "write.audit.clear";
    }

    /// <summary>JSON 序列化选项（双方必须一致）。</summary>
    public static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
    };
}
