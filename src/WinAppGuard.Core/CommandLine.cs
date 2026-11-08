namespace WinAppGuard.Core;

/// <summary>命令行模式要执行的命令。</summary>
public enum CommandKind
{
    /// <summary>没有命令行指令 —— 照常启动图形界面（双击就是这个路径）。</summary>
    None,

    /// <summary><c>--block &lt;程序路径&gt;</c></summary>
    Block,

    /// <summary><c>--list-blocked</c></summary>
    ListBlocked,

    /// <summary><c>--unblock-all [--yes]</c></summary>
    UnblockAll,

    /// <summary><c>--migrate</c>：把 1.x 的规则迁到 2.0（通常不用手动执行）。</summary>
    Migrate,

    /// <summary><c>--recover</c>：清掉本程序留下的一切，把机器恢复原状。</summary>
    Recover,

    /// <summary><c>--help</c></summary>
    Help,

    /// <summary>参数写错了。</summary>
    Invalid,

    /// <summary>5.3：显示版本。</summary>
    Version,

    /// <summary>5.3：显示服务 / 规则 / 检测状态。</summary>
    Status,

    /// <summary>5.3：列出规则（可按动作过滤）。</summary>
    ListRules,

    /// <summary>5.3：解除某个程序的阻止规则。</summary>
    Unblock,

    /// <summary>5.3：导出规则文件。</summary>
    ExportRules,

    /// <summary>5.3：导入规则文件。</summary>
    ImportRules,

    /// <summary>5.3：反网络攻击状态。</summary>
    NetworkStatus,

    /// <summary>5.3：反网络攻击告警列表。</summary>
    NetworkAlerts,

    /// <summary>5.3：标记一条反网络攻击告警为已读。</summary>
    NetworkAck,

    /// <summary>5.3：清空反网络攻击告警。</summary>
    NetworkClear,

    /// <summary>5.3：对一条反网络攻击告警发起手动拦截。</summary>
    NetworkBlock,

    /// <summary>5.3：释放一个手动拦截。</summary>
    NetworkUnblock,

    /// <summary>5.3：释放全部手动拦截。</summary>
    NetworkUnblockAll,

    /// <summary>5.3：设置监听网卡。</summary>
    NetworkSetAdapter,

    /// <summary>5.3：设置规则分类。</summary>
    NetworkSetCategories,

    /// <summary>5.3：只读诊断。</summary>
    Doctor,

    /// <summary>5.3：读取最近审计记录。</summary>
    AuditTail,

    /// <summary>5.7：列出当前 TCP 连接（只读）。</summary>
    Connections,

    /// <summary>5.7：列出当前 DNS 查询记录（只读）。</summary>
    Dns,

    /// <summary>5.3：服务状态（--status 的别名，保留给脚本）。</summary>
    ServiceStatus,

    /// <summary>5.3：显示日志目录。</summary>
    LogPath,
}

/// <summary>解析后的命令行选项。</summary>
/// <param name="Kind">要执行的命令。</param>
/// <param name="ProgramPath">主参数：程序路径、规则文件、告警 id、网卡 id 等。</param>
/// <param name="Confirmed">是否带了 <c>--yes</c>。</param>
/// <param name="IsAutostart">是否由「开机自启」计划任务拉起（命令行含 <c>--autostart</c>）。</param>
/// <param name="Error">参数错误时的说明；没错时为 null。</param>
/// <param name="Language"><c>--lang</c> 的值（zh / en / auto）；没传时为 null。</param>
public sealed record CommandLineOptions(
    CommandKind Kind,
    string? ProgramPath,
    bool Confirmed,
    bool IsAutostart,
    string? Error,
    string? Language = null)
{
    /// <summary>5.3：输出 JSON。</summary>
    public bool Json { get; init; }

    /// <summary>5.3：text / tsv / json。</summary>
    public string Format { get; init; } = "text";

    /// <summary>5.3：只输出错误和必要结果。</summary>
    public bool Quiet { get; init; }

    /// <summary>5.3：只预览，不执行。</summary>
    public bool DryRun { get; init; }

    /// <summary>5.3：--unblock 找不到时返回失败。</summary>
    public bool RequireMatch { get; init; }

    /// <summary>5.3：--minutes 的值。</summary>
    public int? Minutes { get; init; }

    /// <summary>5.3：到下次重启解除。</summary>
    public bool UntilReboot { get; init; }

    /// <summary>5.3：按规则名解除。</summary>
    public string? RuleName { get; init; }

    /// <summary>5.3：block / allow / all。</summary>
    public string? Action { get; init; }

    /// <summary>5.3：网络拦截范围。</summary>
    public string? Scope { get; init; }

    /// <summary>5.3：列表 / 审计条数上限。</summary>
    public int Limit { get; init; } = 50;

    /// <summary>5.3：是否显式给了 --limit。</summary>
    public bool LimitSpecified { get; init; }

    /// <summary>5.3：只显示未读告警。</summary>
    public bool UnreadOnly { get; init; }
}

/// <summary>
/// 命令行参数解析。
///
/// 解析保持为**纯函数**：不读服务、不碰系统，自检可以在普通权限下断言所有组合。
/// 约定：
///   - 参数不区分大小写；
///   - 只有 <c>--autostart</c> 被忽略掉之后没有任何其它参数时，才启动图形界面；
///   - 无法识别的参数一律报错，不静默忽略。
/// </summary>
public static class CommandLine
{
    public const string BlockSwitch = "--block";
    public const string ListBlockedSwitch = "--list-blocked";
    public const string UnblockAllSwitch = "--unblock-all";
    public const string MigrateSwitch = "--migrate";
    public const string RecoverSwitch = "--recover";
    public const string YesSwitch = "--yes";
    public const string HelpSwitch = "--help";
    public const string AutostartSwitch = "--autostart";
    public const string LanguageSwitch = "--lang";

    public const string VersionSwitch = "--version";
    public const string StatusSwitch = "--status";
    public const string ServiceStatusSwitch = "--service-status";
    public const string ListRulesSwitch = "--list-rules";
    public const string UnblockSwitch = "--unblock";
    public const string ExportRulesSwitch = "--export-rules";
    public const string ImportRulesSwitch = "--import-rules";
    public const string NetworkStatusSwitch = "--network-status";
    public const string NetworkAlertsSwitch = "--network-alerts";
    public const string NetworkAckSwitch = "--network-ack";
    public const string NetworkClearSwitch = "--network-clear";
    public const string NetworkBlockSwitch = "--network-block";
    public const string NetworkUnblockSwitch = "--network-unblock";
    public const string NetworkUnblockAllSwitch = "--network-unblock-all";
    public const string NetworkSetAdapterSwitch = "--network-set-adapter";
    public const string NetworkSetCategoriesSwitch = "--network-set-categories";
    public const string DoctorSwitch = "--doctor";
    public const string AuditTailSwitch = "--audit-tail";
    public const string ConnectionsSwitch = "--connections";
    public const string DnsSwitch = "--dns";
    public const string LogPathSwitch = "--log-path";

    public const string JsonSwitch = "--json";
    public const string FormatSwitch = "--format";
    public const string QuietSwitch = "--quiet";
    public const string DryRunSwitch = "--dry-run";
    public const string RequireMatchSwitch = "--require-match";
    public const string MinutesSwitch = "--minutes";
    public const string UntilRebootSwitch = "--until-reboot";
    public const string ActionSwitch = "--action";
    public const string ScopeSwitch = "--scope";
    public const string NameSwitch = "--name";
    public const string LimitSwitch = "--limit";
    public const string UnreadSwitch = "--unread";

    /// <summary>解析命令行。</summary>
    public static CommandLineOptions Parse(IReadOnlyList<string> args)
    {
        var isAutostart = args.Any(arg => Is(arg, AutostartSwitch));
        var language = (string?)null;
        var json = false;
        var format = "text";
        var quiet = false;
        var remaining = new List<string>();

        for (var i = 0; i < args.Count; i++)
        {
            var arg = args[i];

            if (Is(arg, LanguageSwitch))
            {
                if (i + 1 >= args.Count)
                {
                    return Invalid(isAutostart, true,
                        $"{LanguageSwitch} 后面要跟 zh / en / auto",
                        $"{LanguageSwitch} must be followed by zh, en or auto");
                }

                language = args[++i];
                continue;
            }

            if (arg.StartsWith(LanguageSwitch + "=", StringComparison.OrdinalIgnoreCase))
            {
                language = arg[(LanguageSwitch.Length + 1)..];
                continue;
            }

            if (Is(arg, JsonSwitch))
            {
                json = true;
                format = "json";
                continue;
            }

            if (Is(arg, QuietSwitch))
            {
                quiet = true;
                continue;
            }

            if (Is(arg, FormatSwitch))
            {
                if (i + 1 >= args.Count)
                {
                    return Invalid(isAutostart, true,
                        $"{FormatSwitch} 后面要跟 text / tsv / json",
                        $"{FormatSwitch} must be followed by text, tsv or json",
                        language);
                }

                format = args[++i];
                continue;
            }

            if (arg.StartsWith(FormatSwitch + "=", StringComparison.OrdinalIgnoreCase))
            {
                format = arg[(FormatSwitch.Length + 1)..];
                continue;
            }

            remaining.Add(arg);
        }

        language = language?.ToLowerInvariant();

        if (language is not null && language is not ("auto" or "zh" or "en"))
        {
            return Invalid(isAutostart, true,
                $"{LanguageSwitch} 只能是 zh / en / auto。",
                $"{LanguageSwitch} must be zh, en or auto.",
                language);
        }

        format = format.ToLowerInvariant();

        if (format is not ("text" or "tsv" or "json"))
        {
            return Invalid(isAutostart, true,
                $"{FormatSwitch} 只能是 text / tsv / json。",
                $"{FormatSwitch} must be text, tsv or json.",
                language);
        }

        if (format == "json")
        {
            json = true;
        }

        var english = language switch
        {
            "en" => true,
            "zh" => false,
            _ => !System.Globalization.CultureInfo.CurrentUICulture
                .TwoLetterISOLanguageName.Equals("zh", StringComparison.OrdinalIgnoreCase),
        };

        if (remaining.Any(arg => Is(arg, HelpSwitch) || Is(arg, "-h") || Is(arg, "/?")))
        {
            return new CommandLineOptions(
                CommandKind.Help, null, false, isAutostart, null, language)
            {
                Json = json,
                Format = format,
                Quiet = quiet,
            };
        }

        var tokens = remaining.Where(arg => !Is(arg, AutostartSwitch)).ToList();

        if (tokens.Count == 0)
        {
            return new CommandLineOptions(
                CommandKind.None, null, false, isAutostart, null, language)
            {
                Json = json,
                Format = format,
                Quiet = quiet,
            };
        }

        var command = tokens[0].ToLowerInvariant();
        var parsed = ParseCommand(
            command, tokens.Skip(1).ToList(), isAutostart, english, language);

        return parsed with
        {
            Json = json,
            Format = format,
            Quiet = quiet,
        };
    }

    private static CommandLineOptions ParseCommand(
        string command,
        IReadOnlyList<string> tokens,
        bool isAutostart,
        bool english,
        string? language)
    {
        var positionals = new List<string>();
        var flags = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        for (var i = 0; i < tokens.Count; i++)
        {
            var token = tokens[i];

            if (!token.StartsWith('-'))
            {
                positionals.Add(token);
                continue;
            }

            if (Is(token, YesSwitch))
            {
                flags.Add(YesSwitch);
                continue;
            }

            if (Is(token, DryRunSwitch))
            {
                flags.Add(DryRunSwitch);
                continue;
            }

            if (Is(token, RequireMatchSwitch))
            {
                flags.Add(RequireMatchSwitch);
                continue;
            }

            if (Is(token, UntilRebootSwitch))
            {
                flags.Add(UntilRebootSwitch);
                continue;
            }

            if (Is(token, UnreadSwitch))
            {
                flags.Add(UnreadSwitch);
                continue;
            }

            if (Is(token, MinutesSwitch)
                || Is(token, ActionSwitch)
                || Is(token, ScopeSwitch)
                || Is(token, NameSwitch)
                || Is(token, LimitSwitch))
            {
                if (i + 1 >= tokens.Count)
                {
                    return InvalidArg(
                        isAutostart, english, language,
                        $"{token} 后面要跟一个值。",
                        $"{token} must be followed by a value.");
                }

                values[token] = tokens[++i];
                continue;
            }

            return InvalidArg(
                isAutostart, english, language,
                $"无法识别的参数：{token}",
                $"Unknown argument: {token}");
        }

        CommandLineOptions Make(CommandKind kind)
        {
            var minutes = (int?)null;

            if (values.TryGetValue(MinutesSwitch, out var minutesText))
            {
                if (!int.TryParse(minutesText, out var parsedMinutes)
                    || parsedMinutes < 1
                    || parsedMinutes > 43_200)
                {
                    return InvalidArg(
                        isAutostart, english, language,
                        $"{MinutesSwitch} 必须是 1–43200 之间的整数。",
                        $"{MinutesSwitch} must be an integer between 1 and 43200.");
                }

                minutes = parsedMinutes;
            }

            var limit = 50;

            if (values.TryGetValue(LimitSwitch, out var limitText))
            {
                if (!int.TryParse(limitText, out limit) || limit < 1 || limit > 5000)
                {
                    return InvalidArg(
                        isAutostart, english, language,
                        $"{LimitSwitch} 必须是 1–5000 之间的整数。",
                        $"{LimitSwitch} must be an integer between 1 and 5000.");
                }
            }

            return new CommandLineOptions(
                kind,
                positionals.Count > 0 ? positionals[0] : null,
                flags.Contains(YesSwitch),
                isAutostart,
                null,
                language)
            {
                DryRun = flags.Contains(DryRunSwitch),
                RequireMatch = flags.Contains(RequireMatchSwitch),
                UntilReboot = flags.Contains(UntilRebootSwitch),
                UnreadOnly = flags.Contains(UnreadSwitch),
                Minutes = minutes,
                RuleName = values.TryGetValue(NameSwitch, out var name) ? name : null,
                Action = values.TryGetValue(ActionSwitch, out var action)
                    ? action.ToLowerInvariant()
                    : null,
                Scope = values.TryGetValue(ScopeSwitch, out var scope)
                    ? scope.ToLowerInvariant()
                    : null,
                Limit = limit,
                LimitSpecified = values.ContainsKey(LimitSwitch),
            };
        }

        bool NoPositionals()
            => positionals.Count == 0;

        bool OnePositional()
            => positionals.Count == 1 && !string.IsNullOrWhiteSpace(positionals[0]);

        bool OnlyFlags(params string[] allowed)
            => flags.All(flag => allowed.Contains(flag, StringComparer.OrdinalIgnoreCase));

        bool OnlyValues(params string[] allowed)
            => values.Keys.All(key => allowed.Contains(key, StringComparer.OrdinalIgnoreCase));

        switch (command)
        {
            case BlockSwitch:
                if (!OnePositional())
                {
                    return InvalidArg(
                        isAutostart, english, language,
                        $"{BlockSwitch} 后面要跟程序的完整路径，例如：--block \"C:\\Tools\\a.exe\"",
                        $"{BlockSwitch} must be followed by the full path, e.g. --block \"C:\\Tools\\a.exe\"");
                }

                var blockBatch = positionals[0].StartsWith('@');

                if (!(blockBatch
                        ? OnlyFlags(DryRunSwitch, UntilRebootSwitch, YesSwitch)
                        : OnlyFlags(DryRunSwitch, UntilRebootSwitch))
                    || !OnlyValues(MinutesSwitch))
                {
                    return InvalidArg(
                        isAutostart, english, language,
                        "这里不支持这个参数。",
                        "This argument is not supported here.");
                }

                if (flags.Contains(UntilRebootSwitch)
                    && values.ContainsKey(MinutesSwitch))
                {
                    return InvalidArg(
                        isAutostart, english, language,
                        $"{UntilRebootSwitch} 和 {MinutesSwitch} 不能同时使用。",
                        $"{UntilRebootSwitch} and {MinutesSwitch} cannot be used together.");
                }

                return Make(CommandKind.Block);

            case ListBlockedSwitch:
                return NoPositionals() && flags.Count == 0 && values.Count == 0
                    ? Make(CommandKind.ListBlocked)
                    : InvalidArg(isAutostart, english, language,
                        $"多余的参数：{positionals.FirstOrDefault() ?? flags.FirstOrDefault() ?? values.Keys.FirstOrDefault()}",
                        $"Unexpected argument: {positionals.FirstOrDefault() ?? flags.FirstOrDefault() ?? values.Keys.FirstOrDefault()}");

            case UnblockAllSwitch:
                return NoPositionals()
                       && OnlyFlags(YesSwitch)
                       && values.Count == 0
                    ? Make(CommandKind.UnblockAll)
                    : InvalidArg(isAutostart, english, language,
                        $"无法识别的参数：{flags.FirstOrDefault(flag => !Is(flag, YesSwitch)) ?? values.Keys.FirstOrDefault() ?? positionals.FirstOrDefault()}",
                        $"Unknown argument: {flags.FirstOrDefault(flag => !Is(flag, YesSwitch)) ?? values.Keys.FirstOrDefault() ?? positionals.FirstOrDefault()}");

            case MigrateSwitch:
                return NoPositionals() && flags.Count == 0 && values.Count == 0
                    ? Make(CommandKind.Migrate)
                    : InvalidArg(isAutostart, english, language,
                        $"多余的参数：{positionals.FirstOrDefault()}",
                        $"Unexpected argument: {positionals.FirstOrDefault()}");

            case RecoverSwitch:
                return NoPositionals() && flags.Count == 0 && values.Count == 0
                    ? Make(CommandKind.Recover)
                    : InvalidArg(isAutostart, english, language,
                        $"多余的参数：{positionals.FirstOrDefault()}",
                        $"Unexpected argument: {positionals.FirstOrDefault()}");

            case VersionSwitch:
                return NoPositionals() && flags.Count == 0 && values.Count == 0
                    ? Make(CommandKind.Version)
                    : InvalidArg(isAutostart, english, language,
                        $"{VersionSwitch} 不接受其它参数。",
                        $"{VersionSwitch} takes no other arguments.");

            case StatusSwitch:
            case ServiceStatusSwitch:
                return NoPositionals() && flags.Count == 0 && values.Count == 0
                    ? Make(command == StatusSwitch ? CommandKind.Status : CommandKind.ServiceStatus)
                    : InvalidArg(isAutostart, english, language,
                        $"{command} 不接受其它参数。",
                        $"{command} takes no other arguments.");

            case ListRulesSwitch:
                return NoPositionals()
                       && flags.Count == 0
                       && OnlyValues(ActionSwitch, LimitSwitch)
                       && (values.TryGetValue(ActionSwitch, out var actionValue)
                           ? actionValue.ToLowerInvariant() is "block" or "allow" or "all"
                           : true)
                    ? Make(CommandKind.ListRules)
                    : InvalidArg(isAutostart, english, language,
                        $"{ListRulesSwitch} 只接受 --action block|allow|all 和 --limit N。",
                        $"{ListRulesSwitch} only accepts --action block|allow|all and --limit N.");

            case UnblockSwitch:
                if ((positionals.Count == 0 && !values.ContainsKey(NameSwitch))
                    || positionals.Count > 1
                    || (positionals.Count > 0 && values.ContainsKey(NameSwitch)))
                {
                    return InvalidArg(isAutostart, english, language,
                        $"{UnblockSwitch} 后面要跟程序路径，或使用 --name 规则名（二选一）。",
                        $"{UnblockSwitch} needs a program path, or --name RULE (not both).");
                }

                return OnlyFlags(DryRunSwitch, RequireMatchSwitch)
                       && OnlyValues(NameSwitch)
                    ? Make(CommandKind.Unblock)
                    : InvalidArg(isAutostart, english, language,
                        $"{UnblockSwitch} 只接受 --dry-run、--require-match、--name。",
                        $"{UnblockSwitch} only accepts --dry-run, --require-match and --name.");

            case ExportRulesSwitch:
                return OnePositional()
                       && OnlyFlags(YesSwitch)
                       && OnlyValues(ActionSwitch)
                       && (values.TryGetValue(ActionSwitch, out var exportAction)
                           ? exportAction.ToLowerInvariant() is "block" or "allow"
                           : true)
                    ? Make(CommandKind.ExportRules)
                    : InvalidArg(isAutostart, english, language,
                        $"{ExportRulesSwitch} <文件> [--action block|allow] [--yes]",
                        $"{ExportRulesSwitch} <file> [--action block|allow] [--yes]");

            case ImportRulesSwitch:
                return OnePositional()
                       && OnlyFlags(DryRunSwitch, YesSwitch)
                       && OnlyValues(ActionSwitch)
                       && (values.TryGetValue(ActionSwitch, out var importAction)
                           ? importAction.ToLowerInvariant() is "block" or "allow"
                           : true)
                    ? Make(CommandKind.ImportRules)
                    : InvalidArg(isAutostart, english, language,
                        $"{ImportRulesSwitch} <文件> [--action block|allow] [--dry-run] [--yes]",
                        $"{ImportRulesSwitch} <file> [--action block|allow] [--dry-run] [--yes]");

            case NetworkStatusSwitch:
                return NoPositionals() && flags.Count == 0 && values.Count == 0
                    ? Make(CommandKind.NetworkStatus)
                    : InvalidArg(isAutostart, english, language,
                        $"{NetworkStatusSwitch} 不接受其它参数。",
                        $"{NetworkStatusSwitch} takes no other arguments.");

            case NetworkAlertsSwitch:
                return NoPositionals()
                       && OnlyFlags(UnreadSwitch)
                       && OnlyValues(LimitSwitch)
                    ? Make(CommandKind.NetworkAlerts)
                    : InvalidArg(isAutostart, english, language,
                        $"{NetworkAlertsSwitch} 只接受 --limit N 和 --unread。",
                        $"{NetworkAlertsSwitch} only accepts --limit N and --unread.");

            case NetworkAckSwitch:
                return OnePositional() && flags.Count == 0 && values.Count == 0
                    ? Make(CommandKind.NetworkAck)
                    : InvalidArg(isAutostart, english, language,
                        $"{NetworkAckSwitch} <告警 id>",
                        $"{NetworkAckSwitch} <alert id>");

            case NetworkClearSwitch:
                return NoPositionals() && OnlyFlags(YesSwitch) && values.Count == 0
                    ? Make(CommandKind.NetworkClear)
                    : InvalidArg(isAutostart, english, language,
                        $"{NetworkClearSwitch} [--yes]",
                        $"{NetworkClearSwitch} [--yes]");

            case NetworkBlockSwitch:
                if (!OnePositional())
                {
                    return InvalidArg(isAutostart, english, language,
                        $"{NetworkBlockSwitch} <告警 id> --scope ip-port|connection|ip [--minutes N] [--yes]",
                        $"{NetworkBlockSwitch} <alert id> --scope ip-port|connection|ip [--minutes N] [--yes]");
                }

                if (!OnlyFlags(YesSwitch)
                    || !OnlyValues(ScopeSwitch, MinutesSwitch)
                    || !values.TryGetValue(ScopeSwitch, out var blockScope)
                    || blockScope.ToLowerInvariant() is not ("ip-port" or "connection" or "ip"))
                {
                    return InvalidArg(isAutostart, english, language,
                        $"{NetworkBlockSwitch} 需要 --scope ip-port|connection|ip，且只接受 --minutes 和 --yes。",
                        $"{NetworkBlockSwitch} needs --scope ip-port|connection|ip; only --minutes and --yes are accepted.");
                }

                return Make(CommandKind.NetworkBlock);

            case NetworkUnblockSwitch:
                return OnePositional() && flags.Count == 0 && values.Count == 0
                    ? Make(CommandKind.NetworkUnblock)
                    : InvalidArg(isAutostart, english, language,
                        $"{NetworkUnblockSwitch} <拦截 id>",
                        $"{NetworkUnblockSwitch} <block id>");

            case NetworkUnblockAllSwitch:
                return NoPositionals() && OnlyFlags(YesSwitch) && values.Count == 0
                    ? Make(CommandKind.NetworkUnblockAll)
                    : InvalidArg(isAutostart, english, language,
                        $"{NetworkUnblockAllSwitch} [--yes]",
                        $"{NetworkUnblockAllSwitch} [--yes]");

            case NetworkSetAdapterSwitch:
                return OnePositional() && flags.Count == 0 && values.Count == 0
                    ? Make(CommandKind.NetworkSetAdapter)
                    : InvalidArg(isAutostart, english, language,
                        $"{NetworkSetAdapterSwitch} auto|<网卡 GUID>",
                        $"{NetworkSetAdapterSwitch} auto|<adapter GUID>");

            case NetworkSetCategoriesSwitch:
                return OnePositional() && flags.Count == 0 && values.Count == 0
                    ? Make(CommandKind.NetworkSetCategories)
                    : InvalidArg(isAutostart, english, language,
                        $"{NetworkSetCategoriesSwitch} <逗号分隔的分类>",
                        $"{NetworkSetCategoriesSwitch} <comma-separated categories>");

            case DoctorSwitch:
                return NoPositionals() && flags.Count == 0 && values.Count == 0
                    ? Make(CommandKind.Doctor)
                    : InvalidArg(isAutostart, english, language,
                        $"{DoctorSwitch} 不接受其它参数。",
                        $"{DoctorSwitch} takes no other arguments.");

            case AuditTailSwitch:
                return NoPositionals()
                       && flags.Count == 0
                       && OnlyValues(LimitSwitch)
                    ? Make(CommandKind.AuditTail)
                    : InvalidArg(isAutostart, english, language,
                        $"{AuditTailSwitch} [--limit N]",
                        $"{AuditTailSwitch} [--limit N]");

            case ConnectionsSwitch:
                return NoPositionals()
                       && flags.Count == 0
                       && OnlyValues(LimitSwitch)
                    ? Make(CommandKind.Connections)
                    : InvalidArg(isAutostart, english, language,
                        $"{ConnectionsSwitch} [--limit N] [--json]",
                        $"{ConnectionsSwitch} [--limit N] [--json]");

            case DnsSwitch:
                return NoPositionals()
                       && flags.Count == 0
                       && OnlyValues(LimitSwitch)
                    ? Make(CommandKind.Dns)
                    : InvalidArg(isAutostart, english, language,
                        $"{DnsSwitch} [--limit N] [--json]",
                        $"{DnsSwitch} [--limit N] [--json]");

            case LogPathSwitch:
                return NoPositionals() && flags.Count == 0 && values.Count == 0
                    ? Make(CommandKind.LogPath)
                    : InvalidArg(isAutostart, english, language,
                        $"{LogPathSwitch} 不接受其它参数。",
                        $"{LogPathSwitch} takes no other arguments.");

            default:
                return InvalidArg(
                    isAutostart, english, language,
                    $"无法识别的参数：{command}",
                    $"Unknown argument: {command}");
        }
    }

    private static CommandLineOptions InvalidArg(
        bool isAutostart, bool english, string? language,
        string chinese, string englishText)
        => new(
            CommandKind.Invalid, null, false, isAutostart,
            english ? englishText : chinese, language);

    private static CommandLineOptions Invalid(
        bool isAutostart, bool english, string chinese, string englishText,
        string? language = null)
        => new(
            CommandKind.Invalid, null, false, isAutostart,
            english ? englishText : chinese, language);

    private static bool Is(string arg, string expected)
        => string.Equals(arg, expected, StringComparison.OrdinalIgnoreCase);
}
