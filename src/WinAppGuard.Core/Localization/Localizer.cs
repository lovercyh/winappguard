using System.Globalization;
using System.Reflection;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace WinAppGuard.Localization;

/// <summary>
/// 共享的界面/CLI 文案翻译（3.2 起 GUI，3.3 起 CLI）。
///
/// 这里刻意**不引用 WinForms**：服务、CLI、安装器都可以用；
/// 控件树的应用逻辑在 UI 程序集的 ControlLocalizer 里。
/// </summary>
public static class Localizer
{
    public enum LanguageMode
    {
        Auto,
        Chinese,
        English,
    }

    private sealed class Resource
    {
        public Dictionary<string, string> Controls { get; set; } =
            new(StringComparer.Ordinal);

        public Dictionary<string, string> Texts { get; set; } =
            new(StringComparer.Ordinal);
    }

    private static readonly Resource English = LoadEnglish();

    public static LanguageMode Current { get; private set; } = LanguageMode.Chinese;

    public static bool IsEnglish => Current == LanguageMode.English;

    public static string LanguageDisplayName => IsEnglish ? "English" : "简体中文";

    /// <summary>根据设置解析语言；auto 时中文系统中文，其它系统一律英文。</summary>
    public static void Initialize(string? setting)
    {
        Current = setting switch
        {
            "zh" => LanguageMode.Chinese,
            "en" => LanguageMode.English,
            _ => CultureInfo.CurrentUICulture.TwoLetterISOLanguageName
                .Equals("zh", StringComparison.OrdinalIgnoreCase)
                ? LanguageMode.Chinese
                : LanguageMode.English,
        };
    }

    /// <summary>翻译一条完整的中文文案；英文资源缺失时保留中文，避免空白。</summary>
    public static string T(string text)
    {
        if (!IsEnglish || string.IsNullOrEmpty(text))
        {
            return text;
        }

        if (English.Texts.TryGetValue(text, out var translated))
        {
            return translated;
        }

        return TranslatePattern(text) ?? text;
    }

    /// <summary>翻译带占位符的格式串，再格式化。</summary>
    public static string F(string format, params object?[] args)
        => string.Format(CultureInfo.CurrentCulture, T(format), args);

    /// <summary>控件名优先，其次按当前中文文案；都没有返回 fallback。</summary>
    public static string TranslateControl(string? name, string fallback)
    {
        if (!IsEnglish)
        {
            return fallback;
        }

        if (!string.IsNullOrEmpty(name)
            && English.Controls.TryGetValue(name, out var byName))
        {
            return byName;
        }

        return string.IsNullOrEmpty(fallback) ? fallback : T(fallback);
    }

    private static readonly (Regex Pattern, string Replacement)[] DynamicPatterns =
    {
        (new Regex(@"^确定要把「(.+)」加入白名单吗？$"), "Add “$1” to the whitelist?"),
        (new Regex(@"^确定要把「(.+)」移出白名单吗？$"), "Remove “$1” from the whitelist?"),
        (new Regex(@"^确定要移除全部 (\d+) 个白名单程序吗？$"), "Remove all $1 whitelist programs?"),
        (new Regex(@"^确定要阻止「(.+)」联网吗？$"), "Block network access for “$1”?"),
        (new Regex(@"^确定要解除对「(.+)」的阻止吗？$"), "Unblock “$1”?"),
        (new Regex(@"^确定要清空黑名单吗？（共 (\d+) 条阻止规则）$"), "Clear the blocklist? ($1 block rules)"),
        (new Regex(@"^确定要把这 (\d+) 条规则导入(.+)吗？$"), "Import $1 rules into $2?"),
        (new Regex(@"^确定要删除全部记录吗？$"), "Delete all records?"),
        (new Regex(@"^确定要封禁 IP「(.+)」吗？$"), "Block IP “$1”?"),
        (new Regex(@"^确定要让 WinAppGuard 随 Windows 开机自动启动吗？$"), "Start WinAppGuard automatically at Windows logon?"),
        (new Regex(@"^确定要删除开机自启任务吗？$"), "Delete the auto-start task?"),
        (new Regex(@"^确定要退出 WinAppGuard 吗？$"), "Exit WinAppGuard?"),
        (new Regex(@"^确定要关闭严格模式吗？$"), "Disable strict mode?"),
        (new Regex(@"^确定要继续吗？$"), "Continue?"),
        (new Regex(@"^剩余 (\d+) 小时 (\d+) 分钟$"), "$1 h $2 min left"),
        (new Regex(@"^剩余 (\d+) 分钟$"), "$1 min left"),
        (new Regex(@"^未知\((\d+)\)$"), "Unknown ($1)"),
        (new Regex(@"^(\d+) 个$"), "$1"),
        (new Regex(@"^(\d+) 条$"), "$1"),
        (new Regex(@"^（ID (\d+)）$"), "(ID $1)"),
        (new Regex(@"^当前被阻止的 (\d+) 个程序会继续保持被阻止状态。$"),
            "The $1 currently blocked programs stay blocked."),
        (new Regex(@"^(\d+) 个正在联网、但没加白名单的程序$"),
            "$1 connected programs are not on the whitelist."),
        (new Regex(@"^本工具白名单 (\d+) 个程序 \+ 本程序 \+ (\d+) 个系统必需程序$"),
            "This app's whitelist: $1 programs + this app + $2 required system programs."),
        (new Regex(@"^确认后该程序会立刻无法联网；实测中它当前正在进行中的 (\d+) 条连接也会马上断开（浏览器会立刻掉线）。$"),
            "Once confirmed, the program cannot connect immediately; its $1 active connections drop at once (browsers go offline)."),
        (new Regex(@"^只拦「(.+)」：其它端口 / 网络位置上的连接不受影响。$"),
            "Only \"$1\" is blocked: connections on other ports or networks are unaffected."),
        (new Regex(@"^（(\d+) 个）$"), "($1)"),
    };

    private static string? TranslatePattern(string text)
    {
        foreach (var (pattern, replacement) in DynamicPatterns)
        {
            if (pattern.IsMatch(text))
            {
                return pattern.Replace(text, replacement);
            }
        }

        return null;
    }

    private static Resource LoadEnglish()
    {
        try
        {
            using var stream = Assembly.GetExecutingAssembly()
                .GetManifestResourceStream("WinAppGuard.Localization.en.json");

            if (stream is null)
            {
                return new Resource();
            }

            return JsonSerializer.Deserialize<Resource>(
                       stream,
                       new JsonSerializerOptions { PropertyNameCaseInsensitive = true })
                   ?? new Resource();
        }
        catch (Exception)
        {
            // 语言包坏了就回退中文；绝不让界面/CLI 起不来。
            return new Resource();
        }
    }
}
