using System.Globalization;
using System.Reflection;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace WinAppGuard.Localization;

/// <summary>
/// 界面语言切换（3.2）。
///
/// 只影响 GUI：服务、CLI、日志、协议都不变。
/// 语言在启动时确定；切换后保存设置并提示重启，避免运行中重排整个窗体。
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

    /// <summary>
    /// 把英文应用到整棵控件树。只在窗体初始化后调用一次；
    /// 动态状态由对应的刷新方法重新设置，避免把动态值改成静态英文。
    /// </summary>
    public static void Apply(Control root)
    {
        if (!IsEnglish)
        {
            return;
        }

        ApplyControl(root);

        if (root is ToolStrip strip)
        {
            ApplyToolStripItems(strip.Items);
        }
    }

    private static void ApplyControl(Control control)
    {
        if (!string.IsNullOrEmpty(control.Name)
            && English.Controls.TryGetValue(control.Name, out var byName))
        {
            control.Text = byName;
        }
        else if (!string.IsNullOrEmpty(control.Text)
                 && English.Texts.TryGetValue(control.Text, out var byText))
        {
            control.Text = byText;
        }

        if (control is DataGridView grid)
        {
            foreach (DataGridViewColumn column in grid.Columns)
            {
                if (English.Texts.TryGetValue(column.HeaderText, out var header))
                {
                    column.HeaderText = header;
                }
            }
        }

        foreach (Control child in control.Controls)
        {
            ApplyControl(child);
        }

        if (control is ToolStrip childStrip)
        {
            ApplyToolStripItems(childStrip.Items);
        }
    }

    private static void ApplyToolStripItems(ToolStripItemCollection items)
    {
        foreach (ToolStripItem item in items)
        {
            if (English.Texts.TryGetValue(item.Text ?? string.Empty, out var text))
            {
                item.Text = text;
            }

            if (item is ToolStripDropDownItem dropDown)
            {
                ApplyToolStripItems(dropDown.DropDownItems);
            }
        }
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
            // 语言包坏了就回退中文；绝不让界面起不来。
            return new Resource();
        }
    }
}
