using System.Text.Json;

namespace WinAppGuard.Localization;

/// <summary>
/// 读取 GUI 已经生效的语言（供 CLI 使用）。
///
/// 只读同一个 ui-state.json 的 AppliedLanguage / Language 字段；
/// 不写文件、不依赖 UI 程序集。文件缺失/损坏时返回 null = 跟随系统。
/// 注意：ui-state.json 的属性名是 PascalCase（System.Text.Json 默认），
/// 所以这里按名称**不区分大小写**查找。
/// </summary>
public static class UiLanguageStore
{
    /// <summary>默认状态文件路径。</summary>
    public static string DefaultPath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        AppConstants.AppDataFolderName,
        "ui-state.json");

    /// <summary>
    /// 读取 GUI 已生效的语言：优先 AppliedLanguage，旧文件没有该字段时退回 Language。
    /// </summary>
    /// <param name="path">仅测试用；传 null 读真实的 ui-state.json。</param>
    public static string? ReadAppliedLanguage(string? path = null)
    {
        try
        {
            var file = path ?? DefaultPath;

            if (!File.Exists(file))
            {
                return null;
            }

            using var document = JsonDocument.Parse(File.ReadAllText(file));
            var values = new Dictionary<string, string?>(StringComparer.OrdinalIgnoreCase);

            foreach (var property in document.RootElement.EnumerateObject())
            {
                if (property.Value.ValueKind == JsonValueKind.String)
                {
                    values[property.Name] = property.Value.GetString();
                }
            }

            foreach (var key in new[] { "appliedLanguage", "language" })
            {
                if (values.TryGetValue(key, out var language)
                    && language is "auto" or "zh" or "en")
                {
                    return language;
                }
            }

            return null;
        }
        catch (Exception)
        {
            return null;
        }
    }
}
