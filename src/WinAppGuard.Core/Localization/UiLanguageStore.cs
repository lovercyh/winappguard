using System.Text.Json;

namespace WinAppGuard.Localization;

/// <summary>
/// 读取 GUI 已经生效的语言（供 CLI 使用）。
///
/// 只读同一个 ui-state.json 的 appliedLanguage/language 字段；
/// 不写文件、不依赖 UI 程序集。文件缺失/损坏时返回 null = 跟随系统。
/// </summary>
public static class UiLanguageStore
{
    public static string? ReadAppliedLanguage()
    {
        try
        {
            var path = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                AppConstants.AppDataFolderName,
                "ui-state.json");

            if (!File.Exists(path))
            {
                return null;
            }

            using var document = JsonDocument.Parse(File.ReadAllText(path));
            var root = document.RootElement;

            foreach (var property in new[] { "appliedLanguage", "language" })
            {
                if (root.TryGetProperty(property, out var value)
                    && value.ValueKind == JsonValueKind.String)
                {
                    var language = value.GetString();

                    if (language is "auto" or "zh" or "en")
                    {
                        return language;
                    }
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
