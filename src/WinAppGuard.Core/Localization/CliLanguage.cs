namespace WinAppGuard.Localization;

/// <summary>
/// CLI 语言解析（3.3）。
///
/// 优先级固定为：<c>--lang</c> &gt; GUI 已生效语言 &gt; 系统语言（auto）。
/// 单独抽成纯函数是为了能被自检直接断言 —— 这条优先级一旦写错，
/// 用户会遇到"GUI 是英文、命令行却是中文"的怪现象。
/// </summary>
public static class CliLanguage
{
    /// <summary>
    /// 解析本次 CLI 使用的语言。
    /// </summary>
    /// <param name="requested"><c>--lang</c> 的值；没传时为 null。</param>
    /// <param name="applied">GUI 已生效的语言；读不到时为 null。</param>
    /// <param name="language">解析结果：auto / zh / en。</param>
    /// <returns>参数合法返回 true；<c>--lang</c> 非法返回 false。</returns>
    public static bool TryResolve(string? requested, string? applied, out string language)
    {
        var value = requested ?? applied ?? "auto";

        if (value is "auto" or "zh" or "en")
        {
            language = value;
            return true;
        }

        language = "auto";
        return false;
    }
}
