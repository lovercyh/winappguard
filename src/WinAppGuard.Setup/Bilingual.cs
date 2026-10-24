namespace WinAppGuard.Setup;

/// <summary>
/// 安装器 / 卸载器的**固定双语**输出（3.3）。
///
/// 这里刻意不做语言开关：安装器可能被中文用户、英文用户、以及看不懂当前
/// 系统语言的用户运行，所以每条消息都同时给出中文和英文。
///   - 短状态行：中文 | English 在同一行；
///   - 警告 / 错误 / 长说明：中文一行、英文一行，避免长句挤成一行看不清。
/// </summary>
internal static class Bilingual
{
    private const string Separator = "  |  ";

    /// <summary>把一对中英文拼成一行（供需要自己调用 Console 的地方使用）。</summary>
    internal static string One(string chinese, string english)
        => $"{chinese}{Separator}{english}";

    /// <summary>输出一条短状态：中文 | English。</summary>
    internal static void Say(string chinese, string english)
        => Console.WriteLine(One(chinese, english));

    /// <summary>输出一条警告/错误：中文一行、英文一行（写到标准错误）。</summary>
    internal static void Fail(string chinese, string english)
        => Console.Error.WriteLine(chinese + Environment.NewLine + english);
}
