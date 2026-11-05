namespace WinAppGuard.Core;

/// <summary>
/// 5.4：系统 PATH 的纯字符串处理。
///
/// 单独抽出来是为了能在不自检/不修改注册表的情况下断言：
/// 去重、保留其它项、大小写、引号、尾部反斜杠、环境变量展开。
/// 真正读写 Machine PATH 的代码在安装器里。
/// </summary>
public static class EnvironmentPath
{
    /// <summary>PATH 里是否已经有这个目录（大小写不敏感）。</summary>
    public static bool Contains(string? path, string directory)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return false;
        }

        var target = Normalize(directory);

        return Split(path).Any(entry =>
            string.Equals(Normalize(entry), target, StringComparison.OrdinalIgnoreCase));
    }

    /// <summary>
    /// 把目录追加到 PATH；已存在时原样返回。
    /// 保留原有项的顺序和写法，只去掉末尾多余的分号。
    /// </summary>
    public static string Add(string? path, string directory)
    {
        if (Contains(path, directory))
        {
            return path ?? string.Empty;
        }

        var prefix = string.IsNullOrWhiteSpace(path)
            ? string.Empty
            : path.TrimEnd(';') + ";";

        return prefix + directory.Trim();
    }

    /// <summary>
    /// 从 PATH 删除目录；不存在时原样返回。
    ///
    /// 这里会规范化其余项的分隔符（去掉空项和项首尾空格），
    /// 但不会展开/改写其它项里的环境变量。
    /// </summary>
    public static string Remove(string? path, string directory)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            return path ?? string.Empty;
        }

        var target = Normalize(directory);
        var entries = Split(path)
            .Where(entry => !string.Equals(
                Normalize(entry), target, StringComparison.OrdinalIgnoreCase));

        return string.Join(';', entries);
    }

    private static IEnumerable<string> Split(string path)
        => path.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    private static string Normalize(string value)
        => Environment.ExpandEnvironmentVariables(
                value.Trim().Trim('"').TrimEnd('\\'))
            .TrimEnd('\\');
}
