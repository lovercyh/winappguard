namespace WinAppGuard.Core;

/// <summary>
/// 5.13：文件夹扫描结果。只返回路径，不碰 WFP，便于 UI 预览和单元测试。
/// </summary>
public sealed class FolderScanResult
{
    /// <summary>找到的 .exe 完整路径（已去重、已排序）。</summary>
    public List<string> Files { get; } = new();

    /// <summary>扫描错误（文件夹不存在、网络路径、根目录不可读等）。</summary>
    public List<string> Errors { get; } = new();

    /// <summary>是否因为达到上限而提前停止。</summary>
    public bool Truncated { get; set; }
}

/// <summary>
/// 5.13：扫描文件夹里的 .exe。
///
/// 约束：
///   - 只返回 .exe；
///   - 不跟随 junction / symlink（AttributesToSkip = ReparsePoint）；
///   - 不访问网络路径（UNC）；
///   - 忽略不可读子目录，不因此让整次扫描失败；
///   - 达到上限就停止，并把 Truncated 置为 true。
/// </summary>
public static class FolderRuleScanner
{
    public const int DefaultMaxFiles = 2000;

    public static FolderScanResult Scan(
        string folder,
        bool recursive,
        int maxFiles = DefaultMaxFiles,
        CancellationToken cancellationToken = default)
    {
        var result = new FolderScanResult();

        if (string.IsNullOrWhiteSpace(folder))
        {
            result.Errors.Add("文件夹路径为空。");
            return result;
        }

        string fullPath;

        try
        {
            fullPath = Path.GetFullPath(folder);
        }
        catch (Exception ex)
        {
            result.Errors.Add($"路径无效：{ex.Message}");
            return result;
        }

        if (fullPath.StartsWith(@"\\", StringComparison.Ordinal))
        {
            result.Errors.Add("不支持网络路径（UNC）。");
            return result;
        }

        if (!Directory.Exists(fullPath))
        {
            result.Errors.Add($"文件夹不存在：{fullPath}");
            return result;
        }

        maxFiles = Math.Clamp(maxFiles, 1, 5000);

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        var options = new EnumerationOptions
        {
            RecurseSubdirectories = recursive,
            IgnoreInaccessible = true,
            AttributesToSkip = FileAttributes.ReparsePoint,
            ReturnSpecialDirectories = false,
        };

        try
        {
            foreach (var file in Directory.EnumerateFiles(fullPath, "*", options))
            {
                cancellationToken.ThrowIfCancellationRequested();

                if (!string.Equals(
                        Path.GetExtension(file), ".exe", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                if (!seen.Add(file))
                {
                    continue;
                }

                result.Files.Add(file);

                if (result.Files.Count >= maxFiles)
                {
                    result.Truncated = true;
                    break;
                }
            }
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            result.Errors.Add($"扫描失败：{ex.Message}");
        }

        result.Files.Sort(StringComparer.OrdinalIgnoreCase);
        return result;
    }
}
