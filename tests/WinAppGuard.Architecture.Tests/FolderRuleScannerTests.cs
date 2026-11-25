using WinAppGuard.Core;

namespace WinAppGuard.Architecture.Tests;

public sealed class FolderRuleScannerTests
{
    [Fact]
    public void FindsExeRecursivelyAndIgnoresOtherFiles()
    {
        var root = CreateTempDirectory();

        try
        {
            File.WriteAllText(Path.Combine(root, "a.exe"), "x");
            File.WriteAllText(Path.Combine(root, "b.txt"), "x");

            var sub = Directory.CreateDirectory(Path.Combine(root, "sub"));
            File.WriteAllText(Path.Combine(sub.FullName, "c.exe"), "x");

            var recursive = FolderRuleScanner.Scan(root, recursive: true);
            var flat = FolderRuleScanner.Scan(root, recursive: false);

            Assert.Equal(2, recursive.Files.Count);
            Assert.Single(flat.Files);
            Assert.EndsWith("a.exe", flat.Files[0], StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            TryDelete(root);
        }
    }

    [Fact]
    public void StopsAtLimitAndMarksTruncated()
    {
        var root = CreateTempDirectory();

        try
        {
            for (var i = 0; i < 5; i++)
            {
                File.WriteAllText(Path.Combine(root, $"p{i}.exe"), "x");
            }

            var result = FolderRuleScanner.Scan(root, recursive: false, maxFiles: 3);

            Assert.Equal(3, result.Files.Count);
            Assert.True(result.Truncated);
        }
        finally
        {
            TryDelete(root);
        }
    }

    [Fact]
    public void RejectsMissingFolderAndNetworkPath()
    {
        var missing = FolderRuleScanner.Scan(
            Path.Combine(Path.GetTempPath(), "wag-no-such-folder-" + Guid.NewGuid().ToString("N")),
            recursive: true);

        Assert.Empty(missing.Files);
        Assert.NotEmpty(missing.Errors);

        var unc = FolderRuleScanner.Scan(@"\\server\share", recursive: true);

        Assert.Empty(unc.Files);
        Assert.Contains(unc.Errors, error => error.Contains("网络路径", StringComparison.Ordinal));
    }

    [Fact]
    public void IncludesHiddenExe()
    {
        var root = CreateTempDirectory();

        try
        {
            var hidden = Path.Combine(root, "hidden.exe");
            File.WriteAllText(hidden, "x");
            File.SetAttributes(hidden, FileAttributes.Hidden);

            var result = FolderRuleScanner.Scan(root, recursive: false);

            Assert.Single(result.Files);
            Assert.Equal(hidden, result.Files[0], StringComparer.OrdinalIgnoreCase);
        }
        finally
        {
            TryDelete(root);
        }
    }

    private static string CreateTempDirectory()
    {
        var path = Path.Combine(
            Path.GetTempPath(), "wag-folder-scan-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(path);
        return path;
    }

    private static void TryDelete(string path)
    {
        try
        {
            Directory.Delete(path, recursive: true);
        }
        catch (Exception)
        {
            // 临时目录删不掉不影响测试结论。
        }
    }
}
