using System.Security.Cryptography;

namespace WinAppGuard.Core.Audit;

/// <summary>数据迁移结果。</summary>
/// <param name="Migrated">成功迁移的文件数（含"目标已有相同内容"的去重删除）。</param>
/// <param name="Failed">失败并保留源文件的数量。</param>
/// <param name="Message">给人看的一句话。</param>
internal sealed record AuditMigrationResult(int Migrated, int Failed, string Message);

/// <summary>
/// 把 2.x 的用户目录审计记录迁移到 3.0 的机器级目录（方案 C：复制 → 校验 → 删源）。
///
/// 为什么必须校验：记录文件丢了没法重建，而"复制一半就删源"是最糟的结果。
/// 所以只在**哈希一致**之后才删除源文件；任何一步失败都保留源文件。
/// 目标已存在同名文件时：内容相同 → 删源去重；内容不同 → 保留双方并报失败，
/// 绝不覆盖已有记录。
/// </summary>
internal static class AuditMigration
{
    internal static AuditMigrationResult Migrate(string sourceDirectory, string targetDirectory)
    {
        if (!Directory.Exists(sourceDirectory))
        {
            return new AuditMigrationResult(0, 0, "没有旧记录需要迁移。");
        }

        Directory.CreateDirectory(targetDirectory);

        var migrated = 0;
        var failed = 0;

        foreach (var source in Directory.GetFiles(sourceDirectory, "audit-*.jsonl"))
        {
            var name = Path.GetFileName(source);
            var target = Path.Combine(targetDirectory, name);
            var temporary = target + ".migrating";

            try
            {
                if (File.Exists(target))
                {
                    if (string.Equals(Hash(source), Hash(target), StringComparison.Ordinal))
                    {
                        // 之前迁过一半：目标内容完整，删掉源文件即可。
                        File.Delete(source);
                        migrated++;
                    }
                    else
                    {
                        failed++;
                        LocalLog.Warning(
                            $"记录迁移：目标已有同名文件但内容不同，保留双方：{name}");
                    }

                    continue;
                }

                File.Copy(source, temporary, overwrite: true);

                if (!string.Equals(Hash(temporary), Hash(source), StringComparison.Ordinal))
                {
                    TryDelete(temporary);
                    failed++;
                    LocalLog.Warning($"记录迁移：复制后校验不一致，保留源文件：{name}");
                    continue;
                }

                File.Move(temporary, target);
                File.Delete(source);
                migrated++;
            }
            catch (Exception ex)
            {
                TryDelete(temporary);
                failed++;
                LocalLog.Warning($"记录迁移失败（保留源文件）：{name} — {ex.Message}");
            }
        }

        var message = failed == 0
            ? $"记录迁移完成：{migrated} 个文件。"
            : $"记录迁移：成功 {migrated} 个，失败 {failed} 个（失败的源文件已保留）。";

        if (migrated > 0 || failed > 0)
        {
            LocalLog.Operation(message);
        }

        return new AuditMigrationResult(migrated, failed, message);
    }

    private static string Hash(string path)
    {
        using var stream = File.OpenRead(path);
        return Convert.ToHexString(SHA256.HashData(stream));
    }

    private static void TryDelete(string path)
    {
        try
        {
            if (File.Exists(path))
            {
                File.Delete(path);
            }
        }
        catch (Exception)
        {
            // 临时文件删不掉不影响结论。
        }
    }
}
