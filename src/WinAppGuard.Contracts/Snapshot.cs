using System.Text;
using System.Text.Json;

namespace WinAppGuard.Contracts;

/// <summary>
/// 规则的权威副本（3.0-c）。
///
/// 服务每次成功写入规则后更新它；界面在服务不可用时读它，
/// 显示"上次已知状态"（明确标注不是实时状态）。
/// 后续篡改防护也会拿它当"应该有哪些规则"的基准。
/// </summary>
public sealed class RuleSnapshot
{
    /// <summary>文件格式版本（不兼容变更时 +1）。</summary>
    public int Version { get; set; } = 1;

    /// <summary>写入时间（UTC）。离线界面要显示"这是什么时候的状态"。</summary>
    public DateTime SavedUtc { get; set; }

    /// <summary>规则列表（含分组）。</summary>
    public List<RuleDto> Rules { get; set; } = new();
}

/// <summary>快照文件的读写（原子写；坏文件按"没有"处理，绝不让界面崩）。</summary>
public static class RuleSnapshotFile
{
    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
    };

    /// <summary>原子写：先写临时文件再替换，避免界面读到写了一半的 JSON。</summary>
    public static void Write(string path, RuleSnapshot snapshot)
    {
        var directory = Path.GetDirectoryName(path);

        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        snapshot.SavedUtc = DateTime.UtcNow;

        var json = JsonSerializer.Serialize(snapshot, Options);
        var temporary = path + ".tmp";

        File.WriteAllText(temporary, json, new UTF8Encoding(false));
        File.Move(temporary, path, overwrite: true);
    }

    /// <summary>读快照；文件不存在、损坏、版本不认识都返回 null。</summary>
    public static RuleSnapshot? TryRead(string path)
    {
        try
        {
            if (!File.Exists(path))
            {
                return null;
            }

            var snapshot = JsonSerializer.Deserialize<RuleSnapshot>(
                File.ReadAllText(path, Encoding.UTF8), Options);

            if (snapshot is null || snapshot.Version != 1 || snapshot.Rules is null)
            {
                return null;
            }

            return snapshot;
        }
        catch (Exception)
        {
            return null;
        }
    }
}
