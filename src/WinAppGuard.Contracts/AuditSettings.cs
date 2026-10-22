using System.Text;
using System.Text.Json;

namespace WinAppGuard.Contracts;

/// <summary>
/// 审计（记录页）的机器级设置（3.0-c 起由服务持有）。
///
/// 为什么不再放用户设置：采集发生在服务里（SYSTEM），服务不知道哪个用户登录；
/// 记录本身也是机器级的（WFP 事件不分用户），设置必须跟数据在同一个层级。
/// </summary>
public sealed class AuditSettings
{
    public bool Enabled { get; set; } = true;

    public bool DomainLookup { get; set; } = true;

    public int RetentionDays { get; set; } = 7;

    public const int MinRetentionDays = 1;
    public const int MaxRetentionDays = 30;
    public const int DefaultRetentionDays = 7;

    public AuditSettings Clone() => new()
    {
        Enabled = Enabled,
        DomainLookup = DomainLookup,
        RetentionDays = RetentionDays,
    };

    /// <summary>把越界的保留期拉回合法范围。</summary>
    public void Normalize()
    {
        if (RetentionDays < MinRetentionDays || RetentionDays > MaxRetentionDays)
        {
            RetentionDays = DefaultRetentionDays;
        }
    }
}

/// <summary>审计设置的读写（原子写；坏文件回落默认值）。</summary>
public static class AuditSettingsFile
{
    private static readonly JsonSerializerOptions Options = new()
    {
        WriteIndented = true,
    };

    public static AuditSettings Read(string path)
    {
        try
        {
            if (!File.Exists(path))
            {
                return new AuditSettings();
            }

            var settings = JsonSerializer.Deserialize<AuditSettings>(
                File.ReadAllText(path, Encoding.UTF8), Options) ?? new AuditSettings();

            settings.Normalize();
            return settings;
        }
        catch (Exception)
        {
            return new AuditSettings();
        }
    }

    public static void Write(string path, AuditSettings settings)
    {
        var directory = Path.GetDirectoryName(path);

        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        settings.Normalize();

        var temporary = path + ".tmp";
        File.WriteAllText(temporary, JsonSerializer.Serialize(settings, Options), new UTF8Encoding(false));
        File.Move(temporary, path, overwrite: true);
    }
}
