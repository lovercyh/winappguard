using System.Text.Json;

namespace WinAppGuard.Core.Storage;

/// <summary>
/// 5.9：状态文件只有一种写法。
///
/// 新格式：
/// <code>
/// {
///   "schema": 1,
///   "savedAtUtc": "...",
///   "data": { ... }
/// }
/// </code>
///
/// 兼容策略：
///   - 新代码读取旧的无外壳 JSON 时，直接按 T 反序列化；
///   - 提供 <see cref="Migrate"/> 时，旧数据先交给迁移函数；
///   - schema 不匹配且没有迁移函数 → 不静默覆盖，保留现场并报错；
///   - 坏文件改名为 .corrupt-*，保留现场。
///
/// 安全敏感文件（OwnerKey / 受保护模式 / WFP DACL 标记）不使用本类。
/// </summary>
public sealed class JsonStateFile<T> where T : class, new()
{
    public static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    /// <summary>迁移函数可复用的反序列化：与状态文件相同的 camelCase/大小写不敏感选项。</summary>
    public static T? Deserialize(JsonElement element) => element.Deserialize<T>(JsonOptions);

    public JsonStateFile(string path, int schemaVersion)
    {
        if (string.IsNullOrWhiteSpace(path))
        {
            throw new ArgumentException("状态文件路径不能为空。", nameof(path));
        }

        Path = path;
        SchemaVersion = schemaVersion;
    }

    public string Path { get; }

    public int SchemaVersion { get; }

    /// <summary>旧 schema → 当前 schema 的迁移函数；返回 null 表示无法迁移。</summary>
    public Func<JsonElement, T?>? Migrate { get; init; }

    public T? Load(out string? error)
        => Load(out error, out _);

    /// <summary>
    /// 读取状态。<paramref name="migrated"/> 为 true 表示文件是旧格式或旧 schema，
    /// 调用方应尽快 <see cref="Save"/> 一次，完成“读旧写新”。
    /// </summary>
    public T? Load(out string? error, out bool migrated)
    {
        error = null;
        migrated = false;

        if (!File.Exists(Path))
        {
            return null;
        }

        try
        {
            var json = File.ReadAllText(Path);
            using var document = JsonDocument.Parse(json);
            var root = document.RootElement;

            if (root.ValueKind != JsonValueKind.Object)
            {
                // 旧格式可能不是对象（例如 FirstSeen 旧文件是顶层数组）。
                // 有迁移函数时先交给它；迁移不了才按损坏处理。
                if (Migrate is not null)
                {
                    var converted = Migrate(root);

                    if (converted is not null)
                    {
                        migrated = true;
                        return converted;
                    }
                }

                error = "状态文件顶层不是对象。";
                BackupCorruptFile();
                return null;
            }

            if (root.TryGetProperty("data", out var data)
                && root.TryGetProperty("schema", out var schemaElement)
                && schemaElement.TryGetInt32(out var schema))
            {
                if (schema != SchemaVersion)
                {
                    if (Migrate is null)
                    {
                        error = $"状态文件 schema={schema}，当前需要 {SchemaVersion}，没有迁移函数。";
                        return null;
                    }

                    var converted = Migrate(data);

                    if (converted is null)
                    {
                        error = $"状态文件 schema={schema} 无法迁移到 {SchemaVersion}。";
                        return null;
                    }

                    migrated = true;
                    return converted;
                }

                var value = data.Deserialize<T>(JsonOptions);

                if (value is null)
                {
                    error = "状态文件的 data 为空或类型不匹配。";
                    BackupCorruptFile();
                }

                return value;
            }

            // 旧格式：没有外壳。先尝试迁移函数，再按原结构反序列化。
            var legacy = Migrate is not null
                ? Migrate(root)
                : root.Deserialize<T>(JsonOptions);

            if (legacy is null)
            {
                error = "状态文件是旧格式，且无法迁移。";
            }
            else
            {
                migrated = true;
            }

            return legacy;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            BackupCorruptFile();
            return null;
        }
    }

    public void Save(T value)
    {
        ArgumentNullException.ThrowIfNull(value);

        var directory = System.IO.Path.GetDirectoryName(Path);

        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        var wrapper = new StateEnvelope<T>
        {
            Schema = SchemaVersion,
            SavedAtUtc = DateTime.UtcNow,
            Data = value,
        };

        var json = JsonSerializer.Serialize(wrapper, JsonOptions);
        var temporary = Path + ".tmp";

        try
        {
            using (var stream = new FileStream(
                       temporary,
                       FileMode.Create,
                       FileAccess.Write,
                       FileShare.None,
                       4096,
                       FileOptions.WriteThrough))
            using (var writer = new StreamWriter(stream))
            {
                writer.Write(json);
                writer.Flush();
                stream.Flush(flushToDisk: true);
            }

            File.Move(temporary, Path, overwrite: true);
        }
        catch
        {
            try
            {
                if (File.Exists(temporary))
                {
                    File.Delete(temporary);
                }
            }
            catch (Exception)
            {
                // 清理临时文件失败不掩盖原始异常。
            }

            throw;
        }
    }

    private void BackupCorruptFile()
    {
        try
        {
            if (!File.Exists(Path))
            {
                return;
            }

            var suffix = DateTime.UtcNow.ToString("yyyyMMddHHmmssfff");
            var backup = $"{Path}.corrupt-{suffix}";

            if (File.Exists(backup))
            {
                backup += "-" + Guid.NewGuid().ToString("N")[..8];
            }

            File.Move(Path, backup, overwrite: false);
        }
        catch (Exception)
        {
            // 备份失败不改变 Load 的返回值；调用方仍会拿到错误。
        }
    }

    private sealed class StateEnvelope<TData> where TData : class
    {
        public int Schema { get; set; }

        public DateTime SavedAtUtc { get; set; }

        public TData? Data { get; set; }
    }
}
