using System.Security.Principal;
using System.Text.Json;

namespace WinAppGuard.Core.ProtectedMode;

/// <summary>
/// 受保护模式的公开配置（3.1）。
///
/// 只包含公开信息：所有者、公钥、entropy、指纹；
/// **私钥绝不写进这个文件**。
/// 服务启动时读它来验签；界面用它判断当前账户是不是所有者。
/// </summary>
internal sealed class ProtectedModeConfig
{
    internal const int CurrentVersion = 1;

    internal static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        PropertyNameCaseInsensitive = true,
    };

    public int Version { get; set; } = CurrentVersion;

    /// <summary>所有者的 SID（字符串形式，S-1-5-...）。</summary>
    public string OwnerSid { get; set; } = string.Empty;

    /// <summary>所有者的显示名（DOMAIN\user），只用于展示/日志。</summary>
    public string OwnerName { get; set; } = string.Empty;

    /// <summary>ECDSA P-256 公钥（SubjectPublicKeyInfo）的 Base64。</summary>
    public string PublicKey { get; set; } = string.Empty;

    /// <summary>DPAPI entropy（32 字节）的 Base64；不是机密。</summary>
    public string Entropy { get; set; } = string.Empty;

    /// <summary>公钥 SHA-256 的十六进制（64 字符）。</summary>
    public string Fingerprint { get; set; } = string.Empty;

    public DateTimeOffset CreatedUtc { get; set; }

    internal SecurityIdentifier GetOwnerSid() => new(OwnerSid);

    internal byte[] GetPublicKeyBytes() => Convert.FromBase64String(PublicKey);

    internal byte[] GetEntropyBytes() => Convert.FromBase64String(Entropy);

    /// <summary>严格校验；任何一项不对都按“配置损坏”处理，不猜。</summary>
    internal void Validate()
    {
        if (Version != CurrentVersion)
        {
            throw new InvalidDataException($"不认识受保护模式配置版本：{Version}。");
        }

        if (string.IsNullOrWhiteSpace(OwnerSid))
        {
            throw new InvalidDataException("受保护模式配置缺少所有者 SID。");
        }

        try
        {
            _ = new SecurityIdentifier(OwnerSid);
        }
        catch (Exception ex)
        {
            throw new InvalidDataException("受保护模式配置里的所有者 SID 无效。", ex);
        }

        if (string.IsNullOrWhiteSpace(PublicKey))
        {
            throw new InvalidDataException("受保护模式配置缺少公钥。");
        }

        byte[] publicKey;

        try
        {
            publicKey = GetPublicKeyBytes();
        }
        catch (FormatException ex)
        {
            throw new InvalidDataException("受保护模式配置里的公钥不是合法 Base64。", ex);
        }

        try
        {
            using var key = OwnerKey.ImportPublicKey(publicKey);

            if (!string.Equals(key.Fingerprint, Fingerprint, StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidDataException("受保护模式配置里的公钥与指纹不一致。");
            }
        }
        catch (InvalidDataException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new InvalidDataException("受保护模式配置里的公钥无效。", ex);
        }

        byte[] entropy;

        try
        {
            entropy = GetEntropyBytes();
        }
        catch (FormatException ex)
        {
            throw new InvalidDataException("受保护模式配置里的 entropy 不是合法 Base64。", ex);
        }

        if (entropy.Length != 32)
        {
            throw new InvalidDataException("受保护模式配置里的 entropy 必须是 32 字节。");
        }

        if (CreatedUtc == default)
        {
            throw new InvalidDataException("受保护模式配置缺少创建时间。");
        }
    }

    internal static ProtectedModeConfig Load(string path)
    {
        var json = File.ReadAllText(path);

        ProtectedModeConfig? config;

        try
        {
            config = JsonSerializer.Deserialize<ProtectedModeConfig>(json, JsonOptions);
        }
        catch (JsonException ex)
        {
            throw new InvalidDataException($"受保护模式配置不是合法 JSON：{path}", ex);
        }

        if (config is null)
        {
            throw new InvalidDataException($"受保护模式配置为空：{path}");
        }

        config.Validate();
        return config;
    }

    internal byte[] ToJsonBytes() => JsonSerializer.SerializeToUtf8Bytes(this, JsonOptions);
}
