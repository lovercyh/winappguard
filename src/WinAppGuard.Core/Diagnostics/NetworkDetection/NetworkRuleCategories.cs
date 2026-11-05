namespace WinAppGuard.Core.Diagnostics.NetworkDetection;

/// <summary>
/// 5.1：反网络攻击的规则分类。
///
/// 分类文件由构建/安装包生成，运行时只按用户选择拼接成 active.rules。
/// 分类 id 同时是规则文件名（malware.rules 等）。
/// </summary>
public static class NetworkRuleCategories
{
    public const string Malware = "malware";
    public const string Exploit = "exploit";
    public const string Dns = "dns";
    public const string Ja3 = "ja3";
    public const string Coinminer = "coinminer";
    public const string Phishing = "phishing";
    public const string WebClient = "web_client";
    public const string Other = "other";

    public static readonly IReadOnlyList<string> All = new[]
    {
        Malware,
        Exploit,
        Dns,
        Ja3,
        Coinminer,
        Phishing,
        WebClient,
        Other,
    };

    /// <summary>默认启用：除钓鱼外全部开启。</summary>
    public static readonly IReadOnlyList<string> DefaultEnabled = new[]
    {
        Malware,
        Exploit,
        Dns,
        Ja3,
        Coinminer,
        WebClient,
        Other,
    };

    public static bool IsKnown(string? id)
        => !string.IsNullOrWhiteSpace(id)
           && All.Contains(id, StringComparer.OrdinalIgnoreCase);

    public static string FileName(string id) => id + ".rules";

    /// <summary>界面显示名；英文模式由 Localizer 翻译。</summary>
    public static string DisplayName(string id) => id switch
    {
        Malware => "恶意软件",
        Exploit => "漏洞利用",
        Dns => "DNS",
        Ja3 => "TLS / JA3",
        Coinminer => "挖矿",
        Phishing => "钓鱼",
        WebClient => "Web 客户端",
        Other => "其他",
        _ => id,
    };
}
