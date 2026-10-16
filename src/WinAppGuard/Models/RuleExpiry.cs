using System.Globalization;

namespace WinAppGuard.Models;

/// <summary>阻断的到期方式。</summary>
public enum RuleExpiryKind
{
    /// <summary>永久，直到用户手动解除。</summary>
    Never = 0,

    /// <summary>到某个 UTC 时刻自动解除。</summary>
    AtTime,

    /// <summary>到下次重启自动解除。</summary>
    OnNextBoot,
}

/// <summary>
/// 一条防火墙规则的「自动解除」信息。
///
/// <b>存在哪里</b>：存在**规则自己的 Description 里**——不另建文件、不写设置文件。
/// 这么设计有三个好处：
///   1. 规则和到期时间永远绑在一起，不会出现「规则还在、时间丢了」；
///   2. 用户在 <c>wf.msc</c> 里双击规则就能**直接看到**什么时候解除（透明）；
///   3. 不需要新增任何本机文件 —— 也就不会碰到
///      「设置文件只存布尔值、不存 IP / 路径 / 时间戳」那条既有约定。
///
/// <b>编码格式</b>（放在描述的最后，便于解析）：
/// <code>
///   永久     不写标记
///   限时     自动解除=2026-10-16T10:30:00Z
///   下次重启 自动解除=重启@2026-10-16T09:00:00Z     （@ 后面是创建时推算出的开机时刻）
/// </code>
///
/// 「永久不写标记」这一条很重要：**旧版本创建的规则没有标记，因此天然被当成永久**，
/// 不会被新版本误删。
///
/// <b>解析不出来时一律当作永久</b>——宁可让用户手动解除，也不要自动删掉一条看不懂的规则。
/// </summary>
public sealed record RuleExpiry(RuleExpiryKind Kind, DateTime? ExpiresAtUtc, DateTime? BootTimeUtc)
{
    /// <summary>描述里的标记前缀。</summary>
    private const string MarkerPrefix = "自动解除=";

    /// <summary>「下次重启」这类值的前缀。</summary>
    private const string OnBootPrefix = "重启@";

    /// <summary>时间格式（UTC，不带毫秒，短且好读）。</summary>
    private const string TimeFormat = "yyyy-MM-ddTHH:mm:ssZ";

    /// <summary>
    /// 判断「开机时刻变了」的容差。
    ///
    /// 不能要求完全相等：休眠、时钟同步、夏令时都可能让「当前时间 − 开机时长」
    /// 这个推算值漂移。5 分钟足够吸收这些噪声，又远小于任何一次真实重启的间隔。
    /// </summary>
    public static readonly TimeSpan BootTimeTolerance = TimeSpan.FromMinutes(5);

    /// <summary>永久：不写标记。</summary>
    public static readonly RuleExpiry Never = new(RuleExpiryKind.Never, null, null);

    /// <summary>到指定 UTC 时刻解除。</summary>
    public static RuleExpiry At(DateTime utc) => new(RuleExpiryKind.AtTime, utc.ToUniversalTime(), null);

    /// <summary>到下次重启解除。<paramref name="bootTimeUtc"/> 是创建时推算出的开机时刻。</summary>
    public static RuleExpiry OnNextBoot(DateTime bootTimeUtc)
        => new(RuleExpiryKind.OnNextBoot, null, bootTimeUtc.ToUniversalTime());

    /// <summary>是不是永久规则。</summary>
    public bool IsPermanent => Kind == RuleExpiryKind.Never;

    /// <summary>
    /// 生成要写进规则 Description 的那段标记。永久规则返回空字符串。
    /// </summary>
    public string Encode() => Kind switch
    {
        RuleExpiryKind.AtTime when ExpiresAtUtc is { } at =>
            MarkerPrefix + at.ToUniversalTime().ToString(TimeFormat, CultureInfo.InvariantCulture),

        RuleExpiryKind.OnNextBoot when BootTimeUtc is { } boot =>
            MarkerPrefix + OnBootPrefix + boot.ToUniversalTime().ToString(TimeFormat, CultureInfo.InvariantCulture),

        _ => string.Empty,
    };

    /// <summary>
    /// 从规则 Description 里解析到期信息。
    /// 找不到标记、或标记看不懂，一律返回 <see cref="Never"/>（永久）。
    /// </summary>
    public static RuleExpiry Parse(string? description)
    {
        if (string.IsNullOrEmpty(description))
        {
            return Never;
        }

        // 用 LastIndexOf：万一程序路径里恰好含这个词，也以最后一个（我们写的那个）为准。
        var index = description.LastIndexOf(MarkerPrefix, StringComparison.Ordinal);
        if (index < 0)
        {
            return Never;
        }

        var value = description[(index + MarkerPrefix.Length)..].Trim();

        if (value.StartsWith(OnBootPrefix, StringComparison.Ordinal))
        {
            var bootText = value[OnBootPrefix.Length..].Trim();
            return TryParseTime(bootText, out var boot) ? OnNextBoot(boot) : Never;
        }

        return TryParseTime(value, out var at) ? At(at) : Never;
    }

    /// <summary>
    /// 现在是不是已经到期了。
    /// </summary>
    /// <param name="nowUtc">当前 UTC 时间。</param>
    /// <param name="currentBootTimeUtc">
    /// 当前这次开机的时刻（由 <c>现在 − 开机时长</c> 推算）。
    /// 只有「下次重启」这类规则会用到它。
    /// </param>
    /// <param name="freshLogonSession">
    /// 本次程序是不是**由登录触发的开机自启拉起的**。
    ///
    /// 这个参数是为了兜住一个实测踩到的坑：**Windows 的「快速启动」**。
    /// 用「关机 → 开机」时，内核是从休眠文件恢复的，**开机时长不会归零** ——
    /// 于是「现在 − 开机时长」推出来的开机时刻和上次**完全一样**，
    /// 光靠它判断会得出「没重启过」，规则就永远不解除（用户实际报过这个问题）。
    ///
    /// 而「登录触发的自启动跑起来了」这件事是**确定无疑**的：
    /// 它就意味着刚刚发生过一次登录（重启或重新登录都算）。
    /// </param>
    public bool IsExpired(DateTime nowUtc, DateTime currentBootTimeUtc, bool freshLogonSession = false) => Kind switch
    {
        RuleExpiryKind.AtTime when ExpiresAtUtc is { } at => nowUtc.ToUniversalTime() >= at,

        // 「下次重启」有两个判定信号，命中任意一个就算过期：
        //   1. 本次是新的登录会话（登录触发的自启动拉起了本程序）；
        //   2. 开机时刻变了（真正的重启，开机时长归零）。
        // 保留第 2 条是因为「用户没开自启、手动打开程序」时它仍然能起作用。
        RuleExpiryKind.OnNextBoot when BootTimeUtc is { } boot =>
            freshLogonSession
            || (currentBootTimeUtc.ToUniversalTime() - boot).Duration() > BootTimeTolerance,

        // 永久：永远不到期。
        _ => false,
    };

    /// <summary>
    /// 给用户看的说明（例如「永久」「剩余 12 分钟」「重启后解除」）。
    /// </summary>
    public string Describe(DateTime nowUtc)
    {
        switch (Kind)
        {
            case RuleExpiryKind.AtTime when ExpiresAtUtc is { } at:
            {
                var remaining = at - nowUtc.ToUniversalTime();
                if (remaining <= TimeSpan.Zero)
                {
                    return "已到期";
                }

                return remaining.TotalHours >= 1
                    ? $"剩余 {Math.Floor(remaining.TotalHours)} 小时 {remaining.Minutes} 分钟"
                    : $"剩余 {Math.Max(1, Math.Ceiling(remaining.TotalMinutes))} 分钟";
            }

            case RuleExpiryKind.OnNextBoot:
                return "重启后自动解除";

            default:
                return "永久";
        }
    }

    /// <summary>
    /// 给日志用的说明：说清「什么时候解除」的**绝对**说法。
    /// 与 <see cref="Describe"/> 的区别：那个是倒计时（「剩余 12 分钟」），
    /// 适合界面实时显示；日志里写绝对时间才有追溯价值。
    /// </summary>
    public string DescribeSchedule() => Kind switch
    {
        RuleExpiryKind.AtTime when ExpiresAtUtc is { } at =>
            $"到 {at.ToLocalTime():yyyy-MM-dd HH:mm}",

        RuleExpiryKind.OnNextBoot => "到下次重启或重新登录",

        _ => "永久",
    };

    private static bool TryParseTime(string text, out DateTime utc)
        => DateTime.TryParseExact(
            text,
            TimeFormat,
            CultureInfo.InvariantCulture,
            DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
            out utc);
}
