using System.Net;
using System.Net.NetworkInformation;
using WinAppGuard.Models;

namespace WinAppGuard.Core;

/// <summary>
/// 证书吊销状态的检查方式。
///
/// ⚠️ 这个选择直接决定程序**会不会联网**，所以做成显式的枚举，不允许隐式默认。
/// </summary>
public enum RevocationMode
{
    /// <summary>
    /// 只用本机缓存的吊销信息，**绝不联网**。
    ///
    /// 代价：一个证书已被吊销、但本地缓存里没有记录的程序，仍会被判定为「签名有效」。
    /// 关掉证书吊销检查之后，本程序完全不留网络流量。
    /// </summary>
    CacheOnly,

    /// <summary>
    /// 允许联网向 CA 服务器查询证书吊销列表（CRL / OCSP）。
    ///
    /// ⚠️ 此时本程序**会产生对外网络流量**。
    /// 流量是 Windows 证书服务（Crypt32）发起的，不是本程序的代码，
    /// 但从「资源监视器看 WinAppGuard.exe」的角度看是一样的。
    /// 界面上的「设置 → 数据与隐私」里明确告知了这一点。
    /// </summary>
    Online,
}

/// <summary>
/// 检查 PE 文件的数字签名。
///
/// Windows 有**两套**签名机制，缺一不可：
///
///   **内嵌签名** —— 存在 exe 自己的 PE 证书表里。
///                    第三方软件（Chrome / Steam / Git / 微信）基本都是这种。
///
///   **目录签名** —— 存在 C:\Windows\System32\CatRoot\ 的 .cat 文件里，exe 里什么都没有。
///                    大量 Windows 系统文件只有这种：notepad.exe、cmd.exe、winver.exe
///                    全都属于这一类。
///
/// **只查内嵌签名会把大批系统文件误报成「未签名」** —— 这个坑实测踩过，
/// 所以这里两条路径都会走。判定顺序和依据见 <see cref="CheckCore"/>。
///
/// 线程要求：<see cref="Check"/> 和 <see cref="Prefetch"/> 都很慢（要算文件哈希、
/// 验证证书链），**只能在后台线程调用**。界面线程只读已经填好的结果。
/// </summary>
public static class DigitalSignature
{
    /// <summary>
    /// 结果缓存。键是文件完整路径。
    ///
    /// 为什么要缓存：目录签名验证要把整个文件哈希一遍，几十毫秒到几百毫秒；
    /// 而连接列表每 3 秒刷新一次、同一个程序反复出现 —— 不缓存界面会卡死。
    /// 键用路径而不是 PID：签名是**文件**的属性，不是进程的属性。
    /// </summary>
    private static readonly Dictionary<string, CacheEntry> Cache =
        new(StringComparer.OrdinalIgnoreCase);

    /// <summary>4.6：缓存项同时记下“是不是联网查的、当时有没有网关、什么时候查的”。</summary>
    private readonly record struct CacheEntry(
        SignatureInfo Info,
        DateTime FileWriteTimeUtc,
        bool Online,
        bool NetworkAvailable,
        DateTime CheckedUtc);

    /// <summary>4.6：联网结果最多信 5 分钟，避免“链路还在但外网断了”一直显示正常。</summary>
    private static readonly TimeSpan OnlineCacheTtl = TimeSpan.FromMinutes(5);

    /// <summary>缓存会被多个后台线程访问，需要加锁。</summary>
    private static readonly object CacheGate = new();

    // 4.6：有没有默认网关（每 30 秒最多枚举一次网卡）。
    private static readonly object NetworkGate = new();
    private static DateTime _nextGatewayCheckUtc = DateTime.MinValue;
    private static bool _hasDefaultGateway = true;

    /// <summary>已经检查过的不同文件数量。</summary>
    public static int CachedFileCount
    {
        get
        {
            lock (CacheGate)
            {
                return Cache.Count;
            }
        }
    }

    // ==================================================================
    // 对外接口
    // ==================================================================

    /// <summary>
    /// 检查一个文件的签名。重复检查同一个文件会命中缓存。
    /// </summary>
    /// <param name="filePath">文件完整路径。</param>
    /// <param name="mode">吊销检查方式，决定会不会联网。</param>
    public static SignatureInfo Check(string filePath, RevocationMode mode)
    {
        if (string.IsNullOrWhiteSpace(filePath))
        {
            return SignatureInfo.None;
        }

        if (!File.Exists(filePath))
        {
            // 进程可能已经退出，这不是错误，只是查不到了。
            return new SignatureInfo(SignatureState.Unknown, string.Empty, "文件不存在或已无法访问");
        }

        DateTime writeTime;
        try
        {
            writeTime = File.GetLastWriteTimeUtc(filePath);
        }
        catch (Exception)
        {
            writeTime = DateTime.MinValue;
        }

        var online = mode == RevocationMode.Online;
        var gatewayAvailable = online ? HasDefaultGateway() : false;
        var now = DateTime.UtcNow;

        lock (CacheGate)
        {
            // 命中缓存，而且文件没有被改动过。
            // 比对写入时间是为了处理「程序更新了，同一个路径内容变了」的情况。
            //
            // 4.6：联网吊销结果还要和“当前是否有网关”一致、且不超过 5 分钟。
            // 断网后旧的“已验证”缓存必须失效，否则界面会继续显示正常签名，
            // 用户看不出吊销其实没核对。
            if (Cache.TryGetValue(filePath, out var cached)
                && cached.FileWriteTimeUtc == writeTime
                && (!online
                    || (cached.Online
                        && cached.NetworkAvailable == gatewayAvailable
                        && now - cached.CheckedUtc < OnlineCacheTtl)))
            {
                return cached.Info;
            }
        }

        var info = CheckCoreSafe(filePath, mode);

        // 4.6：「无网络」不是文件的稳定属性。不要缓存，否则联网后刷新仍然显示“没核对”。
        if (info.State != SignatureState.RevocationUnknown)
        {
            lock (CacheGate)
            {
                Cache[filePath] = new CacheEntry(
                    info, writeTime, online, gatewayAvailable, now);
            }
        }

        return info;
    }

    /// <summary>
    /// 4.6：只读缓存。扫描时先把已有结论立刻显示出来，
    /// 不用等后台再查一轮（尤其是离线环境下证书吊销检查很慢）。
    /// </summary>
    public static bool TryGetCached(string filePath, RevocationMode mode, out SignatureInfo info)
    {
        info = SignatureInfo.None;

        if (string.IsNullOrWhiteSpace(filePath))
        {
            return false;
        }

        DateTime writeTime;

        try
        {
            writeTime = File.GetLastWriteTimeUtc(filePath);
        }
        catch (Exception)
        {
            return false;
        }

        var online = mode == RevocationMode.Online;
        var gatewayAvailable = online ? HasDefaultGateway() : false;
        var now = DateTime.UtcNow;

        lock (CacheGate)
        {
            if (Cache.TryGetValue(filePath, out var cached)
                && cached.FileWriteTimeUtc == writeTime
                && (!online
                    || (cached.Online
                        && cached.NetworkAvailable == gatewayAvailable
                        && now - cached.CheckedUtc < OnlineCacheTtl)))
            {
                info = cached.Info;
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// 批量检查，命中缓存的会直接跳过。连接列表刷新时调用它。
    /// </summary>
    /// <param name="filePaths">文件路径集合，可以含重复项和空值。</param>
    /// <param name="mode">吊销检查方式。</param>
    public static void Prefetch(IEnumerable<string> filePaths, RevocationMode mode)
    {
        foreach (var path in filePaths)
        {
            if (string.IsNullOrWhiteSpace(path))
            {
                continue;
            }

            Check(path, mode);
        }
    }

    /// <summary>
    /// 清空缓存。用于用户切换了吊销检查方式之后强制重新判定 ——
    /// 因为两种模式下「证书被吊销」的结论可能不一样。
    /// </summary>
    public static void ClearCache()
    {
        lock (CacheGate)
        {
            Cache.Clear();
        }
    }

    /// <summary>
    /// 4.6：网络状态变化（断网/联网）时调用：强制重新判断网关并清空缓存。
    /// 否则断网后旧的“已验证”结果会继续显示。
    /// </summary>
    public static void NotifyNetworkChanged()
    {
        lock (NetworkGate)
        {
            _nextGatewayCheckUtc = DateTime.MinValue;
        }

        ClearCache();
    }

    // ==================================================================
    // 判定逻辑
    // ==================================================================

    /// <summary>
    /// 判定顺序（这个顺序是有讲究的，不要随意调整）：
    ///
    ///   1. 先验**内嵌签名**。
    ///      成功 → 就是结论。
    ///
    ///   2. 内嵌签名报「压根没有签名」时，再去查**目录签名**。
    ///      成功 → 就是结论（系统文件走的就是这条路）。
    ///      目录也查不到 → 才是真的「未签名」。
    ///
    ///   3. 内嵌签名**存在但验证失败**（被篡改 / 证书不受信任 / 已过期）时，
    ///      直接以该结论为准，**不再去查目录**。
    ///
    /// 第 3 条是关键：一个文件如果有内嵌签名却验证不过，说明签名被破坏了 ——
    /// 这时候假如它还恰好被某个目录收录过，去查目录就会把这个严重信号洗白，
    /// 让用户以为一切正常。所以必须在这里停下。
    /// </summary>
    /// <summary>4.6：单个文件检查失败只影响它自己，不中断整批。</summary>
    private static SignatureInfo CheckCoreSafe(string filePath, RevocationMode mode)
    {
        try
        {
            return CheckCore(filePath, mode);
        }
        catch (Exception ex)
        {
            return new SignatureInfo(
                SignatureState.Error,
                string.Empty,
                $"检查签名时出错：{ex.GetType().Name}: {ex.Message}");
        }
    }

    private static SignatureInfo CheckCore(string filePath, RevocationMode mode)
    {
        var allowNetwork = mode == RevocationMode.Online;
        var embedded = CertificateTrust.VerifyEmbedded(filePath, allowNetwork);

        if (embedded.IsTrusted)
        {
            return Valid(embedded, "内嵌签名", mode);
        }

        if (!embedded.IsNoSignature)
        {
            // 有内嵌签名但验证失败 —— 这本身就是结论。见上面第 3 条。
            return Interpret(embedded, mode);
        }

        var catalog = CertificateTrust.VerifyCatalog(filePath, allowNetwork);

        if (catalog.IsTrusted)
        {
            return Valid(catalog, "系统目录签名", mode);
        }

        if (catalog.IsNoSignature)
        {
            return new SignatureInfo(
                SignatureState.Unsigned,
                string.Empty,
                "该文件没有数字签名（内嵌签名和系统目录签名都没有）");
        }

        return Interpret(catalog, mode);
    }

    /// <summary>构造「签名有效」的结果。</summary>
    private static SignatureInfo Valid(TrustResult result, string source, RevocationMode mode)
    {
        if (mode == RevocationMode.Online
            && (result.RevocationUnknown || !HasDefaultGateway()))
        {
            var signer = string.IsNullOrEmpty(result.SignerName)
                ? string.Empty
                : $"（签名者：{result.SignerName}）";

            return new SignatureInfo(
                SignatureState.RevocationUnknown,
                result.SignerName,
                $"签名本身有效（{source}）{signer}，但当前无网络，无法联网查询证书吊销状态。\n" +
                "联网后刷新可重新核对；也可以在「设置 → 数据与隐私」关闭“检查证书吊销状态”。");
        }

        var detail = string.IsNullOrEmpty(result.SignerName)
            ? $"签名有效且受信任（{source}）"
            : $"签名有效且受信任（{source}）：{result.SignerName}";

        return new SignatureInfo(SignatureState.Valid, result.SignerName, detail);
    }

    /// <summary>
    /// 4.6：本机是否存在默认网关。没有网关基本等于没有可用的外网，
    /// 此时吊销检查不可能成功；每 30 秒最多枚举一次网卡。
    /// </summary>
    private static bool HasDefaultGateway()
    {
        lock (NetworkGate)
        {
            var now = DateTime.UtcNow;

            if (now < _nextGatewayCheckUtc)
            {
                return _hasDefaultGateway;
            }

            try
            {
                _hasDefaultGateway = NetworkInterface.GetAllNetworkInterfaces()
                    .Where(nic => nic.OperationalStatus == OperationalStatus.Up
                                  && nic.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                    .SelectMany(nic => nic.GetIPProperties().GatewayAddresses)
                    .Any(gateway => gateway.Address is not null
                                    && !gateway.Address.Equals(IPAddress.Any)
                                    && !gateway.Address.Equals(IPAddress.IPv6Any));
            }
            catch (Exception)
            {
                // 枚举失败时按“有网关”处理，交给证书链标志判断。
                _hasDefaultGateway = true;
            }

            _nextGatewayCheckUtc = now.AddSeconds(30);
            return _hasDefaultGateway;
        }
    }

    /// <summary>把验证失败的 HRESULT 翻译成给用户看的结果。</summary>
    private static SignatureInfo Interpret(TrustResult result, RevocationMode mode)
    {
        var hex = $"0x{result.HResult:X8}";
        var source = result.FromCatalog ? "目录签名" : "内嵌签名";

        // 签名者名字可能取不到，拼说明时要兜住空字符串，不能拼出「（）」。
        string WithSigner(string text)
            => string.IsNullOrEmpty(result.SignerName) ? text : $"{text}（{result.SignerName}）";

        var state = result.HResult switch
        {
            TrustResult.TrustENosignature or TrustResult.TrustENoSignedData
                or TrustResult.TrustESubjectFormUnknown => SignatureState.Unsigned,

            TrustResult.TrustEBadDigest => SignatureState.Tampered,

            TrustResult.CertEUntrustedRoot or TrustResult.CertEChaining
                or TrustResult.TrustESubjectNotTrusted or TrustResult.CertECnNoMatch
                or TrustResult.TrustEExplicitDistrust => SignatureState.Untrusted,

            TrustResult.CertEExpired or TrustResult.CertERevoked
                or TrustResult.CryptESecuritySettings => SignatureState.CertificateProblem,

            _ => SignatureState.Error,
        };

        // 4.6：离线导致吊销查不到时，不把“没查成”说成“证书异常/检查失败”。
        if (mode == RevocationMode.Online
            && result.RevocationUnknown
            && state is SignatureState.CertificateProblem or SignatureState.Error)
        {
            return new SignatureInfo(
                SignatureState.RevocationUnknown,
                result.SignerName,
                $"当前无网络，无法联网查询证书吊销状态（{source}，{hex}）。\n" +
                "联网后刷新重试，或在「设置 → 数据与隐私」关闭“检查证书吊销状态”。");
        }

        var text = state switch
        {
            SignatureState.Unsigned => "该文件没有数字签名",
            SignatureState.Tampered => $"文件内容与签名不匹配，签名之后被改动过（{source}，{hex}）",
            SignatureState.Untrusted => $"有签名，但证书链不受信任，可能是自签名证书（{source}，{hex}）",
            SignatureState.CertificateProblem => $"签名证书已过期或被吊销（{source}，{hex}）",
            _ => $"签名验证失败（{source}，{hex}）",
        };

        return new SignatureInfo(state, result.SignerName, WithSigner(text));
    }
}
