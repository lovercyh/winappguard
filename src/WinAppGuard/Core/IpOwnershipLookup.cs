using System.Net;
using System.Net.Sockets;
using System.Text;
using WinAppGuard.Models;

namespace WinAppGuard.Core;

/// <summary>
/// IP 归属查询（Team Cymru WHOIS）。
///
/// ★★ 这是本项目**唯一**会主动发起网络连接的地方。
///    与 FirewallManager（唯一的防火墙出口）、AutoStartManager（唯一的计划任务出口）同一约定：
///    联网行为集中在这一个文件里，审计联网边界只需要看这一个文件。
///
/// 行为边界（安全约定，改动前必须想清楚）：
///   1. 只连接 AppConstants.OwnershipLookupHost:OwnershipLookupPort 这一个固定地址，
///      绝不访问任何其它主机；直接用 TcpClient 连 TCP，不使用 HTTP、不带任何 URL。
///   2. 只发送 IP 地址字符串。不发送进程名、路径、PID、端口或任何本机信息。
///   3. 私有 / 回环 / 链路本地 / 未指定地址根本不会发送出去（见 <see cref="IsQueryable"/>），
///      避免把内网拓扑泄露给第三方。
///   4. 超时与失败一律不向上抛异常，只返回 Failed 状态 —— 归属查询是纯附加信息，
///      它失败不允许影响主功能。
///   5. 本类只应在「设置里显式开启」时才被调用；关闭时不会有任何流量。
///
/// 一个必须如实说明的细节：按主机名连接时，.NET 运行时会先对 whois.cymru.com
/// 做一次 DNS 解析。这不是 HTTP 请求，但确实是一次额外的域名查询，
/// 而且这一步发生在托管代码之外，元数据审计看不到。
/// </summary>
public static class IpOwnershipLookup
{
    /// <summary>
    /// 把一个地址归一化成「键」。
    ///
    /// 缓存、待查队列、请求报文、响应解析全都用这一个写法 ——
    /// 只要有一处用了别的写法（比如 IPv6 的不同压缩形式），请求和响应就会对不上。
    /// </summary>
    public static string ToKey(IPAddress address)
    {
        var normalized = address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
        return normalized.ToString();
    }

    /// <summary>
    /// 判断一个地址是否值得发出去查询。
    ///
    /// 被拦下的全是「查了也没意义、而且会泄露内网信息」的地址：
    /// 回环、私有网段、链路本地、运营商级 NAT 网段、组播、保留段、未指定地址。
    /// 这个判断放在发送之前，而不是靠服务端返回 NA —— 因为我们的目标是
    /// 「这些地址根本不出本机」。
    /// </summary>
    public static bool IsQueryable(IPAddress address)
    {
        if (address is null)
        {
            return false;
        }

        // IPv4-mapped IPv6（::ffff:a.b.c.d）按它映射的 IPv4 地址判断。
        if (address.IsIPv4MappedToIPv6)
        {
            address = address.MapToIPv4();
        }

        if (IPAddress.IsLoopback(address)
            || address.Equals(IPAddress.Any)
            || address.Equals(IPAddress.IPv6Any)
            || address.Equals(IPAddress.Broadcast))
        {
            return false;
        }

        var bytes = address.GetAddressBytes();

        if (bytes.Length == 4)
        {
            if (bytes[0] == 10) return false;                                        // 10.0.0.0/8
            if (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31) return false;   // 172.16.0.0/12
            if (bytes[0] == 192 && bytes[1] == 168) return false;                    // 192.168.0.0/16
            if (bytes[0] == 169 && bytes[1] == 254) return false;                    // 169.254.0.0/16
            if (bytes[0] == 100 && bytes[1] >= 64 && bytes[1] <= 127) return false;  // 100.64.0.0/10（运营商级 NAT）
            if (bytes[0] == 0) return false;                                         // 0.0.0.0/8
            if (bytes[0] >= 224) return false;                                       // 组播 + 保留
            return true;
        }

        // IPv6：链路本地 / 已废弃的站点本地（fe80::/9）、唯一本地地址（fc00::/7）、组播（ff00::/8）
        if (bytes[0] == 0xFE && (bytes[1] & 0xC0) != 0) return false;
        if ((bytes[0] & 0xFE) == 0xFC) return false;
        if (bytes[0] == 0xFF) return false;
        return true;
    }

    /// <summary>
    /// 查询一批 IP 的归属信息。
    ///
    /// 返回的字典对**每一个不同的输入地址**都有一条记录（键是地址的规范字符串）：
    /// <list type="bullet">
    ///   <item>本机 / 局域网地址 → <see cref="IpOwnershipState.LocalOnly"/>（根本没有发出去）</item>
    ///   <item>查询成功且有数据 → <see cref="IpOwnershipState.Known"/></item>
    ///   <item>查询成功但无归属 → <see cref="IpOwnershipState.NotCovered"/></item>
    ///   <item>查询失败 → <see cref="IpOwnershipState.Failed"/></item>
    /// </list>
    ///
    /// 本方法是**阻塞**的（内部同步收发 TCP），调用方必须放在后台线程，
    /// 并且不要传入界面线程仍在修改的集合（先做快照）。
    /// </summary>
    public static IReadOnlyDictionary<string, IpOwnershipInfo> Query(IReadOnlyList<IPAddress>? addresses)
    {
        var result = new Dictionary<string, IpOwnershipInfo>(StringComparer.Ordinal);
        var pending = new List<string>();

        if (addresses is not null)
        {
            foreach (var raw in addresses)
            {
                if (raw is null)
                {
                    continue;
                }

                var address = raw.IsIPv4MappedToIPv6 ? raw.MapToIPv4() : raw;
                var key = ToKey(address);

                // 同一个地址在一批里出现多次时只查一次。
                if (result.ContainsKey(key))
                {
                    continue;
                }

                if (!IsQueryable(address))
                {
                    result[key] = IpOwnershipInfo.LocalOnly;
                    continue;
                }

                result[key] = IpOwnershipInfo.None;
                pending.Add(key);
            }
        }

        // 分块查询：服务端一次能吃下的 IP 数量有限，按常量切块。
        for (var offset = 0; offset < pending.Count; offset += AppConstants.OwnershipMaxIpsPerQuery)
        {
            var count = Math.Min(AppConstants.OwnershipMaxIpsPerQuery, pending.Count - offset);
            QueryChunk(pending.GetRange(offset, count), result);
        }

        return result;
    }

    /// <summary>查询一块 IP，并把结果写进 <paramref name="sink"/>。任何失败都降级成 Failed。</summary>
    private static void QueryChunk(IReadOnlyList<string> chunk, Dictionary<string, IpOwnershipInfo> sink)
    {
        string response;

        try
        {
            response = Exchange(BuildRequest(chunk));
        }
        catch (Exception ex)
        {
            // 归属查询是附加信息，绝不允许因为网络问题把主功能带崩，
            // 所以这里刻意把所有异常都兜住（与全局异常兜底同一思路）。
            var reason = DescribeFailure(ex);
            foreach (var key in chunk)
            {
                sink[key] = IpOwnershipInfo.Failed(reason);
            }

            return;
        }

        // 先统一当作「服务通了、但这个地址查不到归属」，再用返回行覆盖。
        // 这样即使服务端少回了一行，也不会留下 Unknown。
        foreach (var key in chunk)
        {
            sink[key] = IpOwnershipInfo.NotCovered;
        }

        ParseRows(response, sink);
    }

    /// <summary>把异常翻译成给用户看的短原因。</summary>
    private static string DescribeFailure(Exception ex) => ex switch
    {
        TimeoutException => "连接超时",
        SocketException socket => $"网络错误（{socket.SocketErrorCode}）",
        IOException => "读取响应失败或超时",
        _ => ex.Message,
    };

    /// <summary>组装 Cymru 的 bulk 查询请求。格式是固定的：begin / verbose / 各 IP 一行 / end。</summary>
    private static string BuildRequest(IReadOnlyList<string> addresses)
    {
        var builder = new StringBuilder();
        builder.Append("begin\n");
        builder.Append("verbose\n");

        foreach (var address in addresses)
        {
            builder.Append(address).Append('\n');
        }

        builder.Append("end\n");
        return builder.ToString();
    }

    /// <summary>建立连接、发送请求、读到服务端关闭为止。</summary>
    private static string Exchange(string request)
    {
        using var client = new TcpClient
        {
            ReceiveTimeout = AppConstants.OwnershipReadTimeoutMs,
            SendTimeout = AppConstants.OwnershipReadTimeoutMs,
        };

        using (var timeout = new CancellationTokenSource(AppConstants.OwnershipConnectTimeoutMs))
        {
            try
            {
                // 用带取消令牌的重载 + GetAwaiter().GetResult()：
                // 这样超时是 TimeoutException，连接失败是原始的 SocketException，
                // 而不会包一层 AggregateException，DescribeFailure 才好分类。
                client.ConnectAsync(
                        AppConstants.OwnershipLookupHost,
                        AppConstants.OwnershipLookupPort,
                        timeout.Token)
                    .GetAwaiter()
                    .GetResult();
            }
            catch (OperationCanceledException)
            {
                throw new TimeoutException();
            }
        }

        var stream = client.GetStream();

        var payload = Encoding.ASCII.GetBytes(request);
        stream.Write(payload, 0, payload.Length);
        stream.Flush();

        var builder = new StringBuilder();
        var buffer = new byte[8192];

        while (true)
        {
            int read;

            try
            {
                read = stream.Read(buffer, 0, buffer.Length);
            }
            catch (IOException) when (builder.Length > 0)
            {
                // 读超时但已经拿到内容：服务端没有主动关连接，用已读到的部分解析即可。
                break;
            }

            if (read <= 0)
            {
                break;
            }

            builder.Append(Encoding.ASCII.GetString(buffer, 0, read));

            // 防御：正常响应只有几 KB，异常情况下也不允许无限读下去。
            if (builder.Length >= AppConstants.OwnershipMaxResponseBytes)
            {
                break;
            }
        }

        return builder.ToString();
    }

    /// <summary>解析 Cymru 的 bulk 响应，写进结果字典。</summary>
    private static void ParseRows(string response, Dictionary<string, IpOwnershipInfo> sink)
    {
        foreach (var rawLine in response.Split('\n'))
        {
            var line = rawLine.Trim();
            if (line.Length == 0
                || line.StartsWith("Bulk mode", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            // 数据行固定 7 列：AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name
            var fields = line.Split('|');
            if (fields.Length < 7)
            {
                continue;
            }

            var asn = fields[0].Trim();

            // 表头行（"AS | IP | ..."）等非数据行的 AS 字段既不是数字也不是 NA。
            if (!IsAsnField(asn))
            {
                continue;
            }

            var key = NormalizeKey(fields[1].Trim());
            if (key.Length == 0 || !sink.ContainsKey(key))
            {
                // 不是我们请求过的地址，忽略。
                continue;
            }

            var asnText = NullIfNotAvailable(asn);
            var country = NullIfNotAvailable(fields[3].Trim());

            sink[key] = new IpOwnershipInfo(
                State: string.IsNullOrEmpty(asnText) && string.IsNullOrEmpty(country)
                    ? IpOwnershipState.NotCovered
                    : IpOwnershipState.Known,
                Asn: asnText,
                AsName: NullIfNotAvailable(fields[6].Trim()),
                CountryCode: country,
                Prefix: NullIfNotAvailable(fields[2].Trim()),
                Registry: NullIfNotAvailable(fields[4].Trim()),
                Allocated: NullIfNotAvailable(fields[5].Trim()));
        }
    }

    /// <summary>AS 字段的合法取值：纯数字，或表示「不适用」的 NA。</summary>
    private static bool IsAsnField(string value)
        => value.Equals("NA", StringComparison.OrdinalIgnoreCase)
           || (value.Length > 0 && value.All(char.IsAsciiDigit));

    /// <summary>
    /// 把服务端回显的 IP 归一化成和请求时一致的字符串，用来对上字典的键。
    /// 服务端通常原样回显，但不同写法（IPv6 压缩形式）经 IPAddress 归一后一致，避免对不上。
    /// </summary>
    private static string NormalizeKey(string value)
    {
        if (!IPAddress.TryParse(value, out var parsed))
        {
            return string.Empty;
        }

        return ToKey(parsed);
    }

    /// <summary>把服务端的「不适用」（NA）统一成空字符串，界面据此省略该行。</summary>
    private static string NullIfNotAvailable(string value)
        => value.Equals("NA", StringComparison.OrdinalIgnoreCase) ? string.Empty : value;
}
