using System.IO.Compression;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using WinAppGuard.Contracts;
using WinAppGuard.Core.Audit;
using WinAppGuard.Core.Diagnostics.AntiScan;
using WinAppGuard.Models;

namespace WinAppGuard.Core.Diagnostics;

/// <summary>
/// 5.7：诊断包的内容开关与来源目录。
///
/// 生产环境全部用默认值；自检工具可以传临时目录，避免碰用户真实数据。
/// </summary>
public sealed class DiagnosticBundleOptions
{
    public bool IncludeConnections { get; init; } = true;

    public bool IncludeServiceSnapshots { get; init; } = true;

    public bool IncludeAuditFiles { get; init; } = true;

    public bool IncludeRulesSnapshot { get; init; } = true;

    public bool IncludeLogs { get; init; } = true;

    public bool IncludeSettings { get; init; } = true;

    public bool IncludeFirstSeenPrograms { get; init; } = true;

    public string? UiLogDirectory { get; init; }

    public string? ServiceLogDirectory { get; init; }

    public string? AuditDirectory { get; init; }

    public string? RulesSnapshotPath { get; init; }

    public string? SettingsPath { get; init; }

    public string? FirstSeenProgramsPath { get; init; }
}

/// <summary>诊断包生成结果。路径和大小只用于界面提示。</summary>
public sealed record DiagnosticBundleResult(
    string Path,
    long Bytes,
    int Entries,
    IReadOnlyList<string> Warnings);

/// <summary>
/// 5.7：生成一个只写本地磁盘的诊断 zip。
///
/// 包含：
///   - 系统 / 版本 / 服务 / WFP / Npcap 摘要
///   - 当前 TCP 连接
///   - 服务查询快照：规则、DNS、流量、反网络攻击、IDS、反扫描、局域网、
///     DNS 安全、IPv6、配置完整性、名称解析
///   - 审计原始文件
///   - 规则权威快照
///   - 界面 / 服务日志
///   - 设置文件
///
/// **这是用户主动生成的排障文件，可能包含程序路径、远端 IP、DNS 查询和规则。**
/// 界面必须在生成前明确提示这一点；本类只负责打包，不做任何网络上传。
/// </summary>
public static class DiagnosticBundle
{
    private const string FormatVersion = "1";

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    private static readonly (string Command, string FileName)[] ServiceSnapshots =
    {
        (ServiceProtocol.Commands.ListRules, "rules.json"),
        (ServiceProtocol.Commands.QueryDns, "dns.json"),
        (ServiceProtocol.Commands.QueryTraffic, "traffic.json"),
        (ServiceProtocol.Commands.QueryNetworkDetection, "network-detection.json"),
        (ServiceProtocol.Commands.QueryIdsAlerts, "ids-alerts.json"),
        (ServiceProtocol.Commands.QueryAntiScan, "anti-scan.json"),
        (ServiceProtocol.Commands.QueryLan, "lan.json"),
        (ServiceProtocol.Commands.QueryDnsSecurity, "dns-security.json"),
        (ServiceProtocol.Commands.QueryIpv6Security, "ipv6-security.json"),
        (ServiceProtocol.Commands.QueryConfigIntegrity, "config-integrity.json"),
        (ServiceProtocol.Commands.QueryNameResolution, "name-resolution.json"),
    };

    public static DiagnosticBundleResult Create(
        string path,
        DiagnosticBundleOptions? options = null)
    {
        options ??= new DiagnosticBundleOptions();

        var warnings = new List<string>();
        var counts = new Dictionary<string, int>(StringComparer.Ordinal);
        var serviceStatus = TryGetStatus();
        var npcapState = NpcapLocator.GetState(out var npcapVersion);

        var directory = Path.GetDirectoryName(path);

        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        using var zip = ZipFile.Open(path, ZipArchiveMode.Create);

        AddText(zip, "README.txt", BuildReadme());
        AddText(zip, "system.txt", BuildSystemText(serviceStatus, npcapState, npcapVersion));
        AddText(
            zip,
            "service-status.json",
            serviceStatus is null
                ? "{\n  \"available\": false\n}\n"
                : JsonSerializer.Serialize(serviceStatus, JsonOptions));
        AddText(
            zip,
            "npcap.json",
            JsonSerializer.Serialize(new { state = npcapState.ToString(), version = npcapVersion }, JsonOptions));

        if (options.IncludeSettings)
        {
            CopyFileOrNote(
                zip,
                options.SettingsPath ?? AppSettings.SettingsFilePath,
                "settings.json",
                warnings,
                "设置文件");
        }

        if (options.IncludeConnections)
        {
            AddConnections(zip, warnings, counts);
        }

        if (options.IncludeFirstSeenPrograms)
        {
            AddFirstSeenPrograms(zip, options, warnings, counts);
        }

        if (options.IncludeServiceSnapshots)
        {
            AddServiceSnapshots(zip, warnings, counts);
        }

        if (options.IncludeRulesSnapshot)
        {
            CopyFileOrNote(
                zip,
                options.RulesSnapshotPath ?? ServicePaths.RulesSnapshotFile,
                "data/raw/rules-snapshot.json",
                warnings,
                "规则权威快照");
        }

        if (options.IncludeAuditFiles)
        {
            var auditDirectory = options.AuditDirectory ?? ServicePaths.AuditDirectory;

            CopyDirectoryFiles(
                zip,
                auditDirectory,
                "data/audit",
                warnings,
                "审计文件",
                counts,
                "audit");

            AddAuditCsv(zip, auditDirectory, warnings, counts);
        }

        if (options.IncludeLogs)
        {
            CopyDirectoryFiles(
                zip,
                options.UiLogDirectory ?? LocalLog.LogDirectory,
                "logs/ui",
                warnings,
                "界面日志",
                counts,
                "uiLogs");

            CopyDirectoryFiles(
                zip,
                options.ServiceLogDirectory ?? ServiceLogDirectory,
                "logs/service",
                warnings,
                "服务日志",
                counts,
                "serviceLogs");
        }

        AddText(zip, "summary.txt", BuildSummary(serviceStatus, npcapState, npcapVersion, counts, warnings));

        // 关闭 zip 后再读大小/条目数；Create 模式下不能访问 Entries。
        zip.Dispose();

        int entries;

        using (var read = ZipFile.OpenRead(path))
        {
            entries = read.Entries.Count;
        }

        return new DiagnosticBundleResult(
            path,
            new FileInfo(path).Length,
            entries,
            warnings);
    }

    private static ServiceStatus? TryGetStatus()
    {
        try
        {
            return ServiceClient.TryGetStatus(TimeSpan.FromSeconds(3));
        }
        catch (Exception)
        {
            return null;
        }
    }

    private static void AddConnections(
        ZipArchive zip,
        List<string> warnings,
        Dictionary<string, int> counts)
    {
        try
        {
            var items = ConnectionScanner.Scan(new ConnectionScanOptions
                {
                    IncludeListening = true,
                    IncludeClosed = false,
                    IncludeOwnerless = true,
                    HideLoopback = false,
                })
                .ToList();

            var connections = items
                .Select(item => new
                {
                    processName = item.ProcessName,
                    processPath = item.ProcessPath,
                    pid = item.Pid,
                    protocol = item.Protocol,
                    localPort = item.LocalPort,
                    remoteAddress = item.RemoteAddressText,
                    remotePort = item.RemotePort,
                    state = item.State.ToString(),
                    trafficOutBytes = item.TrafficBytesOut,
                    trafficInBytes = item.TrafficBytesIn,
                    blocked = item.IsBlocked,
                    whitelist = item.Whitelist.ToString(),
                    signatureState = item.Signature.State.ToString(),
                    signer = item.Signature.SignerName,
                })
                .ToList();

            counts["connections"] = connections.Count;

            AddText(zip, "data/connections.csv", DiagnosticCsv.Connections(items));
            AddText(
                zip,
                "data/raw/connections.json",
                JsonSerializer.Serialize(
                    new
                    {
                        generatedUtc = DateTime.UtcNow,
                        count = connections.Count,
                        connections,
                    },
                    JsonOptions));
        }
        catch (Exception ex)
        {
            warnings.Add($"连接快照失败：{ex.Message}");
            AddText(zip, "data/connections.csv", string.Empty);
            AddText(zip, "data/raw/connections.json", ErrorJson("连接快照失败", ex));
        }
    }

    private static void AddFirstSeenPrograms(
        ZipArchive zip,
        DiagnosticBundleOptions options,
        List<string> warnings,
        Dictionary<string, int> counts)
    {
        try
        {
            var store = new FirstSeenProgramStore(options.FirstSeenProgramsPath);
            var records = store.Snapshot();

            counts["firstSeenPrograms"] = records.Count;

            AddText(
                zip,
                "data/new-programs.csv",
                DiagnosticCsv.FromObjects("new-programs", records));

            AddText(
                zip,
                "data/raw/new-programs.json",
                JsonSerializer.Serialize(records, JsonOptions));
        }
        catch (Exception ex)
        {
            warnings.Add($"新程序联网提醒记录读取失败：{ex.Message}");
        }
    }

    private static void AddServiceSnapshots(
        ZipArchive zip,
        List<string> warnings,
        Dictionary<string, int> counts)    {
        foreach (var (command, fileName) in ServiceSnapshots)
        {
            ActionResult? response = null;

            try
            {
                response = ServiceClient.TryRequest(
                    new ServiceRequest { Command = command },
                    TimeSpan.FromSeconds(2),
                    out _);
            }
            catch (Exception ex)
            {
                warnings.Add($"{command} 查询失败：{ex.Message}");
            }

            if (response is null)
            {
                AddText(zip, $"data/raw/service/{fileName}", ErrorJson($"{command} 没有响应", null));
                continue;
            }

            AddText(zip, $"data/raw/service/{fileName}", JsonSerializer.Serialize(response, JsonOptions));
            AddServiceCsv(zip, response, fileName);

            var count = fileName switch
            {
                "rules.json" => response.Rules?.Count,
                "dns.json" => response.DnsRecords?.Count,
                "traffic.json" => response.Traffic?.Count,
                "network-detection.json" => response.NetworkAlerts?.Count,
                "ids-alerts.json" => response.IdsAlerts?.Count,
                "anti-scan.json" => response.AntiScanEvents?.Count,
                "lan.json" => response.LanEvents?.Count,
                "dns-security.json" => response.DnsSecurityEvents?.Count,
                "ipv6-security.json" => response.Ipv6SecurityEvents?.Count,
                "config-integrity.json" => response.ConfigIntegrityEvents?.Count,
                "name-resolution.json" => response.NameResolutionEvents?.Count,
                _ => null,
            };

            if (count is not null)
            {
                counts[fileName] = count.Value;
            }
        }
    }

    /// <summary>把服务响应当中的列表导出成可直接用 Excel 打开的 CSV。</summary>
    private static void AddServiceCsv(
        ZipArchive zip,
        ActionResult response,
        string fileName)
    {
        switch (fileName)
        {
            case "rules.json":
                AddText(zip, "data/rules.csv", DiagnosticCsv.FromObjects("rules", response.Rules));
                break;

            case "dns.json":
                AddText(zip, "data/dns.csv", DiagnosticCsv.FromObjects("dns", response.DnsRecords));
                break;

            case "traffic.json":
                AddText(zip, "data/traffic.csv", DiagnosticCsv.FromObjects("traffic", response.Traffic));
                break;

            case "network-detection.json":
                AddText(
                    zip,
                    "data/network-alerts.csv",
                    DiagnosticCsv.FromObjects("network-alerts", response.NetworkAlerts));
                AddText(
                    zip,
                    "data/network-blocks.csv",
                    DiagnosticCsv.FromObjects("network-blocks", response.NetworkBlocks));
                break;

            case "ids-alerts.json":
                AddText(zip, "data/ids-alerts.csv", DiagnosticCsv.FromObjects("ids-alerts", response.IdsAlerts));
                break;

            case "anti-scan.json":
                AddText(
                    zip,
                    "data/anti-scan.csv",
                    DiagnosticCsv.FromObjects("anti-scan", response.AntiScanEvents));
                AddText(
                    zip,
                    "data/anti-scan-blocks.csv",
                    DiagnosticCsv.FromObjects("anti-scan-blocks", response.AntiScanBlocks));
                break;

            case "lan.json":
                AddText(zip, "data/lan.csv", DiagnosticCsv.FromObjects("lan", response.LanEvents));
                break;

            case "dns-security.json":
                AddText(
                    zip,
                    "data/dns-security.csv",
                    DiagnosticCsv.FromObjects("dns-security", response.DnsSecurityEvents));
                break;

            case "ipv6-security.json":
                AddText(
                    zip,
                    "data/ipv6-security.csv",
                    DiagnosticCsv.FromObjects("ipv6-security", response.Ipv6SecurityEvents));
                break;

            case "config-integrity.json":
                AddText(
                    zip,
                    "data/config-integrity.csv",
                    DiagnosticCsv.FromObjects("config-integrity", response.ConfigIntegrityEvents));
                break;

            case "name-resolution.json":
                AddText(
                    zip,
                    "data/name-resolution.csv",
                    DiagnosticCsv.FromObjects("name-resolution", response.NameResolutionEvents));
                break;
        }
    }

    private static void AddAuditCsv(
        ZipArchive zip,
        string auditDirectory,
        List<string> warnings,
        Dictionary<string, int> counts)
    {
        try
        {
            using var store = new AuditStore(auditDirectory);
            var events = store.ReadRecent(int.MaxValue);

            counts["auditEvents"] = events.Count;
            AddText(zip, "data/audit.csv", DiagnosticCsv.Audit(events));
        }
        catch (Exception ex)
        {
            warnings.Add($"审计记录 CSV 生成失败：{ex.Message}");
            AddText(zip, "data/audit.csv", string.Empty);
        }
    }

    private static void CopyDirectoryFiles(
        ZipArchive zip,
        string directory,
        string entryPrefix,
        List<string> warnings,
        string label,
        Dictionary<string, int> counts,
        string countKey)
    {
        try
        {
            if (!Directory.Exists(directory))
            {
                warnings.Add($"{label}目录不存在：{directory}");
                counts[countKey] = 0;
                return;
            }

            var files = Directory.EnumerateFiles(directory, "*", SearchOption.TopDirectoryOnly)
                .OrderBy(file => file, StringComparer.OrdinalIgnoreCase)
                .ToList();

            foreach (var file in files)
            {
                var name = Path.GetFileName(file);
                AddFile(zip, file, $"{entryPrefix}/{name}");
            }

            counts[countKey] = files.Count;
        }
        catch (Exception ex)
        {
            warnings.Add($"{label}读取失败：{ex.Message}");
        }
    }

    private static void CopyFileOrNote(
        ZipArchive zip,
        string source,
        string entryName,
        List<string> warnings,
        string label)
    {
        try
        {
            if (!File.Exists(source))
            {
                warnings.Add($"{label}不存在：{source}");
                return;
            }

            AddFile(zip, source, entryName);
        }
        catch (Exception ex)
        {
            warnings.Add($"{label}读取失败：{ex.Message}");
        }
    }

    private static void AddFile(ZipArchive zip, string source, string entryName)
    {
        var entry = zip.CreateEntry(entryName, CompressionLevel.Optimal);

        using var output = entry.Open();
        using var input = new FileStream(
            source, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        input.CopyTo(output);
    }

    private static void AddText(ZipArchive zip, string entryName, string text)
    {
        var entry = zip.CreateEntry(entryName, CompressionLevel.Optimal);

        using var writer = new StreamWriter(entry.Open(), new UTF8Encoding(false));
        writer.Write(text);
    }

    private static string BuildReadme()
        => "WinAppGuard 诊断包\r\n" +
           "==================\r\n\r\n" +
           "这是由你主动在本机生成的排障文件，不会自动上传到任何地方。\r\n\r\n" +
           "默认提供可直接用 Excel 打开的 CSV（data/*.csv）；\r\n" +
           "data/raw 下保留服务原始 JSON，嵌套字段或完整结构以那里为准。\r\n\r\n" +
           "包含的内容可能包括：\r\n" +
           "  - 程序路径、PID、远端 IP / 端口\r\n" +
           "  - DNS 查询记录\r\n" +
           "  - 防火墙规则（本工具创建的规则）\r\n" +
           "  - 审计记录（CSV + 原始 .jsonl）\r\n" +
           "  - 新程序联网提醒记录\r\n" +
           "  - 流量、网络检测 / IDS / 局域网 / IPv6 / 配置完整性事件\r\n" +
           "  - 界面与服务日志\r\n" +
           "  - 设置文件（只有开关和保留天数）\r\n\r\n" +
           "不包含：受保护模式私钥、Suricata 规则文件、HTTPS 正文、任何未列出的系统数据。\r\n\r\n" +
           "分享前请确认接收方可信；需要时可以解压后自行删除敏感文件。\r\n";

    private static string BuildSystemText(
        ServiceStatus? status,
        NpcapState npcapState,
        string? npcapVersion)
    {
        var builder = new StringBuilder();

        builder.AppendLine("WinAppGuard system summary");
        builder.AppendLine("==========================");
        builder.AppendLine($"generatedUtc: {DateTime.UtcNow:O}");
        builder.AppendLine($"os: {RuntimeInformation.OSDescription}");
        builder.AppendLine($"osArchitecture: {RuntimeInformation.OSArchitecture}");
        builder.AppendLine($"processArchitecture: {RuntimeInformation.ProcessArchitecture}");
        builder.AppendLine($"64BitOS: {Environment.Is64BitOperatingSystem}");
        builder.AppendLine($"64BitProcess: {Environment.Is64BitProcess}");
        builder.AppendLine($"machineName: {Environment.MachineName}");
        builder.AppendLine($"user: {Environment.UserName}");
        builder.AppendLine($"admin: {AdminHelper.IsRunningAsAdmin()}");
        builder.AppendLine($"bootTimeUtc: {SystemUptime.BootTimeUtc:O}");
        builder.AppendLine($"uiLogDirectory: {LocalLog.LogDirectory}");
        builder.AppendLine($"serviceLogDirectory: {ServiceLogDirectory}");
        builder.AppendLine($"npcap: {npcapState} ({npcapVersion ?? "unknown"})");
        builder.AppendLine($"serviceAvailable: {status is not null}");

        if (status is not null)
        {
            builder.AppendLine($"serviceVersion: {status.ServiceVersion}");
            builder.AppendLine($"protocolVersion: {status.ProtocolVersion}");
            builder.AppendLine($"protectedMode: {status.ProtectedMode}");
            builder.AppendLine($"wfpSublayer: {status.SublayerPresent}");
            builder.AppendLine($"blockRules: {status.BlockRuleCount}");
            builder.AppendLine($"allowRules: {status.AllowRuleCount}");
            builder.AppendLine($"ipRules: {status.IpRuleCount}");
            builder.AppendLine($"trafficCollecting: {status.TrafficCollecting}");
            builder.AppendLine($"dnsCollecting: {status.DnsCollecting}");
            builder.AppendLine($"idsCollecting: {status.IdsCollecting}");
            builder.AppendLine($"antiScanCollecting: {status.AntiScanCollecting}");
            builder.AppendLine($"lanCollecting: {status.LanCollecting}");
            builder.AppendLine($"dnsSecurityCollecting: {status.DnsSecurityCollecting}");
            builder.AppendLine($"ipv6SecurityCollecting: {status.Ipv6SecurityCollecting}");
        }

        return builder.ToString();
    }

    private static string BuildSummary(
        ServiceStatus? status,
        NpcapState npcapState,
        string? npcapVersion,
        Dictionary<string, int> counts,
        List<string> warnings)
    {
        var builder = new StringBuilder();

        builder.AppendLine("WinAppGuard diagnostics summary");
        builder.AppendLine("===============================");
        builder.AppendLine($"formatVersion: {FormatVersion}");
        builder.AppendLine($"generatedUtc: {DateTime.UtcNow:O}");
        builder.AppendLine($"toolVersion: {typeof(DiagnosticBundle).Assembly.GetName().Version}");
        builder.AppendLine($"service: {(status is null ? "not available" : "running")}");
        builder.AppendLine($"npcap: {npcapState} ({npcapVersion ?? "unknown"})");

        if (status is not null)
        {
            builder.AppendLine($"protectedMode: {status.ProtectedMode}");
            builder.AppendLine($"wfpSublayer: {status.SublayerPresent}");
            builder.AppendLine($"rules: block={status.BlockRuleCount}, allow={status.AllowRuleCount}, ip={status.IpRuleCount}");
        }

        builder.AppendLine();
        builder.AppendLine("Data:");
        builder.AppendLine($"  connections: {GetCount(counts, "connections")}");
        builder.AppendLine($"  auditFiles: {GetCount(counts, "audit")}");
        builder.AppendLine($"  auditEvents: {GetCount(counts, "auditEvents")}");
        builder.AppendLine($"  rulesFromService: {GetCount(counts, "rules.json")}");
        builder.AppendLine($"  firstSeenPrograms: {GetCount(counts, "firstSeenPrograms")}");
        builder.AppendLine($"  dnsRecords: {GetCount(counts, "dns.json")}");
        builder.AppendLine($"  trafficRows: {GetCount(counts, "traffic.json")}");
        builder.AppendLine($"  networkAlerts: {GetCount(counts, "network-detection.json")}");
        builder.AppendLine($"  idsAlerts: {GetCount(counts, "ids-alerts.json")}");
        builder.AppendLine($"  antiScanEvents: {GetCount(counts, "anti-scan.json")}");
        builder.AppendLine($"  lanEvents: {GetCount(counts, "lan.json")}");
        builder.AppendLine($"  dnsSecurityEvents: {GetCount(counts, "dns-security.json")}");
        builder.AppendLine($"  ipv6SecurityEvents: {GetCount(counts, "ipv6-security.json")}");
        builder.AppendLine($"  configIntegrityEvents: {GetCount(counts, "config-integrity.json")}");
        builder.AppendLine($"  nameResolutionEvents: {GetCount(counts, "name-resolution.json")}");
        builder.AppendLine($"  uiLogFiles: {GetCount(counts, "uiLogs")}");
        builder.AppendLine($"  serviceLogFiles: {GetCount(counts, "serviceLogs")}");

        if (warnings.Count > 0)
        {
            builder.AppendLine();
            builder.AppendLine("Warnings:");
            foreach (var warning in warnings)
            {
                builder.AppendLine($"  - {warning}");
            }
        }

        builder.AppendLine();
        builder.AppendLine("Privacy: this bundle may contain program paths, remote IPs, DNS queries,");
        builder.AppendLine("firewall rules and audit records. It is never uploaded automatically.");
        builder.AppendLine("Review it before sharing it with anyone.");

        return builder.ToString();
    }

    private static int GetCount(Dictionary<string, int> counts, string key)
        => counts.TryGetValue(key, out var value) ? value : 0;

    private static string ErrorJson(string message, Exception? ex)
        => JsonSerializer.Serialize(
            new
            {
                ok = false,
                error = message,
                detail = ex?.Message,
                generatedUtc = DateTime.UtcNow,
            },
            JsonOptions);

    private static string ServiceLogDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
        "WinAppGuard",
        "logs");
}
