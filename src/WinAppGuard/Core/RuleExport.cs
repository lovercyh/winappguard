using System.Net;
using System.Text;
using System.Text.Json;
using WinAppGuard.Models;

namespace WinAppGuard.Core;

/// <summary>导出文件里的一条规则。</summary>
internal sealed class RuleExportEntry
{
    /// <summary><c>program</c> 或 <c>ip</c>。</summary>
    public string Kind { get; set; } = string.Empty;

    /// <summary>程序完整路径（program）或 IP 地址（ip）。</summary>
    public string Value { get; set; } = string.Empty;

    /// <summary><c>block</c> 或 <c>allow</c>。</summary>
    public string Action { get; set; } = string.Empty;

    /// <summary>到期标记（<see cref="RuleExpiry.Encode"/> 的产物）；空字符串 = 永久。</summary>
    public string Expiry { get; set; } = string.Empty;

    /// <summary>分组名；空字符串 = 未分组。</summary>
    public string Group { get; set; } = string.Empty;
}

/// <summary>一条导出文件 = 一个文档。</summary>
internal sealed class RuleExportDocument
{
    /// <summary>固定标记，用来识别"这是不是我们的文件"。</summary>
    public string Format { get; set; } = RuleExport.FormatName;

    /// <summary>格式版本。</summary>
    public int Version { get; set; } = RuleExport.CurrentVersion;

    /// <summary>
    /// 导出范围：<c>block</c>（黑名单）/ <c>allow</c>（白名单）。
    /// 空字符串表示旧文件（没有这个字段），导入时按条目自身的动作校验。
    /// </summary>
    public string Scope { get; set; } = string.Empty;

    /// <summary>导出时间（UTC，仅供人看）。</summary>
    public DateTime ExportedUtc { get; set; } = DateTime.UtcNow;

    public List<RuleExportEntry> Rules { get; set; } = new();
}

/// <summary>
/// 规则的导入 / 导出（JSON，纯本地文件，不联网）。
///
/// 设计取舍：
///   - **只导出"能重建规则"的最小信息**：类型、路径/IP、动作、到期、分组。
///     规则名可以由路径/IP 重新算出来（见 <see cref="RuleNaming"/>），不必存；
///   - **导入时全部走 RuleEngine**，不直接碰 WFP —— 这样系统关键进程保护、
///     路径校验等安全闸一条都不会被绕过；
///   - 文件里**会包含程序路径**（否则导出了也导不回来），所以导出前必须在界面上说清楚：
///     这是你自己的数据，发给别人等于公开你在用哪些软件。
/// </summary>
internal static class RuleExport
{
    internal const string FormatName = "WinAppGuard.Rules";
    internal const int CurrentVersion = 1;

    /// <summary>一次最多导入多少条（防止一个荒唐的文件把界面卡死）。</summary>
    internal const int MaxRules = 5000;

    /// <summary>文件大小上限（2 MB，正常规则文件远小于这个）。</summary>
    internal const int MaxBytes = 2 * 1024 * 1024;

    /// <summary>
    /// 把某一类规则（黑名单 = Block，白名单 = Allow）+ 分组导出成文档。
    /// 两个页签各导各的，但用的是同一种文件格式。
    /// </summary>
    internal static RuleExportDocument Build(
        IEnumerable<FirewallRuleItem> rules,
        RuleGroupStore groups,
        FirewallAction scope)
    {
        var document = new RuleExportDocument
        {
            Scope = scope == FirewallAction.Block ? "block" : "allow",
        };

        foreach (var rule in rules.Where(rule => rule.Action == scope))
        {
            var isIp = !string.IsNullOrEmpty(rule.IpAddress);

            document.Rules.Add(new RuleExportEntry
            {
                Kind = isIp ? "ip" : "program",
                Value = isIp ? rule.IpAddress! : rule.ApplicationPath,
                Action = rule.Action == FirewallAction.Block ? "block" : "allow",
                Expiry = rule.Expiry.Encode(),
                Group = groups.GetGroup(rule.Name),
            });
        }

        return document;
    }

    internal static string Serialize(RuleExportDocument document)
        => JsonSerializer.Serialize(document, new JsonSerializerOptions { WriteIndented = true });

    /// <summary>
    /// 解析并校验导入文件。
    /// 任何"这不像我们的文件"的情况都返回 false + 一句能看懂的原因，
    /// 绝不让半个坏文件进入创建规则的流程。
    /// </summary>
    internal static bool TryParse(string? json, out RuleExportDocument? document, out string error)
    {
        document = null;

        if (string.IsNullOrWhiteSpace(json))
        {
            error = "文件是空的。";
            return false;
        }

        if (Encoding.UTF8.GetByteCount(json) > MaxBytes)
        {
            error = $"文件太大（超过 {MaxBytes / 1024 / 1024} MB），不像是规则文件。";
            return false;
        }

        RuleExportDocument? parsed;

        try
        {
            parsed = JsonSerializer.Deserialize<RuleExportDocument>(json);
        }
        catch (JsonException ex)
        {
            error = $"不是合法的 JSON：{ex.Message}";
            return false;
        }

        if (parsed is null)
        {
            error = "文件内容为空。";
            return false;
        }

        if (!string.Equals(parsed.Format, FormatName, StringComparison.Ordinal))
        {
            error = $"不是 WinAppGuard 规则文件（Format = {parsed.Format ?? "null"}）。";
            return false;
        }

        if (parsed.Version <= 0 || parsed.Version > CurrentVersion)
        {
            error = $"规则文件版本 {parsed.Version} 不受支持（本程序支持到 {CurrentVersion}）。";
            return false;
        }

        parsed.Scope = (parsed.Scope ?? string.Empty).Trim().ToLowerInvariant();

        if (parsed.Scope.Length > 0 && parsed.Scope is not ("block" or "allow"))
        {
            error = $"规则文件的导出范围不认识：{parsed.Scope}。";
            return false;
        }

        if (parsed.Rules is null)
        {
            error = "文件里没有 Rules 数组。";
            return false;
        }

        if (parsed.Rules.Count > MaxRules)
        {
            error = $"规则太多（{parsed.Rules.Count} 条，上限 {MaxRules}）。";
            return false;
        }

        for (var i = 0; i < parsed.Rules.Count; i++)
        {
            var entry = parsed.Rules[i];
            var position = $"第 {i + 1} 条";

            if (entry is null)
            {
                error = $"{position}是空的。";
                return false;
            }

            entry.Kind = (entry.Kind ?? string.Empty).Trim().ToLowerInvariant();
            entry.Action = (entry.Action ?? string.Empty).Trim().ToLowerInvariant();
            entry.Value = (entry.Value ?? string.Empty).Trim();
            entry.Expiry ??= string.Empty;
            entry.Group = (entry.Group ?? string.Empty).Trim();

            if (entry.Kind is not ("program" or "ip"))
            {
                error = $"{position}的类型不认识：{entry.Kind}。";
                return false;
            }

            if (entry.Action is not ("block" or "allow"))
            {
                error = $"{position}的动作不认识：{entry.Action}。";
                return false;
            }

            if (entry.Value.Length == 0)
            {
                error = $"{position}没有值（路径或 IP）。";
                return false;
            }

            if (entry.Kind == "ip" && !IPAddress.TryParse(entry.Value, out _))
            {
                error = $"{position}的 IP 不合法：{entry.Value}。";
                return false;
            }

            if (entry.Kind == "program" && !Path.IsPathFullyQualified(entry.Value))
            {
                error = $"{position}的程序路径不是完整路径：{entry.Value}。";
                return false;
            }

            if (entry.Group.Length > 40)
            {
                entry.Group = entry.Group[..40];
            }
        }

        document = parsed;
        error = string.Empty;
        return true;
    }

    /// <summary>
    /// 这份文件能不能在当前页导入。
    ///
    /// 规则分两个页签之后，**不能把"黑名单文件"导进白名单页** ——
    /// 那会悄悄创建一批阻止规则，用户还以为自己在恢复白名单。
    /// 旧文件没有 <see cref="RuleExportDocument.Scope"/>，就按条目动作判断：
    /// 只要混了两类，同样拒绝，避免"导进去一半"。
    /// </summary>
    internal static bool TryMatchScope(
        RuleExportDocument document, FirewallAction expected, out string error)
    {
        var expectedScope = expected == FirewallAction.Block ? "block" : "allow";
        var expectedName = expected == FirewallAction.Block ? "黑名单" : "白名单";
        var otherName = expected == FirewallAction.Block ? "白名单" : "黑名单";

        if (document.Scope.Length > 0 && document.Scope != expectedScope)
        {
            error = $"这个文件是「{otherName}」导出的，请到「{otherName}」页导入。";
            return false;
        }

        if (document.Rules.Any(entry => entry.Action != expectedScope))
        {
            error = $"文件里混有「{otherName}」规则，请到对应页面分别导入。";
            return false;
        }

        error = string.Empty;
        return true;
    }

    /// <summary>给确认框用的一句话摘要，例如「阻止 3 条 / 允许 1 条，其中 2 条有分组」。</summary>
    internal static string Summarize(RuleExportDocument document)
    {
        var blocks = document.Rules.Count(entry => entry.Action == "block");
        var allows = document.Rules.Count - blocks;
        var ipRules = document.Rules.Count(entry => entry.Kind == "ip");
        var grouped = document.Rules.Count(entry => entry.Group.Length > 0);

        var parts = new List<string>
        {
            $"阻止 {blocks} 条",
            $"允许 {allows} 条",
        };

        if (ipRules > 0)
        {
            parts.Add($"其中 IP 规则 {ipRules} 条");
        }

        if (grouped > 0)
        {
            parts.Add($"{grouped} 条带分组");
        }

        return string.Join(" · ", parts);
    }
}
