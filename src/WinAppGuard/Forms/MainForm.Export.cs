using WinAppGuard.Core;
using WinAppGuard.Core.Export;
using WinAppGuard.Localization;
using WinAppGuard.Models;

namespace WinAppGuard.Forms;

/// <summary>
/// 5.7：各页面的「导出当前视图」。
///
/// 统一原则：
///   - 导出的是**用户当前看到的那批行**（已经过滤、排序后的结果）；
///   - CSV 用界面语言表头，JSON 用固定英文 key；
///   - 只写用户选择的本地文件，不发网络请求、不改系统状态。
/// </summary>
public sealed partial class MainForm
{
    private static string ExportToolVersion => Application.ProductVersion;

    /// <summary>Ctrl+E：导出当前页；没有导出能力的页面给出不做事，避免误解。</summary>
    private void ExportCurrentPage()
    {
        if (_tabControl.SelectedTab == _tabConnections)
        {
            ExportConnectionsView();
        }
        else if (_tabControl.SelectedTab == _tabAudit)
        {
            ExportAuditView();
        }
        else if (_tabControl.SelectedTab == _tabDns)
        {
            ExportDnsView();
        }
        else if (_tabControl.SelectedTab == _tabNetworkDetection)
        {
            ExportNetworkAlertsView();
        }
        else if (_tabControl.SelectedTab == _tabTraffic)
        {
            ExportTrafficView();
        }
    }

    private void ExportConnectionsView()
    {
        if (_connectionViewMode == ConnectionViewMode.Summary)
        {
            ExportTable(
                "connections-summary",
                "连接汇总",
                "WinAppGuard-连接汇总",
                new[]
                {
                    Column("processName", "程序名"),
                    Column("processPath", "程序路径"),
                    Column("pids", "PID"),
                    Column("connectionCount", "连接数"),
                    Column("remoteEndpointCount", "远端数"),
                    Column("remoteEndpoints", "远端地址"),
                    Column("establishedCount", "已建立"),
                    Column("listeningCount", "监听"),
                    Column("trafficOutBytes", "上传字节"),
                    Column("trafficInBytes", "下载字节"),
                    Column("trafficTotalBytes", "总字节"),
                    Column("blocked", "已阻止"),
                    Column("whitelist", "放行"),
                    Column("signatureState", "签名状态"),
                    Column("signer", "签名者"),
                    Column("signatureDetail", "签名详情"),
                },
                _connectionSummary
                    .Select(item => Row(
                        ("processName", item.ProcessName),
                        ("processPath", item.ProcessPath),
                        ("pids", string.Join(",", item.Pids)),
                        ("connectionCount", item.ConnectionCount),
                        ("remoteEndpointCount", item.RemoteEndpoints.Count),
                        ("remoteEndpoints", string.Join("; ", item.RemoteEndpoints)),
                        ("establishedCount", item.EstablishedCount),
                        ("listeningCount", item.ListeningCount),
                        ("trafficOutBytes", item.Representative.TrafficBytesOut),
                        ("trafficInBytes", item.Representative.TrafficBytesIn),
                        ("trafficTotalBytes", item.Representative.TrafficBytesOut + item.Representative.TrafficBytesIn),
                        ("blocked", item.IsBlocked),
                        ("whitelist", item.Representative.Whitelist.ToString()),
                        ("signatureState", item.Representative.Signature.State.ToString()),
                        ("signer", item.Representative.Signature.SignerName),
                        ("signatureDetail", item.Representative.Signature.Detail)))
                    .ToList());
            return;
        }

        ExportTable(
            "connections",
            "连接",
            "WinAppGuard-连接",
            new[]
            {
                Column("processName", "程序名"),
                Column("processPath", "程序路径"),
                Column("pid", "PID"),
                Column("protocol", "协议"),
                Column("localPort", "本地端口"),
                Column("remoteAddress", "远程 IP"),
                Column("remotePort", "远程端口"),
                Column("state", "状态"),
                Column("trafficOutBytes", "上传字节"),
                Column("trafficInBytes", "下载字节"),
                Column("trafficTotalBytes", "总字节"),
                Column("blocked", "已阻止"),
                Column("whitelist", "放行"),
                Column("signatureState", "签名状态"),
                Column("signer", "签名者"),
                Column("signatureDetail", "签名详情"),
            },
            _connections
                .Select(item => Row(
                    ("processName", item.ProcessName),
                    ("processPath", item.ProcessPath),
                    ("pid", item.Pid),
                    ("protocol", item.Protocol),
                    ("localPort", item.LocalPort),
                    ("remoteAddress", item.RemoteAddressText),
                    ("remotePort", item.RemotePort),
                    ("state", item.State.ToString()),
                    ("trafficOutBytes", item.TrafficBytesOut),
                    ("trafficInBytes", item.TrafficBytesIn),
                    ("trafficTotalBytes", item.TrafficBytesOut + item.TrafficBytesIn),
                    ("blocked", item.IsBlocked),
                    ("whitelist", item.Whitelist.ToString()),
                    ("signatureState", item.Signature.State.ToString()),
                    ("signer", item.Signature.SignerName),
                    ("signatureDetail", item.Signature.Detail)))
                .ToList());
    }

    private void ExportAuditView()
    {
        ExportTable(
            "audit",
            "记录",
            "WinAppGuard-记录",
            new[]
            {
                Column("timeUtc", "时间（UTC）"),
                Column("kind", "类型"),
                Column("processName", "程序名"),
                Column("processPath", "程序路径"),
                Column("remote", "远端"),
                Column("remoteAddress", "远端 IP"),
                Column("domain", "域名（推测）"),
                Column("rule", "命中规则"),
                Column("detail", "详情"),
            },
            _auditGrid.Rows
                .Cast<DataGridViewRow>()
                .Select(row => row.Tag)
                .OfType<AuditRow>()
                .Select(row => Row(
                    ("timeUtc", row.TimeUtc),
                    ("kind", row.Kind),
                    ("processName", row.ProcessName),
                    ("processPath", row.ProcessPath),
                    ("remote", row.Remote),
                    ("remoteAddress", row.RemoteAddress),
                    ("domain", row.Domain),
                    ("rule", row.Rule),
                    ("detail", row.Detail)))
                .ToList());
    }

    private void ExportDnsView()
    {
        ExportTable(
            "dns",
            "DNS",
            "WinAppGuard-DNS",
            new[]
            {
                Column("time", "时间"),
                Column("processName", "程序"),
                Column("processPath", "程序路径"),
                Column("pid", "PID"),
                Column("queryName", "域名"),
                Column("status", "结果"),
            },
            _dnsGrid.Rows
                .Cast<DataGridViewRow>()
                .Select(row => row.DataBoundItem)
                .OfType<DnsRow>()
                .Select(row => Row(
                    ("time", row.TimeText),
                    ("processName", row.ProcessText),
                    ("processPath", row.ProcessPath),
                    ("pid", row.Pid),
                    ("queryName", row.QueryName),
                    ("status", row.StatusText)))
                .ToList());
    }

    private void ExportNetworkAlertsView()
    {
        ExportTable(
            "network-alerts",
            "反网络攻击",
            "WinAppGuard-反网络攻击",
            new[]
            {
                Column("id", "告警 ID"),
                Column("time", "时间"),
                Column("severity", "级别"),
                Column("status", "状态"),
                Column("signature", "规则"),
                Column("remoteAddress", "远端 IP"),
                Column("target", "远端"),
                Column("process", "进程"),
                Column("evidence", "证据"),
                Column("blockState", "拦截状态"),
            },
            _ndGrid.Rows
                .Cast<DataGridViewRow>()
                .Select(row => row.DataBoundItem)
                .OfType<NdRow>()
                .Select(row => Row(
                    ("id", row.Id),
                    ("time", row.TimeText),
                    ("severity", row.SeverityText),
                    ("status", row.StatusText),
                    ("signature", row.Signature),
                    ("remoteAddress", row.RemoteAddress),
                    ("target", row.TargetText),
                    ("process", row.ProcessText),
                    ("evidence", row.Evidence),
                    ("blockState", row.BlockStateText)))
                .ToList());
    }

    private void ExportTrafficView()
    {
        ExportTable(
            "traffic",
            "流量",
            "WinAppGuard-流量",
            new[]
            {
                Column("name", "程序"),
                Column("processPath", "程序路径"),
                Column("uploadBytes", "上传字节"),
                Column("downloadBytes", "下载字节"),
                Column("totalBytes", "总字节"),
                Column("uploadRate", "上传速率（字节/秒）"),
                Column("downloadRate", "下载速率（字节/秒）"),
                Column("lastSeenUtc", "最后活动（UTC）"),
                Column("note", "备注"),
            },
            _trafficGrid.Rows
                .Cast<DataGridViewRow>()
                .Select(row => row.DataBoundItem)
                .OfType<TrafficRow>()
                .Select(row => Row(
                    ("name", row.Name),
                    ("processPath", row.PathText),
                    ("uploadBytes", row.BytesOut),
                    ("downloadBytes", row.BytesIn),
                    ("totalBytes", row.Total),
                    ("uploadRate", row.RateOut),
                    ("downloadRate", row.RateIn),
                    ("lastSeenUtc", row.LastSeenUtc),
                    ("note", row.Note)))
                .ToList());
    }

    /// <summary>连接页右键「复制选中行」：按表格当前显示顺序抄成 TSV，粘到 Excel 正好分列。</summary>
    private void OnCopyConnectionRowClick(object? sender, EventArgs e)
    {
        var grid = _connectionViewMode == ConnectionViewMode.Summary
            ? _connectionSummaryGrid
            : _connectionGrid;

        if (grid.CurrentRow is null)
        {
            return;
        }

        var text = string.Join(
            "\t",
            grid.CurrentRow.Cells
                .Cast<DataGridViewCell>()
                .Select(cell => cell.FormattedValue?.ToString() ?? string.Empty));

        try
        {
            Clipboard.SetText(text);
        }
        catch (Exception)
        {
            // 剪贴板被别的程序占用时静默失败，不值得打断用户。
        }
    }

    private static TableExportColumn Column(string key, string header)
        => new(key, Localizer.T(header));

    private static IReadOnlyDictionary<string, object?> Row(
        params (string Key, object? Value)[] values)
    {
        var row = new Dictionary<string, object?>(values.Length, StringComparer.Ordinal);

        foreach (var (key, value) in values)
        {
            row[key] = value;
        }

        return row;
    }

    /// <summary>弹出保存对话框并写入 CSV / JSON。</summary>
    private void ExportTable(
        string view,
        string pageTitle,
        string fileBaseName,
        IReadOnlyList<TableExportColumn> columns,
        IReadOnlyList<IReadOnlyDictionary<string, object?>> rows)
    {
        if (rows.Count == 0)
        {
            UiMessageBox.Show(
                this,
                Localizer.F("当前{0}视图没有可导出的行。", pageTitle),
                AppConstants.AppName,
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
            return;
        }

        using var dialog = new SaveFileDialog
        {
            Title = Localizer.F("导出{0}", pageTitle),
            Filter = "CSV (*.csv)|*.csv|JSON (*.json)|*.json",
            FilterIndex = 1,
            FileName = $"{fileBaseName}-{DateTime.Now:yyyyMMdd-HHmmss}",
            DefaultExt = "csv",
            AddExtension = true,
            OverwritePrompt = true,
            RestoreDirectory = true,
        };

        if (dialog.ShowDialog(this) != DialogResult.OK)
        {
            return;
        }

        var csv = dialog.FilterIndex == 1;
        var path = Path.ChangeExtension(dialog.FileName, csv ? ".csv" : ".json");

        var document = new TableExportDocument
        {
            ToolVersion = ExportToolVersion,
            View = view,
            Columns = columns,
            Rows = rows,
        };

        try
        {
            if (csv)
            {
                TableExport.WriteCsv(path, document);
            }
            else
            {
                TableExport.WriteJson(path, document);
            }

            LocalLog.Operation(LocalLog.Pick(
                $"导出{pageTitle}：{rows.Count} 行 → {path}",
                $"Export {view}: {rows.Count} rows -> {path}."));

            UiMessageBox.Show(
                this,
                Localizer.F("已导出 {0} 行。\n\n{1}", rows.Count, path),
                AppConstants.AppName,
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
        }
        catch (Exception ex)
        {
            ShowError($"导出{pageTitle}失败", ex, $"Failed to export {view}");
        }
    }
}
