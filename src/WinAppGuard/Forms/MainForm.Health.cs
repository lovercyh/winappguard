using WinAppGuard.Contracts;
using WinAppGuard.Localization;

namespace WinAppGuard.Forms;

/// <summary>6.0：检测健康度页（进程 ETW + 服务模块）。</summary>
public sealed partial class MainForm
{
    private TabPage _tabDetectionHealth = null!;
    private Label _etwHealthLabel = null!;
    private Label _moduleHealthLabel = null!;

    private void InitializeHealthPage()
    {
        _tabDetectionHealth = new TabPage
        {
            Name = "_tabDetectionHealth",
            Text = Localizer.T("检测健康度"),
            Padding = new Padding(12),
            UseVisualStyleBackColor = true,
        };

        _etwHealthLabel = new Label
        {
            AutoSize = false,
            Dock = DockStyle.Top,
            Height = 132,
            Font = new Font(Font, FontStyle.Regular),
            Text = Localizer.T("进程 ETW：状态未知"),
        };

        _moduleHealthLabel = new Label
        {
            AutoSize = false,
            Dock = DockStyle.Fill,
            Text = string.Empty,
        };

        _tabDetectionHealth.Controls.Add(_moduleHealthLabel);
        _tabDetectionHealth.Controls.Add(_etwHealthLabel);
        _tabControl.Controls.Add(_tabDetectionHealth);
    }

    private void UpdateHealthPage(ServiceStatus? status)
    {
        if (_etwHealthLabel is null || _etwHealthLabel.IsDisposed)
        {
            return;
        }

        if (status is null)
        {
            _etwHealthLabel.Text = Localizer.T("检测健康度：服务未连接");
            _moduleHealthLabel.Text = string.Empty;
            return;
        }

        var etw = status.ProcessEtw;
        var etwText = etw is null
            ? Localizer.T("进程 ETW：服务未返回状态")
            : Localizer.IsEnglish
                ? $"Process ETW: {(etw.Running ? "running" : "fallback polling")}\n"
                  + $"table={etw.TableEntries}, events={etw.EventsSeen}, parseFailures={etw.ParseFailures}\n"
                  + $"lastEvent={etw.LastEventUtc?.ToLocalTime():yyyy-MM-dd HH:mm:ss}"
                  + (string.IsNullOrWhiteSpace(etw.LastError) ? string.Empty : $"\nlastError={etw.LastError}")
                : $"进程 ETW：{(etw.Running ? "运行中" : "已降级为轮询归因")}\n"
                  + $"进程表 {etw.TableEntries} 条，事件 {etw.EventsSeen}，解析失败 {etw.ParseFailures}，LOLBin {etw.LolbinMatches}，重启尝试 {etw.RestartAttempts}\n"
                  + $"最近事件：{etw.LastEventUtc?.ToLocalTime():yyyy-MM-dd HH:mm:ss}"
                  + (etw.NextRetryUtc is { } next ? $"；下次重试：{next.ToLocalTime():HH:mm:ss}" : string.Empty)
                  + (string.IsNullOrWhiteSpace(etw.LastError) ? string.Empty : $"\n最近错误：{etw.LastError}");
        _etwHealthLabel.Text = etwText;

        var dnsBypass = status.DnsBypass;
        if (dnsBypass is not null)
        {
            _etwHealthLabel.Text += "\n" + (Localizer.IsEnglish
                ? $"DNS bypass: {dnsBypass.Count} event(s); last={dnsBypass.LastRemote} {dnsBypass.LastUtc?.ToLocalTime():HH:mm:ss}"
                : $"DNS 绕过：{dnsBypass.Count} 次；最近 {dnsBypass.LastRemote} {dnsBypass.LastUtc?.ToLocalTime():HH:mm:ss}");
        }

        var ioc = status.Ioc;
        if (ioc is not null)
        {
            _etwHealthLabel.Text += "\n" + (Localizer.IsEnglish
                ? $"ThreatFox IOC: {(ioc.Loaded ? $"{ioc.Count} entries" : "not loaded")} " +
                  $"(>= {ioc.MinConfidence}%), matches={ioc.Matches}, " +
                  $"snapshot={ioc.SourceUtc?.ToLocalTime():yyyy-MM-dd}"
                : $"ThreatFox IOC：{(ioc.Loaded ? $"{ioc.Count} 条" : "未加载")}" +
                  $"（≥ {ioc.MinConfidence}%），命中 {ioc.Matches} 次，" +
                  $"快照 {ioc.SourceUtc?.ToLocalTime():yyyy-MM-dd}");
        }

        var modules = status.Modules;
        if (modules is null || modules.Count == 0)
        {
            _moduleHealthLabel.Text = Localizer.T("模块健康度：暂无数据");
            return;
        }

        _moduleHealthLabel.Text = string.Join(
            Environment.NewLine,
            modules.OrderBy(item => item.Order).Select(item =>
                $"{item.Name,-24} {item.State,-10} {item.Detail}"
                + (string.IsNullOrWhiteSpace(item.LastError) ? string.Empty : $"  [{item.LastError}]")));
    }
}
