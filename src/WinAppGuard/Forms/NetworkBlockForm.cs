using WinAppGuard.Contracts;
using WinAppGuard.Localization;

namespace WinAppGuard.Forms;

/// <summary>
/// 5.0：用户手动拦截范围选择。
///
/// 默认只拦“远端 IP:端口”，因为它能阻止后续连接且不会误伤整个程序；
/// “此连接”更精确但受本机临时端口影响；“远端 IP”影响面最大。
/// </summary>
internal sealed class NetworkBlockForm : Form
{
    private readonly RadioButton _ipPortRadio;
    private readonly RadioButton _connectionRadio;
    private readonly RadioButton _ipRadio;
    private readonly NumericUpDown _minutes;
    private readonly NetworkAlertDto _alert;

    private NetworkBlockForm(NetworkAlertDto alert)
    {
        _alert = alert;
        Text = Localizer.T("拦截网络流量");
        Font = new Font("Microsoft YaHei UI", 9F);
        FormBorderStyle = FormBorderStyle.FixedDialog;
        StartPosition = FormStartPosition.CenterParent;
        MaximizeBox = false;
        MinimizeBox = false;
        ShowInTaskbar = false;

        // Win11 的字体/DPI 度量比 Win10 大，固定 520x300 会把底部按钮裁掉。
        // 改为 AutoSize + 最小尺寸，内容变高时窗体一起长高；极端 DPI 下还能滚动。
        AutoScaleMode = AutoScaleMode.Font;
        AutoSize = true;
        AutoSizeMode = AutoSizeMode.GrowAndShrink;
        AutoScroll = true;
        MinimumSize = new Size(560, 360);
        ClientSize = new Size(560, 360);

        var layout = new TableLayoutPanel
        {
            Dock = DockStyle.Top,
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            ColumnCount = 1,
            Padding = new Padding(16),
            RowCount = 6,
        };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));

        layout.Controls.Add(new Label
        {
            AutoSize = true,
            MaximumSize = new Size(480, 0),
            Text = Localizer.F(
                "规则：{0}\n远端：{1}:{2}    本机：{3}:{4}",
                alert.Signature,
                alert.RemoteAddress,
                alert.RemotePort,
                alert.LocalAddress,
                alert.LocalPort),
        }, 0, 0);

        layout.Controls.Add(new Label
        {
            AutoSize = true,
            Margin = new Padding(0, 12, 0, 6),
            Text = Localizer.T("选择拦截范围："),
        }, 0, 1);

        _ipPortRadio = new RadioButton
        {
            AutoSize = true,
            MaximumSize = new Size(500, 0),
            Checked = true,
            Text = Localizer.F(
                "远端 IP:端口（推荐，阻止所有程序访问 {0}:{1}）",
                alert.RemoteAddress,
                alert.RemotePort),
        };

        _connectionRadio = new RadioButton
        {
            AutoSize = true,
            MaximumSize = new Size(500, 0),
            Enabled = alert.LocalPort > 0 && !string.IsNullOrEmpty(alert.LocalAddress),
            Text = Localizer.T("只拦截此连接（五元组，精确但可能只影响当前连接）"),
        };

        _ipRadio = new RadioButton
        {
            AutoSize = true,
            MaximumSize = new Size(500, 0),
            Text = Localizer.F(
                "远端 IP（影响所有程序访问 {0}，范围最大）",
                alert.RemoteAddress),
        };

        var scopePanel = new FlowLayoutPanel
        {
            FlowDirection = FlowDirection.TopDown,
            AutoSize = true,
            WrapContents = false,
            Margin = new Padding(0),
        };
        scopePanel.Controls.Add(_ipPortRadio);
        scopePanel.Controls.Add(_connectionRadio);
        scopePanel.Controls.Add(_ipRadio);
        layout.Controls.Add(scopePanel, 0, 2);

        var durationPanel = new FlowLayoutPanel
        {
            AutoSize = true,
            Margin = new Padding(0, 12, 0, 0),
        };
        durationPanel.Controls.Add(new Label
        {
            AutoSize = true,
            Text = Localizer.T("拦截时长（分钟）："),
            Margin = new Padding(0, 6, 6, 0),
        });

        _minutes = new NumericUpDown
        {
            Minimum = 1,
            Maximum = 60,
            Value = 10,
            Width = 70,
        };
        durationPanel.Controls.Add(_minutes);
        layout.Controls.Add(durationPanel, 0, 3);

        layout.Controls.Add(new Label
        {
            AutoSize = true,
            ForeColor = Color.FromArgb(150, 90, 0),
            MaximumSize = new Size(480, 0),
            Margin = new Padding(0, 10, 0, 0),
            Text = Localizer.T(
                "这是事后阻断：触发告警的请求可能已经发出；拦截通过 WFP 动态过滤器执行，服务重启后自动解除。"),
        }, 0, 4);

        var buttons = new FlowLayoutPanel
        {
            FlowDirection = FlowDirection.RightToLeft,
            Dock = DockStyle.Fill,
            AutoSize = true,
            Margin = new Padding(0, 12, 0, 0),
        };
        var cancel = new Button { Text = Localizer.T("取消"), DialogResult = DialogResult.Cancel, Width = 88 };
        var ok = new Button { Text = Localizer.T("确认拦截"), DialogResult = DialogResult.OK, Width = 100 };
        buttons.Controls.Add(cancel);
        buttons.Controls.Add(ok);
        layout.Controls.Add(buttons, 0, 5);

        Controls.Add(layout);
        AcceptButton = ok;
        CancelButton = cancel;
    }

    internal static BlockChoice? Ask(IWin32Window? owner, NetworkAlertDto alert)
    {
        using var form = new NetworkBlockForm(alert);

        if (form.ShowDialog(owner) != DialogResult.OK)
        {
            return null;
        }

        var kind = form._connectionRadio.Checked
            ? "connection"
            : form._ipRadio.Checked
                ? "ip"
                : "ip-port";

        var target = kind switch
        {
            "connection" => string.Join('|',
                alert.Protocol,
                alert.LocalAddress,
                alert.LocalPort,
                alert.RemoteAddress,
                alert.RemotePort),
            "ip" => alert.RemoteAddress,
            _ => string.Join('|', alert.RemoteAddress, alert.RemotePort, alert.Protocol),
        };

        return new BlockChoice(kind, target, (int)form._minutes.Value);
    }

    internal readonly record struct BlockChoice(string Kind, string Target, int Minutes);
}
