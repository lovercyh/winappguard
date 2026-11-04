using WinAppGuard.Contracts;
using WinAppGuard.Localization;

namespace WinAppGuard.Forms;

/// <summary>5.0：网络被动检测设置。</summary>
internal sealed class NetworkDetectionSettingsForm : Form
{
    private readonly CheckBox _enabled;
    private readonly ComboBox _profile;
    private readonly CheckBox _notify;
    private readonly NumericUpDown _retention;

    private NetworkDetectionSettingsForm(NetworkDetectionSettingsDto current)
    {
        Text = Localizer.T("反网络攻击设置");
        Font = new Font("Microsoft YaHei UI", 9F);
        FormBorderStyle = FormBorderStyle.FixedDialog;
        StartPosition = FormStartPosition.CenterParent;
        MaximizeBox = false;
        MinimizeBox = false;
        ShowInTaskbar = false;
        ClientSize = new Size(460, 300);

        var layout = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            Padding = new Padding(16),
            RowCount = 8,
        };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));

        _enabled = new CheckBox
        {
            AutoSize = true,
            Checked = current.Enabled,
            Text = Localizer.T("启用反网络攻击检测（Suricata + ET Open）"),
        };
        layout.Controls.Add(_enabled, 0, 0);

        layout.Controls.Add(new Label
        {
            AutoSize = true,
            Margin = new Padding(0, 12, 0, 4),
            Text = Localizer.T("规则档位："),
        }, 0, 1);

        _profile = new ComboBox
        {
            DropDownStyle = ComboBoxStyle.DropDownList,
            Width = 320,
        };
        _profile.Items.Add(Localizer.T("标准（推荐，客户端高价值规则）"));
        _profile.Items.Add(Localizer.T("全量（ET Open 全部规则，资源占用更高）"));
        _profile.SelectedIndex = string.Equals(
            current.RuleProfile, "full", StringComparison.OrdinalIgnoreCase) ? 1 : 0;
        layout.Controls.Add(_profile, 0, 2);

        _notify = new CheckBox
        {
            AutoSize = true,
            Checked = current.Notify,
            Margin = new Padding(0, 12, 0, 0),
            Text = Localizer.T("新的高危告警显示托盘通知"),
        };
        layout.Controls.Add(_notify, 0, 3);

        var retentionPanel = new FlowLayoutPanel
        {
            AutoSize = true,
            Margin = new Padding(0, 12, 0, 0),
        };
        retentionPanel.Controls.Add(new Label
        {
            AutoSize = true,
            Text = Localizer.T("告警保留天数："),
            Margin = new Padding(0, 6, 6, 0),
        });

        _retention = new NumericUpDown
        {
            Minimum = 1,
            Maximum = 365,
            Value = Math.Clamp(current.RetentionDays, 1, 365),
            Width = 80,
        };
        retentionPanel.Controls.Add(_retention);
        layout.Controls.Add(retentionPanel, 0, 4);

        layout.Controls.Add(new Label
        {
            AutoSize = true,
            ForeColor = Color.FromArgb(150, 90, 0),
            MaximumSize = new Size(420, 0),
            Margin = new Padding(0, 14, 0, 0),
            Text = Localizer.T(
                "被动检测只告警，不自动拦截。规则命中后由你手动选择是否用 WFP 临时阻断；HTTPS 正文不可见。"),
        }, 0, 5);

        var buttons = new FlowLayoutPanel
        {
            FlowDirection = FlowDirection.RightToLeft,
            Dock = DockStyle.Fill,
            AutoSize = true,
            Margin = new Padding(0, 16, 0, 0),
        };
        var cancel = new Button { Text = Localizer.T("取消"), DialogResult = DialogResult.Cancel, Width = 88 };
        var ok = new Button { Text = Localizer.T("保存"), DialogResult = DialogResult.OK, Width = 88 };
        buttons.Controls.Add(cancel);
        buttons.Controls.Add(ok);
        layout.Controls.Add(buttons, 0, 6);

        Controls.Add(layout);
        AcceptButton = ok;
        CancelButton = cancel;
    }

    internal static NetworkDetectionSettingsDto? Ask(
        IWin32Window? owner,
        NetworkDetectionSettingsDto current)
    {
        using var form = new NetworkDetectionSettingsForm(current);

        if (form.ShowDialog(owner) != DialogResult.OK)
        {
            return null;
        }

        return new NetworkDetectionSettingsDto
        {
            Enabled = form._enabled.Checked,
            RuleProfile = form._profile.SelectedIndex == 1 ? "full" : "standard",
            Notify = form._notify.Checked,
            RetentionDays = (int)form._retention.Value,
        };
    }
}


