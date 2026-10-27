using WinAppGuard.Contracts;
using WinAppGuard.Localization;

namespace WinAppGuard.Forms;

/// <summary>
/// 4.0：反端口扫描设置。
///
/// 只收集用户选择；真正写入由主窗体走提权 IPC（write.antiscan.configure）。
/// </summary>
internal sealed class AntiScanSettingsForm : Form
{
    private readonly CheckBox _enabled;
    private readonly CheckBox _autoBlock;
    private readonly ComboBox _sensitivity;
    private readonly ComboBox _blockMinutes;
    private readonly TextBox _allowlist;

    private AntiScanSettingsForm(
        AntiScanSettingsDto current,
        bool npcapAvailable,
        string? npcapVersion)
    {
        Text = Localizer.T("反端口扫描设置");
        FormBorderStyle = FormBorderStyle.FixedDialog;
        StartPosition = FormStartPosition.CenterParent;
        MaximizeBox = false;
        MinimizeBox = false;
        ShowInTaskbar = false;
        ClientSize = new Size(520, 500);
        Font = new Font("Microsoft YaHei UI", 9F);

        var layout = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            Padding = new Padding(16),
            RowCount = 11,
        };

        for (var i = 0; i < 11; i++)
        {
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        }

        var npcap = new Label
        {
            Text = npcapAvailable
                ? Localizer.F("Npcap：已安装（{0}）", npcapVersion ?? "?")
                : Localizer.T("Npcap：未安装，反扫描不可用。安装 WinAppGuard 时可选安装 Npcap。"),
            AutoSize = true,
            ForeColor = npcapAvailable ? Color.FromArgb(0, 120, 0) : Color.FromArgb(191, 87, 0),
            Dock = DockStyle.Fill,
        };

        _enabled = new CheckBox
        {
            Text = Localizer.T("启用反端口扫描（入站 TCP SYN）"),
            Checked = current.Enabled,
            AutoSize = true,
        };

        _autoBlock = new CheckBox
        {
            Text = Localizer.T("高危扫描自动临时封禁来源 IP（默认关闭）"),
            Checked = current.AutoBlock,
            AutoSize = true,
        };

        var sensitivityLabel = new Label
        {
            Text = Localizer.T("敏感度："),
            AutoSize = true,
            Margin = new Padding(3, 10, 3, 3),
        };

        _sensitivity = new ComboBox
        {
            DropDownStyle = ComboBoxStyle.DropDownList,
            Width = 300,
        };
        _sensitivity.Items.Add(Localizer.T("标准（20 端口 / 60 秒起）"));
        _sensitivity.Items.Add(Localizer.T("保守（约 2 倍阈值）"));
        _sensitivity.SelectedIndex = current.Sensitivity == "conservative" ? 1 : 0;

        var minutesLabel = new Label
        {
            Text = Localizer.T("临时封禁时长："),
            AutoSize = true,
            Margin = new Padding(3, 10, 3, 3),
        };

        _blockMinutes = new ComboBox
        {
            DropDownStyle = ComboBoxStyle.DropDownList,
            Width = 160,
        };
        _blockMinutes.Items.AddRange(new object[]
        {
            Localizer.T("5 分钟"),
            Localizer.T("10 分钟"),
            Localizer.T("30 分钟"),
            Localizer.T("60 分钟"),
        });

        var minutes = new[] { 5, 10, 30, 60 };
        var index = Array.IndexOf(minutes, Math.Clamp(current.BlockMinutes, 5, 60));
        _blockMinutes.SelectedIndex = index >= 0 ? index : 1;

        var allowLabel = new Label
        {
            Text = Localizer.T("永不自动封禁的地址（一行一个，IPv4/IPv6）："),
            AutoSize = true,
            Margin = new Padding(3, 12, 3, 3),
        };

        _allowlist = new TextBox
        {
            Multiline = true,
            ScrollBars = ScrollBars.Vertical,
            Dock = DockStyle.Fill,
            Height = 76,
            Text = string.Join(Environment.NewLine, current.Allowlist ?? new List<string>()),
        };

        var hint = new Label
        {
            Text = Localizer.T(
                "只检测入站 TCP SYN；不读载荷、不做 DPI。\n" +
                "封禁只拦新入站连接，不会切断已有连接；解除后立刻恢复。\n" +
                "服务关闭或反扫描关闭时，临时封禁会解除。"),
            AutoSize = true,
            ForeColor = SystemColors.GrayText,
            Dock = DockStyle.Fill,
            Margin = new Padding(3, 10, 3, 3),
        };

        var buttons = new FlowLayoutPanel
        {
            FlowDirection = FlowDirection.RightToLeft,
            Dock = DockStyle.Fill,
            AutoSize = true,
        };

        var ok = new Button
        {
            Text = Localizer.T("确定"),
            DialogResult = DialogResult.OK,
            AutoSize = true,
            MinimumSize = new Size(88, 30),
        };

        var cancel = new Button
        {
            Text = Localizer.T("取消"),
            DialogResult = DialogResult.Cancel,
            AutoSize = true,
            MinimumSize = new Size(88, 30),
        };

        buttons.Controls.Add(ok);
        buttons.Controls.Add(cancel);

        layout.Controls.Add(npcap, 0, 0);
        layout.Controls.Add(_enabled, 0, 1);
        layout.Controls.Add(_autoBlock, 0, 2);
        layout.Controls.Add(sensitivityLabel, 0, 3);
        layout.Controls.Add(_sensitivity, 0, 4);
        layout.Controls.Add(minutesLabel, 0, 5);
        layout.Controls.Add(_blockMinutes, 0, 6);
        layout.Controls.Add(allowLabel, 0, 7);
        layout.Controls.Add(_allowlist, 0, 8);
        layout.Controls.Add(hint, 0, 9);
        layout.Controls.Add(buttons, 0, 10);

        Controls.Add(layout);
        AcceptButton = ok;
        CancelButton = cancel;

        _autoBlock.Enabled = current.Enabled;
        _enabled.CheckedChanged += (_, _) => _autoBlock.Enabled = _enabled.Checked;
    }

    /// <summary>取消返回 null；确定返回设置。</summary>
    internal static AntiScanSettingsDto? Ask(
        IWin32Window? owner,
        AntiScanSettingsDto current,
        bool npcapAvailable,
        string? npcapVersion)
    {
        using var form = new AntiScanSettingsForm(current, npcapAvailable, npcapVersion);

        if (form.ShowDialog(owner) != DialogResult.OK)
        {
            return null;
        }

        var allowlist = form._allowlist.Lines
            .Select(line => line.Trim())
            .Where(line => line.Length > 0)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var minutes = new[] { 5, 10, 30, 60 };

        return new AntiScanSettingsDto
        {
            Enabled = form._enabled.Checked,
            AutoBlock = form._autoBlock.Checked,
            Sensitivity = form._sensitivity.SelectedIndex == 1 ? "conservative" : "standard",
            BlockMinutes = minutes[Math.Max(0, form._blockMinutes.SelectedIndex)],
            Allowlist = allowlist,
        };
    }
}
