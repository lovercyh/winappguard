using WinAppGuard.Localization;

namespace WinAppGuard.Forms;

/// <summary>
/// 3.7：抑制一条 IDS 告警的小对话框（1 小时 / 24 小时 / 永久）。
///
/// 抑制只影响相同「规则 + 程序 + 目标」的后续告警，不会关闭整条规则。
/// </summary>
internal sealed class IdsSuppressForm : Form
{
    private readonly RadioButton _oneHour;
    private readonly RadioButton _oneDay;
    private readonly RadioButton _forever;

    private IdsSuppressForm(string rule, string process, string target)
    {
        Text = Localizer.T("抑制 IDS 告警");
        FormBorderStyle = FormBorderStyle.FixedDialog;
        StartPosition = FormStartPosition.CenterParent;
        MaximizeBox = false;
        MinimizeBox = false;
        ShowInTaskbar = false;
        ClientSize = new Size(470, 264);
        Font = new Font("Microsoft YaHei UI", 9F);

        var layout = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            Padding = new Padding(16),
            RowCount = 6,
        };

        for (var i = 0; i < 5; i++)
        {
            layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        }

        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

        var scope = new Label
        {
            Text = Localizer.F(
                "只抑制相同规则 / 程序 / 目标的告警：\n规则：{0}\n程序：{1}\n目标：{2}",
                rule, process, target),
            AutoSize = true,
            Dock = DockStyle.Fill,
        };

        _oneHour = new RadioButton
        {
            Text = Localizer.T("1 小时"),
            AutoSize = true,
        };

        _oneDay = new RadioButton
        {
            Text = Localizer.T("24 小时"),
            AutoSize = true,
            Checked = true,
        };

        _forever = new RadioButton
        {
            Text = Localizer.T("永久（可在设置里取消）"),
            AutoSize = true,
        };

        var hint = new Label
        {
            Text = Localizer.T(
                "抑制不会删除已有告警，也不会阻断连接；只是不再为同一目标反复提示。"),
            AutoSize = true,
            ForeColor = SystemColors.GrayText,
            Dock = DockStyle.Fill,
            Margin = new Padding(3, 12, 3, 3),
        };

        var buttons = new FlowLayoutPanel
        {
            FlowDirection = FlowDirection.RightToLeft,
            Dock = DockStyle.Fill,
            AutoSize = true,
        };

        var ok = new Button
        {
            Text = Localizer.T("抑制"),
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

        layout.Controls.Add(scope, 0, 0);
        layout.Controls.Add(_oneHour, 0, 1);
        layout.Controls.Add(_oneDay, 0, 2);
        layout.Controls.Add(_forever, 0, 3);
        layout.Controls.Add(hint, 0, 4);
        layout.Controls.Add(buttons, 0, 5);

        Controls.Add(layout);
        AcceptButton = ok;
        CancelButton = cancel;
    }

    /// <summary>取消返回 null；否则返回抑制时长（null = 永久）。</summary>
    internal static Choice? Ask(
        IWin32Window? owner, string rule, string process, string target)
    {
        using var form = new IdsSuppressForm(rule, process, target);

        if (form.ShowDialog(owner) != DialogResult.OK)
        {
            return null;
        }

        return form._forever.Checked
            ? new Choice(null)
            : new Choice(form._oneHour.Checked ? TimeSpan.FromHours(1) : TimeSpan.FromHours(24));
    }

    internal readonly record struct Choice(TimeSpan? Duration);
}
