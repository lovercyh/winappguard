namespace WinAppGuard.Forms;

/// <summary>
/// 「设置分组」的小对话框：可选已有分组，也可以直接输入新名字。
///
/// 为什么不用 InputBox：它没法列出已经有分组（用户会拼出"游戏"和"游戏 "两个组），
/// 也没法在框里说清"分组只影响界面归类，不影响规则是否生效"。
/// </summary>
internal sealed class RuleGroupPrompt : Form
{
    private readonly ComboBox _combo;

    private RuleGroupPrompt(IReadOnlyList<string> groups, string current)
    {
        Text = "设置分组";
        FormBorderStyle = FormBorderStyle.FixedDialog;
        StartPosition = FormStartPosition.CenterParent;
        MaximizeBox = false;
        MinimizeBox = false;
        ShowInTaskbar = false;
        ClientSize = new Size(430, 170);
        Font = new Font("Microsoft YaHei UI", 9F);

        var layout = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            Padding = new Padding(16),
            RowCount = 4,
        };
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));

        var title = new Label
        {
            Text = "分组名（留空 = 未分组）：",
            AutoSize = true,
        };

        _combo = new ComboBox
        {
            Dock = DockStyle.Top,
            DropDownStyle = ComboBoxStyle.DropDown,
            Width = 390,
        };
        _combo.Items.AddRange(groups.Cast<object>().ToArray());
        _combo.Text = current;

        var hint = new Label
        {
            Text = "分组只影响界面怎么归类，不影响规则是否生效。\n可以输入一个新名字来创建分组。",
            AutoSize = true,
            ForeColor = SystemColors.GrayText,
            Dock = DockStyle.Fill,
        };

        var buttons = new FlowLayoutPanel
        {
            FlowDirection = FlowDirection.RightToLeft,
            Dock = DockStyle.Fill,
            AutoSize = true,
        };

        var okButton = new Button
        {
            Text = "确定",
            DialogResult = DialogResult.OK,
            AutoSize = true,
            MinimumSize = new Size(88, 30),
        };

        var cancelButton = new Button
        {
            Text = "取消",
            DialogResult = DialogResult.Cancel,
            AutoSize = true,
            MinimumSize = new Size(88, 30),
        };

        buttons.Controls.Add(okButton);
        buttons.Controls.Add(cancelButton);

        layout.Controls.Add(title, 0, 0);
        layout.Controls.Add(_combo, 0, 1);
        layout.Controls.Add(hint, 0, 2);
        layout.Controls.Add(buttons, 0, 3);

        Controls.Add(layout);
        AcceptButton = okButton;
        CancelButton = cancelButton;
    }

    /// <summary>
    /// 显示对话框。
    /// </summary>
    /// <returns>取消返回 null；确定返回分组名（空字符串 = 未分组）。</returns>
    internal static string? Ask(IWin32Window? owner, IReadOnlyList<string> groups, string current)
    {
        using var form = new RuleGroupPrompt(groups, current);

        return form.ShowDialog(owner) == DialogResult.OK
            ? form._combo.Text.Trim()
            : null;
    }
}
