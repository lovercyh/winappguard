namespace WinAppGuard.Forms;

/// <summary>用户对新程序的处理选择。</summary>
internal enum NewProgramChoice
{
    /// <summary>允许联网（以后不再询问）。</summary>
    Allow,

    /// <summary>不建规则，以后也不再询问。</summary>
    Ignore,

    /// <summary>阻止联网（会创建一条阻止规则）。</summary>
    Block,

    /// <summary>这次先不决定，下次联网再问。</summary>
    Later,
}

/// <summary>
/// 「新程序正在联网」提示框。
///
/// 为什么不用 MessageBox：它最多两个按钮，而这里需要**四个**明确选择。
/// 也不做成托盘气泡：气泡点不了按钮，等于没给用户选择权。
/// </summary>
internal sealed class NewProgramPrompt : Form
{
    private NewProgramChoice _choice = NewProgramChoice.Later;

    private NewProgramPrompt(string path)
    {
        Text = "新程序正在联网";
        FormBorderStyle = FormBorderStyle.FixedDialog;
        StartPosition = FormStartPosition.CenterParent;
        MaximizeBox = false;
        MinimizeBox = false;
        ShowInTaskbar = false;
        ClientSize = new Size(560, 250);
        Font = new Font("Microsoft YaHei UI", 9F);

        var layout = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            Padding = new Padding(18),
            RowCount = 4,
        };
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        layout.RowStyles.Add(new RowStyle(SizeType.AutoSize));

        var title = new Label
        {
            Text = $"「{Path.GetFileName(path)}」正在连接网络。",
            Font = new Font(Font, FontStyle.Bold),
            AutoSize = true,
            Dock = DockStyle.Fill,
        };

        var detail = new Label
        {
            Text = $"程序路径：\n{path}\n\n" +
                   "你可以现在决定怎么处理它。\n" +
                   "「阻止联网」会创建一条阻止规则，之后可以在「规则」页删除。",
            AutoSize = true,
            Dock = DockStyle.Fill,
        };

        var buttons = new FlowLayoutPanel
        {
            FlowDirection = FlowDirection.RightToLeft,
            Dock = DockStyle.Fill,
            AutoSize = true,
            Padding = new Padding(0, 8, 0, 0),
        };

        var allowButton = MakeButton("允许联网", DialogResult.OK, NewProgramChoice.Allow);
        var ignoreButton = MakeButton("忽略", DialogResult.OK, NewProgramChoice.Ignore);
        var blockButton = MakeButton("阻止联网", DialogResult.OK, NewProgramChoice.Block);
        var laterButton = MakeButton("稍后", DialogResult.Cancel, NewProgramChoice.Later);

        buttons.Controls.Add(allowButton);
        buttons.Controls.Add(ignoreButton);
        buttons.Controls.Add(blockButton);
        buttons.Controls.Add(laterButton);

        layout.Controls.Add(title, 0, 0);
        layout.Controls.Add(detail, 0, 1);
        layout.Controls.Add(new Label { Text = string.Empty, AutoSize = true }, 0, 2);
        layout.Controls.Add(buttons, 0, 3);

        Controls.Add(layout);
        AcceptButton = allowButton;
        CancelButton = laterButton;
    }

    private Button MakeButton(string text, DialogResult result, NewProgramChoice choice)
    {
        var button = new Button
        {
            Text = text,
            AutoSize = true,
            MinimumSize = new Size(96, 30),
            DialogResult = result,
        };

        button.Click += (_, _) => _choice = choice;
        return button;
    }

    /// <summary>显示提示框并返回用户选择（关掉窗口按「稍后」处理）。</summary>
    internal static NewProgramChoice Ask(IWin32Window? owner, string path)
    {
        using var form = new NewProgramPrompt(path);
        _ = form.ShowDialog(owner);
        return form._choice;
    }
}
