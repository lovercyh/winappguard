namespace WinAppGuard.Forms;

/// <summary>
/// 危险操作确认框。
///
/// 本工具所有会改动系统状态的操作都必须先过这一关（安全要求 5）。
///
/// 为什么不用 MessageBox：MessageBox 只能显示一段纯文本，做不到这三件事：
///   1. 把「程序名 / 完整路径 / 影响范围 / 即将创建的规则名」结构化地列出来，
///      而不是全部塞进一句话里，用户根本看不清自己要同意的是什么；
///   2. 把风险和注意事项用醒目的颜色单独列出来；
///   3. 确认按钮的文案可以按操作定制（「阻止联网」远比笼统的「确定」清楚）。
///
/// 布局是手写的，没有拆 Designer 文件：本窗体结构单一，放在一起读更顺。
///
/// 关于回车键（这里踩过一次坑，写清楚以免后人误解）：
///   本窗体**没有设置 AcceptButton**，但按回车仍然会确认。
///   原因是初始焦点在确认按钮上（<see cref="Control.ActiveControl"/>），
///   而 WinForms 的 ButtonBase.ProcessDialogKey 会在按钮获得焦点时把回车当成一次点击，
///   这条路径根本不经过 AcceptButton。
///   实测下来这符合 Windows 用户的普遍预期（回车 = 确认），因此保留这个行为。
///   如果将来确实要改成「回车无效」，正确做法是把初始焦点移到一个非按钮控件上，
///   而不是去掉 AcceptButton —— 去掉没有用。
/// </summary>
public sealed class ConfirmForm : Form
{
    /// <summary>正文可用宽度（像素）。窗体宽度 = 这个值 + 左右内边距。</summary>
    private const int ContentWidth = 620;

    private readonly Button _confirmButton;

    private ConfirmForm(
        string title,
        string question,
        IReadOnlyList<KeyValuePair<string, string>> details,
        IReadOnlyList<string> warnings,
        string confirmText)
    {
        // ---------------- 窗体本身 ----------------
        Text = title;
        Font = new Font("Microsoft YaHei UI", 9F, FontStyle.Regular, GraphicsUnit.Point);
        FormBorderStyle = FormBorderStyle.FixedDialog;
        StartPosition = FormStartPosition.CenterParent;
        MaximizeBox = false;
        MinimizeBox = false;
        ShowInTaskbar = false;
        AutoSize = true;
        AutoSizeMode = AutoSizeMode.GrowAndShrink;
        Padding = new Padding(16);
        MinimumSize = new Size(ContentWidth + 32, 0);

        // ---------------- 内容容器 ----------------
        var root = new TableLayoutPanel
        {
            ColumnCount = 1,
            Dock = DockStyle.Fill,
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            GrowStyle = TableLayoutPanelGrowStyle.AddRows,
        };
        root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));

        var row = 0;

        // ---------------- 第一行：警告图标 + 标题 ----------------
        var header = new Panel
        {
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            Dock = DockStyle.Fill,
        };
        header.Controls.Add(new PictureBox
        {
            Image = SystemIcons.Warning.ToBitmap(),
            SizeMode = PictureBoxSizeMode.AutoSize,
            Location = new Point(0, 2),
        });
        header.Controls.Add(new Label
        {
            Text = title,
            AutoSize = true,
            Font = new Font("Microsoft YaHei UI", 12F, FontStyle.Bold, GraphicsUnit.Point),
            Location = new Point(44, 6),
        });

        root.Controls.Add(header, 0, row);
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        row++;

        // ---------------- 第二行：主要问题 ----------------
        root.Controls.Add(new Label
        {
            Text = question,
            AutoSize = true,
            MaximumSize = new Size(ContentWidth, 0),
            Margin = new Padding(0, 12, 0, 0),
        }, 0, row);
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
        row++;

        // ---------------- 第三行：结构化的详情 ----------------
        if (details.Count > 0)
        {
            var detailsTable = new TableLayoutPanel
            {
                ColumnCount = 2,
                AutoSize = true,
                AutoSizeMode = AutoSizeMode.GrowAndShrink,
                Dock = DockStyle.Fill,
                Margin = new Padding(0, 12, 0, 0),
            };
            detailsTable.ColumnStyles.Add(new ColumnStyle(SizeType.AutoSize));
            detailsTable.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));

            var detailRow = 0;
            foreach (var (label, value) in details)
            {
                detailsTable.Controls.Add(new Label
                {
                    Text = label,
                    AutoSize = true,
                    ForeColor = SystemColors.GrayText,
                    Margin = new Padding(0, 5, 14, 0),
                }, 0, detailRow);

                detailsTable.Controls.Add(new Label
                {
                    Text = value,
                    AutoSize = true,
                    // 程序路径可能很长，给一个宽度上限让它自动折行，不要撑破对话框。
                    MaximumSize = new Size(ContentWidth - 110, 0),
                    Margin = new Padding(0, 5, 0, 0),
                }, 1, detailRow);

                detailsTable.RowStyles.Add(new RowStyle(SizeType.AutoSize));
                detailRow++;
            }

            root.Controls.Add(detailsTable, 0, row);
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            row++;
        }

        // ---------------- 第四行：风险与注意事项 ----------------
        if (warnings.Count > 0)
        {
            root.Controls.Add(new Label
            {
                Text = string.Join(Environment.NewLine, warnings.Select(w => "· " + w)),
                AutoSize = true,
                MaximumSize = new Size(ContentWidth, 0),
                ForeColor = Color.FromArgb(191, 87, 0),
                Margin = new Padding(0, 14, 0, 0),
            }, 0, row);
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            row++;
        }

        // ---------------- 第五行：按钮 ----------------
        // 从左到右依次是「确认」「取消」，与 Windows 对话框的习惯一致。
        var buttons = new FlowLayoutPanel
        {
            FlowDirection = FlowDirection.LeftToRight,
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            Anchor = AnchorStyles.Right,
            Margin = new Padding(0, 18, 0, 0),
        };

        _confirmButton = new Button
        {
            Text = confirmText,
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            MinimumSize = new Size(120, 32),
            Margin = new Padding(0, 0, 10, 0),
            DialogResult = DialogResult.OK,
        };

        var cancelButton = new Button
        {
            Text = "取消",
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            MinimumSize = new Size(100, 32),
            // 必须和确认按钮用同一套边距，否则取消按钮会因为默认的 Margin(3,3,3,3)
            // 被往下推 3 像素，两个按钮对不齐。
            Margin = new Padding(0),
            DialogResult = DialogResult.Cancel,
        };

        buttons.Controls.Add(_confirmButton);
        buttons.Controls.Add(cancelButton);

        root.Controls.Add(buttons, 0, row);
        root.RowStyles.Add(new RowStyle(SizeType.AutoSize));

        Controls.Add(root);

        // Esc 取消。
        // 注意：这里刻意不设置 AcceptButton，但回车仍然会确认 ——
        // 因为焦点在确认按钮上，回车会被当成对该按钮的点击。详见类注释里的说明。
        CancelButton = cancelButton;
        ActiveControl = _confirmButton;
    }

    /// <summary>
    /// 弹出确认框。
    /// </summary>
    /// <param name="owner">
    /// 父窗口，用于让对话框居中。传 null 时对话框以屏幕为基准居中 ——
    /// 主窗口已经收进托盘（不可见）时必须传 null，否则会以一个看不见的窗口为基准定位。
    /// </param>
    /// <param name="title">对话框标题，同时也是界面上的醒目大标题。</param>
    /// <param name="question">一句话说明这次要做什么。</param>
    /// <param name="details">结构化详情，例如（「完整路径」, "C:\...\a.exe"）。</param>
    /// <param name="warnings">橙色显示的风险提示，每条会自动加「· 」前缀。</param>
    /// <param name="confirmText">确认按钮的文案，例如「阻止联网」。</param>
    /// <returns>用户点了确认返回 true；点取消或按 Esc 返回 false。</returns>
    public static bool Show(
        IWin32Window? owner,
        string title,
        string question,
        IReadOnlyList<KeyValuePair<string, string>> details,
        IReadOnlyList<string> warnings,
        string confirmText)
    {
        using var form = new ConfirmForm(title, question, details, warnings, confirmText);
        return form.ShowDialog(owner) == DialogResult.OK;
    }
}
