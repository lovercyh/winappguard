using WinAppGuard.Core;
using WinAppGuard.Localization;
using WinAppGuard.Models;

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

    // ---- 「阻断时长」这一组控件（只在阻止联网时才创建）----

    private readonly RadioButton? _permanentRadio;
    private readonly RadioButton? _thirtyMinutesRadio;
    private readonly RadioButton? _twoHoursRadio;
    private readonly RadioButton? _nextBootRadio;
    private readonly Label? _durationHint;

    private ConfirmForm(
        string title,
        string question,
        IReadOnlyList<KeyValuePair<string, string>> details,
        IReadOnlyList<string> warnings,
        string confirmText,
        bool offerDuration = false)
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

        // ---------------- 第四行：阻断时长（只对「阻止联网」显示）----------------
        //
        // 为什么要有这一行：临时阻断到期时规则会被**自动删除**，而
        // 「所有会改系统状态的操作必须弹确认框」是项目的硬性安全约定。
        // 自动删除没法再弹一次框（弹了后台程序就永远解不开），
        // 所以在**创建时**就把「什么时候会自动解除」摆出来让用户事先同意。
        if (offerDuration)
        {
            var durationPanel = new FlowLayoutPanel
            {
                FlowDirection = FlowDirection.TopDown,
                WrapContents = false,
                AutoSize = true,
                AutoSizeMode = AutoSizeMode.GrowAndShrink,
                Dock = DockStyle.Fill,
                Margin = new Padding(0, 14, 0, 0),
            };

            durationPanel.Controls.Add(new Label
            {
                Text = "阻断时长（决定这条规则什么时候自动解除）：",
                AutoSize = true,
                Margin = new Padding(0, 0, 0, 6),
            });

            var choices = new FlowLayoutPanel
            {
                FlowDirection = FlowDirection.LeftToRight,
                AutoSize = true,
                AutoSizeMode = AutoSizeMode.GrowAndShrink,
                Margin = new Padding(0),
            };

            // 同一个容器里的单选按钮会自动成为一组，不需要额外的 GroupBox。
            // 默认选「永久」：不改动老用户已经习惯的行为。
            _permanentRadio = CreateDurationRadio("永久（手动解除）", isChecked: true);
            _thirtyMinutesRadio = CreateDurationRadio("30 分钟", isChecked: false);
            _twoHoursRadio = CreateDurationRadio("2 小时", isChecked: false);
            _nextBootRadio = CreateDurationRadio("直到下次重启", isChecked: false);

            choices.Controls.Add(_permanentRadio);
            choices.Controls.Add(_thirtyMinutesRadio);
            choices.Controls.Add(_twoHoursRadio);
            choices.Controls.Add(_nextBootRadio);
            durationPanel.Controls.Add(choices);

            _durationHint = new Label
            {
                AutoSize = true,
                ForeColor = SystemColors.GrayText,
                MaximumSize = new Size(ContentWidth, 0),
                Margin = new Padding(0, 8, 0, 0),
            };
            durationPanel.Controls.Add(_durationHint);

            foreach (var radio in new[] { _permanentRadio, _thirtyMinutesRadio, _twoHoursRadio, _nextBootRadio })
            {
                radio.CheckedChanged += (_, _) => UpdateDurationHint();
            }

            UpdateDurationHint();

            root.Controls.Add(durationPanel, 0, row);
            root.RowStyles.Add(new RowStyle(SizeType.AutoSize));
            row++;
        }

        // ---------------- 第五行：风险与注意事项 ----------------
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

        // ---------------- 第六行：按钮 ----------------
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

        Localizer.Apply(this);
    }

    /// <summary>
    /// 用户选的到期方式（按单选按钮的当前状态算出来）。
    ///
    /// 限时是**在这里现算**的（而不是勾选时就固定），这样「30 分钟」是从
    /// 用户真正点确认那一刻开始算，操作慢了也不会白扣时间。
    /// </summary>
    public RuleExpiry ChosenExpiry
    {
        get
        {
            if (_thirtyMinutesRadio?.Checked == true)
            {
                return RuleExpiry.At(DateTime.UtcNow.AddMinutes(30));
            }

            if (_twoHoursRadio?.Checked == true)
            {
                return RuleExpiry.At(DateTime.UtcNow.AddHours(2));
            }

            if (_nextBootRadio?.Checked == true)
            {
                return RuleExpiry.OnNextBoot(SystemUptime.BootTimeUtc);
            }

            return RuleExpiry.Never;
        }
    }

    private static RadioButton CreateDurationRadio(string text, bool isChecked) => new()
    {
        Text = text,
        Checked = isChecked,
        AutoSize = true,
        Margin = new Padding(0, 0, 18, 0),
    };

    /// <summary>把当前选择翻译成一句人话，让用户在点确认之前就知道会发生什么。</summary>
    private void UpdateDurationHint()
    {
        if (_durationHint is null)
        {
            return;
        }

        var expiry = ChosenExpiry;

        if (expiry.IsPermanent)
        {
            _durationHint.Text = Localizer.IsEnglish
                ? "Permanent: this rule stays in effect until you remove it on the Rules page."
                : "永久：这条规则一直生效，直到你自己在「规则」页解除。";
            return;
        }

        if (expiry.Kind == RuleExpiryKind.OnNextBoot)
        {
            _durationHint.Text =
                "直到下次重启：重启（或重新登录）之后这条规则会自动解除，该程序恢复联网。" +
                "本程序由登录触发的开机自启跑起来时才会清理它。";
            return;
        }

        var local = (expiry.ExpiresAtUtc ?? DateTime.UtcNow).ToLocalTime();
        _durationHint.Text =
            $"限时：规则会在 {local:HH:mm} 自动解除，届时该程序恢复联网。" +
            "注意：本程序退出后就不会再自动清理了，需要重新打开它。";
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
        => Show(owner, title, question, details, warnings, confirmText, offerDuration: false, out _);

    /// <summary>
    /// 弹出确认框，并让用户选择**阻断时长**（只在阻止联网时用）。
    /// </summary>
    /// <param name="offerDuration">是否显示「阻断时长」这一组单选按钮。</param>
    /// <param name="chosenExpiry">
    /// 带回用户选的到期方式。用户取消时是 <see cref="RuleExpiry.Never"/>。
    /// </param>
    /// <returns>用户点了确认返回 true；点取消或按 Esc 返回 false。</returns>
    public static bool Show(
        IWin32Window? owner,
        string title,
        string question,
        IReadOnlyList<KeyValuePair<string, string>> details,
        IReadOnlyList<string> warnings,
        string confirmText,
        bool offerDuration,
        out RuleExpiry chosenExpiry)
    {
        var localizedDetails = details
            .Select(pair => new KeyValuePair<string, string>(
                Localizer.T(pair.Key), Localizer.T(pair.Value)))
            .ToList();

        var localizedWarnings = warnings.Select(Localizer.T).ToList();

        using var form = new ConfirmForm(
            Localizer.T(title),
            Localizer.T(question),
            localizedDetails,
            localizedWarnings,
            Localizer.T(confirmText),
            offerDuration);

        var confirmed = form.ShowDialog(owner) == DialogResult.OK;
        chosenExpiry = confirmed ? form.ChosenExpiry : RuleExpiry.Never;
        return confirmed;
    }
}
