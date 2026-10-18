using WinAppGuard.Core.Audit;

namespace WinAppGuard.Forms;

/// <summary>
/// 学习模式结束时的汇总：把「这段时间里新出现的程序」列出来，
/// 让用户勾选要**阻止**的，一次决定完。
///
/// 设计取舍：
///   - 只有"阻止"需要勾选 —— 允许是默认（不勾），因为大多数新程序是正常的；
///   - 不提供"逐个询问"：学习模式本来就是为了少打断；
///   - 关掉窗口 = 取消，什么都不改（不会静默地把程序标成允许）。
/// </summary>
internal sealed class LearningSummaryForm : Form
{
    private readonly CheckedListBox _list;
    private readonly List<KnownProgram> _programs;

    internal LearningSummaryForm(IReadOnlyList<KnownProgram> programs)
    {
        _programs = programs.ToList();

        Text = "学习模式结束";
        FormBorderStyle = FormBorderStyle.Sizable;
        StartPosition = FormStartPosition.CenterParent;
        MinimumSize = new Size(620, 420);
        ClientSize = new Size(720, 480);
        ShowInTaskbar = false;
        Font = new Font("Microsoft YaHei UI", 9F);

        var title = new Label
        {
            Dock = DockStyle.Top,
            Height = 56,
            Padding = new Padding(14, 12, 14, 0),
            Text = $"学习期间有 {_programs.Count} 个程序联网。\n" +
                   "勾选要**阻止**的程序，不勾的视为允许（以后不再询问）。",
        };

        _list = new CheckedListBox
        {
            Dock = DockStyle.Fill,
            CheckOnClick = true,
            IntegralHeight = false,
            DisplayMember = nameof(KnownProgram.Path),
        };

        foreach (var program in _programs)
        {
            _list.Items.Add(program, isChecked: false);
        }

        var bottom = new FlowLayoutPanel
        {
            Dock = DockStyle.Bottom,
            FlowDirection = FlowDirection.RightToLeft,
            Height = 46,
            Padding = new Padding(0, 8, 12, 8),
        };

        var okButton = new Button
        {
            Text = "确定",
            DialogResult = DialogResult.OK,
            AutoSize = true,
            MinimumSize = new Size(96, 30),
        };

        var cancelButton = new Button
        {
            Text = "取消",
            DialogResult = DialogResult.Cancel,
            AutoSize = true,
            MinimumSize = new Size(96, 30),
        };

        var selectAllButton = new Button
        {
            Text = "全选",
            AutoSize = true,
            MinimumSize = new Size(76, 30),
        };
        selectAllButton.Click += (_, _) => SetAll(true);

        var selectNoneButton = new Button
        {
            Text = "全不选",
            AutoSize = true,
            MinimumSize = new Size(84, 30),
        };
        selectNoneButton.Click += (_, _) => SetAll(false);

        bottom.Controls.Add(okButton);
        bottom.Controls.Add(cancelButton);
        bottom.Controls.Add(selectAllButton);
        bottom.Controls.Add(selectNoneButton);

        Controls.Add(_list);
        Controls.Add(title);
        Controls.Add(bottom);

        AcceptButton = okButton;
        CancelButton = cancelButton;
    }

    /// <summary>勾选列表（自检用：验证列表真的填进去了）。</summary>
    internal CheckedListBox ProgramList => _list;

    private void SetAll(bool value)
    {
        for (var i = 0; i < _list.Items.Count; i++)
        {
            _list.SetItemChecked(i, value);
        }
    }

    /// <summary>
    /// 显示汇总窗。
    /// </summary>
    /// <returns>用户确认时返回"要阻止的程序列表"；取消返回 null（调用方据此什么都不做）。</returns>
    internal static IReadOnlyList<string>? Ask(
        IWin32Window? owner,
        IReadOnlyList<KnownProgram> programs)
    {
        using var form = new LearningSummaryForm(programs);

        if (form.ShowDialog(owner) != DialogResult.OK)
        {
            return null;
        }

        var blocked = new List<string>();

        for (var i = 0; i < form._list.Items.Count; i++)
        {
            if (form._list.GetItemChecked(i) && form._list.Items[i] is KnownProgram program)
            {
                blocked.Add(program.Path);
            }
        }

        return blocked;
    }
}
