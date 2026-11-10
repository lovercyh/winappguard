using WinAppGuard.Localization;
using WinAppGuard.Models;

namespace WinAppGuard.Forms;

/// <summary>
/// 5.8：新程序默认阻止时居中显示的确认框。
///
/// 不使用 Windows 托盘气泡；用户必须明确选择：
///   - 允许联网：界面随后释放服务端的临时阻止；
///   - 保持阻止：不做任何操作，临时阻止继续有效；
///   - 直接关闭窗口 / Esc：按“保持阻止”处理。
/// </summary>
internal sealed class NewProgramPromptForm : Form
{
    public NewProgramPromptForm(
        FirstSeenProgramRecord record,
        string remoteEndpoint,
        bool guardActive)
    {
        Text = Localizer.T("发现新程序联网");
        StartPosition = FormStartPosition.CenterScreen;
        FormBorderStyle = FormBorderStyle.FixedDialog;
        MaximizeBox = false;
        MinimizeBox = false;
        ShowInTaskbar = true;
        TopMost = true;
        AutoScaleMode = AutoScaleMode.Dpi;
        ClientSize = new Size(600, 340);
        BackColor = SystemColors.Window;
        Font = new Font("Microsoft YaHei UI", 9F, FontStyle.Regular, GraphicsUnit.Point);

        var title = new Label
        {
            Text = Localizer.T("发现新程序尝试联网"),
            Font = new Font(Font.FontFamily, 14F, FontStyle.Bold),
            Location = new Point(20, 18),
            AutoSize = true,
        };

        var nameLabel = new Label
        {
            Text = Localizer.F("程序：{0}", record.ProcessNameText),
            Location = new Point(20, 66),
            Width = 550,
            Height = 24,
            AutoEllipsis = true,
        };

        var pathLabel = new Label
        {
            Text = Localizer.F("路径：{0}", record.Path),
            Location = new Point(20, 94),
            Width = 550,
            Height = 38,
            AutoEllipsis = true,
        };

        var remoteLabel = new Label
        {
            Text = string.IsNullOrEmpty(remoteEndpoint)
                ? Localizer.T("远端：未知")
                : Localizer.F("远端：{0}", remoteEndpoint),
            Location = new Point(20, 136),
            Width = 550,
            Height = 24,
            AutoEllipsis = true,
        };

        var explanation = new Label
        {
            Text = guardActive
                ? Localizer.T(
                    "该程序是第一次联网，已为它建立临时阻止。\n" +
                    "选择「允许联网」会立即释放阻止；选择「保持阻止」会继续阻止。\n" +
                    "直接关闭窗口也按「保持阻止」处理。")
                : Localizer.T(
                    "该程序是第一次联网，但临时阻止没有建立成功，程序可能仍能联网。\n" +
                    "建议选择「保持阻止」，然后到规则页手动处理。\n" +
                    "直接关闭窗口也按「保持阻止」处理。"),
            Location = new Point(20, 174),
            Width = 550,
            Height = 72,
            ForeColor = guardActive ? SystemColors.ControlText : Color.FromArgb(180, 30, 30),
        };

        var allowButton = new Button
        {
            Text = Localizer.T("允许联网"),
            DialogResult = DialogResult.Yes,
            Size = new Size(120, 34),
            Location = new Point(330, 286),
            UseVisualStyleBackColor = true,
        };

        var blockButton = new Button
        {
            Text = Localizer.T("保持阻止"),
            DialogResult = DialogResult.No,
            Size = new Size(120, 34),
            Location = new Point(460, 286),
            UseVisualStyleBackColor = true,
        };

        Controls.AddRange(new Control[]
        {
            title,
            nameLabel,
            pathLabel,
            remoteLabel,
            explanation,
            allowButton,
            blockButton,
        });

        AcceptButton = blockButton;
        CancelButton = blockButton;

        var toolTip = new ToolTip();
        toolTip.SetToolTip(pathLabel, record.Path);
        toolTip.SetToolTip(remoteLabel, remoteEndpoint);

        FormClosed += (_, _) => toolTip.Dispose();
    }
}
