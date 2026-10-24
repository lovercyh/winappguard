namespace WinAppGuard.Localization;

/// <summary>
/// 把共享 Localizer 应用到 WinForms 控件树（只在这里引用 WinForms）。
/// </summary>
internal static class ControlLocalizer
{
    internal static void Apply(Control root)
    {
        if (!Localizer.IsEnglish)
        {
            return;
        }

        ApplyControl(root);

        if (root is ToolStrip strip)
        {
            ApplyToolStripItems(strip.Items);
        }
    }

    private static void ApplyControl(Control control)
    {
        control.Text = Localizer.TranslateControl(control.Name, control.Text);

        if (control is DataGridView grid)
        {
            foreach (DataGridViewColumn column in grid.Columns)
            {
                column.HeaderText = Localizer.T(column.HeaderText);
            }
        }

        foreach (Control child in control.Controls)
        {
            ApplyControl(child);
        }

        if (control is ToolStrip childStrip)
        {
            ApplyToolStripItems(childStrip.Items);
        }
    }

    private static void ApplyToolStripItems(ToolStripItemCollection items)
    {
        foreach (ToolStripItem item in items)
        {
            item.Text = Localizer.TranslateControl(item.Name, item.Text ?? string.Empty);

            if (item is ToolStripDropDownItem dropDown)
            {
                ApplyToolStripItems(dropDown.DropDownItems);
            }
        }
    }
}
