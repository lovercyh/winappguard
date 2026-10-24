namespace WinAppGuard.Localization;

using WinAppGuard.Forms;

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

    /// <summary>
    /// 托盘菜单与托盘图标不在窗体的控件树里，必须单独应用一次。
    /// </summary>
    internal static void ApplyTray(ContextMenuStrip? menu, NotifyIcon? icon)
    {
        if (!Localizer.IsEnglish)
        {
            return;
        }

        if (menu is not null)
        {
            ApplyToolStripItems(menu.Items);
        }

        if (icon is not null)
        {
            icon.Text = Localizer.TranslateControl("_trayIcon", icon.Text);
        }
    }

    private static void ApplyControl(Control control)
    {
        control.Text = Localizer.TranslateControl(control.Name, control.Text);

        // 3.3：这两类文字不在 Text 里，3.2 漏掉了，截图里能直接看到中文。
        if (control is TextBox textBox && !string.IsNullOrEmpty(textBox.PlaceholderText))
        {
            textBox.PlaceholderText = Localizer.T(textBox.PlaceholderText);
        }

        if (control is DataGridViewBuffered buffered && !string.IsNullOrEmpty(buffered.EmptyText))
        {
            buffered.EmptyText = Localizer.T(buffered.EmptyText);
        }

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
