namespace WinAppGuard.Forms;

/// <summary>
/// 开启了双缓冲的 DataGridView。
///
/// 连接列表会按固定间隔整体刷新，默认的 DataGridView 每次刷新都会明显闪烁。
/// 开启双缓冲后重绘不再闪烁。这是 WinForms 的常规做法，不需要引入任何第三方库。
/// （DoubleBuffered 是 Control 的受保护属性，只能通过继承来设置。）
///
/// 顺带一个能力：<see cref="EmptyText"/> —— 表格没有数据时在中间显示一行提示。
/// 否则一片空白会让人分不清"真的没有数据"还是"被筛掉了 / 功能坏了"。
/// </summary>
internal sealed class DataGridViewBuffered : DataGridView
{
    public DataGridViewBuffered()
    {
        DoubleBuffered = true;
    }

    /// <summary>没有数据时居中显示的提示（空字符串 = 不显示）。可用 \n 换行。</summary>
    // 这个属性只在代码里设置，不需要 WinForms 设计器序列化（否则分析器报 WFO1000）。
    [System.ComponentModel.DesignerSerializationVisibility(
        System.ComponentModel.DesignerSerializationVisibility.Hidden)]
    public string EmptyText { get; set; } = string.Empty;

    protected override void OnPaint(PaintEventArgs e)
    {
        base.OnPaint(e);

        if (string.IsNullOrEmpty(EmptyText) || Rows.Count > 0)
        {
            return;
        }

        var bounds = ClientRectangle;
        bounds.Inflate(-24, -24);

        TextRenderer.DrawText(
            e.Graphics,
            EmptyText,
            Font,
            bounds,
            SystemColors.GrayText,
            TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter
                | TextFormatFlags.WordBreak);
    }
}
