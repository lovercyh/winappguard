namespace WinAppGuard.Forms;

/// <summary>
/// 开启了双缓冲的 DataGridView。
///
/// 连接列表会按固定间隔整体刷新，默认的 DataGridView 每次刷新都会明显闪烁。
/// 开启双缓冲后重绘不再闪烁。这是 WinForms 的常规做法，不需要引入任何第三方库。
/// （DoubleBuffered 是 Control 的受保护属性，只能通过继承来设置。）
/// </summary>
internal sealed class DataGridViewBuffered : DataGridView
{
    public DataGridViewBuffered()
    {
        DoubleBuffered = true;
    }
}
