using System.Drawing;

namespace WinAppGuard.Forms;

/// <summary>
/// 列宽的「预览线」拖动。
///
/// <b>为什么不用 DataGridView 自带的列宽拖动</b>
///
/// 自带的拖动是**实时**改宽度，于是鼠标每移动一次，整个表格的可见区域就要重画一遍。
/// 实测（配套的性能 harness，120 行数据、1920×1080 窗口、20 个可见行 × 10 列）：
///
///   空表                                   约 5 ms/帧
///   有数据                                 约 33~40 ms/帧   ← 只有 25~30fps，拖起来明显跟不上鼠标
///
/// 而且这个成本**正比于可见格子数**，与我们的代码无关 —— 拖动路径上我们什么都没做
/// （没有 MouseMove 处理器、没有重绘、没有布局）。所以没法靠「优化代码」解决，只能改机制：
/// **拖动时只画一条竖线，松开鼠标才真正改列宽**。这样拖动期间每帧几乎零成本，
/// 快慢机器上都流畅。
///
/// 代价：拖动过程中看不到列宽的实时效果，只有一条指示线。
/// 这是产品负责人明确选择的取舍。
///
/// <b>顺带一件事</b>：既然自带的拖动被关掉了，**悬停时的左右箭头光标也得自己管**，
/// 否则用户根本不知道这里能拖。
/// </summary>
internal sealed class GridColumnResizer
{
    /// <summary>分隔线左右各多少像素算「按住了分隔线」。</summary>
    private const int GripHalfWidth = 4;

    /// <summary>列宽下限（拖到再窄也停在这里）。</summary>
    private const int MinColumnWidth = 40;

    private readonly DataGridView _grid;

    private bool _dragging;
    private DataGridViewColumn? _column;
    private int _startMouseX;
    private int _startLeft;
    private int _startDividerX;
    private int _originalWidth;
    private int? _previewX;

    /// <summary>
    /// 拖动结束（鼠标抬起）之后，紧接着还会触发一次表头点击事件 ——
    /// 必须把它吃掉，否则「拖列宽」会被当成「点表头排序」。
    /// </summary>
    private bool _suppressNextHeaderClick;

    public GridColumnResizer(DataGridView grid)
    {
        _grid = grid;

        _grid.MouseDown += OnMouseDown;
        _grid.MouseMove += OnMouseMove;
        _grid.MouseUp += OnMouseUp;
        _grid.MouseLeave += OnMouseLeave;
        _grid.Paint += OnPaint;
        _grid.KeyDown += OnKeyDown;
    }

    /// <summary>拖动结束后要不要忽略紧接着的那一次表头点击。</summary>
    public bool ConsumeHeaderClickSuppression()
    {
        if (!_suppressNextHeaderClick)
        {
            return false;
        }

        _suppressNextHeaderClick = false;
        return true;
    }

    private void OnMouseDown(object? sender, MouseEventArgs e)
    {
        if (e.Button != MouseButtons.Left || !TryHitDivider(e.X, e.Y, out var column, out var rect))
        {
            return;
        }

        _dragging = true;
        _column = column;
        _startMouseX = e.X;
        _startLeft = rect.Left;
        _startDividerX = rect.Right;
        _originalWidth = column.Width;
        _previewX = _startDividerX;

        _grid.Capture = true;
        _grid.Cursor = Cursors.VSplit;
    }

    private void OnMouseMove(object? sender, MouseEventArgs e)
    {
        if (_dragging)
        {
            UpdatePreview(e.X);
            return;
        }

        // 不在拖动时只做一件事：悬停到分隔线上就把光标换成左右箭头。
        _grid.Cursor = TryHitDivider(e.X, e.Y, out _, out _) ? Cursors.VSplit : Cursors.Default;
    }

    private void OnMouseUp(object? sender, MouseEventArgs e)
    {
        if (!_dragging)
        {
            return;
        }

        EndDrag(apply: true, WidthFromMouse(e.X));
    }

    private void OnMouseLeave(object? sender, EventArgs e)
    {
        if (!_dragging)
        {
            _grid.Cursor = Cursors.Default;
        }
    }

    private void OnKeyDown(object? sender, KeyEventArgs e)
    {
        if (_dragging && e.KeyCode == Keys.Escape)
        {
            // Esc 取消：宽度恢复原样。
            EndDrag(apply: false, 0);
            e.Handled = true;
        }
    }

    private void EndDrag(bool apply, int newWidth)
    {
        _dragging = false;
        _grid.Capture = false;
        _grid.Cursor = Cursors.Default;

        if (_previewX is int oldX)
        {
            InvalidatePreview(oldX);
            _previewX = null;
        }

        if (apply && _column is { } column)
        {
            column.Width = newWidth;
        }

        _column = null;

        // 紧接着会触发一次表头点击，吃掉它（见字段说明）。
        _suppressNextHeaderClick = true;
    }

    private void UpdatePreview(int mouseX)
    {
        var maxX = Math.Max(_startLeft + MinColumnWidth, _grid.ClientSize.Width - 1);
        var x = Math.Clamp(_startLeft + WidthFromMouse(mouseX), _startLeft + MinColumnWidth, maxX);

        if (_previewX == x)
        {
            return;
        }

        if (_previewX is int oldX)
        {
            InvalidatePreview(oldX);
        }

        _previewX = x;
        InvalidatePreview(x);
    }

    /// <summary>根据鼠标位置算出目标列宽（已按下限钳过）。</summary>
    private int WidthFromMouse(int mouseX)
        => Math.Max(MinColumnWidth, _originalWidth + (mouseX - _startMouseX));

    private void InvalidatePreview(int x)
    {
        // 只让这条竖线所在的一小条重画 —— 这是本方案省时间的关键。
        _grid.Invalidate(new Rectangle(x - 1, 0, 3, _grid.ClientSize.Height));
    }

    private void OnPaint(object? sender, PaintEventArgs e)
    {
        if (_previewX is not int x || x < 0 || x >= _grid.ClientSize.Width)
        {
            return;
        }

        var bottom = _grid.ClientSize.Height;
        e.Graphics.DrawLine(SystemPens.ControlDarkDark, x, 0, x, bottom);
        e.Graphics.DrawLine(SystemPens.ControlDarkDark, x + 1, 0, x + 1, bottom);
    }

    /// <summary>
    /// 判断鼠标是不是落在某个列头分隔线上。
    ///
    /// Fill 模式的列**不参与**：它的宽度是算出来的，手动改没有意义
    /// （DataGridView 自带的拖动同样不允许拖它）。
    /// </summary>
    private bool TryHitDivider(int x, int y, out DataGridViewColumn column, out Rectangle rect)
    {
        column = null!;
        rect = Rectangle.Empty;

        var hit = _grid.HitTest(x, y);
        if (hit.Type != DataGridViewHitTestType.ColumnHeader || hit.ColumnIndex < 0)
        {
            return false;
        }

        var candidate = _grid.Columns[hit.ColumnIndex];

        // 注意：这里**不能**检查 candidate.Resizable —— 它在
        // AllowUserToResizeColumns = false 时会返回 False，而那个开关正是我们
        // 为了关掉「自带实时拖动」而设的，检查它会把我们自己的拖动也一起关死
        // （实测踩到：鼠标事件正常送达，但拖动永远不开始）。
        if (candidate is null || candidate.AutoSizeMode == DataGridViewAutoSizeColumnMode.Fill)
        {
            return false;
        }

        var columnRect = _grid.GetColumnDisplayRectangle(hit.ColumnIndex, cutOverflow: true);
        if (columnRect.Width <= 0)
        {
            return false;
        }

        if (x < columnRect.Right - GripHalfWidth || x > columnRect.Right + GripHalfWidth)
        {
            return false;
        }

        column = candidate;
        rect = columnRect;
        return true;
    }
}
