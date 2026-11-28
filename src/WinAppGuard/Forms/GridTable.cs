namespace WinAppGuard.Forms;

/// <summary>
/// 5.9：表格数据绑定只有一套。
///
/// 统一处理“数据签名没变就不重建”，避免定时刷新时每 3 秒打断用户选中/滚动；
/// 数据变化时尽量保留当前选中行。
/// </summary>
internal abstract class GridTable<TRow> where TRow : class
{
    private readonly DataGridView _grid;
    private readonly Func<TRow, string> _signature;
    private readonly Func<TRow, string?>? _idSelector;
    private string? _lastSignature;

    protected GridTable(
        DataGridView grid,
        Func<TRow, string> signature,
        Func<TRow, string?>? idSelector = null)
    {
        _grid = grid ?? throw new ArgumentNullException(nameof(grid));
        _signature = signature ?? throw new ArgumentNullException(nameof(signature));
        _idSelector = idSelector;
    }

    internal void Bind(
        IReadOnlyList<TRow> rows,
        Action? beforeRebind = null,
        Action? afterRebind = null)
    {
        ArgumentNullException.ThrowIfNull(rows);

        // 5.16：对全部行做哈希。只取前 100 行会让长列表尾部的新事件“消失”。
        var signature = ComputeSignature(rows);

        if (string.Equals(signature, _lastSignature, StringComparison.Ordinal))
        {
            return;
        }

        string? selectedId = null;

        if (_idSelector is not null
            && _grid.CurrentRow?.DataBoundItem is TRow current)
        {
            selectedId = _idSelector(current);
        }

        beforeRebind?.Invoke();
        _lastSignature = signature;
        _grid.DataSource = rows.ToList();

        if (selectedId is not null && _idSelector is not null)
        {
            foreach (DataGridViewRow gridRow in _grid.Rows)
            {
                if (gridRow.DataBoundItem is TRow row
                    && string.Equals(_idSelector(row), selectedId, StringComparison.Ordinal))
                {
                    gridRow.Selected = true;
                    break;
                }
            }
        }

        afterRebind?.Invoke();
    }

    /// <summary>强制下一次 Bind 重建（清空、删除、信任状态变化后使用）。</summary>
    internal void Invalidate() => _lastSignature = null;

    private string ComputeSignature(IReadOnlyList<TRow> rows)
    {
        // FNV-1a：遍历全部行，避免长列表只比较前 100 行。
        var hash = 1469598103934665603UL;

        foreach (var row in rows)
        {
            foreach (var ch in _signature(row))
            {
                hash ^= ch;
                hash *= 1099511628211UL;
            }

            hash ^= '\n';
            hash *= 1099511628211UL;
        }

        return $"{rows.Count:X8}:{hash:X16}";
    }
}

/// <summary>事件表：时间/规则/状态类列表。</summary>
internal sealed class EventTable<TRow> : GridTable<TRow> where TRow : class
{
    internal EventTable(
        DataGridView grid,
        Func<TRow, string> signature,
        Func<TRow, string?>? idSelector = null)
        : base(grid, signature, idSelector)
    {
    }
}

/// <summary>阻断表：临时封禁 / 不再提醒类列表。</summary>
internal sealed class BlockTable<TRow> : GridTable<TRow> where TRow : class
{
    internal BlockTable(
        DataGridView grid,
        Func<TRow, string> signature,
        Func<TRow, string?>? idSelector = null)
        : base(grid, signature, idSelector)
    {
    }
}

/// <summary>基线表：网关 / DHCP / 邻居等“当前基线”列表。</summary>
internal sealed class BaselineTable<TRow> : GridTable<TRow> where TRow : class
{
    internal BaselineTable(
        DataGridView grid,
        Func<TRow, string> signature,
        Func<TRow, string?>? idSelector = null)
        : base(grid, signature, idSelector)
    {
    }
}
