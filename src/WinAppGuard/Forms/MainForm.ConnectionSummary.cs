using WinAppGuard.Core;
using WinAppGuard.Localization;
using WinAppGuard.Models;

namespace WinAppGuard.Forms;

/// <summary>
/// 5.7：「联网连接」页的「按程序汇总」视图。
///
/// 为什么不改原表格的数据源：
///   现有阻止 / 允许 / 白名单 / 右键菜单都依赖 <see cref="TcpConnectionItem"/>。
///   单独一张汇总表、按当前模式返回代表连接，可以复用全部动作逻辑，
///   比把原表改成多态数据源风险低得多。
/// </summary>
public sealed partial class MainForm
{
    private enum ConnectionViewMode
    {
        Detail,
        Summary,
    }

    private readonly BindingSource _connectionSummarySource = new();
    private readonly List<ConnectionSummaryItem> _connectionSummary = new();

    private CheckBox _connectionSummaryCheckBox = null!;
    private DataGridViewBuffered _connectionSummaryGrid = null!;

    private ConnectionViewMode _connectionViewMode = ConnectionViewMode.Detail;
    private ConnectionSummarySortColumn _summarySortColumn = ConnectionSummarySortColumn.None;
    private bool _summarySortAscending = true;
    private bool _isRebindingSummary;

    /// <summary>创建汇总开关、汇总表和初始列。由 <see cref="SetupConnectionGrid"/> 调用。</summary>
    private void SetupConnectionSummary()
    {
        _connectionSummaryCheckBox = new CheckBox
        {
            AutoSize = true,
            Text = Localizer.T("按程序汇总"),
            Checked = false,
            Margin = new Padding(12, 3, 3, 3),
            TabIndex = 6,
        };
        _connectionSummaryCheckBox.CheckedChanged += OnConnectionSummaryChanged;

        _toolRowFilters.Controls.Add(_connectionSummaryCheckBox);

        var exportButton = new Button
        {
            Text = Localizer.T("导出…"),
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            MinimumSize = new Size(78, 27),
            Margin = new Padding(8, 0, 0, 0),
        };
        exportButton.Click += (_, _) => ExportConnectionsView();
        _toolRowFilters.Controls.Add(exportButton);

        var copyRowItem = new ToolStripMenuItem(Localizer.T("复制选中行"));
        copyRowItem.Click += OnCopyConnectionRowClick;
        _gridContextMenu.Items.Add(new ToolStripSeparator());
        _gridContextMenu.Items.Add(copyRowItem);

        _toolTip.SetToolTip(
            _connectionSummaryCheckBox,
            "把同一程序的多个连接合并成一行，显示连接数、远端数和总流量。\n" +
            "点击汇总行仍可阻止 / 允许 / 加入白名单；拿不到路径的连接会按 PID 分组，操作按钮保持禁用。");

        _connectionSummaryGrid = new DataGridViewBuffered
        {
            Dock = DockStyle.Fill,
            AllowUserToAddRows = false,
            AllowUserToDeleteRows = false,
            AllowUserToResizeColumns = false,
            AllowUserToResizeRows = false,
            AutoGenerateColumns = false,
            AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.None,
            BackgroundColor = SystemColors.Window,
            BorderStyle = BorderStyle.Fixed3D,
            ColumnHeadersHeightSizeMode = DataGridViewColumnHeadersHeightSizeMode.DisableResizing,
            ContextMenuStrip = _gridContextMenu,
            EditMode = DataGridViewEditMode.EditProgrammatically,
            MultiSelect = false,
            ReadOnly = true,
            RowHeadersVisible = false,
            SelectionMode = DataGridViewSelectionMode.FullRowSelect,
            Visible = false,
            Name = "_connectionSummaryGrid",
            TabIndex = 2,
        };

        _connectionSummaryGrid.AlternatingRowsDefaultCellStyle = new DataGridViewCellStyle
        {
            BackColor = Color.FromArgb(245, 247, 250),
        };

        AddColumn(_connectionSummaryGrid, "程序名", nameof(ConnectionSummaryItem.ProcessName), 120, sortable: true);
        AddColumn(_connectionSummaryGrid, "PID", nameof(ConnectionSummaryItem.PidText), 90);
        AddColumn(_connectionSummaryGrid, "连接数", nameof(ConnectionSummaryItem.ConnectionCountText), 70, sortable: true);
        AddColumn(_connectionSummaryGrid, "远端数", nameof(ConnectionSummaryItem.RemoteEndpointCountText), 70, sortable: true);
        AddColumn(_connectionSummaryGrid, "状态", nameof(ConnectionSummaryItem.StateSummaryText), 140);
        AddColumn(_connectionSummaryGrid, "上传", nameof(ConnectionSummaryItem.TrafficOutText), 60, sortable: true);
        AddColumn(_connectionSummaryGrid, "下载", nameof(ConnectionSummaryItem.TrafficInText), 60, sortable: true);
        AddColumn(_connectionSummaryGrid, "总计", nameof(ConnectionSummaryItem.TrafficTotalText), 65, sortable: true);
        AddColumn(_connectionSummaryGrid, "阻止状态", nameof(ConnectionSummaryItem.BlockStateText), 70);
        AddColumn(_connectionSummaryGrid, "放行", nameof(ConnectionSummaryItem.WhitelistText), 110);
        AddColumn(_connectionSummaryGrid, "数字签名", nameof(ConnectionSummaryItem.SignatureText), 110);
        AddColumn(_connectionSummaryGrid, "程序路径", nameof(ConnectionSummaryItem.ProcessPathText), 220, fill: true, minWidth: 160);

        _connectionSummaryGrid.EmptyText =
            "没有匹配的程序。\r\n可以清除搜索，或取消「按程序汇总」回到明细列表。";

        _connectionSummaryGrid.CellMouseDown += OnGridCellMouseDown;
        _connectionSummaryGrid.ColumnHeaderMouseClick += OnSummaryGridColumnHeaderMouseClick;
        _connectionSummaryGrid.KeyDown += OnGridKeyDown;
        _connectionSummaryGrid.SelectionChanged += OnSummaryGridSelectionChanged;

        _connectionSummarySource.DataSource = _connectionSummary;
        _connectionSummaryGrid.DataSource = _connectionSummarySource;

        _tabConnections.Controls.Add(_connectionSummaryGrid);

        // 和 _connectionGrid 一样是 Fill：放到同一个 z-order 位置，保证不会盖住顶部的工具条。
        _tabConnections.Controls.SetChildIndex(
            _connectionSummaryGrid,
            _tabConnections.Controls.IndexOf(_connectionGrid));
    }

    private void OnConnectionSummaryChanged(object? sender, EventArgs e)
    {
        var summary = _connectionSummaryCheckBox.Checked;

        _connectionViewMode = summary ? ConnectionViewMode.Summary : ConnectionViewMode.Detail;
        _connectionSelectionConfirmed = false;

        _connectionGrid.Visible = !summary;
        _connectionSummaryGrid.Visible = summary;

        if (summary)
        {
            RebuildSummaryView();
            RebindSummaryGrid(null);
            _connectionSummaryGrid.Focus();
        }
        else
        {
            _connectionGrid.Focus();
        }

        UpdateSummary();
        UpdateActionState();
    }

    /// <summary>按当前过滤结果重建汇总列表。</summary>
    private void RebuildSummaryView()
    {
        // _connections 已经按搜索词过滤过；这里不再重复传关键词。
        var view = ConnectionFilter.Summarize(
            _connections,
            keyword: null,
            _summarySortColumn,
            _summarySortAscending);

        _connectionSummary.Clear();
        _connectionSummary.AddRange(view);
    }

    /// <summary>重新绑定汇总表，并尽量恢复原来选中的程序。</summary>
    private void RebindSummaryGrid(string? selectedKey)
    {
        if (_connectionSummaryGrid is null)
        {
            return;
        }

        var firstDisplayedRow = CaptureFirstDisplayedRow(_connectionSummaryGrid);

        _isRebindingSummary = true;
        try
        {
            _connectionSummarySource.ResetBindings(metadataChanged: false);
        }
        finally
        {
            _isRebindingSummary = false;
        }

        if (selectedKey is not null)
        {
            foreach (DataGridViewRow row in _connectionSummaryGrid.Rows)
            {
                if (row.DataBoundItem is ConnectionSummaryItem item
                    && string.Equals(item.Key, selectedKey, StringComparison.OrdinalIgnoreCase))
                {
                    _connectionSummaryGrid.CurrentCell = row.Cells[0];
                    break;
                }
            }
        }
        else
        {
            // 没有明确选中项时不要自动落到第一行，避免用户以为它已经被选中。
            _connectionSummaryGrid.CurrentCell = null;
        }

        AttachSummaryTooltips();
        UpdateSummarySortGlyphs();
        RestoreFirstDisplayedRow(_connectionSummaryGrid, firstDisplayedRow);
    }

    private string? CaptureSummarySelection()
    {
        if (_connectionViewMode != ConnectionViewMode.Summary || !_connectionSelectionConfirmed)
        {
            return null;
        }

        return (_connectionSummaryGrid.CurrentRow?.DataBoundItem as ConnectionSummaryItem)?.Key;
    }

    private void OnSummaryGridSelectionChanged(object? sender, EventArgs e)
    {
        if (_isRebindingSummary)
        {
            return;
        }

        UpdateActionState();
    }

    private void OnSummaryGridColumnHeaderMouseClick(object? sender, DataGridViewCellMouseEventArgs e)
    {
        if (e.ColumnIndex < 0 || e.ColumnIndex >= _connectionSummaryGrid.Columns.Count)
        {
            return;
        }

        var target = SummaryColumnToSortColumn(_connectionSummaryGrid.Columns[e.ColumnIndex].Name);

        if (target == ConnectionSummarySortColumn.None)
        {
            return;
        }

        if (_summarySortColumn == target)
        {
            _summarySortAscending = !_summarySortAscending;
        }
        else
        {
            _summarySortColumn = target;
            _summarySortAscending = target == ConnectionSummarySortColumn.ProcessName;
        }

        RebuildSummaryView();
        RebindSummaryGrid(CaptureSummarySelection());
        UpdateSummary();
    }

    private static ConnectionSummarySortColumn SummaryColumnToSortColumn(string? columnName)
        => columnName switch
        {
            nameof(ConnectionSummaryItem.ProcessName) => ConnectionSummarySortColumn.ProcessName,
            nameof(ConnectionSummaryItem.ConnectionCountText) => ConnectionSummarySortColumn.ConnectionCount,
            nameof(ConnectionSummaryItem.RemoteEndpointCountText) => ConnectionSummarySortColumn.RemoteEndpointCount,
            nameof(ConnectionSummaryItem.TrafficOutText) => ConnectionSummarySortColumn.TrafficOut,
            nameof(ConnectionSummaryItem.TrafficInText) => ConnectionSummarySortColumn.TrafficIn,
            nameof(ConnectionSummaryItem.TrafficTotalText) => ConnectionSummarySortColumn.TrafficTotal,
            _ => ConnectionSummarySortColumn.None,
        };

    private static string? SummarySortColumnToColumnName(ConnectionSummarySortColumn column)
        => column switch
        {
            ConnectionSummarySortColumn.ProcessName => nameof(ConnectionSummaryItem.ProcessName),
            ConnectionSummarySortColumn.ConnectionCount => nameof(ConnectionSummaryItem.ConnectionCountText),
            ConnectionSummarySortColumn.RemoteEndpointCount => nameof(ConnectionSummaryItem.RemoteEndpointCountText),
            ConnectionSummarySortColumn.TrafficOut => nameof(ConnectionSummaryItem.TrafficOutText),
            ConnectionSummarySortColumn.TrafficIn => nameof(ConnectionSummaryItem.TrafficInText),
            ConnectionSummarySortColumn.TrafficTotal => nameof(ConnectionSummaryItem.TrafficTotalText),
            _ => null,
        };

    private void UpdateSummarySortGlyphs()
    {
        foreach (DataGridViewColumn column in _connectionSummaryGrid.Columns)
        {
            column.HeaderCell.SortGlyphDirection = SortOrder.None;
        }

        var name = SummarySortColumnToColumnName(_summarySortColumn);

        if (name is not null && _connectionSummaryGrid.Columns[name] is { } target)
        {
            target.HeaderCell.SortGlyphDirection =
                _summarySortAscending ? SortOrder.Ascending : SortOrder.Descending;
        }
    }

    /// <summary>给路径和远端数列挂悬停提示；汇总行不重复显示每个远端地址，但要让用户能展开看。</summary>
    private void AttachSummaryTooltips()
    {
        var remoteColumn = _connectionSummaryGrid.Columns[nameof(ConnectionSummaryItem.RemoteEndpointCountText)];
        var pathColumn = _connectionSummaryGrid.Columns[nameof(ConnectionSummaryItem.ProcessPathText)];

        foreach (DataGridViewRow row in _connectionSummaryGrid.Rows)
        {
            if (row.DataBoundItem is not ConnectionSummaryItem item)
            {
                continue;
            }

            if (remoteColumn is not null)
            {
                row.Cells[remoteColumn.Index].ToolTipText = item.EndpointsTooltip;
            }

            if (pathColumn is not null)
            {
                row.Cells[pathColumn.Index].ToolTipText = item.ProcessPathText;
            }
        }
    }

    /// <summary>汇总模式下的状态栏文字。</summary>
    private string BuildSummaryStatusText(DateTime time)
    {
        var timeText = time == DateTime.MinValue ? "--:--:--" : time.ToString("HH:mm:ss");

        return Localizer.F(
            "最后刷新：{0}    显示 {1} 个程序（{2} 条连接） / 共 {3} 条连接",
            timeText,
            _connectionSummary.Count,
            _connections.Count,
            _scannedConnections.Count);
    }
}
