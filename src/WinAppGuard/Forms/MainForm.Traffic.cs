using WinAppGuard.Contracts;
using WinAppGuard.Core;
using WinAppGuard.Localization;
using WinAppGuard.Models;

namespace WinAppGuard.Forms;

/// <summary>
/// 3.6：「流量」页 —— 按程序汇总**服务本次运行以来**的上传/下载/总计。
///
/// 数据来自 3.5 的 <c>query.traffic</c>；本页只做过滤、排序和展示，不在界面里算总量。
/// 「本次运行」指服务本次启动，服务重启或点「清空」后从 0 开始。
/// </summary>
public sealed partial class MainForm
{
    private const int TrafficRefreshIntervalMs = 3000;

    private TextBox _trafficSearchBox = null!;
    private Label _trafficSummaryLabel = null!;
    private Button _trafficRefreshButton = null!;
    private Button _trafficClearButton = null!;
    private DataGridViewBuffered _trafficGrid = null!;
    private System.Windows.Forms.Timer? _trafficTimer;

    private List<TrafficDto> _trafficRecords = new();
    private DateTime? _trafficStartedUtc;
    private bool _trafficLoading;
    private bool _trafficServiceAvailable = true;
    private string? _trafficSignature;

    private TrafficSortColumn _trafficSort = TrafficSortColumn.Total;
    private bool _trafficSortAscending;

    private enum TrafficSortColumn
    {
        None,
        Name,
        Path,
        Upload,
        Download,
        Total,
        LastSeen,
    }

    private void InitializeTrafficPage()
    {
        var top = new Panel
        {
            Dock = DockStyle.Top,
            Height = 72,
            Padding = new Padding(0, 4, 0, 0),
        };

        _trafficSearchBox = new TextBox
        {
            Location = new Point(0, 8),
            Width = 260,
            PlaceholderText = "搜索：程序 / 路径",
        };
        _trafficSearchBox.TextChanged += (_, _) => RebuildTrafficView();

        _trafficRefreshButton = new Button
        {
            Location = new Point(272, 6),
            Width = 76,
            Text = "刷新",
        };
        _trafficRefreshButton.Click += (_, _) => _ = RefreshTrafficAsync();

        _trafficClearButton = new Button
        {
            Location = new Point(356, 6),
            Width = 96,
            Text = "清空…",
        };
        _trafficClearButton.Click += OnTrafficClearClick;

        _trafficSummaryLabel = new Label
        {
            Location = new Point(0, 42),
            Width = 1000,
            ForeColor = SystemColors.GrayText,
            AutoEllipsis = true,
        };

        top.Resize += (_, _) =>
            _trafficSummaryLabel.Width = Math.Max(200, top.ClientSize.Width - 8);

        top.Controls.AddRange(new Control[]
        {
            _trafficSearchBox,
            _trafficRefreshButton,
            _trafficClearButton,
            _trafficSummaryLabel,
        });

        _trafficGrid = new DataGridViewBuffered
        {
            Dock = DockStyle.Fill,
            ReadOnly = true,
            AllowUserToAddRows = false,
            AllowUserToDeleteRows = false,
            AllowUserToResizeRows = false,
            RowHeadersVisible = false,
            MultiSelect = false,
            SelectionMode = DataGridViewSelectionMode.FullRowSelect,
            AutoGenerateColumns = false,
            AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.None,
            BackgroundColor = SystemColors.Window,
        };

        AddTrafficColumn("程序", nameof(TrafficRow.Name), 140, TrafficSortColumn.Name);
        AddTrafficColumn("路径", nameof(TrafficRow.PathText), 240, TrafficSortColumn.Path);
        AddTrafficColumn("上传", nameof(TrafficRow.OutText), 75, TrafficSortColumn.Upload);
        AddTrafficColumn("下载", nameof(TrafficRow.InText), 75, TrafficSortColumn.Download);
        AddTrafficColumn("总计", nameof(TrafficRow.TotalText), 85, TrafficSortColumn.Total);
        AddTrafficColumn("最后活动", nameof(TrafficRow.LastSeenText), 120, TrafficSortColumn.LastSeen);
        AddTrafficColumn("备注", nameof(TrafficRow.Note), 100, TrafficSortColumn.None, fill: true);

        _trafficGrid.ColumnHeaderMouseClick += OnTrafficColumnHeaderClick;
        _trafficGrid.EmptyText =
            "还没有流量记录。\r\n服务本次运行以来还没有统计到任何程序的流量。";

        // 停靠顺序：先加 Fill，再加 Top（后加的优先占边）。
        _tabTraffic.Controls.Add(_trafficGrid);
        _tabTraffic.Controls.Add(top);

        _tabControl.SelectedIndexChanged += (_, _) =>
        {
            if (_tabControl.SelectedTab == _tabTraffic)
            {
                _ = RefreshTrafficAsync();
            }
        };

        _trafficTimer = new System.Windows.Forms.Timer { Interval = TrafficRefreshIntervalMs };
        _trafficTimer.Tick += (_, _) =>
        {
            // 只在用户真的看着这一页时拉数据。
            if (_tabControl.SelectedTab == _tabTraffic)
            {
                _ = RefreshTrafficAsync();
            }
        };
        _trafficTimer.Start();

        UpdateTrafficSortGlyphs();
        UpdateTrafficButtons();
        UpdateTrafficSummary(0);
    }

    private void AddTrafficColumn(
        string header, string property, int width, TrafficSortColumn sort, bool fill = false)
    {
        var column = new DataGridViewTextBoxColumn
        {
            HeaderText = header,
            DataPropertyName = property,
            Name = property,
            ReadOnly = true,
            SortMode = sort == TrafficSortColumn.None
                ? DataGridViewColumnSortMode.NotSortable
                : DataGridViewColumnSortMode.Programmatic,
        };

        if (fill)
        {
            column.AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill;
            column.MinimumWidth = width;
        }
        else
        {
            column.Width = width;
        }

        _trafficGrid.Columns.Add(column);
    }

    private async Task RefreshTrafficAsync()
    {
        if (SuppressBackgroundServices || _trafficLoading || IsDisposed || Disposing)
        {
            return;
        }

        _trafficLoading = true;
        UpdateTrafficButtons();

        try
        {
            var result = await Task.Run(QueryTrafficRecordsSnapshot);

            if (IsDisposed || Disposing)
            {
                return;
            }

            if (result is not null)
            {
                _trafficServiceAvailable = true;
                _trafficRecords = result.Value.Records;
                _trafficStartedUtc = result.Value.StartedUtc;
                RebuildTrafficView();
            }
            else
            {
                _trafficServiceAvailable = false;
                UpdateTrafficSummary(_trafficGrid.Rows.Count);
            }
        }
        catch (Exception ex)
        {
            _trafficServiceAvailable = false;
            LocalLog.Error(
                LocalLog.Pick("读取流量记录失败", "Failed to read traffic records."), ex);
            UpdateTrafficSummary(_trafficGrid.Rows.Count);
        }
        finally
        {
            _trafficLoading = false;

            if (!IsDisposed && !Disposing)
            {
                UpdateTrafficButtons();
            }
        }
    }

    private static TrafficRecordsResult? QueryTrafficRecordsSnapshot()
    {
        try
        {
            var response = ServiceClient.TryRequest(
                new ServiceRequest { Command = ServiceProtocol.Commands.QueryTraffic },
                TimeSpan.FromSeconds(2),
                out _);

            return response is { Ok: true }
                ? new TrafficRecordsResult(
                    response.Traffic ?? new List<TrafficDto>(),
                    response.TrafficStartedUtc)
                : null;
        }
        catch (Exception)
        {
            return null;
        }
    }

    private readonly record struct TrafficRecordsResult(
        List<TrafficDto> Records,
        DateTime? StartedUtc);

    private void RebuildTrafficView()
    {
        var keyword = _trafficSearchBox.Text.Trim();

        var filtered = _trafficRecords
            .Where(record => TrafficMatches(record, keyword))
            .ToList();

        var rows = filtered
            .Select(ToTrafficRow)
            .ToList();

        IOrderedEnumerable<TrafficRow> ordered = _trafficSort switch
        {
            TrafficSortColumn.Name => Order(rows, row => row.Name, StringComparer.OrdinalIgnoreCase),
            TrafficSortColumn.Path => Order(rows, row => row.PathText, StringComparer.OrdinalIgnoreCase),
            TrafficSortColumn.Upload => Order(rows, row => row.BytesOut),
            TrafficSortColumn.Download => Order(rows, row => row.BytesIn),
            TrafficSortColumn.LastSeen => Order(rows, row => row.LastSeenUtc),
            _ => Order(rows, row => row.Total),
        };

        var list = ordered
            .ThenBy(row => row.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();

        // 数据没变就不重绑，避免每 3 秒把选中/滚动冲掉。
        var signature = string.Join(
            "|",
            list.Take(100).Select(row =>
                $"{row.Key}/{row.BytesIn}/{row.BytesOut}/{row.LastSeenUtc.Ticks}"));

        if (!string.Equals(signature, _trafficSignature, StringComparison.Ordinal))
        {
            var selectedKey = (_trafficGrid.CurrentRow?.DataBoundItem as TrafficRow)?.Key;

            _trafficSignature = signature;
            _trafficGrid.DataSource = list;

            if (selectedKey is not null)
            {
                foreach (DataGridViewRow gridRow in _trafficGrid.Rows)
                {
                    if (gridRow.DataBoundItem is TrafficRow row
                        && string.Equals(row.Key, selectedKey, StringComparison.Ordinal))
                    {
                        gridRow.Selected = true;
                        break;
                    }
                }
            }
        }

        UpdateTrafficSortGlyphs();
        UpdateTrafficSummary(list.Count);
        UpdateTrafficButtons();
    }

    /// <summary>
    /// 按当前方向排序。数值/时间默认降序（大的、新的在前），名称/路径默认升序。
    /// </summary>
    private IOrderedEnumerable<TrafficRow> Order<TKey>(
        List<TrafficRow> rows, Func<TrafficRow, TKey> selector, IComparer<TKey>? comparer = null)
        => _trafficSortAscending
            ? rows.OrderBy(selector, comparer)
            : rows.OrderByDescending(selector, comparer);

    private TrafficRow ToTrafficRow(TrafficDto record)
    {
        var pathKnown = record.IsPathKnown && !string.IsNullOrEmpty(record.Path);
        var total = record.BytesOut > long.MaxValue - record.BytesIn
            ? long.MaxValue
            : record.BytesOut + record.BytesIn;

        return new TrafficRow
        {
            Key = record.Key,
            Name = string.IsNullOrEmpty(record.Name)
                ? Localizer.T("（未知程序）")
                : record.Name,
            PathText = pathKnown ? record.Path! : Localizer.T("（无法获取）"),
            BytesOut = record.BytesOut,
            BytesIn = record.BytesIn,
            Total = total,
            LastSeenUtc = record.LastSeenUtc,
            Note = pathKnown ? string.Empty : Localizer.T("路径未知"),
        };
    }

    private static bool TrafficMatches(TrafficDto record, string keyword)
    {
        if (keyword.Length == 0)
        {
            return true;
        }

        return record.Name.Contains(keyword, StringComparison.OrdinalIgnoreCase)
               || (record.Path?.Contains(keyword, StringComparison.OrdinalIgnoreCase) ?? false);
    }

    private void OnTrafficColumnHeaderClick(object? sender, DataGridViewCellMouseEventArgs e)
    {
        if (e.ColumnIndex < 0 || e.ColumnIndex >= _trafficGrid.Columns.Count)
        {
            return;
        }

        var target = ColumnToTrafficSort(_trafficGrid.Columns[e.ColumnIndex].Name);

        if (target == TrafficSortColumn.None)
        {
            return;
        }

        if (_trafficSort == target)
        {
            _trafficSortAscending = !_trafficSortAscending;
        }
        else
        {
            _trafficSort = target;
            _trafficSortAscending = target is TrafficSortColumn.Name or TrafficSortColumn.Path;
        }

        RebuildTrafficView();
    }

    private static TrafficSortColumn ColumnToTrafficSort(string? columnName) => columnName switch
    {
        nameof(TrafficRow.Name) => TrafficSortColumn.Name,
        nameof(TrafficRow.PathText) => TrafficSortColumn.Path,
        nameof(TrafficRow.OutText) => TrafficSortColumn.Upload,
        nameof(TrafficRow.InText) => TrafficSortColumn.Download,
        nameof(TrafficRow.TotalText) => TrafficSortColumn.Total,
        nameof(TrafficRow.LastSeenText) => TrafficSortColumn.LastSeen,
        _ => TrafficSortColumn.None,
    };

    private void UpdateTrafficSortGlyphs()
    {
        foreach (DataGridViewColumn column in _trafficGrid.Columns)
        {
            column.HeaderCell.SortGlyphDirection = SortOrder.None;
        }

        var target = _trafficSort switch
        {
            TrafficSortColumn.Name => nameof(TrafficRow.Name),
            TrafficSortColumn.Path => nameof(TrafficRow.PathText),
            TrafficSortColumn.Upload => nameof(TrafficRow.OutText),
            TrafficSortColumn.Download => nameof(TrafficRow.InText),
            TrafficSortColumn.Total => nameof(TrafficRow.TotalText),
            TrafficSortColumn.LastSeen => nameof(TrafficRow.LastSeenText),
            _ => null,
        };

        if (target is not null && _trafficGrid.Columns[target] is { } targetColumn)
        {
            targetColumn.HeaderCell.SortGlyphDirection = _trafficSortAscending
                ? SortOrder.Ascending
                : SortOrder.Descending;
        }
    }

    private void UpdateTrafficSummary(int shown)
    {
        var total = _trafficRecords.Count;
        var outBytes = SumTraffic(_trafficRecords, upload: true);
        var inBytes = SumTraffic(_trafficRecords, upload: false);

        var countText = shown < total
            ? Localizer.F("显示 {0} / 共 {1} 个程序", shown, total)
            : Localizer.F("共 {0} 个程序", total);

        var text = _trafficStartedUtc is { } startedUtc
            ? Localizer.F(
                "统计自 {0}（服务本次运行） · {1} · 合计 上传 {2} / 下载 {3}",
                startedUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss"),
                countText,
                TcpConnectionItem.FormatTrafficBytes(outBytes),
                TcpConnectionItem.FormatTrafficBytes(inBytes))
            : Localizer.F(
                "统计起点未知（服务本次运行） · {0} · 合计 上传 {1} / 下载 {2}",
                countText,
                TcpConnectionItem.FormatTrafficBytes(outBytes),
                TcpConnectionItem.FormatTrafficBytes(inBytes));

        if (!_trafficServiceAvailable && total > 0)
        {
            text += Localizer.T(" · 服务不可用，显示上次数据");
        }

        _trafficSummaryLabel.Text = text;
    }

    private static long SumTraffic(IEnumerable<TrafficDto> records, bool upload)
    {
        Int128 sum = 0;

        foreach (var record in records)
        {
            sum += upload ? record.BytesOut : record.BytesIn;
        }

        return sum > long.MaxValue ? long.MaxValue : (long)sum;
    }

    private void UpdateTrafficButtons()
    {
        _trafficRefreshButton.Enabled = !_trafficLoading;
        _trafficClearButton.Enabled = !_trafficLoading
                                      && _trafficServiceAvailable
                                      && _trafficRecords.Count > 0;
    }

    private void OnTrafficClearClick(object? sender, EventArgs e)
    {
        var confirmed = ConfirmForm.Show(
            owner: DialogOwner,
            title: "清空流量统计",
            question: "确定要清空本次运行的流量统计吗？",
            details: new[]
            {
                new KeyValuePair<string, string>(
                    "将要做的", "把所有程序的上传 / 下载计数归零"),
                new KeyValuePair<string, string>(
                    "影响", "只影响流量记录；规则、白名单和临时锁网都不变"),
            },
            warnings: new[]
            {
                "服务重启后本来也会从 0 开始。",
                "不会修改任何规则或 Windows 防火墙设置。",
            },
            confirmText: "清空统计");

        if (!confirmed)
        {
            return;
        }

        try
        {
            var response = CallService(
                ServiceProtocol.Commands.ClearTraffic,
                new ServiceRequest(),
                "清空流量统计");

            if (response is null)
            {
                return;
            }

            _trafficRecords = new List<TrafficDto>();
            _trafficStartedUtc = response.TrafficStartedUtc ?? DateTime.UtcNow;
            _trafficSignature = null;
            _trafficGrid.DataSource = new List<TrafficRow>();
            RebuildTrafficView();

            LocalLog.Operation(LocalLog.Pick(
                $"流量统计已清空：{response.Affected} 个程序",
                $"Traffic counters cleared ({response.Affected} programs)."));

            ShowTrayBalloon("流量统计已清空", "所有程序的上传 / 下载计数已归零。");
        }
        catch (Exception ex)
        {
            ShowError("清空流量统计失败", ex, "Failed to clear traffic counters");
        }
    }

    private sealed class TrafficRow
    {
        public string Key { get; init; } = string.Empty;

        public string Name { get; init; } = string.Empty;

        public string PathText { get; init; } = string.Empty;

        public long BytesOut { get; init; }

        public long BytesIn { get; init; }

        public long Total { get; init; }

        public DateTime LastSeenUtc { get; init; }

        public string Note { get; init; } = string.Empty;

        public string OutText => TcpConnectionItem.FormatTrafficBytes(BytesOut);

        public string InText => TcpConnectionItem.FormatTrafficBytes(BytesIn);

        public string TotalText => TcpConnectionItem.FormatTrafficBytes(Total);

        public string LastSeenText => LastSeenUtc.ToLocalTime().ToString("MM-dd HH:mm:ss");
    }
}
