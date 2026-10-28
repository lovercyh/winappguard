using WinAppGuard.Contracts;
using WinAppGuard.Core;
using WinAppGuard.Localization;
using WinAppGuard.Models;

namespace WinAppGuard.Forms;

/// <summary>
/// 4.1：「流量」页 —— 按程序展示 **Npcap 按包精确统计** 的入站/出站与实时速率。
///
/// 4.1 起这里只有一个数据源：Npcap。ETW 不再提供任何流量数字（它只服务 IDS）。
/// 字节口径是 IP 载荷（TCP/UDP 头 + 数据），含重传、不含回环；
/// 归属不到的流量单独显示为「未归属」。
/// </summary>
public sealed partial class MainForm
{
    private const int TrafficRefreshIntervalMs = 3000;

    private TextBox _trafficSearchBox = null!;
    private Label _trafficSummaryLabel = null!;
    private Button _trafficRefreshButton = null!;
    private Button _trafficPauseButton = null!;
    private Button _trafficClearButton = null!;
    private CheckBox _trafficAutoRefreshCheckBox = null!;
    private TrafficChart _trafficChart = null!;
    private DataGridViewBuffered _trafficGrid = null!;
    private System.Windows.Forms.Timer? _trafficTimer;

    private List<TrafficDto> _trafficRecords = new();
    private TrafficSeriesDto? _trafficSeries;
    private TrafficStatusDto? _trafficStatus;
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
        Download,
        Upload,
        DownRate,
        UpRate,
        Total,
        LastSeen,
    }

    private void InitializeTrafficPage()
    {
        var top = new Panel
        {
            Dock = DockStyle.Top,
            Height = 96,
            Padding = new Padding(0, 4, 0, 0),
        };

        var notice = new Label
        {
            Location = new Point(0, 0),
            Width = 1000,
            Height = 20,
            ForeColor = Color.FromArgb(191, 87, 0),
            Text = Localizer.T(
                "精确统计（Npcap）：按网卡上真实出现的字节计数，含重传与被拒绝的入站包，不含回环。"),
            AutoEllipsis = true,
        };

        _trafficSearchBox = new TextBox
        {
            Location = new Point(0, 26),
            Width = 200,
            PlaceholderText = Localizer.T("搜索：程序 / 路径"),
        };
        _trafficSearchBox.TextChanged += (_, _) => RebuildTrafficView();

        _trafficRefreshButton = new Button
        {
            Text = Localizer.T("刷新"),
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            MinimumSize = new Size(68, 27),
            Margin = new Padding(0, 0, 8, 0),
        };
        _trafficRefreshButton.Click += (_, _) => _ = RefreshTrafficAsync();

        _trafficPauseButton = new Button
        {
            Text = Localizer.T("暂停统计"),
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            MinimumSize = new Size(88, 27),
            Margin = new Padding(0, 0, 8, 0),
        };
        _trafficPauseButton.Click += OnTrafficPauseClick;

        _trafficClearButton = new Button
        {
            Text = Localizer.T("清空…"),
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            MinimumSize = new Size(76, 27),
        };
        _trafficClearButton.Click += OnTrafficClearClick;

        _trafficAutoRefreshCheckBox = new CheckBox
        {
            Text = Localizer.T("每 3 秒自动刷新"),
            AutoSize = true,
            Checked = true,
            Margin = new Padding(4, 6, 0, 0),
        };
        _trafficAutoRefreshCheckBox.CheckedChanged += OnTrafficAutoRefreshChanged;

        var actions = new FlowLayoutPanel
        {
            Location = new Point(210, 22),
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            WrapContents = false,
            FlowDirection = FlowDirection.LeftToRight,
        };
        actions.Controls.AddRange(new Control[]
        {
            _trafficRefreshButton, _trafficPauseButton, _trafficClearButton,
            _trafficAutoRefreshCheckBox,
        });

        _trafficSummaryLabel = new Label
        {
            Location = new Point(0, 60),
            Width = 1000,
            Height = 32,
            ForeColor = SystemColors.GrayText,
            AutoEllipsis = true,
        };

        top.Resize += (_, _) =>
        {
            var width = Math.Max(200, top.ClientSize.Width - 8);
            notice.Width = width;
            _trafficSummaryLabel.Width = width;
        };

        top.Controls.AddRange(new Control[]
        {
            notice,
            _trafficSearchBox,
            actions,
            _trafficSummaryLabel,
        });

        _trafficChart = new TrafficChart
        {
            Dock = DockStyle.Top,
            Height = 150,
            Margin = new Padding(0),
        };

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

        AddTrafficColumn("程序", nameof(TrafficRow.Name), 120, TrafficSortColumn.Name);
        AddTrafficColumn("路径", nameof(TrafficRow.PathText), 160, TrafficSortColumn.Path);
        AddTrafficColumn("入站", nameof(TrafficRow.InText), 76, TrafficSortColumn.Download);
        AddTrafficColumn("出站", nameof(TrafficRow.OutText), 76, TrafficSortColumn.Upload);
        AddTrafficColumn("下行", nameof(TrafficRow.InRateText), 76, TrafficSortColumn.DownRate);
        AddTrafficColumn("上行", nameof(TrafficRow.OutRateText), 76, TrafficSortColumn.UpRate);
        AddTrafficColumn("总计", nameof(TrafficRow.TotalText), 78, TrafficSortColumn.Total);
        AddTrafficColumn("最后活动", nameof(TrafficRow.LastSeenText), 100, TrafficSortColumn.LastSeen);
        AddTrafficColumn("备注", nameof(TrafficRow.Note), 100, TrafficSortColumn.None, fill: true);

        _trafficGrid.ColumnHeaderMouseClick += OnTrafficColumnHeaderClick;
        _trafficGrid.SelectionChanged += (_, _) => UpdateTrafficSummary(_trafficGrid.Rows.Count);
        _trafficGrid.EmptyText =
            "还没有流量记录。\r\nNpcap 采集还没有看到 TCP / UDP 流量。";

        // 停靠顺序：先加 Fill，再加 Top（后加的优先占边）。
        _tabTraffic.Controls.Add(_trafficGrid);
        _tabTraffic.Controls.Add(_trafficChart);
        _tabTraffic.Controls.Add(top);

        _tabControl.SelectedIndexChanged += (_, _) =>
        {
            if (_tabControl.SelectedTab == _tabTraffic)
            {
                _ = RefreshTrafficAsync();
            }
        };

        _trafficTimer = new System.Windows.Forms.Timer
        {
            Interval = TrafficRefreshIntervalMs,
            Enabled = _trafficAutoRefreshCheckBox.Checked,
        };

        _trafficTimer.Tick += (_, _) =>
        {
            // 只在用户真的看着这一页、并且没关掉自动刷新时拉数据。
            if (_trafficAutoRefreshCheckBox.Checked && _tabControl.SelectedTab == _tabTraffic)
            {
                _ = RefreshTrafficAsync();
            }
        };


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
                _trafficSeries = result.Value.Series;
                _trafficStatus = result.Value.Status;

                _trafficChart.SetSeries(
                    _trafficSeries?.BytesIn ?? new List<long>(),
                    _trafficSeries?.BytesOut ?? new List<long>());

                RebuildTrafficView();
            }
            else
            {
                _trafficServiceAvailable = false;
                _trafficChart.SetSeries(Array.Empty<long>(), Array.Empty<long>());
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
                    response.TrafficStartedUtc,
                    response.TrafficSeries,
                    response.TrafficStatus)
                : null;
        }
        catch (Exception)
        {
            return null;
        }
    }

    private readonly record struct TrafficRecordsResult(
        List<TrafficDto> Records,
        DateTime? StartedUtc,
        TrafficSeriesDto? Series,
        TrafficStatusDto? Status);

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
            TrafficSortColumn.Download => Order(rows, row => row.BytesIn),
            TrafficSortColumn.Upload => Order(rows, row => row.BytesOut),
            TrafficSortColumn.DownRate => Order(rows, row => row.RateIn),
            TrafficSortColumn.UpRate => Order(rows, row => row.RateOut),
            TrafficSortColumn.LastSeen => Order(rows, row => row.LastSeenUtc),
            _ => Order(rows, row => row.Total),
        };

        var list = ordered
            .ThenBy(row => row.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();

        // 数据没变就不重绑，避免每秒把选中/滚动冲掉。
        var signature = string.Join(
            "|",
            list.Take(100).Select(row =>
                $"{row.Key}/{row.BytesIn}/{row.BytesOut}/{row.RateIn}/{row.RateOut}/{row.LastSeenUtc.Ticks}"));

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

        var unattributed = string.Equals(
            record.Key, "unattributed", StringComparison.OrdinalIgnoreCase);

        return new TrafficRow
        {
            Key = record.Key,
            Name = unattributed
                ? Localizer.T("未归属（PID 未知）")
                : string.IsNullOrEmpty(record.Name)
                    ? Localizer.T("（未知程序）")
                    : record.Name,
            PathText = pathKnown ? record.Path! : Localizer.T("（无法获取）"),
            BytesOut = record.BytesOut,
            BytesIn = record.BytesIn,
            RateIn = record.RateIn,
            RateOut = record.RateOut,
            TcpBytesIn = record.TcpBytesIn,
            TcpBytesOut = record.TcpBytesOut,
            UdpBytesIn = record.UdpBytesIn,
            UdpBytesOut = record.UdpBytesOut,
            Total = total,
            LastSeenUtc = record.LastSeenUtc,
            Note = unattributed
                ? Localizer.T("未归属")
                : pathKnown ? string.Empty : Localizer.T("路径未知"),
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
        nameof(TrafficRow.InText) => TrafficSortColumn.Download,
        nameof(TrafficRow.OutText) => TrafficSortColumn.Upload,
        nameof(TrafficRow.InRateText) => TrafficSortColumn.DownRate,
        nameof(TrafficRow.OutRateText) => TrafficSortColumn.UpRate,
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
            TrafficSortColumn.Download => nameof(TrafficRow.InText),
            TrafficSortColumn.Upload => nameof(TrafficRow.OutText),
            TrafficSortColumn.DownRate => nameof(TrafficRow.InRateText),
            TrafficSortColumn.UpRate => nameof(TrafficRow.OutRateText),
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

        var parts = new List<string>
        {
            Localizer.T("精确统计（Npcap）"),
        };

        if (_trafficStatus is { } status)
        {
            parts.Add(status.Paused
                ? Localizer.T("已暂停")
                : status.Collecting
                    ? Localizer.T("采集中")
                    : Localizer.T("采集未运行"));

            if (!string.IsNullOrWhiteSpace(status.NpcapVersion))
            {
                parts.Add(Localizer.F("Npcap {0}", status.NpcapVersion!));
            }

            if (status.Pps > 0)
            {
                parts.Add(Localizer.F("{0} 包/秒", status.Pps));
            }

            if (status.Dropped > 0)
            {
                parts.Add(Localizer.F("丢包 {0}，数据可能不完整", status.Dropped));
            }

            if (status.Sampled)
            {
                parts.Add(Localizer.T("采样估算"));
            }

            if (!string.IsNullOrWhiteSpace(status.LastError))
            {
                parts.Add(status.LastError!);
            }
        }

        if (_trafficStartedUtc is { } startedUtc)
        {
            parts.Add(Localizer.F("统计自 {0}", startedUtc.ToLocalTime().ToString("HH:mm:ss")));
        }

        parts.Add(countText);
        parts.Add(Localizer.F(
            "合计 入站 {0} / 出站 {1}",
            TcpConnectionItem.FormatTrafficBytes(inBytes),
            TcpConnectionItem.FormatTrafficBytes(outBytes)));

        var text = string.Join(" · ", parts);

        if (_trafficGrid.CurrentRow?.DataBoundItem is TrafficRow selected)
        {
            text += " · " + Localizer.F(
                "选中：{0} TCP 入 {1} / 出 {2} · UDP 入 {3} / 出 {4}",
                selected.Name,
                TcpConnectionItem.FormatTrafficBytes(selected.TcpBytesIn),
                TcpConnectionItem.FormatTrafficBytes(selected.TcpBytesOut),
                TcpConnectionItem.FormatTrafficBytes(selected.UdpBytesIn),
                TcpConnectionItem.FormatTrafficBytes(selected.UdpBytesOut));
        }

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
        var available = _trafficServiceAvailable;
        var paused = _trafficStatus?.Paused == true;

        _trafficRefreshButton.Enabled = !_trafficLoading;
        _trafficPauseButton.Enabled = available && !_trafficLoading;
        _trafficPauseButton.Text = paused
            ? Localizer.T("继续统计")
            : Localizer.T("暂停统计");
        _trafficClearButton.Enabled = !_trafficLoading
                                      && available
                                      && _trafficRecords.Count > 0;
    }

    private void OnTrafficAutoRefreshChanged(object? sender, EventArgs e)
    {
        if (_trafficTimer is not null)
        {
            _trafficTimer.Enabled = _trafficAutoRefreshCheckBox.Checked;
        }

        // 勾上时立刻刷新一次，不用再等 3 秒。
        if (_trafficAutoRefreshCheckBox.Checked)
        {
            _ = RefreshTrafficAsync();
        }
    }

    private void OnTrafficPauseClick(object? sender, EventArgs e)
    {
        var paused = _trafficStatus?.Paused != true;

        try
        {
            var response = CallService(
                ServiceProtocol.Commands.ConfigureTraffic,
                new ServiceRequest { TrafficPaused = paused },
                Localizer.T(paused ? "暂停精确流量统计" : "继续精确流量统计"));

            if (response is null)
            {
                return;
            }

            _trafficStatus = response.TrafficStatus ?? _trafficStatus;
            _trafficSeries = response.TrafficSeries ?? _trafficSeries;
            _trafficRecords = response.Traffic ?? _trafficRecords;
            _trafficSignature = null;

            _trafficChart.SetSeries(
                _trafficSeries?.BytesIn ?? new List<long>(),
                _trafficSeries?.BytesOut ?? new List<long>());

            RebuildTrafficView();
        }
        catch (Exception ex)
        {
            ShowError(
                Localizer.T(paused ? "暂停精确流量统计失败" : "继续精确流量统计失败"),
                ex,
                "Failed to change precise traffic state");
        }
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
                    "将要做的", "把所有程序的入站 / 出站计数和速率曲线归零"),
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
            _trafficSeries = response.TrafficSeries;
            _trafficStatus = response.TrafficStatus ?? _trafficStatus;
            _trafficStartedUtc = response.TrafficStartedUtc ?? DateTime.UtcNow;
            _trafficSignature = null;
            _trafficGrid.DataSource = new List<TrafficRow>();
            _trafficChart.SetSeries(Array.Empty<long>(), Array.Empty<long>());
            RebuildTrafficView();

            LocalLog.Operation(LocalLog.Pick(
                $"流量统计已清空：{response.Affected} 个程序",
                $"Traffic counters cleared ({response.Affected} programs)."));

            ShowTrayBalloon("流量统计已清空", "所有程序的入站 / 出站计数已归零。");
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

        public long RateIn { get; init; }

        public long RateOut { get; init; }

        public long TcpBytesIn { get; init; }

        public long TcpBytesOut { get; init; }

        public long UdpBytesIn { get; init; }

        public long UdpBytesOut { get; init; }

        public long Total { get; init; }

        public DateTime LastSeenUtc { get; init; }

        public string Note { get; init; } = string.Empty;

        public string OutText => TcpConnectionItem.FormatTrafficBytes(BytesOut);

        public string InText => TcpConnectionItem.FormatTrafficBytes(BytesIn);

        public string InRateText => FormatRate(RateIn);

        public string OutRateText => FormatRate(RateOut);

        public string TotalText => TcpConnectionItem.FormatTrafficBytes(Total);

        public string LastSeenText => LastSeenUtc.ToLocalTime().ToString("MM-dd HH:mm:ss");

        private static string FormatRate(long bytesPerSecond)
            => bytesPerSecond <= 0
                ? "—"
                : TcpConnectionItem.FormatTrafficBytes(bytesPerSecond) + "/s";
    }
}
