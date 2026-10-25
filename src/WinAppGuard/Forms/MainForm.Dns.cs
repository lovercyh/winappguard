using WinAppGuard.Contracts;
using WinAppGuard.Core;
using WinAppGuard.Localization;

namespace WinAppGuard.Forms;

/// <summary>
/// 主窗体的「DNS」页（3.5）。
///
/// 数据来自服务（ETW 实时采集），界面只读 + 本地过滤；清空走服务命令，
/// 避免「界面清掉、下次刷新又回来」的假动作。
///
/// 边界写死在这一页上：只记录系统 DNS 客户端看到的查询，DoH/DoT 可能完全看不到；
/// 记录在内存里，服务重启即清空。
/// </summary>
public sealed partial class MainForm
{
    private const int DnsRefreshIntervalMs = 5000;

    private TextBox _dnsSearchBox = null!;
    private Label _dnsStatusLabel = null!;
    private Label _dnsHintLabel = null!;
    private Button _dnsRefreshButton = null!;
    private Button _dnsClearButton = null!;
    private DataGridViewBuffered _dnsGrid = null!;
    private System.Windows.Forms.Timer? _dnsTimer;

    private List<DnsDto> _dnsRecords = new();
    private bool _dnsCollecting;
    private bool _dnsLoading;
    private string? _dnsSignature;

    private void InitializeDnsPage()
    {
        var top = new Panel
        {
            Dock = DockStyle.Top,
            Height = 72,
            Padding = new Padding(0, 4, 0, 0),
        };

        _dnsSearchBox = new TextBox
        {
            Location = new Point(0, 8),
            Width = 280,
            PlaceholderText = "搜索：程序 / 域名",
        };
        _dnsSearchBox.TextChanged += (_, _) => RebindDnsGrid();

        _dnsRefreshButton = new Button
        {
            Location = new Point(292, 6),
            Width = 76,
            Text = "刷新",
        };
        _dnsRefreshButton.Click += (_, _) => _ = RefreshDnsAsync();

        _dnsClearButton = new Button
        {
            Location = new Point(376, 6),
            Width = 96,
            Text = "清空…",
        };
        _dnsClearButton.Click += OnDnsClearClick;

        _dnsStatusLabel = new Label
        {
            Location = new Point(486, 10),
            Width = 540,
            Text = "DNS 采集：检测中…",
            ForeColor = SystemColors.GrayText,
        };

        _dnsHintLabel = new Label
        {
            Location = new Point(0, 42),
            Width = 1000,
            Text = "只记录系统 DNS 客户端看到的域名；DoH/DoT 可能看不到。内存保留最近 2000 条，服务重启后清空。",
            ForeColor = SystemColors.GrayText,
        };

        top.Controls.AddRange(new Control[]
        {
            _dnsSearchBox,
            _dnsRefreshButton,
            _dnsClearButton,
            _dnsStatusLabel,
            _dnsHintLabel,
        });

        _dnsGrid = new DataGridViewBuffered
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
            AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill,
            BackgroundColor = SystemColors.Window,
        };

        AddDnsColumn("时间", nameof(DnsRow.TimeText), 100);
        AddDnsColumn("程序", nameof(DnsRow.ProcessText), 160);
        AddDnsColumn("PID", nameof(DnsRow.Pid), 55);
        AddDnsColumn("域名", nameof(DnsRow.QueryName), 300);
        AddDnsColumn("结果", nameof(DnsRow.StatusText), 100);

        _dnsGrid.EmptyText =
            "还没有 DNS 记录。\r\n打开网站或程序联网后，这里会出现最近的域名查询。";

        // 停靠顺序：先加 Fill，再加 Top（后加的优先占边）。
        _tabDns.Controls.Add(_dnsGrid);
        _tabDns.Controls.Add(top);

        _tabControl.SelectedIndexChanged += (_, _) =>
        {
            if (_tabControl.SelectedTab == _tabDns)
            {
                _ = RefreshDnsAsync();
            }
        };

        _dnsTimer = new System.Windows.Forms.Timer { Interval = DnsRefreshIntervalMs };
        _dnsTimer.Tick += (_, _) =>
        {
            // 只在用户真的看着这一页时拉数据，避免后台白白占用管道。
            if (_tabControl.SelectedTab == _tabDns)
            {
                _ = RefreshDnsAsync();
            }
        };
        _dnsTimer.Start();
    }

    private void AddDnsColumn(string title, string property, int fillWeight)
    {
        _dnsGrid.Columns.Add(new DataGridViewTextBoxColumn
        {
            HeaderText = title,
            DataPropertyName = property,
            Name = property,
            ReadOnly = true,
            SortMode = DataGridViewColumnSortMode.NotSortable,
            FillWeight = fillWeight,
        });
    }

    private async Task RefreshDnsAsync()
    {
        if (_dnsLoading || IsDisposed || Disposing)
        {
            return;
        }

        _dnsLoading = true;
        _dnsRefreshButton.Enabled = false;

        try
        {
            var records = await Task.Run(QueryDnsSnapshot);

            if (IsDisposed || Disposing)
            {
                return;
            }

            if (records is not null)
            {
                _dnsRecords = records;
                RebindDnsGrid();
            }
            else
            {
                UpdateDnsStatus(_dnsGrid.Rows.Count);
            }
        }
        catch (Exception ex)
        {
            LocalLog.Error(
                LocalLog.Pick("读取 DNS 记录失败", "Failed to read DNS records."), ex);
            UpdateDnsStatus(_dnsGrid.Rows.Count);
        }
        finally
        {
            _dnsLoading = false;

            if (!IsDisposed && !Disposing)
            {
                _dnsRefreshButton.Enabled = true;
            }
        }
    }

    private static List<DnsDto>? QueryDnsSnapshot()
    {
        try
        {
            var response = ServiceClient.TryRequest(
                new ServiceRequest { Command = ServiceProtocol.Commands.QueryDns },
                TimeSpan.FromSeconds(2),
                out _);

            return response is { Ok: true, DnsRecords: not null }
                ? response.DnsRecords
                : null;
        }
        catch (Exception)
        {
            return null;
        }
    }

    private void RebindDnsGrid()
    {
        var keyword = _dnsSearchBox.Text.Trim();

        var view = _dnsRecords
            .Where(record => DnsMatches(record, keyword))
            .Select(record => new DnsRow
            {
                TimeText = record.TimeUtc.ToLocalTime().ToString("MM-dd HH:mm:ss"),
                ProcessText = record.ProcessName,
                Pid = record.Pid,
                QueryName = record.QueryName,
                StatusText = string.IsNullOrEmpty(record.Status)
                    ? "—"
                    : record.Status,
            })
            .ToList();

        // 数据没变就不重绑：每 5 秒重绑会把用户的滚动位置和选中行冲掉。
        var signature = string.Join(
            "|",
            view.Take(80).Select(row => $"{row.TimeText}/{row.Pid}/{row.QueryName}/{row.StatusText}"));

        if (!string.Equals(signature, _dnsSignature, StringComparison.Ordinal))
        {
            _dnsSignature = signature;
            _dnsGrid.DataSource = view;
        }

        UpdateDnsStatus(view.Count);
    }

    private static bool DnsMatches(DnsDto record, string keyword)
    {
        if (keyword.Length == 0)
        {
            return true;
        }

        return record.QueryName.Contains(keyword, StringComparison.OrdinalIgnoreCase)
               || record.ProcessName.Contains(keyword, StringComparison.OrdinalIgnoreCase)
               || (record.ProcessPath?.Contains(keyword, StringComparison.OrdinalIgnoreCase) ?? false)
               || record.Pid.ToString().Contains(keyword, StringComparison.Ordinal);
    }

    private void UpdateDnsStatus(int shown)
    {
        _dnsStatusLabel.Text = !_serviceAvailable
            ? Localizer.T("DNS 采集：服务未运行")
            : !_dnsCollecting
                ? Localizer.T("DNS 采集：未运行（详见服务日志 WAG-DNS-*）")
                : Localizer.F("DNS 采集：运行中 · 显示 {0} / 共 {1} 条", shown, _dnsRecords.Count);
    }

    private void OnDnsClearClick(object? sender, EventArgs e)
    {
        var confirmed = ConfirmForm.Show(
            owner: DialogOwner,
            title: "清空 DNS 记录",
            question: "确定要清空当前的 DNS 记录吗？",
            details: new[]
            {
                new KeyValuePair<string, string>("将要做的", "清空服务内存里的 DNS 查询记录"),
                new KeyValuePair<string, string>("影响", "只影响本次服务运行；之后的新查询会继续记录"),
            },
            warnings: new[]
            {
                "不会修改任何系统 DNS 设置。",
                "记录本来就不会写盘，服务重启后同样会清空。",
            },
            confirmText: "清空记录");

        if (!confirmed)
        {
            return;
        }

        try
        {
            var response = CallService(
                ServiceProtocol.Commands.ClearDns,
                new ServiceRequest(),
                "清空 DNS 记录");

            if (response is null)
            {
                return;
            }

            _dnsRecords = new List<DnsDto>();
            _dnsSignature = null;
            _dnsGrid.DataSource = null;
            UpdateDnsStatus(0);

            LocalLog.Operation(LocalLog.Pick(
                $"DNS 记录已清空：{response.Affected} 条",
                $"DNS records cleared ({response.Affected})."));
        }
        catch (Exception ex)
        {
            ShowError("清空 DNS 记录失败", ex, "Failed to clear DNS records");
        }
    }

    private sealed class DnsRow
    {
        public string TimeText { get; init; } = string.Empty;

        public string ProcessText { get; init; } = string.Empty;

        public int Pid { get; init; }

        public string QueryName { get; init; } = string.Empty;

        public string StatusText { get; init; } = string.Empty;
    }
}
