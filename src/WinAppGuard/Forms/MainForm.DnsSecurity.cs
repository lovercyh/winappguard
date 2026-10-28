using WinAppGuard.Contracts;
using WinAppGuard.Core;
using WinAppGuard.Localization;
using WinAppGuard.Models;

namespace WinAppGuard.Forms;

/// <summary>
/// 4.3：「防护 → DNS 安全」页 —— 本地 DNS 投毒 / 劫持与明文 DNS 绕过的告警。
///
/// 只展示服务端的检测结果；界面不抓包、不做判断，也不提供阻断。
/// 事件与 4.2 存在同一个文件里，用 <c>dns_</c> 前缀区分。
/// </summary>
public sealed partial class MainForm
{
    private const int DnsSecurityRefreshIntervalMs = 3000;
    private const int DnsSecurityNotifyIntervalMs = 30000;
    private static readonly TimeSpan DnsSecurityNotifyCooldown = TimeSpan.FromMinutes(5);

    private Label _dnsSecStatusLabel = null!;
    private Button _dnsSecRefreshButton = null!;
    private Button _dnsSecClearButton = null!;
    private Button _dnsSecTrustButton = null!;
    private Button _dnsSecClearTrustButton = null!;
    private CheckBox _dnsSecAutoRefreshCheckBox = null!;
    private DataGridViewBuffered _dnsSecServerGrid = null!;
    private DataGridViewBuffered _dnsSecEventGrid = null!;
    private System.Windows.Forms.Timer? _dnsSecTimer;
    private System.Windows.Forms.Timer? _dnsSecNotifyTimer;

    private List<DnsSecurityServerDto> _dnsSecServers = new();
    private List<LanEventDto> _dnsSecEvents = new();
    private DnsSecurityStatusDto? _dnsSecStatus;
    private bool _dnsSecLoading;
    private bool _dnsSecServiceAvailable = true;
    private string? _dnsSecServerSignature;
    private string? _dnsSecEventSignature;
    private string? _dnsSecLastNotifiedId;
    private DateTime _dnsSecLastNotifyUtc = DateTime.MinValue;
    private bool _dnsSecBalloonPending;

    private void InitializeDnsSecurityPage()
    {
        var top = new Panel
        {
            Dock = DockStyle.Top,
            Height = 96,
            Padding = new Padding(0, 4, 0, 0),
        };

        _dnsSecRefreshButton = new Button
        {
            Text = Localizer.T("刷新"),
            AutoSize = true,
            MinimumSize = new Size(68, 27),
        };
        _dnsSecRefreshButton.Click += (_, _) => _ = RefreshDnsSecurityAsync();

        _dnsSecClearButton = new Button
        {
            Text = Localizer.T("清空…"),
            AutoSize = true,
            MinimumSize = new Size(76, 27),
        };
        _dnsSecClearButton.Click += OnDnsSecClearClick;

        _dnsSecTrustButton = new Button
        {
            Text = Localizer.T("信任此 DNS 服务器"),
            AutoSize = true,
            MinimumSize = new Size(120, 27),
        };
        _dnsSecTrustButton.Click += OnDnsSecTrustClick;

        _dnsSecClearTrustButton = new Button
        {
            Text = Localizer.T("清空信任…"),
            AutoSize = true,
            MinimumSize = new Size(88, 27),
        };
        _dnsSecClearTrustButton.Click += OnDnsSecClearTrustClick;

        var actions = new FlowLayoutPanel
        {
            Location = new Point(0, 2),
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            WrapContents = false,
            FlowDirection = FlowDirection.LeftToRight,
        };
        actions.Controls.AddRange(new Control[]
        {
            _dnsSecRefreshButton, _dnsSecClearButton, _dnsSecTrustButton, _dnsSecClearTrustButton,
        });

        _dnsSecAutoRefreshCheckBox = new CheckBox
        {
            Location = new Point(340, 42),
            AutoSize = true,
            Text = Localizer.T("每 3 秒自动刷新"),
            Checked = true,
        };
        _dnsSecAutoRefreshCheckBox.CheckedChanged += OnDnsSecAutoRefreshChanged;

        var notice = new Label
        {
            Location = new Point(0, 42),
            Width = 320,
            Height = 20,
            ForeColor = Color.FromArgb(191, 87, 0),
            Text = Localizer.T("只告警、不阻断：DNS 与正常上网共用链路，拦截会打断上网。"),
            AutoEllipsis = true,
        };

        _dnsSecStatusLabel = new Label
        {
            Location = new Point(0, 68),
            Width = 1000,
            Height = 22,
            ForeColor = SystemColors.GrayText,
            AutoEllipsis = true,
        };

        top.Resize += (_, _) =>
        {
            var width = Math.Max(200, top.ClientSize.Width - 8);
            _dnsSecStatusLabel.Width = width;
            _dnsSecAutoRefreshCheckBox.Left = Math.Max(340, width - 170);
        };

        top.Controls.AddRange(new Control[]
        {
            actions, notice, _dnsSecAutoRefreshCheckBox, _dnsSecStatusLabel,
        });

        _dnsSecServerGrid = CreateDnsSecurityGrid(
            Localizer.T("还没有 DNS 服务器。\r\n配置或观察到 DNS 服务器后会显示在这里。"));
        AddDnsSecurityColumn(_dnsSecServerGrid, Localizer.T("地址"), nameof(DnsSecurityServerRow.Address), 150);
        AddDnsSecurityColumn(_dnsSecServerGrid, Localizer.T("网卡"), nameof(DnsSecurityServerRow.Adapter), 220);
        AddDnsSecurityColumn(_dnsSecServerGrid, Localizer.T("来源"), nameof(DnsSecurityServerRow.SourceText), 90);
        AddDnsSecurityColumn(_dnsSecServerGrid, Localizer.T("MAC"), nameof(DnsSecurityServerRow.Mac), 130);
        AddDnsSecurityColumn(_dnsSecServerGrid, Localizer.T("信任"), nameof(DnsSecurityServerRow.TrustedText), 80, fill: true);

        _dnsSecEventGrid = CreateDnsSecurityGrid(
            Localizer.T("还没有 DNS 安全告警。\r\nDNS 投毒与明文绕过检测结果会出现在这里。"));
        AddDnsSecurityColumn(_dnsSecEventGrid, Localizer.T("时间"), nameof(LanEventRow.TimeText), 110);
        AddDnsSecurityColumn(_dnsSecEventGrid, Localizer.T("类型"), nameof(LanEventRow.KindText), 160);
        AddDnsSecurityColumn(_dnsSecEventGrid, Localizer.T("级别"), nameof(LanEventRow.SeverityText), 55);
        AddDnsSecurityColumn(_dnsSecEventGrid, Localizer.T("网卡"), nameof(LanEventRow.Adapter), 150);
        AddDnsSecurityColumn(_dnsSecEventGrid, Localizer.T("详情"), nameof(LanEventRow.Detail), 320, fill: true);

        var split = new SplitContainer
        {
            Dock = DockStyle.Fill,
            Orientation = Orientation.Horizontal,
            SplitterWidth = 6,
        };
        split.Panel1.Controls.Add(_dnsSecServerGrid);
        split.Panel2.Controls.Add(_dnsSecEventGrid);

        split.Resize += (_, _) =>
        {
            if (split.Height > 200)
            {
                split.SplitterDistance = Math.Max(100, (int)(split.Height * 0.34));
            }
        };

        _dnsSecServerGrid.SelectionChanged += (_, _) => UpdateDnsButtons();

        _tabDnsSecurity.Controls.Add(split);
        _tabDnsSecurity.Controls.Add(top);

        _dnsSecTimer = new System.Windows.Forms.Timer
        {
            Interval = DnsSecurityRefreshIntervalMs,
            Enabled = _dnsSecAutoRefreshCheckBox.Checked,
        };
        _dnsSecTimer.Tick += (_, _) =>
        {
            if (_dnsSecAutoRefreshCheckBox.Checked && IsProtectionTab(_tabDnsSecurity))
            {
                _ = RefreshDnsSecurityAsync();
            }
        };

        // 高危 DNS 事件与 IDS 共用托盘气泡通道，点击定位到 DNS 安全子标签。
        _dnsSecNotifyTimer = new System.Windows.Forms.Timer { Interval = DnsSecurityNotifyIntervalMs };
        _dnsSecNotifyTimer.Tick += (_, _) =>
        {
            if (!IsProtectionTab(_tabDnsSecurity))
            {
                _ = CheckDnsSecurityNotificationsAsync();
            }
        };
        _dnsSecNotifyTimer.Start();

        _trayIcon.BalloonTipClicked += (_, _) =>
        {
            if (!_dnsSecBalloonPending)
            {
                return;
            }

            _dnsSecBalloonPending = false;
            ShowMainWindow();
            SelectProtectionTab(_tabDnsSecurity);
            _ = RefreshDnsSecurityAsync();
        };

        UpdateDnsButtons();
        UpdateDnsSummary();
    }

    private static DataGridViewBuffered CreateDnsSecurityGrid(string emptyText) => new()
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
        EmptyText = emptyText,
    };

    private static void AddDnsSecurityColumn(
        DataGridView grid, string header, string property, int width, bool fill = false)
    {
        var column = new DataGridViewTextBoxColumn
        {
            HeaderText = header,
            DataPropertyName = property,
            Name = property,
            ReadOnly = true,
            SortMode = DataGridViewColumnSortMode.NotSortable,
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

        grid.Columns.Add(column);
    }

    private async Task RefreshDnsSecurityAsync()
    {
        if (SuppressBackgroundServices || _dnsSecLoading || IsDisposed || Disposing)
        {
            return;
        }

        _dnsSecLoading = true;
        UpdateDnsButtons();

        try
        {
            var result = await Task.Run(QueryDnsSecuritySnapshot);

            if (IsDisposed || Disposing)
            {
                return;
            }

            if (result is not null)
            {
                _dnsSecServiceAvailable = true;
                _dnsSecStatus = result.Value.Status;
                _dnsSecServers = result.Value.Servers;
                _dnsSecEvents = result.Value.Events;
                RebuildDnsSecurityView();
            }
            else
            {
                _dnsSecServiceAvailable = false;
                UpdateDnsSummary();
            }
        }
        catch (Exception ex)
        {
            _dnsSecServiceAvailable = false;
            LocalLog.Error(LocalLog.Pick("读取 DNS 安全检测失败", "Failed to read DNS security detection."), ex);
            UpdateDnsSummary();
        }
        finally
        {
            _dnsSecLoading = false;

            if (!IsDisposed && !Disposing)
            {
                UpdateDnsButtons();
            }
        }
    }

    private static DnsSecuritySnapshotResult? QueryDnsSecuritySnapshot()
    {
        try
        {
            var response = ServiceClient.TryRequest(
                new ServiceRequest { Command = ServiceProtocol.Commands.QueryDnsSecurity },
                TimeSpan.FromSeconds(2),
                out _);

            return response is { Ok: true }
                ? new DnsSecuritySnapshotResult(
                    response.DnsSecurityStatus,
                    response.DnsSecurityServers ?? new List<DnsSecurityServerDto>(),
                    response.DnsSecurityEvents ?? new List<LanEventDto>())
                : null;
        }
        catch (Exception)
        {
            return null;
        }
    }

    private readonly record struct DnsSecuritySnapshotResult(
        DnsSecurityStatusDto? Status,
        List<DnsSecurityServerDto> Servers,
        List<LanEventDto> Events);

    private void RebuildDnsSecurityView()
    {
        var serverRows = _dnsSecServers.Select(item => new DnsSecurityServerRow(item)).ToList();
        var serverSignature = string.Join(
            "|",
            serverRows.Select(row => $"{row.Address}/{row.Source}/{row.Mac}/{row.Trusted}"));

        if (!string.Equals(serverSignature, _dnsSecServerSignature, StringComparison.Ordinal))
        {
            _dnsSecServerSignature = serverSignature;
            _dnsSecServerGrid.DataSource = serverRows;
        }

        var eventRows = _dnsSecEvents.Select(item => new LanEventRow(item)).ToList();
        var eventSignature = string.Join(
            "|",
            eventRows.Take(100).Select(row => $"{row.Id}/{row.Kind}/{row.TimeUtc.Ticks}"));

        if (!string.Equals(eventSignature, _dnsSecEventSignature, StringComparison.Ordinal))
        {
            _dnsSecEventSignature = eventSignature;
            _dnsSecEventGrid.DataSource = eventRows;
        }

        UpdateDnsSummary();
        UpdateDnsButtons();
    }

    private void UpdateDnsSummary()
    {
        var status = _dnsSecStatus;
        var parts = new List<string> { Localizer.T("DNS 安全检测") };

        if (!_dnsSecServiceAvailable)
        {
            parts.Add(Localizer.T("服务不可用，显示上次数据"));
        }

        if (status is null)
        {
            parts.Add(Localizer.T("状态未知"));
        }
        else
        {
            parts.Add(status.Collecting ? Localizer.T("采集中") : Localizer.T("采集未运行"));
            parts.Add(status.BaselineReady
                ? Localizer.F("基线已就绪（{0}）", status.BaselineUtc?.ToLocalTime().ToString("MM-dd HH:mm") ?? "?")
                : Localizer.T("基线学习中"));
            parts.Add(Localizer.F("事件 {0}", status.EventCount));
            parts.Add(Localizer.F("DNS 服务器 {0}", status.ConfiguredCount));

            if (!string.IsNullOrWhiteSpace(status.LastError))
            {
                parts.Add(status.LastError!);
            }
        }

        _dnsSecStatusLabel.Text = string.Join(" · ", parts);
    }

    private void UpdateDnsButtons()
    {
        var available = _dnsSecServiceAvailable && !_dnsSecLoading;
        var server = _dnsSecServerGrid.CurrentRow?.DataBoundItem as DnsSecurityServerRow;

        _dnsSecRefreshButton.Enabled = !_dnsSecLoading;
        _dnsSecClearButton.Enabled = available && _dnsSecEvents.Count > 0;
        _dnsSecTrustButton.Enabled = available && server is not null;
        _dnsSecTrustButton.Text = server?.Trusted == true
            ? Localizer.T("取消信任此 DNS 服务器")
            : Localizer.T("信任此 DNS 服务器");
        _dnsSecClearTrustButton.Enabled = available
                                          && _dnsSecServers.Any(item => item.Trusted);
    }

    private void OnDnsSecAutoRefreshChanged(object? sender, EventArgs e)
    {
        if (_dnsSecTimer is not null)
        {
            _dnsSecTimer.Enabled = _dnsSecAutoRefreshCheckBox.Checked;
        }

        if (_dnsSecAutoRefreshCheckBox.Checked)
        {
            _ = RefreshDnsSecurityAsync();
        }
    }

    private void OnDnsSecClearClick(object? sender, EventArgs e)
    {
        var confirmed = ConfirmForm.Show(
            owner: DialogOwner,
            title: Localizer.T("清空 DNS 安全告警"),
            question: Localizer.T("确定要清空全部 DNS 安全告警吗？"),
            details: new[]
            {
                new KeyValuePair<string, string>(
                    Localizer.T("将要做的"),
                    Localizer.T("删除已落盘的 DNS 安全事件（dns_*）")),
                new KeyValuePair<string, string>(
                    Localizer.T("不会影响"),
                    Localizer.T("ARP / DHCP 事件、基线、信任列表和其它防护功能")),
            },
            warnings: new[]
            {
                Localizer.T("清空后历史事件无法恢复。"),
                Localizer.T("不会修改任何系统设置。"),
            },
            confirmText: Localizer.T("清空"));

        if (!confirmed)
        {
            return;
        }

        try
        {
            var response = CallService(
                ServiceProtocol.Commands.ClearDnsSecurity,
                new ServiceRequest(),
                Localizer.T("清空 DNS 安全告警"));

            if (response is null)
            {
                return;
            }

            _dnsSecServerSignature = null;
            _dnsSecEventSignature = null;
            _dnsSecEvents = new List<LanEventDto>();
            _dnsSecStatus = response.DnsSecurityStatus ?? _dnsSecStatus;
            _dnsSecServers = response.DnsSecurityServers ?? _dnsSecServers;
            RebuildDnsSecurityView();
            ShowTrayBalloon(
                Localizer.T("DNS 安全告警已清空"),
                Localizer.T("只删除了 dns_* 事件。"));
        }
        catch (Exception ex)
        {
            ShowError(Localizer.T("清空 DNS 安全告警失败"), ex, "Failed to clear DNS security events");
        }
    }

    private void OnDnsSecTrustClick(object? sender, EventArgs e)
    {
        if (_dnsSecServerGrid.CurrentRow?.DataBoundItem is not DnsSecurityServerRow row)
        {
            return;
        }

        var trust = !row.Trusted;

        try
        {
            var response = CallService(
                ServiceProtocol.Commands.TrustDnsServer,
                new ServiceRequest { DnsTrustAddress = row.Address, DnsTrustEnabled = trust },
                Localizer.T(trust ? "信任此 DNS 服务器" : "取消信任此 DNS 服务器"));

            if (response is null)
            {
                return;
            }

            _dnsSecServerSignature = null;
            _dnsSecEventSignature = null;
            _dnsSecServers = response.DnsSecurityServers ?? _dnsSecServers;
            _dnsSecEvents = response.DnsSecurityEvents ?? _dnsSecEvents;
            _dnsSecStatus = response.DnsSecurityStatus ?? _dnsSecStatus;
            RebuildDnsSecurityView();
            ShowTrayBalloon(
                Localizer.T(trust ? "已信任 DNS 服务器" : "已取消信任"),
                row.Address);
        }
        catch (Exception ex)
        {
            ShowError(
                Localizer.T("修改 DNS 信任失败"),
                ex,
                "Failed to change DNS server trust");
        }
    }

    private void OnDnsSecClearTrustClick(object? sender, EventArgs e)
    {
        var trusted = _dnsSecServers
            .Where(item => item.Trusted)
            .Select(item => item.Address)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        if (trusted.Count == 0)
        {
            return;
        }

        var confirmed = ConfirmForm.Show(
            owner: DialogOwner,
            title: Localizer.T("清空 DNS 信任"),
            question: Localizer.F("确定要取消信任全部 {0} 个 DNS 服务器吗？", trusted.Count),
            details: new[]
            {
                new KeyValuePair<string, string>(
                    Localizer.T("将要做的"),
                    Localizer.T("取消全部 DNS 服务器的信任")),
                new KeyValuePair<string, string>(
                    Localizer.T("不会影响"),
                    Localizer.T("网关/DHCP 基线、已落盘事件和其它防护功能")),
            },
            warnings: new[]
            {
                Localizer.T("取消信任后，这些服务器重新参与绕过与应答校验。"),
                Localizer.T("不会修改任何系统 DNS 设置。"),
            },
            confirmText: Localizer.T("清空信任"));

        if (!confirmed)
        {
            return;
        }

        try
        {
            ServiceResponse? response = null;

            foreach (var address in trusted)
            {
                response = CallService(
                    ServiceProtocol.Commands.TrustDnsServer,
                    new ServiceRequest { DnsTrustAddress = address, DnsTrustEnabled = false },
                    Localizer.T("清空 DNS 信任"));

                if (response is null)
                {
                    return;
                }
            }

            if (response is not null)
            {
                _dnsSecServerSignature = null;
                _dnsSecEventSignature = null;
                _dnsSecServers = response.DnsSecurityServers ?? _dnsSecServers;
                _dnsSecEvents = response.DnsSecurityEvents ?? _dnsSecEvents;
                _dnsSecStatus = response.DnsSecurityStatus ?? _dnsSecStatus;
                RebuildDnsSecurityView();
            }

            ShowTrayBalloon(
                Localizer.T("DNS 信任已清空"),
                Localizer.F("{0} 个服务器", trusted.Count));
        }
        catch (Exception ex)
        {
            ShowError(
                Localizer.T("清空 DNS 信任失败"),
                ex,
                "Failed to clear DNS trust");
        }
    }

    private async Task CheckDnsSecurityNotificationsAsync()
    {
        if (SuppressBackgroundServices || IsDisposed || Disposing)
        {
            return;
        }

        List<LanEventDto> events;

        try
        {
            var snapshot = await Task.Run(QueryDnsSecuritySnapshot);

            if (snapshot is null || IsDisposed || Disposing)
            {
                return;
            }

            events = snapshot.Value.Events;
        }
        catch (Exception)
        {
            return;
        }

        var high = events
            .Where(item => string.Equals(item.Severity, "high", StringComparison.OrdinalIgnoreCase)
                           && item.TimeUtc >= DateTime.UtcNow.AddMinutes(-10))
            .OrderByDescending(item => item.TimeUtc)
            .FirstOrDefault();

        if (high is null
            || string.Equals(high.Id, _dnsSecLastNotifiedId, StringComparison.Ordinal)
            || DateTime.UtcNow - _dnsSecLastNotifyUtc < DnsSecurityNotifyCooldown)
        {
            return;
        }

        _dnsSecLastNotifiedId = high.Id;
        _dnsSecLastNotifyUtc = DateTime.UtcNow;
        _dnsSecBalloonPending = true;

        ShowTrayBalloon(
            Localizer.T("DNS 安全发现高危事件"),
            Localizer.F(
                "{0}\n点击打开「DNS 安全」页查看详情；只告警，不阻断。",
                high.Detail),
            ToolTipIcon.Warning);
    }

    private sealed class DnsSecurityServerRow
    {
        public DnsSecurityServerRow(DnsSecurityServerDto item)
        {
            Address = item.Address;
            Adapter = string.IsNullOrWhiteSpace(item.Adapter) ? "—" : item.Adapter;
            Source = item.Source;
            Mac = item.Mac ?? "—";
            Trusted = item.Trusted;
        }

        public string Address { get; }

        public string Adapter { get; }

        public string Source { get; }

        public string Mac { get; }

        public bool Trusted { get; }

        public string SourceText => Localizer.T(Source switch
        {
            "configured" => "系统配置",
            "trusted" => "已信任",
            _ => "观察到",
        });

        public string TrustedText => Localizer.T(Trusted ? "已信任" : "未信任");
    }
}
