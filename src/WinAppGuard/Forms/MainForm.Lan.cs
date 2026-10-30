using WinAppGuard.Contracts;
using WinAppGuard.Core;
using WinAppGuard.Localization;
using WinAppGuard.Models;

namespace WinAppGuard.Forms;

/// <summary>
/// 4.2：「防护 → 局域网」页 —— ARP 欺骗与虚假 DHCP 的告警、基线、信任与临时阻断。
///
/// 只展示服务端的检测结果；界面不抓包、不做判断。
/// 默认只告警；DHCP 阻断是可选功能（默认关闭）。
/// </summary>
public sealed partial class MainForm
{
    private const int LanRefreshIntervalMs = 3000;

    private Label _lanStatusLabel = null!;
    private Label _lanAdapterLabel = null!;
    private Button _lanRefreshButton = null!;
    private Button _lanClearButton = null!;
    private Button _lanResetBaselineButton = null!;
    private Button _lanTrustGatewayButton = null!;
    private Button _lanTrustDhcpButton = null!;
    private Button _lanBlockDhcpButton = null!;
    private ComboBox _lanRetentionCombo = null!;
    private CheckBox _lanBlockEnabledCheck = null!;
    private CheckBox _lanAutoRefreshCheckBox = null!;
    private DataGridViewBuffered _lanGatewayGrid = null!;
    private DataGridViewBuffered _lanDhcpGrid = null!;
    private DataGridViewBuffered _lanEventGrid = null!;
    private TabControl _lanTabs = null!;
    private TabPage _lanIpv4Page = null!;
    private TabPage _lanIpv6Page = null!;
    private System.Windows.Forms.Timer? _lanTimer;

    private List<LanEventDto> _lanEvents = new();
    private List<LanGatewayDto> _lanGateways = new();
    private List<LanDhcpServerDto> _lanServers = new();
    private List<LanBlockDto> _lanBlocks = new();
    private LanStatusDto? _lanStatus;
    private LanSettingsDto _lanSettings = new();
    private bool _lanLoading;
    private bool _lanServiceAvailable = true;
    private string? _lanGatewaySignature;
    private string? _lanDhcpSignature;
    private string? _lanEventSignature;
    private bool _lanBindingSettings;

    private void InitializeLanPage()
    {
        var top = new Panel
        {
            Dock = DockStyle.Top,
            Height = 118,
            Padding = new Padding(0, 4, 0, 0),
        };

        _lanRefreshButton = new Button { Text = Localizer.T("刷新"), AutoSize = true, MinimumSize = new Size(68, 27) };
        _lanRefreshButton.Click += (_, _) => _ = RefreshLanAsync();

        _lanClearButton = new Button { Text = Localizer.T("清空…"), AutoSize = true, MinimumSize = new Size(76, 27) };
        _lanClearButton.Click += OnLanClearClick;

        _lanResetBaselineButton = new Button
        {
            Text = Localizer.T("重置基线…"),
            AutoSize = true,
            MinimumSize = new Size(96, 27),
        };
        _lanResetBaselineButton.Click += OnLanResetBaselineClick;

        _lanTrustGatewayButton = new Button
        {
            Text = Localizer.T("信任此网关"),
            AutoSize = true,
            MinimumSize = new Size(96, 27),
        };
        _lanTrustGatewayButton.Click += OnLanTrustGatewayClick;

        _lanTrustDhcpButton = new Button
        {
            Text = Localizer.T("信任此 DHCP"),
            AutoSize = true,
            MinimumSize = new Size(104, 27),
        };
        _lanTrustDhcpButton.Click += OnLanTrustDhcpClick;

        _lanBlockDhcpButton = new Button
        {
            Text = Localizer.T("临时阻断此服务器"),
            AutoSize = true,
            MinimumSize = new Size(128, 27),
        };
        _lanBlockDhcpButton.Click += OnLanBlockDhcpClick;

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
            _lanRefreshButton, _lanClearButton, _lanResetBaselineButton,
            _lanTrustGatewayButton, _lanTrustDhcpButton, _lanBlockDhcpButton,
        });

        var retentionLabel = new Label
        {
            Location = new Point(0, 42),
            AutoSize = true,
            Text = Localizer.T("事件保留"),
            ForeColor = SystemColors.GrayText,
        };

        _lanRetentionCombo = new ComboBox
        {
            Location = new Point(64, 38),
            Width = 88,
            DropDownStyle = ComboBoxStyle.DropDownList,
        };
        _lanRetentionCombo.Items.AddRange(new object[]
        {
            Localizer.F("{0} 天", 7),
            Localizer.F("{0} 天", 15),
            Localizer.F("{0} 天", 30),
        });
        _lanRetentionCombo.SelectedIndex = 0;
        _lanRetentionCombo.SelectedIndexChanged += OnLanRetentionChanged;

        _lanBlockEnabledCheck = new CheckBox
        {
            Location = new Point(170, 40),
            AutoSize = true,
            Text = Localizer.T("允许临时阻断 DHCP 服务器（默认关闭）"),
        };
        _lanBlockEnabledCheck.CheckedChanged += OnLanBlockEnabledChanged;

        _lanAutoRefreshCheckBox = new CheckBox
        {
            Location = new Point(470, 40),
            AutoSize = true,
            Text = Localizer.T("每 3 秒自动刷新"),
            Checked = true,
        };
        _lanAutoRefreshCheckBox.CheckedChanged += OnLanAutoRefreshChanged;

        _lanStatusLabel = new Label
        {
            Location = new Point(0, 68),
            Width = 1000,
            Height = 20,
            ForeColor = SystemColors.GrayText,
            AutoEllipsis = true,
        };

        _lanAdapterLabel = new Label
        {
            Location = new Point(0, 90),
            Width = 1000,
            Height = 20,
            ForeColor = SystemColors.GrayText,
            AutoEllipsis = true,
        };

        top.Resize += (_, _) =>
        {
            var width = Math.Max(200, top.ClientSize.Width - 8);
            _lanStatusLabel.Width = width;
            _lanAdapterLabel.Width = width;
            _lanAutoRefreshCheckBox.Left = Math.Max(470, width - 170);
        };

        top.Controls.AddRange(new Control[]
        {
            actions, _lanRetentionCombo, retentionLabel, _lanBlockEnabledCheck,
            _lanAutoRefreshCheckBox, _lanStatusLabel, _lanAdapterLabel,
        });

        _lanGatewayGrid = CreateLanGrid(
            "还没有网关基线。\r\n基线学习完成后，这里会显示每个网卡的网关 MAC。");
        AddLanColumn(_lanGatewayGrid, "网卡", nameof(LanGatewayRow.Adapter), 115);
        AddLanColumn(_lanGatewayGrid, "网关 IP", nameof(LanGatewayRow.Ip), 100);
        AddLanColumn(_lanGatewayGrid, "MAC", nameof(LanGatewayRow.Mac), 125);
        AddLanColumn(_lanGatewayGrid, "学习时间", nameof(LanGatewayRow.LearnedText), 90);
        AddLanColumn(_lanGatewayGrid, "信任", nameof(LanGatewayRow.TrustedText), 50, fill: true);

        _lanDhcpGrid = CreateLanGrid(
            "还没有观察到 DHCP 服务器。\r\n基线学习完成后，这里会列出已知的 DHCP 服务器。");
        AddLanColumn(_lanDhcpGrid, "服务器 IP", nameof(LanDhcpRow.ServerIp), 95);
        AddLanColumn(_lanDhcpGrid, "MAC", nameof(LanDhcpRow.Mac), 105);
        AddLanColumn(_lanDhcpGrid, "网卡", nameof(LanDhcpRow.Adapter), 75);
        AddLanColumn(_lanDhcpGrid, "网关", nameof(LanDhcpRow.Gateway), 80);
        AddLanColumn(_lanDhcpGrid, "DNS", nameof(LanDhcpRow.Dns), 80);
        AddLanColumn(_lanDhcpGrid, "租期", nameof(LanDhcpRow.LeaseText), 50);
        AddLanColumn(_lanDhcpGrid, "首次发现", nameof(LanDhcpRow.FirstSeenText), 80, fill: true);

        _lanEventGrid = CreateLanGrid(
            "还没有局域网告警。\r\nARP 欺骗与虚假 DHCP 的检测结果会出现在这里。");
        AddLanColumn(_lanEventGrid, "时间", nameof(LanEventRow.TimeText), 110);
        AddLanColumn(_lanEventGrid, "类型", nameof(LanEventRow.KindText), 150);
        AddLanColumn(_lanEventGrid, "级别", nameof(LanEventRow.SeverityText), 55);
        AddLanColumn(_lanEventGrid, "网卡", nameof(LanEventRow.Adapter), 130);
        AddLanColumn(_lanEventGrid, "详情", nameof(LanEventRow.Detail), 320, fill: true);

        var topHalf = new SplitContainer
        {
            Dock = DockStyle.Fill,
            Orientation = Orientation.Vertical,
            SplitterWidth = 6,
        };
        topHalf.Panel1.Controls.Add(_lanGatewayGrid);
        topHalf.Panel2.Controls.Add(_lanDhcpGrid);

        var mainSplit = new SplitContainer
        {
            Dock = DockStyle.Fill,
            Orientation = Orientation.Horizontal,
            SplitterWidth = 6,
        };
        mainSplit.Panel1.Controls.Add(topHalf);
        mainSplit.Panel2.Controls.Add(_lanEventGrid);

        mainSplit.Resize += (_, _) =>
        {
            if (mainSplit.Height > 200)
            {
                mainSplit.SplitterDistance = Math.Max(120, (int)(mainSplit.Height * 0.42));
            }
        };

        _lanGatewayGrid.SelectionChanged += (_, _) => UpdateLanButtons();
        _lanDhcpGrid.SelectionChanged += (_, _) => UpdateLanButtons();

        _lanTabs = new TabControl
        {
            Dock = DockStyle.Fill,
            Name = "_lanTabs",
        };

        _lanIpv4Page = new TabPage(Localizer.T("IPv4（ARP / DHCP）"))
        {
            Name = "_lanIpv4Page",
            Padding = new Padding(3),
            UseVisualStyleBackColor = true,
        };

        _lanIpv6Page = new TabPage(Localizer.T("IPv6 邻接"))
        {
            Name = "_lanIpv6Page",
            Padding = new Padding(3),
            UseVisualStyleBackColor = true,
        };

        _lanIpv4Page.Controls.Add(mainSplit);
        _lanIpv4Page.Controls.Add(top);
        _lanTabs.Controls.Add(_lanIpv4Page);
        _lanTabs.Controls.Add(_lanIpv6Page);
        _tabLan.Controls.Add(_lanTabs);

        _lanTabs.SelectedIndexChanged += (_, _) =>
        {
            if (!IsProtectionTab(_tabLan))
            {
                return;
            }

            if (_lanTabs.SelectedTab == _lanIpv6Page)
            {
                _ = RefreshIpv6Async();
            }
            else
            {
                _ = RefreshLanAsync();
            }
        };

        _lanTimer = new System.Windows.Forms.Timer
        {
            Interval = LanRefreshIntervalMs,
            Enabled = _lanAutoRefreshCheckBox.Checked,
        };
        _lanTimer.Tick += (_, _) =>
        {
            if (_lanAutoRefreshCheckBox.Checked && IsLanIpv4Tab)
            {
                _ = RefreshLanAsync();
            }
        };

        UpdateLanButtons();
        UpdateLanSummary();
    }

    private bool IsLanIpv4Tab
        => IsProtectionTab(_tabLan) && _lanTabs.SelectedTab == _lanIpv4Page;

    private bool IsLanIpv6Tab
        => IsProtectionTab(_tabLan) && _lanTabs.SelectedTab == _lanIpv6Page;

    private static DataGridViewBuffered CreateLanGrid(string emptyText) => new()
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

    private static void AddLanColumn(
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

    private async Task RefreshLanAsync()
    {
        if (SuppressBackgroundServices || _lanLoading || IsDisposed || Disposing)
        {
            return;
        }

        _lanLoading = true;
        UpdateLanButtons();

        try
        {
            var result = await Task.Run(QueryLanSnapshot);

            if (IsDisposed || Disposing)
            {
                return;
            }

            if (result is not null)
            {
                _lanServiceAvailable = true;
                _lanEvents = result.Value.Events;
                _lanGateways = result.Value.Gateways;
                _lanServers = result.Value.Servers;
                _lanBlocks = result.Value.Blocks;
                _lanStatus = result.Value.Status;
                _lanSettings = result.Value.Settings ?? _lanSettings;
                ApplyLanSettingsToControls();
                RebuildLanView();
            }
            else
            {
                _lanServiceAvailable = false;
                UpdateLanSummary();
            }
        }
        catch (Exception ex)
        {
            _lanServiceAvailable = false;
            LocalLog.Error(LocalLog.Pick("读取局域网检测失败", "Failed to read LAN detection."), ex);
            UpdateLanSummary();
        }
        finally
        {
            _lanLoading = false;

            if (!IsDisposed && !Disposing)
            {
                UpdateLanButtons();
            }
        }
    }

    private static LanSnapshotResult? QueryLanSnapshot()
    {
        try
        {
            var response = ServiceClient.TryRequest(
                new ServiceRequest { Command = ServiceProtocol.Commands.QueryLan },
                TimeSpan.FromSeconds(2),
                out _);

            return response is { Ok: true }
                ? new LanSnapshotResult(
                    response.LanEvents ?? new List<LanEventDto>(),
                    response.LanGateways ?? new List<LanGatewayDto>(),
                    response.LanDhcpServers ?? new List<LanDhcpServerDto>(),
                    response.LanBlocks ?? new List<LanBlockDto>(),
                    response.LanStatus,
                    response.LanSettings)
                : null;
        }
        catch (Exception)
        {
            return null;
        }
    }

    private readonly record struct LanSnapshotResult(
        List<LanEventDto> Events,
        List<LanGatewayDto> Gateways,
        List<LanDhcpServerDto> Servers,
        List<LanBlockDto> Blocks,
        LanStatusDto? Status,
        LanSettingsDto? Settings);

    private void ApplyLanSettingsToControls()
    {
        _lanBindingSettings = true;

        try
        {
            var days = LanRetentionIndex(_lanSettings.RetentionDays);
            _lanRetentionCombo.SelectedIndex = days;
            _lanBlockEnabledCheck.Checked = _lanSettings.DhcpBlockEnabled;
        }
        finally
        {
            _lanBindingSettings = false;
        }
    }

    private static int LanRetentionIndex(int days) => days switch
    {
        15 => 1,
        30 => 2,
        _ => 0,
    };

    private static int LanRetentionDays(int index) => index switch
    {
        1 => 15,
        2 => 30,
        _ => 7,
    };

    private void RebuildLanView()
    {
        var gatewayRows = _lanGateways.Select(item => new LanGatewayRow(item)).ToList();
        var gatewaySignature = string.Join("|", gatewayRows.Select(row => $"{row.Adapter}/{row.Ip}/{row.Mac}/{row.Trusted}"));

        if (!string.Equals(gatewaySignature, _lanGatewaySignature, StringComparison.Ordinal))
        {
            _lanGatewaySignature = gatewaySignature;
            _lanGatewayGrid.DataSource = gatewayRows;
        }

        var dhcpRows = _lanServers.Select(item => new LanDhcpRow(item, _lanBlocks)).ToList();
        var dhcpSignature = string.Join(
            "|",
            dhcpRows.Select(row => $"{row.ServerIp}/{row.Mac}/{row.LeaseText}/{row.Blocked}"));

        if (!string.Equals(dhcpSignature, _lanDhcpSignature, StringComparison.Ordinal))
        {
            _lanDhcpSignature = dhcpSignature;
            _lanDhcpGrid.DataSource = dhcpRows;
        }

        var eventRows = _lanEvents.Select(item => new LanEventRow(item)).ToList();
        var eventSignature = string.Join("|", eventRows.Take(100).Select(row => $"{row.Id}/{row.Kind}/{row.TimeUtc.Ticks}"));

        if (!string.Equals(eventSignature, _lanEventSignature, StringComparison.Ordinal))
        {
            _lanEventSignature = eventSignature;
            _lanEventGrid.DataSource = eventRows;
        }

        UpdateLanSummary();
        UpdateLanButtons();
    }

    private void UpdateLanSummary()
    {
        var status = _lanStatus;
        var parts = new List<string> { Localizer.T("局域网检测") };

        if (!_lanServiceAvailable)
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
            parts.Add(Localizer.F("阻断 {0}", status.BlockedCount));

            if (status.Adapters is { Count: > 0 })
            {
                parts.Add(Localizer.F("网卡 {0}", status.Adapters.Count));
            }

            if (!string.IsNullOrWhiteSpace(status.LastError))
            {
                parts.Add(status.LastError!);
            }
        }

        _lanStatusLabel.Text = string.Join(" · ", parts);

        _lanAdapterLabel.Text = status?.Adapters is { Count: > 0 }
            ? Localizer.F("纳入检测的网卡：{0}", string.Join(" / ", status.Adapters))
            : Localizer.T("纳入检测的网卡：无（Npcap 不可用或全部是虚拟网卡）");
    }

    private void UpdateLanButtons()
    {
        var available = _lanServiceAvailable && !_lanLoading;
        var gateway = _lanGatewayGrid.CurrentRow?.DataBoundItem as LanGatewayRow;
        var dhcp = _lanDhcpGrid.CurrentRow?.DataBoundItem as LanDhcpRow;

        _lanRefreshButton.Enabled = !_lanLoading;
        _lanClearButton.Enabled = available && (_lanEvents.Count > 0 || _lanBlocks.Count > 0);
        _lanResetBaselineButton.Enabled = available;
        _lanTrustGatewayButton.Enabled = available && gateway is not null;
        _lanTrustDhcpButton.Enabled = available && dhcp is not null;
        _lanBlockDhcpButton.Enabled = available
                                      && dhcp is not null
                                      && _lanSettings.DhcpBlockEnabled;
        _lanBlockDhcpButton.Text = dhcp?.Blocked == true
            ? Localizer.T("解除阻断")
            : Localizer.T("临时阻断此服务器");
        _lanRetentionCombo.Enabled = available;
        _lanBlockEnabledCheck.Enabled = available;
    }

    private void OnLanAutoRefreshChanged(object? sender, EventArgs e)
    {
        if (_lanTimer is not null)
        {
            _lanTimer.Enabled = _lanAutoRefreshCheckBox.Checked;
        }

        if (_lanAutoRefreshCheckBox.Checked)
        {
            _ = RefreshLanAsync();
        }
    }

    private void OnLanRetentionChanged(object? sender, EventArgs e)
    {
        if (_lanBindingSettings)
        {
            return;
        }

        SaveLanSettings(
            LanRetentionDays(_lanRetentionCombo.SelectedIndex),
            _lanBlockEnabledCheck.Checked);
    }

    private void OnLanBlockEnabledChanged(object? sender, EventArgs e)
    {
        if (_lanBindingSettings)
        {
            return;
        }

        SaveLanSettings(
            LanRetentionDays(_lanRetentionCombo.SelectedIndex),
            _lanBlockEnabledCheck.Checked);
    }

    private void SaveLanSettings(int retentionDays, bool blockEnabled)
    {
        try
        {
            var response = CallService(
                ServiceProtocol.Commands.ConfigureLan,
                new ServiceRequest
                {
                    LanSettings = new LanSettingsDto
                    {
                        RetentionDays = retentionDays,
                        DhcpBlockEnabled = blockEnabled,
                    },
                },
                Localizer.T("修改局域网检测设置"));

            if (response is null)
            {
                return;
            }

            _lanSettings = response.LanSettings ?? _lanSettings;
            _lanStatus = response.LanStatus ?? _lanStatus;
            _lanBlocks = response.LanBlocks ?? _lanBlocks;
            ApplyLanSettingsToControls();
            RebuildLanView();
        }
        catch (Exception ex)
        {
            ShowError(Localizer.T("修改局域网检测设置失败"), ex, "Failed to change LAN detection settings");
        }
    }

    private void OnLanClearClick(object? sender, EventArgs e)
    {
        var confirmed = ConfirmForm.Show(
            owner: DialogOwner,
            title: "清空局域网告警",
            question: "确定要清空全部局域网告警并解除 DHCP 阻断吗？",
            details: new[]
            {
                new KeyValuePair<string, string>("将要做的", "删除已落盘的 ARP / DHCP 事件，并解除全部临时阻断"),
                new KeyValuePair<string, string>("不会影响", "网关/DHCP 基线、规则和其它防护功能"),
            },
            warnings: new[]
            {
                "清空后历史事件无法恢复。",
                "不会修改任何系统设置。",
            },
            confirmText: "清空并解除");

        if (!confirmed)
        {
            return;
        }

        try
        {
            var response = CallService(
                ServiceProtocol.Commands.ClearLan,
                new ServiceRequest(),
                Localizer.T("清空局域网告警"));

            if (response is null)
            {
                return;
            }

            _lanSignatureReset();
            _lanEvents = new List<LanEventDto>();
            _lanBlocks = new List<LanBlockDto>();
            _lanStatus = response.LanStatus ?? _lanStatus;
            RebuildLanView();
            ShowTrayBalloon(Localizer.T("局域网告警已清空"), Localizer.T("临时阻断已解除。"));
        }
        catch (Exception ex)
        {
            ShowError(Localizer.T("清空局域网告警失败"), ex, "Failed to clear LAN events");
        }
    }

    private void OnLanResetBaselineClick(object? sender, EventArgs e)
    {
        var confirmed = ConfirmForm.Show(
            owner: DialogOwner,
            title: "重置局域网基线",
            question: "确定要清空网关/DHCP 基线并重新学习吗？",
            details: new[]
            {
                new KeyValuePair<string, string>("将要做的", "删除已学习的网关 MAC 与 DHCP 服务器，重新静默学习"),
                new KeyValuePair<string, string>("不会影响", "已有事件、规则和临时阻断"),
            },
            warnings: new[]
            {
                "重新学习期间不会产生新的局域网告警。",
                "换过路由器或 DHCP 服务器后才需要这样做。",
            },
            confirmText: "重置基线");

        if (!confirmed)
        {
            return;
        }

        try
        {
            var response = CallService(
                ServiceProtocol.Commands.ResetLanBaseline,
                new ServiceRequest(),
                Localizer.T("重置局域网基线"));

            if (response is null)
            {
                return;
            }

            _lanSignatureReset();
            _lanGateways = new List<LanGatewayDto>();
            _lanServers = new List<LanDhcpServerDto>();
            _lanStatus = response.LanStatus ?? _lanStatus;
            RebuildLanView();
            ShowTrayBalloon(Localizer.T("局域网基线已重置"), Localizer.T("正在重新静默学习。"));
        }
        catch (Exception ex)
        {
            ShowError(Localizer.T("重置局域网基线失败"), ex, "Failed to reset LAN baseline");
        }
    }

    private void OnLanTrustGatewayClick(object? sender, EventArgs e)
    {
        if (_lanGatewayGrid.CurrentRow?.DataBoundItem is not LanGatewayRow row)
        {
            return;
        }

        TrustLan("gateway", row.Ip, Localizer.T("信任此网关"));
    }

    private void OnLanTrustDhcpClick(object? sender, EventArgs e)
    {
        if (_lanDhcpGrid.CurrentRow?.DataBoundItem is not LanDhcpRow row)
        {
            return;
        }

        TrustLan("dhcp", row.ServerIp, Localizer.T("信任此 DHCP 服务器"));
    }

    private void TrustLan(string kind, string value, string action)
    {
        try
        {
            var response = CallService(
                ServiceProtocol.Commands.TrustLan,
                new ServiceRequest { LanTrustKind = kind, LanTrustValue = value },
                action);

            if (response is null)
            {
                return;
            }

            _lanSignatureReset();
            _lanGateways = response.LanGateways ?? _lanGateways;
            _lanServers = response.LanDhcpServers ?? _lanServers;
            _lanStatus = response.LanStatus ?? _lanStatus;
            RebuildLanView();
            ShowTrayBalloon(Localizer.T("已信任"), Localizer.F("{0} 已写入基线。", value));
        }
        catch (Exception ex)
        {
            ShowError(Localizer.T("信任失败"), ex, "Failed to trust LAN target");
        }
    }

    private void OnLanBlockDhcpClick(object? sender, EventArgs e)
    {
        if (_lanDhcpGrid.CurrentRow?.DataBoundItem is not LanDhcpRow row)
        {
            return;
        }

        var blocking = !row.Blocked;

        if (blocking)
        {
            var confirmed = ConfirmForm.Show(
                owner: DialogOwner,
                title: "临时阻断 DHCP 服务器",
                question: Localizer.F(
                    "确定要临时阻断 DHCP 服务器 {0} 吗？", row.ServerIp),
                details: new[]
                {
                    new KeyValuePair<string, string>("将要做的", "阻止该 IP 发送 DHCP 应答 10 分钟"),
                    new KeyValuePair<string, string>("不会影响", "该 IP 的其它流量（不是整机封禁）"),
                },
                warnings: new[]
                {
                    "如果这是合法服务器，设备可能无法续租，10 分钟后自动解除。",
                    "只在该服务器仍在发 DHCP 应答时有效。",
                },
                confirmText: "临时阻断");

            if (!confirmed)
            {
                return;
            }
        }

        try
        {
            var response = CallService(
                ServiceProtocol.Commands.BlockLanDhcp,
                new ServiceRequest { LanBlockServerIp = row.ServerIp, LanBlockEnabled = blocking },
                Localizer.T(blocking ? "临时阻断 DHCP 服务器" : "解除 DHCP 阻断"));

            if (response is null)
            {
                return;
            }

            _lanBlocks = response.LanBlocks ?? _lanBlocks;
            _lanStatus = response.LanStatus ?? _lanStatus;
            _lanSignatureReset();
            RebuildLanView();
            ShowTrayBalloon(
                Localizer.T(blocking ? "已临时阻断 DHCP 服务器" : "已解除 DHCP 阻断"),
                Localizer.F("{0} · 10 分钟", row.ServerIp));
        }
        catch (Exception ex)
        {
            ShowError(Localizer.T("修改 DHCP 阻断失败"), ex, "Failed to change DHCP block");
        }
    }

    private void _lanSignatureReset()
    {
        _lanGatewaySignature = null;
        _lanDhcpSignature = null;
        _lanEventSignature = null;
    }

    private sealed class LanGatewayRow
    {
        public LanGatewayRow(LanGatewayDto item)
        {
            Adapter = item.Adapter;
            Ip = item.Ip;
            Mac = item.Mac;
            LearnedUtc = item.LearnedUtc;
            Trusted = item.Trusted;
        }

        public string Adapter { get; }

        public string Ip { get; }

        public string Mac { get; }

        public DateTime LearnedUtc { get; }

        public bool Trusted { get; }

        public string LearnedText => LearnedUtc.ToLocalTime().ToString("MM-dd HH:mm");

        public string TrustedText => Localizer.T(Trusted ? "已信任" : "自动学习");
    }

    private sealed class LanDhcpRow
    {
        public LanDhcpRow(LanDhcpServerDto item, List<LanBlockDto> blocks)
        {
            ServerIp = item.ServerIp;
            Mac = item.Mac ?? "—";
            Adapter = item.Adapter;
            Gateway = item.Gateway ?? "—";
            Dns = item.Dns ?? "—";
            LeaseSeconds = item.LeaseSeconds;
            FirstSeenUtc = item.FirstSeenUtc;
            Trusted = item.Trusted;
            Blocked = blocks.Any(block =>
                string.Equals(block.ServerIp, item.ServerIp, StringComparison.OrdinalIgnoreCase));
        }

        public string ServerIp { get; }

        public string Mac { get; }

        public string Adapter { get; }

        public string Gateway { get; }

        public string Dns { get; }

        public int LeaseSeconds { get; }

        public DateTime FirstSeenUtc { get; }

        public bool Trusted { get; }

        public bool Blocked { get; }

        public string LeaseText => LeaseSeconds <= 0
            ? "—"
            : Localizer.F("{0} 秒", LeaseSeconds);

        public string FirstSeenText => FirstSeenUtc.ToLocalTime().ToString("MM-dd HH:mm");
    }

    private sealed class LanEventRow
    {
        public LanEventRow(LanEventDto item)
        {
            Id = item.Id;
            TimeUtc = item.TimeUtc;
            Kind = item.Kind;
            Severity = item.Severity;
            Adapter = item.Adapter;
            Detail = item.Detail;
        }

        public string Id { get; }

        public DateTime TimeUtc { get; }

        public string Kind { get; }

        public string Severity { get; }

        public string Adapter { get; }

        public string Detail { get; }

        public string TimeText => TimeUtc.ToLocalTime().ToString("MM-dd HH:mm:ss");

        public string SeverityText => Localizer.T(Severity switch
        {
            "high" => "高",
            "low" => "低",
            _ => "中",
        });

        public string KindText => Localizer.T(Kind switch
        {
            "arp_gateway_mac_changed" => "网关 MAC 变化",
            "arp_gateway_cache_mismatch" => "网关缓存不一致",
            "arp_mac_claims_many_ips" => "MAC 声称多个 IP",
            "arp_ip_mac_flapping" => "IP 频繁换 MAC",
            "arp_sender_mismatch" => "ARP 源 MAC 不一致",
            "arp_gratuitous_burst" => "免费 ARP 突发",
            "dhcp_unexpected_server" => "未知 DHCP 服务器",
            "dhcp_multiple_servers" => "多个 DHCP 服务器",
            "dhcp_option_mismatch" => "DHCP 下发参数变化",
            "dhcp_short_lease" => "DHCP 租期异常短",
            "dhcp_server_not_gateway" => "DHCP 服务器非网关",
            "dns_response_unexpected_server" => "应答来源异常",
            "dns_transaction_mismatch" => "事务 ID 不匹配",
            "dns_answer_name_mismatch" => "应答域名不符",
            "dns_nxdomain_with_answer" => "NXDOMAIN 带答案",
            "dns_conflicting_answers" => "冲突应答",
            "dns_ttl_suspicious" => "TTL 异常",
            "dns_server_not_gateway" => "DNS 服务器非网关",
            "dns_plaintext_bypass" => "明文 DNS 绕过",
            "ipv6_ra_unexpected_router" => "非基线路由器 RA",
            "ipv6_ra_multiple_routers" => "多个 IPv6 路由器",
            "ipv6_ra_prefix_changed" => "RA 前缀变化",
            "ipv6_ra_flags_or_lifetime_changed" => "RA 标志/生命周期变化",
            "ipv6_ra_flood" => "RA 洪水",
            "ipv6_dhcpv6_unexpected_server" => "非基线 DHCPv6 服务器",
            "ipv6_dhcpv6_multiple_servers" => "多个 DHCPv6 服务器",
            "ipv6_dhcpv6_option_mismatch" => "DHCPv6 参数变化",
            "ipv6_dhcpv6_short_lease" => "DHCPv6 租期异常短",
            "ipv6_na_router_mac_changed" => "路由器 NA MAC 变化",
            "ipv6_na_cache_mismatch" => "邻居缓存不一致",
            "ipv6_na_mac_behavior" => "NA MAC 异常",
            "ipv6_na_unsolicited_burst" => "免费 NA 突发",
            "ipv6_nd_sender_mismatch" => "NDP 源 MAC 不一致",
            "ipv6_redirect_unexpected" => "非网关 Redirect",
            "ipv6_dad_conflict" => "DAD 冲突",
            _ => Kind,
        });
    }
}
