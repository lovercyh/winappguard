using WinAppGuard.Contracts;
using WinAppGuard.Core;
using WinAppGuard.Localization;
using WinAppGuard.Models;

namespace WinAppGuard.Forms;

/// <summary>
/// 4.4：「防护 → 局域网 → IPv6 邻接」页。
///
/// 只展示服务端的 IPv6 RA / DHCPv6 / NDP 检测结果；界面不抓包、不判断。
/// 默认只告警；需要时再按 POC 结果提供临时阻断。
/// </summary>
public sealed partial class MainForm
{
    private const int Ipv6RefreshIntervalMs = 3000;
    private const int Ipv6NotifyIntervalMs = 30000;
    private static readonly TimeSpan Ipv6NotifyCooldown = TimeSpan.FromMinutes(5);

    private Label _ipv6StatusLabel = null!;
    private Button _ipv6RefreshButton = null!;
    private Button _ipv6ClearButton = null!;
    private Button _ipv6ResetBaselineButton = null!;
    private Button _ipv6TrustRouterButton = null!;
    private Button _ipv6TrustDhcpButton = null!;
    private Button _ipv6BlockDhcpButton = null!;
    private CheckBox _ipv6AutoRefreshCheckBox = null!;
    private TabControl _ipv6EndpointTabs = null!;
    private DataGridViewBuffered _ipv6RouterGrid = null!;
    private DataGridViewBuffered _ipv6DhcpGrid = null!;
    private DataGridViewBuffered _ipv6NeighborGrid = null!;
    private DataGridViewBuffered _ipv6EventGrid = null!;
    private System.Windows.Forms.Timer? _ipv6Timer;
    private System.Windows.Forms.Timer? _ipv6NotifyTimer;

    private List<Ipv6RouterDto> _ipv6Routers = new();
    private List<Ipv6DhcpServerDto> _ipv6DhcpServers = new();
    private List<Ipv6NeighborDto> _ipv6Neighbors = new();
    private List<LanEventDto> _ipv6Events = new();
    private Ipv6SecurityStatusDto? _ipv6Status;
    private bool _ipv6Loading;
    private bool _ipv6ServiceAvailable = true;
    private string? _ipv6RouterSignature;
    private string? _ipv6DhcpSignature;
    private string? _ipv6NeighborSignature;
    private string? _ipv6EventSignature;
    private string? _ipv6LastNotifiedId;
    private DateTime _ipv6LastNotifyUtc = DateTime.MinValue;
    private bool _ipv6BalloonPending;

    private void InitializeIpv6Page()
    {
        var top = new Panel
        {
            Dock = DockStyle.Top,
            Height = 118,
            Padding = new Padding(0, 4, 0, 0),
        };

        _ipv6RefreshButton = new Button
        {
            Text = Localizer.T("刷新"),
            AutoSize = true,
            MinimumSize = new Size(68, 27),
        };
        _ipv6RefreshButton.Click += (_, _) => _ = RefreshIpv6Async();

        _ipv6ClearButton = new Button
        {
            Text = Localizer.T("清空…"),
            AutoSize = true,
            MinimumSize = new Size(76, 27),
        };
        _ipv6ClearButton.Click += OnIpv6ClearClick;

        _ipv6ResetBaselineButton = new Button
        {
            Text = Localizer.T("重置基线…"),
            AutoSize = true,
            MinimumSize = new Size(96, 27),
        };
        _ipv6ResetBaselineButton.Click += OnIpv6ResetBaselineClick;

        _ipv6TrustRouterButton = new Button
        {
            Text = Localizer.T("信任此路由器"),
            AutoSize = true,
            MinimumSize = new Size(104, 27),
        };
        _ipv6TrustRouterButton.Click += OnIpv6TrustRouterClick;

        _ipv6TrustDhcpButton = new Button
        {
            Text = Localizer.T("信任此 DHCPv6"),
            AutoSize = true,
            MinimumSize = new Size(112, 27),
        };
        _ipv6TrustDhcpButton.Click += OnIpv6TrustDhcpClick;

        _ipv6BlockDhcpButton = new Button
        {
            Text = Localizer.T("临时阻断此 DHCPv6（10 分钟）"),
            AutoSize = true,
            MinimumSize = new Size(120, 27),
        };
        _ipv6BlockDhcpButton.Click += OnIpv6BlockDhcpClick;

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
            _ipv6RefreshButton, _ipv6ClearButton, _ipv6ResetBaselineButton,
            _ipv6TrustRouterButton, _ipv6TrustDhcpButton, _ipv6BlockDhcpButton,
        });

        _ipv6AutoRefreshCheckBox = new CheckBox
        {
            Location = new Point(600, 42),
            AutoSize = true,
            Text = Localizer.T("每 3 秒自动刷新"),
            Checked = true,
        };
        _ipv6AutoRefreshCheckBox.CheckedChanged += OnIpv6AutoRefreshChanged;

        _ipv6StatusLabel = new Label
        {
            Location = new Point(0, 68),
            Width = 1000,
            Height = 40,
            ForeColor = SystemColors.GrayText,
            AutoEllipsis = true,
        };

        top.Resize += (_, _) =>
        {
            var width = Math.Max(200, top.ClientSize.Width - 8);
            _ipv6StatusLabel.Width = width;
            _ipv6AutoRefreshCheckBox.Left = Math.Max(600, width - 170);
        };

        top.Controls.AddRange(new Control[]
        {
            actions, _ipv6AutoRefreshCheckBox, _ipv6StatusLabel,
        });

        _ipv6RouterGrid = CreateLanGrid(
            Localizer.T("还没有 IPv6 路由器。\r\n基线学习完成后，这里会显示链路本地地址、前缀和 MAC。"));
        AddLanColumn(_ipv6RouterGrid, Localizer.T("链路本地"), nameof(Ipv6RouterRow.LinkLocal), 150);
        AddLanColumn(_ipv6RouterGrid, Localizer.T("MAC"), nameof(Ipv6RouterRow.Mac), 130);
        AddLanColumn(_ipv6RouterGrid, Localizer.T("前缀"), nameof(Ipv6RouterRow.Prefixes), 220);
        AddLanColumn(_ipv6RouterGrid, Localizer.T("标志"), nameof(Ipv6RouterRow.Flags), 55);
        AddLanColumn(_ipv6RouterGrid, Localizer.T("生命周期"), nameof(Ipv6RouterRow.LifetimeText), 80);
        AddLanColumn(_ipv6RouterGrid, Localizer.T("信任"), nameof(Ipv6RouterRow.TrustedText), 70, fill: true);

        _ipv6DhcpGrid = CreateLanGrid(
            Localizer.T("还没有 DHCPv6 服务器。\r\n基线学习完成后，这里会显示 Server ID、DNS 和租期。"));
        AddLanColumn(_ipv6DhcpGrid, "Server ID", nameof(Ipv6DhcpRow.ServerId), 120);
        AddLanColumn(_ipv6DhcpGrid, Localizer.T("地址"), nameof(Ipv6DhcpRow.Address), 140);
        AddLanColumn(_ipv6DhcpGrid, Localizer.T("MAC"), nameof(Ipv6DhcpRow.Mac), 120);
        AddLanColumn(_ipv6DhcpGrid, Localizer.T("DNS"), nameof(Ipv6DhcpRow.Dns), 160);
        AddLanColumn(_ipv6DhcpGrid, Localizer.T("域名"), nameof(Ipv6DhcpRow.Domains), 120);
        AddLanColumn(_ipv6DhcpGrid, Localizer.T("租期"), nameof(Ipv6DhcpRow.LeaseText), 70);
        AddLanColumn(_ipv6DhcpGrid, Localizer.T("阻断"), nameof(Ipv6DhcpRow.BlockText), 110);
        AddLanColumn(_ipv6DhcpGrid, Localizer.T("信任"), nameof(Ipv6DhcpRow.TrustedText), 70, fill: true);

        _ipv6NeighborGrid = CreateLanGrid(
            Localizer.T("还没有 IPv6 邻居。\r\n收到 NA / NS 后会显示邻居地址与 MAC。"));
        AddLanColumn(_ipv6NeighborGrid, Localizer.T("地址"), nameof(Ipv6NeighborRow.Address), 220);
        AddLanColumn(_ipv6NeighborGrid, Localizer.T("MAC"), nameof(Ipv6NeighborRow.Mac), 140);
        AddLanColumn(_ipv6NeighborGrid, Localizer.T("路由器"), nameof(Ipv6NeighborRow.RouterText), 60);
        AddLanColumn(_ipv6NeighborGrid, Localizer.T("首次发现"), nameof(Ipv6NeighborRow.FirstSeenText), 90, fill: true);

        _ipv6EventGrid = CreateLanGrid(
            Localizer.T("还没有 IPv6 邻接告警。\r\nRA / DHCPv6 / NDP 的检测结果会出现在这里。"));
        AddLanColumn(_ipv6EventGrid, Localizer.T("时间"), nameof(LanEventRow.TimeText), 110);
        AddLanColumn(_ipv6EventGrid, Localizer.T("类型"), nameof(LanEventRow.KindText), 190);
        AddLanColumn(_ipv6EventGrid, Localizer.T("级别"), nameof(LanEventRow.SeverityText), 55);
        AddLanColumn(_ipv6EventGrid, Localizer.T("网卡"), nameof(LanEventRow.Adapter), 140);
        AddLanColumn(_ipv6EventGrid, Localizer.T("详情"), nameof(LanEventRow.Detail), 320, fill: true);

        _ipv6EndpointTabs = new TabControl
        {
            Dock = DockStyle.Fill,
            Name = "_ipv6EndpointTabs",
        };

        var routerPage = new TabPage(Localizer.T("路由器"))
        {
            Name = "_ipv6RouterTab",
            Padding = new Padding(3),
            UseVisualStyleBackColor = true,
        };
        var dhcpPage = new TabPage("DHCPv6")
        {
            Name = "_ipv6DhcpTab",
            Padding = new Padding(3),
            UseVisualStyleBackColor = true,
        };
        var neighborPage = new TabPage(Localizer.T("邻居"))
        {
            Name = "_ipv6NeighborTab",
            Padding = new Padding(3),
            UseVisualStyleBackColor = true,
        };

        routerPage.Controls.Add(_ipv6RouterGrid);
        dhcpPage.Controls.Add(_ipv6DhcpGrid);
        neighborPage.Controls.Add(_ipv6NeighborGrid);
        _ipv6EndpointTabs.Controls.Add(routerPage);
        _ipv6EndpointTabs.Controls.Add(dhcpPage);
        _ipv6EndpointTabs.Controls.Add(neighborPage);

        var split = new SplitContainer
        {
            Dock = DockStyle.Fill,
            Orientation = Orientation.Horizontal,
            SplitterWidth = 6,
        };
        split.Panel1.Controls.Add(_ipv6EndpointTabs);
        split.Panel2.Controls.Add(_ipv6EventGrid);

        split.Resize += (_, _) =>
        {
            if (split.Height > 220)
            {
                split.SplitterDistance = Math.Max(120, (int)(split.Height * 0.46));
            }
        };

        _ipv6RouterGrid.SelectionChanged += (_, _) => UpdateIpv6Buttons();
        _ipv6DhcpGrid.SelectionChanged += (_, _) => UpdateIpv6Buttons();
        _ipv6NeighborGrid.SelectionChanged += (_, _) => UpdateIpv6Buttons();
        _ipv6EndpointTabs.SelectedIndexChanged += (_, _) => UpdateIpv6Buttons();

        _lanIpv6Page.Controls.Add(split);
        _lanIpv6Page.Controls.Add(top);

        _ipv6Timer = new System.Windows.Forms.Timer
        {
            Interval = Ipv6RefreshIntervalMs,
            Enabled = _ipv6AutoRefreshCheckBox.Checked,
        };
        _ipv6Timer.Tick += (_, _) =>
        {
            if (_ipv6AutoRefreshCheckBox.Checked && IsLanIpv6Tab)
            {
                _ = RefreshIpv6Async();
            }
        };

        _ipv6NotifyTimer = new System.Windows.Forms.Timer { Interval = Ipv6NotifyIntervalMs };
        _ipv6NotifyTimer.Tick += (_, _) =>
        {
            if (!IsLanIpv6Tab)
            {
                _ = CheckIpv6NotificationsAsync();
            }
        };
        _ipv6NotifyTimer.Start();

        _trayIcon.BalloonTipClicked += (_, _) =>
        {
            if (!_ipv6BalloonPending)
            {
                return;
            }

            _ipv6BalloonPending = false;
            ShowMainWindow();
            SelectProtectionTab(_tabLan);
            _lanTabs.SelectedTab = _lanIpv6Page;
            _ = RefreshIpv6Async();
        };

        UpdateIpv6Buttons();
        UpdateIpv6Summary();
    }

    private async Task RefreshIpv6Async()
    {
        if (SuppressBackgroundServices || _ipv6Loading || IsDisposed || Disposing)
        {
            return;
        }

        _ipv6Loading = true;
        UpdateIpv6Buttons();

        try
        {
            var result = await Task.Run(QueryIpv6Snapshot);

            if (IsDisposed || Disposing)
            {
                return;
            }

            if (result is not null)
            {
                _ipv6ServiceAvailable = true;
                _ipv6Status = result.Value.Status;
                _ipv6Routers = result.Value.Routers;
                _ipv6DhcpServers = result.Value.Servers;
                _ipv6Neighbors = result.Value.Neighbors;
                _ipv6Events = result.Value.Events;
                RebuildIpv6View();
            }
            else
            {
                _ipv6ServiceAvailable = false;
                UpdateIpv6Summary();
            }
        }
        catch (Exception ex)
        {
            _ipv6ServiceAvailable = false;
            LocalLog.Error(LocalLog.Pick("读取 IPv6 邻接安全失败", "Failed to read IPv6 security."), ex);
            UpdateIpv6Summary();
        }
        finally
        {
            _ipv6Loading = false;

            if (!IsDisposed && !Disposing)
            {
                UpdateIpv6Buttons();
            }
        }
    }

    private static Ipv6SnapshotResult? QueryIpv6Snapshot()
    {
        try
        {
            var response = ServiceClient.TryRequest(
                new ServiceRequest { Command = ServiceProtocol.Commands.QueryIpv6Security },
                TimeSpan.FromSeconds(2),
                out _);

            return response is { Ok: true }
                ? new Ipv6SnapshotResult(
                    response.Ipv6SecurityStatus,
                    response.Ipv6Routers ?? new List<Ipv6RouterDto>(),
                    response.Ipv6DhcpServers ?? new List<Ipv6DhcpServerDto>(),
                    response.Ipv6Neighbors ?? new List<Ipv6NeighborDto>(),
                    response.Ipv6SecurityEvents ?? new List<LanEventDto>())
                : null;
        }
        catch (Exception)
        {
            return null;
        }
    }

    private readonly record struct Ipv6SnapshotResult(
        Ipv6SecurityStatusDto? Status,
        List<Ipv6RouterDto> Routers,
        List<Ipv6DhcpServerDto> Servers,
        List<Ipv6NeighborDto> Neighbors,
        List<LanEventDto> Events);

    private void RebuildIpv6View()
    {
        var routerRows = _ipv6Routers.Select(item => new Ipv6RouterRow(item)).ToList();
        var routerSignature = string.Join(
            "|",
            routerRows.Select(row => $"{row.LinkLocal}/{row.Mac}/{row.Prefixes}/{row.Trusted}"));

        if (!string.Equals(routerSignature, _ipv6RouterSignature, StringComparison.Ordinal))
        {
            _ipv6RouterSignature = routerSignature;
            _ipv6RouterGrid.DataSource = routerRows;
        }

        var dhcpRows = _ipv6DhcpServers.Select(item => new Ipv6DhcpRow(item)).ToList();
        var dhcpSignature = string.Join(
            "|",
            dhcpRows.Select(row =>
                $"{row.ServerId}/{row.Address}/{row.Trusted}/{row.Blocked}/{row.BlockExpiresUtc?.Ticks}"));

        if (!string.Equals(dhcpSignature, _ipv6DhcpSignature, StringComparison.Ordinal))
        {
            _ipv6DhcpSignature = dhcpSignature;
            _ipv6DhcpGrid.DataSource = dhcpRows;
        }

        var neighborRows = _ipv6Neighbors.Select(item => new Ipv6NeighborRow(item)).ToList();
        var neighborSignature = string.Join(
            "|",
            neighborRows.Select(row => $"{row.Address}/{row.Mac}"));

        if (!string.Equals(neighborSignature, _ipv6NeighborSignature, StringComparison.Ordinal))
        {
            _ipv6NeighborSignature = neighborSignature;
            _ipv6NeighborGrid.DataSource = neighborRows;
        }

        var eventRows = _ipv6Events.Select(item => new LanEventRow(item)).ToList();
        var eventSignature = string.Join(
            "|",
            eventRows.Take(100).Select(row => $"{row.Id}/{row.Kind}/{row.TimeUtc.Ticks}"));

        if (!string.Equals(eventSignature, _ipv6EventSignature, StringComparison.Ordinal))
        {
            _ipv6EventSignature = eventSignature;
            _ipv6EventGrid.DataSource = eventRows;
        }

        UpdateIpv6Summary();
        UpdateIpv6Buttons();
    }

    private void UpdateIpv6Summary()
    {
        var status = _ipv6Status;
        var parts = new List<string> { Localizer.T("IPv6 邻接安全") };

        if (!_ipv6ServiceAvailable)
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
            parts.Add(Localizer.F("路由器 {0}", status.RouterCount));
            parts.Add(Localizer.F("DHCPv6 {0}", status.DhcpServerCount));
            parts.Add(Localizer.F("邻居 {0}", status.NeighborCount));

            if (status.BlockedCount > 0)
            {
                parts.Add(Localizer.F("已阻断 {0}", status.BlockedCount));
            }

            if (!string.IsNullOrWhiteSpace(status.LastError))
            {
                parts.Add(status.LastError!);
            }
        }

        _ipv6StatusLabel.Text = string.Join(" · ", parts);
    }

    private void UpdateIpv6Buttons()
    {
        var available = _ipv6ServiceAvailable && !_ipv6Loading;
        var router = _ipv6RouterGrid.CurrentRow?.DataBoundItem as Ipv6RouterRow;
        var dhcp = _ipv6DhcpGrid.CurrentRow?.DataBoundItem as Ipv6DhcpRow;

        _ipv6RefreshButton.Enabled = !_ipv6Loading;
        _ipv6ClearButton.Enabled = available && _ipv6Events.Count > 0;
        _ipv6ResetBaselineButton.Enabled = available;
        _ipv6TrustRouterButton.Enabled = available && router is not null;
        _ipv6TrustRouterButton.Text = router?.Trusted == true
            ? Localizer.T("取消信任此路由器")
            : Localizer.T("信任此路由器");
        _ipv6TrustDhcpButton.Enabled = available && dhcp is not null;
        _ipv6TrustDhcpButton.Text = dhcp?.Trusted == true
            ? Localizer.T("取消信任此 DHCPv6")
            : Localizer.T("信任此 DHCPv6");
        _ipv6BlockDhcpButton.Enabled = available && dhcp is not null && dhcp.Trusted != true;
        _ipv6BlockDhcpButton.Text = dhcp?.Blocked == true
            ? Localizer.T("解除阻断")
            : Localizer.T("临时阻断此 DHCPv6（10 分钟）");
        _ipv6AutoRefreshCheckBox.Enabled = available;
    }

    private void OnIpv6AutoRefreshChanged(object? sender, EventArgs e)
    {
        if (_ipv6Timer is not null)
        {
            _ipv6Timer.Enabled = _ipv6AutoRefreshCheckBox.Checked;
        }

        if (_ipv6AutoRefreshCheckBox.Checked)
        {
            _ = RefreshIpv6Async();
        }
    }

    private void OnIpv6ClearClick(object? sender, EventArgs e)
    {
        var confirmed = ConfirmForm.Show(
            owner: DialogOwner,
            title: Localizer.T("清空 IPv6 邻接告警"),
            question: Localizer.T("确定要清空全部 IPv6 邻接告警吗？"),
            details: new[]
            {
                new KeyValuePair<string, string>(
                    Localizer.T("将要做的"),
                    Localizer.T("删除已落盘的 ipv6_* 事件")),
                new KeyValuePair<string, string>(
                    Localizer.T("不会影响"),
                    Localizer.T("IPv4 局域网、DNS 安全事件和其它防护功能")),
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
                ServiceProtocol.Commands.ClearIpv6Security,
                new ServiceRequest(),
                Localizer.T("清空 IPv6 邻接告警"));

            if (response is null)
            {
                return;
            }

            _ipv6RouterSignature = null;
            _ipv6DhcpSignature = null;
            _ipv6NeighborSignature = null;
            _ipv6EventSignature = null;
            _ipv6Events = new List<LanEventDto>();
            _ipv6Status = response.Ipv6SecurityStatus ?? _ipv6Status;
            RebuildIpv6View();
            ShowTrayBalloon(
                Localizer.T("IPv6 邻接告警已清空"),
                Localizer.T("只删除了 ipv6_* 事件。"));
        }
        catch (Exception ex)
        {
            ShowError(Localizer.T("清空 IPv6 邻接告警失败"), ex, "Failed to clear IPv6 events");
        }
    }

    private void OnIpv6ResetBaselineClick(object? sender, EventArgs e)
    {
        var confirmed = ConfirmForm.Show(
            owner: DialogOwner,
            title: Localizer.T("重置 IPv6 基线"),
            question: Localizer.T("确定要清空 IPv6 路由器/DHCPv6/邻居基线并重新学习吗？"),
            details: new[]
            {
                new KeyValuePair<string, string>(
                    Localizer.T("将要做的"),
                    Localizer.T("清空 IPv6 基线，重新静默学习 5 分钟")),
                new KeyValuePair<string, string>(
                    Localizer.T("不会影响"),
                    Localizer.T("IPv4 局域网、DNS 安全和已有事件")),
            },
            warnings: new[]
            {
                Localizer.T("重新学习期间不会产生新的 IPv6 告警。"),
                Localizer.T("信任列表保留。"),
            },
            confirmText: Localizer.T("重置基线"));

        if (!confirmed)
        {
            return;
        }

        try
        {
            var response = CallService(
                ServiceProtocol.Commands.ResetIpv6Baseline,
                new ServiceRequest(),
                Localizer.T("重置 IPv6 基线"));

            if (response is null)
            {
                return;
            }

            _ipv6RouterSignature = null;
            _ipv6DhcpSignature = null;
            _ipv6NeighborSignature = null;
            _ipv6EventSignature = null;
            _ipv6Routers = new List<Ipv6RouterDto>();
            _ipv6DhcpServers = new List<Ipv6DhcpServerDto>();
            _ipv6Neighbors = new List<Ipv6NeighborDto>();
            _ipv6Status = response.Ipv6SecurityStatus ?? _ipv6Status;
            RebuildIpv6View();
            ShowTrayBalloon(Localizer.T("IPv6 基线已重置"), Localizer.T("正在重新静默学习。"));
        }
        catch (Exception ex)
        {
            ShowError(Localizer.T("重置 IPv6 基线失败"), ex, "Failed to reset IPv6 baseline");
        }
    }

    private void OnIpv6TrustRouterClick(object? sender, EventArgs e)
    {
        if (_ipv6RouterGrid.CurrentRow?.DataBoundItem is not Ipv6RouterRow row)
        {
            return;
        }

        TrustIpv6("router", row.LinkLocal, row.Mac, !row.Trusted);
    }

    private void OnIpv6TrustDhcpClick(object? sender, EventArgs e)
    {
        if (_ipv6DhcpGrid.CurrentRow?.DataBoundItem is not Ipv6DhcpRow row)
        {
            return;
        }

        TrustIpv6("dhcpv6", row.ServerId, row.Mac, !row.Trusted);
    }

    /// <summary>
    /// 4.4：临时阻断 / 解除该 DHCPv6 服务器。
    /// 已通过 WFP 传输层 POC（2026-10-31）；RA 未通过前不提供按钮。
    /// </summary>
    private void OnIpv6BlockDhcpClick(object? sender, EventArgs e)
    {
        if (_ipv6DhcpGrid.CurrentRow?.DataBoundItem is not Ipv6DhcpRow row)
        {
            return;
        }

        var enabling = !row.Blocked;

        if (enabling)
        {
            var confirmed = ConfirmForm.Show(
                owner: DialogOwner,
                title: Localizer.T("临时阻断此 DHCPv6"),
                question: Localizer.F("确定要临时阻断 DHCPv6 服务器「{0}」吗？", row.Address),
                details: new[]
                {
                    new KeyValuePair<string, string>(
                        Localizer.T("将要做的"),
                        Localizer.T("用 WFP 传输层阻断该服务器发往本机的 DHCPv6 应答，最长 10 分钟")),
                    new KeyValuePair<string, string>(
                        Localizer.T("不会影响"),
                        Localizer.T("其它 IPv6 流量、合法路由器 RA 和其它防护功能")),
                },
                warnings: new[]
                {
                    Localizer.T("10 分钟后自动解除；服务重启也会解除。"),
                    Localizer.T("阻断期间该服务器下发的地址和 DNS 不会生效。"),
                },
                confirmText: Localizer.T("阻断 10 分钟"));

            if (!confirmed)
            {
                return;
            }
        }

        try
        {
            var response = CallService(
                ServiceProtocol.Commands.BlockIpv6,
                new ServiceRequest
                {
                    Ipv6BlockKind = "dhcpv6",
                    Ipv6BlockAddress = row.Address,
                    Ipv6BlockMinutes = 10,
                    Ipv6BlockEnabled = enabling,
                },
                Localizer.T(enabling ? "临时阻断此 DHCPv6" : "解除 DHCPv6 阻断"));

            if (response is null)
            {
                return;
            }

            _ipv6RouterSignature = null;
            _ipv6DhcpSignature = null;
            _ipv6NeighborSignature = null;
            _ipv6EventSignature = null;
            _ipv6Routers = response.Ipv6Routers ?? _ipv6Routers;
            _ipv6DhcpServers = response.Ipv6DhcpServers ?? _ipv6DhcpServers;
            _ipv6Neighbors = response.Ipv6Neighbors ?? _ipv6Neighbors;
            _ipv6Events = response.Ipv6SecurityEvents ?? _ipv6Events;
            _ipv6Status = response.Ipv6SecurityStatus ?? _ipv6Status;
            RebuildIpv6View();
            ShowTrayBalloon(
                Localizer.T(enabling ? "已临时阻断 DHCPv6 服务器" : "已解除 DHCPv6 阻断"),
                enabling
                    ? Localizer.F("{0}\n10 分钟后自动解除。", row.Address)
                    : row.Address);
        }
        catch (Exception ex)
        {
            ShowError(Localizer.T("修改 DHCPv6 阻断失败"), ex, "Failed to change IPv6 DHCPv6 block");
        }
    }

    private void TrustIpv6(string kind, string value, string? mac, bool enabled)
    {
        try
        {
            var response = CallService(
                ServiceProtocol.Commands.TrustIpv6,
                new ServiceRequest
                {
                    Ipv6TrustKind = kind,
                    Ipv6TrustValue = value,
                    Ipv6TrustMac = mac,
                    Ipv6TrustEnabled = enabled,
                },
                Localizer.T(enabled ? "信任 IPv6 目标" : "取消信任 IPv6 目标"));

            if (response is null)
            {
                return;
            }

            _ipv6RouterSignature = null;
            _ipv6DhcpSignature = null;
            _ipv6NeighborSignature = null;
            _ipv6EventSignature = null;
            _ipv6Routers = response.Ipv6Routers ?? _ipv6Routers;
            _ipv6DhcpServers = response.Ipv6DhcpServers ?? _ipv6DhcpServers;
            _ipv6Neighbors = response.Ipv6Neighbors ?? _ipv6Neighbors;
            _ipv6Events = response.Ipv6SecurityEvents ?? _ipv6Events;
            _ipv6Status = response.Ipv6SecurityStatus ?? _ipv6Status;
            RebuildIpv6View();
            ShowTrayBalloon(
                Localizer.T(enabled ? "已信任 IPv6 目标" : "已取消信任"),
                value);
        }
        catch (Exception ex)
        {
            ShowError(Localizer.T("修改 IPv6 信任失败"), ex, "Failed to change IPv6 trust");
        }
    }

    private async Task CheckIpv6NotificationsAsync()
    {
        if (SuppressBackgroundServices || IsDisposed || Disposing)
        {
            return;
        }

        List<LanEventDto> events;

        try
        {
            var snapshot = await Task.Run(QueryIpv6Snapshot);

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
            || string.Equals(high.Id, _ipv6LastNotifiedId, StringComparison.Ordinal)
            || DateTime.UtcNow - _ipv6LastNotifyUtc < Ipv6NotifyCooldown)
        {
            return;
        }

        _ipv6LastNotifiedId = high.Id;
        _ipv6LastNotifyUtc = DateTime.UtcNow;
        _ipv6BalloonPending = true;

        ShowTrayBalloon(
            Localizer.T("IPv6 邻接安全发现高危事件"),
            Localizer.F(
                "{0}\n点击打开「局域网 → IPv6 邻接」查看详情；只告警，不阻断。",
                high.Detail),
            ToolTipIcon.Warning);
    }

    private sealed class Ipv6RouterRow
    {
        public Ipv6RouterRow(Ipv6RouterDto item)
        {
            LinkLocal = item.LinkLocal;
            Mac = item.Mac;
            Prefixes = item.Prefixes;
            Flags = item.Flags;
            Lifetime = item.Lifetime;
            Trusted = item.Trusted;
            Baseline = item.Baseline;
        }

        public string LinkLocal { get; }

        public string Mac { get; }

        public string Prefixes { get; }

        public string Flags { get; }

        public int Lifetime { get; }

        public bool Trusted { get; }

        public bool Baseline { get; }

        public string LifetimeText => Lifetime <= 0 ? "—" : Localizer.F("{0} 秒", Lifetime);

        public string TrustedText => Localizer.T(Trusted ? "已信任" : Baseline ? "基线" : "未信任");
    }

    private sealed class Ipv6DhcpRow
    {
        public Ipv6DhcpRow(Ipv6DhcpServerDto item)
        {
            ServerId = item.ServerId;
            Address = item.Address;
            Mac = item.Mac ?? "—";
            Dns = item.Dns;
            Domains = item.Domains;
            MinLeaseSeconds = item.MinLeaseSeconds;
            Trusted = item.Trusted;
            Baseline = item.Baseline;
            Blocked = item.Blocked;
            BlockExpiresUtc = item.BlockExpiresUtc;
        }

        public string ServerId { get; }

        public string Address { get; }

        public string Mac { get; }

        public string Dns { get; }

        public string Domains { get; }

        public int MinLeaseSeconds { get; }

        public bool Trusted { get; }

        public bool Baseline { get; }

        public bool Blocked { get; }

        public DateTime? BlockExpiresUtc { get; }

        public string LeaseText => MinLeaseSeconds <= 0
            ? "—"
            : Localizer.F("{0} 秒", MinLeaseSeconds);

        public string BlockText => !Blocked || BlockExpiresUtc is null
            ? "—"
            : Localizer.F(
                "剩余 {0} 分钟",
                Math.Max(1, (int)Math.Ceiling((BlockExpiresUtc.Value - DateTime.UtcNow).TotalMinutes)));

        public string TrustedText => Localizer.T(Trusted ? "已信任" : Baseline ? "基线" : "未信任");
    }

    private sealed class Ipv6NeighborRow
    {
        public Ipv6NeighborRow(Ipv6NeighborDto item)
        {
            Address = item.Address;
            Mac = string.IsNullOrWhiteSpace(item.Mac) ? "—" : item.Mac;
            IsRouter = item.IsRouter;
            FirstSeenUtc = item.FirstSeenUtc;
        }

        public string Address { get; }

        public string Mac { get; }

        public bool IsRouter { get; }

        public DateTime FirstSeenUtc { get; }

        public string RouterText => Localizer.T(IsRouter ? "是" : "否");

        public string FirstSeenText => FirstSeenUtc.ToLocalTime().ToString("MM-dd HH:mm");
    }
}
