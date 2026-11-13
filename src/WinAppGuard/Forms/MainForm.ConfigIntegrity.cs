using WinAppGuard.Contracts;
using WinAppGuard.Core;
using WinAppGuard.Localization;

namespace WinAppGuard.Forms;

/// <summary>
/// 4.5：「防护 → 本机配置」页。
///
/// 展示服务端采集的 hosts / 代理 / PAC / WinHTTP / DNS 快照与基线差异。
/// 只读：不修改任何系统设置；「清空」只删 config_* 事件，
/// 「重新采基线」把当前值当作新的基线。
/// </summary>
public sealed partial class MainForm
{
    private const int ConfigRefreshIntervalMs = 5000;

    private Label _configStatusLabel = null!;
    private Label _configHintLabel = null!;
    private Button _configRefreshButton = null!;
    private Button _configRebaselineButton = null!;
    private Button _configClearButton = null!;
    private CheckBox _configAutoRefreshCheckBox = null!;
    private DataGridViewBuffered _configItemGrid = null!;
    private DataGridViewBuffered _configEventGrid = null!;

    private List<ConfigItemDto> _configItems = new();
    private List<LanEventDto> _configEvents = new();
    private ConfigIntegrityStatusDto? _configStatus;
    private bool _configLoading;
    private bool _configServiceAvailable = true;
    private BaselineTable<ConfigItemRow>? _configItemTable;
    private EventTable<LanEventRow>? _configEventTable;

    private void InitializeConfigIntegrityPage()
    {
        var top = new Panel
        {
            Dock = DockStyle.Top,
            Height = 96,
            Padding = new Padding(0, 4, 0, 0),
        };

        _configRefreshButton = new Button
        {
            Text = Localizer.T("刷新"),
            AutoSize = true,
            MinimumSize = new Size(68, 27),
        };
        _configRefreshButton.Click += (_, _) => _ = RefreshConfigAsync();

        _configRebaselineButton = new Button
        {
            Text = Localizer.T("重新采基线…"),
            AutoSize = true,
            MinimumSize = new Size(104, 27),
        };
        _configRebaselineButton.Click += OnConfigRebaselineClick;

        _configClearButton = new Button
        {
            Text = Localizer.T("清空…"),
            AutoSize = true,
            MinimumSize = new Size(76, 27),
        };
        _configClearButton.Click += OnConfigClearClick;

        _configAutoRefreshCheckBox = new CheckBox
        {
            Location = new Point(600, 8),
            AutoSize = true,
            Text = Localizer.T("每 5 秒自动刷新"),
            Checked = true,
        };
        _configAutoRefreshCheckBox.CheckedChanged += OnConfigAutoRefreshChanged;

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
            _configRefreshButton, _configRebaselineButton, _configClearButton,
        });

        _configStatusLabel = new Label
        {
            Location = new Point(0, 40),
            Width = 1000,
            Height = 22,
            ForeColor = SystemColors.GrayText,
            AutoEllipsis = true,
        };

        _configHintLabel = new Label
        {
            Location = new Point(0, 64),
            Width = 1000,
            Height = 22,
            ForeColor = SystemColors.GrayText,
            AutoEllipsis = true,
            Text = Localizer.T("服务端每 30 秒采集一次；只告警，不会自动修改 hosts 或代理设置。"),
        };

        top.Resize += (_, _) =>
        {
            var width = Math.Max(200, top.ClientSize.Width - 8);
            _configStatusLabel.Width = width;
            _configHintLabel.Width = width;
            _configAutoRefreshCheckBox.Left = Math.Max(600, width - 170);
        };

        top.Controls.AddRange(new Control[]
        {
            actions, _configAutoRefreshCheckBox, _configStatusLabel, _configHintLabel,
        });

        _configItemGrid = CreateLanGrid(
            Localizer.T("还没有配置快照。\r\n服务端首次采集后会显示 hosts、代理、PAC、WinHTTP 与 DNS 设置。"));
        AddLanColumn(_configItemGrid, Localizer.T("项目"), nameof(ConfigItemRow.KindText), 110);
        AddLanColumn(_configItemGrid, Localizer.T("范围"), nameof(ConfigItemRow.ScopeText), 190);
        AddLanColumn(_configItemGrid, Localizer.T("当前值"), nameof(ConfigItemRow.CurrentText), 300, fill: true);
        AddLanColumn(_configItemGrid, Localizer.T("基线值"), nameof(ConfigItemRow.BaselineText), 240);
        AddLanColumn(_configItemGrid, Localizer.T("状态"), nameof(ConfigItemRow.StateText), 70);
        AddLanColumn(_configItemGrid, Localizer.T("级别"), nameof(ConfigItemRow.SeverityText), 55);

        _configEventGrid = CreateLanGrid(
            Localizer.T("还没有配置变更事件。\r\nhosts / 代理 / PAC / WinHTTP / DNS 设置变化时会出现在这里。"));
        AddLanColumn(_configEventGrid, Localizer.T("时间"), nameof(LanEventRow.TimeText), 110);
        AddLanColumn(_configEventGrid, Localizer.T("类型"), nameof(LanEventRow.KindText), 170);
        AddLanColumn(_configEventGrid, Localizer.T("级别"), nameof(LanEventRow.SeverityText), 55);
        AddLanColumn(_configEventGrid, Localizer.T("详情"), nameof(LanEventRow.Detail), 320, fill: true);

        var split = new SplitContainer
        {
            Dock = DockStyle.Fill,
            Orientation = Orientation.Horizontal,
            SplitterWidth = 6,
        };
        split.Panel1.Controls.Add(_configItemGrid);
        split.Panel2.Controls.Add(_configEventGrid);

        split.Resize += (_, _) =>
        {
            if (split.Height > 220)
            {
                split.SplitterDistance = Math.Max(120, (int)(split.Height * 0.5));
            }
        };

        _tabConfig.Controls.Add(split);
        _tabConfig.Controls.Add(top);

        UpdateConfigButtons();
        UpdateConfigSummary();
    }

    private async Task RefreshConfigAsync()
    {
        if (SuppressBackgroundServices || _configLoading || IsDisposed || Disposing)
        {
            return;
        }

        _configLoading = true;
        UpdateConfigButtons();

        try
        {
            var result = await Task.Run(QueryConfigSnapshot);

            if (IsDisposed || Disposing)
            {
                return;
            }

            if (result is not null)
            {
                _configServiceAvailable = true;
                _configStatus = result.Value.Status;
                _configItems = result.Value.Items;
                _configEvents = result.Value.Events;
                RebuildConfigView();
            }
            else
            {
                _configServiceAvailable = false;
                UpdateConfigSummary();
            }
        }
        catch (Exception ex)
        {
            _configServiceAvailable = false;
            LocalLog.Error(
                LocalLog.Pick("读取本机配置完整性失败", "Failed to read config integrity."),
                ex);
            UpdateConfigSummary();
        }
        finally
        {
            _configLoading = false;

            if (!IsDisposed && !Disposing)
            {
                UpdateConfigButtons();
            }
        }
    }

    private static ConfigSnapshotResult? QueryConfigSnapshot()
    {
        try
        {
            var response = Gateway.TryRequest(
                new ServiceRequest { Command = ServiceProtocol.Commands.QueryConfigIntegrity },
                TimeSpan.FromSeconds(3),
                out _);

            return response is { Ok: true }
                ? new ConfigSnapshotResult(
                    response.ConfigIntegrityStatus,
                    response.ConfigItems ?? new List<ConfigItemDto>(),
                    response.ConfigIntegrityEvents ?? new List<LanEventDto>())
                : null;
        }
        catch (Exception)
        {
            return null;
        }
    }

    private readonly record struct ConfigSnapshotResult(
        ConfigIntegrityStatusDto? Status,
        List<ConfigItemDto> Items,
        List<LanEventDto> Events);

    private void RebuildConfigView()
    {
        var itemRows = _configItems.Select(item => new ConfigItemRow(item)).ToList();

        _configItemTable ??= new BaselineTable<ConfigItemRow>(
            _configItemGrid,
            row => $"{row.Kind}/{row.Scope}/{row.Current}/{row.Baseline}/{row.Changed}",
            row => $"{row.Kind}/{row.Scope}");

        _configItemTable.Bind(itemRows);

        var eventRows = _configEvents.Select(item => new LanEventRow(item)).ToList();

        _configEventTable ??= new EventTable<LanEventRow>(
            _configEventGrid,
            row => $"{row.Id}/{row.Kind}/{row.TimeUtc.Ticks}",
            row => row.Id);

        _configEventTable.Bind(eventRows);

        UpdateConfigSummary();
        UpdateConfigButtons();
    }

    private void UpdateConfigSummary()
    {
        var status = _configStatus;
        var parts = new List<string> { Localizer.T("本机配置") };

        if (!_configServiceAvailable)
        {
            parts.Add(Localizer.T("服务不可用，显示上次数据"));
        }

        if (status is null)
        {
            parts.Add(Localizer.T("状态未知"));
        }
        else
        {
            parts.Add(status.BaselineReady
                ? Localizer.F("基线 {0}", status.BaselineUtc?.ToLocalTime().ToString("MM-dd HH:mm") ?? "?")
                : Localizer.T("基线未建立"));
            parts.Add(Localizer.F("监控项 {0}", status.ItemCount));
            parts.Add(Localizer.F("已变更 {0}", status.ChangedCount));
            parts.Add(Localizer.F("事件 {0}", status.EventCount));

            if (!string.IsNullOrWhiteSpace(status.LastError))
            {
                parts.Add(status.LastError!);
            }
        }

        _configStatusLabel.Text = string.Join(" · ", parts);
    }

    private void UpdateConfigButtons()
    {
        var available = _configServiceAvailable && !_configLoading;

        _configRefreshButton.Enabled = !_configLoading;
        _configRebaselineButton.Enabled = available;
        _configClearButton.Enabled = available && _configEvents.Count > 0;
        _configAutoRefreshCheckBox.Enabled = available;
    }

    private void OnConfigAutoRefreshChanged(object? sender, EventArgs e)
    {
        // 5.9：调度器读取复选框状态；这里只负责勾选后立刻刷新一次。
        if (_configAutoRefreshCheckBox.Checked)
        {
            _ = RefreshConfigAsync();
        }
    }

    private async void OnConfigRebaselineClick(object? sender, EventArgs e)
    {
        var confirmed = ConfirmForm.Show(
            owner: DialogOwner,
            title: Localizer.T("重新采集本机配置基线"),
            question: Localizer.T("确定把当前 hosts / 代理 / DNS 设置作为新的基线吗？"),
            details: new[]
            {
                new KeyValuePair<string, string>(
                    Localizer.T("将要做的"),
                    Localizer.T("立即采集一次当前配置，并覆盖已有基线")),
                new KeyValuePair<string, string>(
                    Localizer.T("不会影响"),
                    Localizer.T("任何系统设置；也不会删除已有事件")),
            },
            warnings: new[]
            {
                Localizer.T("如果当前已被篡改，新基线会把篡改后的值当成正常。"),
            },
            confirmText: Localizer.T("重新采基线"));

        if (!confirmed)
        {
            return;
        }

        try
        {
            var response = await CallServiceAsync(
                ServiceProtocol.Commands.RebaselineConfigIntegrity,
                new ServiceRequest(),
                Localizer.T("重新采集本机配置基线"));

            if (response is null)
            {
                return;
            }

            ApplyConfigResponse(response);
            ShowTrayBalloon(
                Localizer.T("本机配置基线已更新"),
                Localizer.T("之后的变更会重新开始对比。"));
        }
        catch (Exception ex)
        {
            ShowError(Localizer.T("重新采集本机配置基线失败"), ex, "Failed to rebaseline config");
        }
    }

    private async void OnConfigClearClick(object? sender, EventArgs e)
    {
        var confirmed = ConfirmForm.Show(
            owner: DialogOwner,
            title: Localizer.T("清空本机配置事件"),
            question: Localizer.T("确定要清空全部本机配置事件吗？"),
            details: new[]
            {
                new KeyValuePair<string, string>(
                    Localizer.T("将要做的"),
                    Localizer.T("删除已落盘的 config_* 事件")),
                new KeyValuePair<string, string>(
                    Localizer.T("不会影响"),
                    Localizer.T("基线、IPv4/IPv6/DNS 事件和其它防护功能")),
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
            var response = await CallServiceAsync(
                ServiceProtocol.Commands.ClearConfigIntegrity,
                new ServiceRequest(),
                Localizer.T("清空本机配置事件"));

            if (response is null)
            {
                return;
            }

            ApplyConfigResponse(response);
            ShowTrayBalloon(
                Localizer.T("本机配置事件已清空"),
                Localizer.T("只删除了 config_* 事件。"));
        }
        catch (Exception ex)
        {
            ShowError(Localizer.T("清空本机配置事件失败"), ex, "Failed to clear config events");
        }
    }

    private void ApplyConfigResponse(ServiceResponse response)
    {
        _configItemTable?.Invalidate();
        _configEventTable?.Invalidate();
        _configStatus = response.ConfigIntegrityStatus ?? _configStatus;
        _configItems = response.ConfigItems ?? _configItems;
        _configEvents = response.ConfigIntegrityEvents ?? _configEvents;
        RebuildConfigView();
    }

    private sealed class ConfigItemRow
    {
        public ConfigItemRow(ConfigItemDto item)
        {
            Kind = item.Kind;
            Scope = item.Scope;
            Current = item.Current;
            Baseline = item.Baseline;
            BaselineExists = item.BaselineExists;
            Changed = item.Changed;
            Severity = item.Severity;
        }

        public string Kind { get; }

        public string Scope { get; }

        public string Current { get; }

        public string Baseline { get; }

        public bool BaselineExists { get; }

        public bool Changed { get; }

        public string Severity { get; }

        public string KindText => Localizer.T(Kind switch
        {
            "hosts" => "hosts 文件",
            "proxy" => "WinINET 代理",
            "pac" => "PAC 自动配置",
            "winhttp" => "WinHTTP 代理",
            "policy" => "组策略代理",
            "dns" => "DNS 服务器",
            _ => Kind,
        });

        public string ScopeText => string.IsNullOrWhiteSpace(Scope)
            ? Localizer.T("系统")
            : Scope;

        public string CurrentText => string.IsNullOrWhiteSpace(Current) ? "—" : Current;

        public string BaselineText => string.IsNullOrWhiteSpace(Baseline) ? "—" : Baseline;

        public string StateText => !BaselineExists
            ? Localizer.T("基线未建立")
            : Localizer.T(Changed ? "已变更" : "一致");

        public string SeverityText => Localizer.T(Severity == "medium" ? "中" : "高");
    }
}
