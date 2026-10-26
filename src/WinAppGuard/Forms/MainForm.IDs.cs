using WinAppGuard.Contracts;
using WinAppGuard.Core;
using WinAppGuard.Localization;

namespace WinAppGuard.Forms;

/// <summary>
/// 3.7：「IDS」页 —— 只展示可疑行为告警，**不阻断任何连接**。
///
/// 数据来自服务的 <c>query.ids.alerts</c>；规则在服务端运行，界面只做过滤和展示。
/// 告警级别、规则和状态都是稳定英文标记，这里翻译成界面语言。
/// </summary>
public sealed partial class MainForm
{
    private const int IdsRefreshIntervalMs = 3000;
    private const int IdsNotifyIntervalMs = 30_000;
    private static readonly TimeSpan IdsNotifyCooldown = TimeSpan.FromMinutes(5);

    private TextBox _idsSearchBox = null!;
    private ComboBox _idsSeverityFilter = null!;
    private ComboBox _idsRuleFilter = null!;
    private Button _idsRefreshButton = null!;
    private Button _idsAckButton = null!;
    private Button _idsSuppressButton = null!;
    private Button _idsSettingsButton = null!;
    private Button _idsClearButton = null!;
    private Label _idsSummaryLabel = null!;
    private DataGridViewBuffered _idsGrid = null!;
    private System.Windows.Forms.Timer? _idsTimer;
    private System.Windows.Forms.Timer? _idsNotifyTimer;

    private List<IdsAlertDto> _idsAlerts = new();
    private List<IdsSuppressionDto> _idsSuppressions = new();
    private IdsSettingsDto? _idsSettings;
    private IdsStatusDto? _idsStatus;

    private bool _idsLoading;
    private bool _idsServiceAvailable = true;
    private string? _idsSignature;
    private string? _idsLastNotifiedId;
    private DateTime _idsLastNotifyUtc = DateTime.MinValue;
    private bool _idsBalloonPending;

    private void InitializeIdsPage()
    {
        var top = new Panel
        {
            Dock = DockStyle.Top,
            Height = 112,
            Padding = new Padding(0, 4, 0, 0),
        };

        var notice = new Label
        {
            Location = new Point(0, 0),
            Width = 1000,
            Height = 20,
            ForeColor = Color.FromArgb(191, 87, 0),
            Text = "只检测、不阻断：这里列出可疑的连接行为，不会自动拦截任何程序。",
            AutoEllipsis = true,
        };

        _idsSearchBox = new TextBox
        {
            Location = new Point(0, 26),
            Width = 168,
            PlaceholderText = "搜索：程序 / 目标 / 证据",
        };
        _idsSearchBox.TextChanged += (_, _) => RebuildIdsView();

        _idsSeverityFilter = new ComboBox
        {
            Location = new Point(176, 25),
            Width = 88,
            DropDownStyle = ComboBoxStyle.DropDownList,
        };
        _idsSeverityFilter.Items.AddRange(new object[]
        {
            Localizer.T("全部级别"),
            Localizer.T("高"),
            Localizer.T("中"),
            Localizer.T("低"),
        });
        _idsSeverityFilter.SelectedIndex = 0;
        _idsSeverityFilter.SelectedIndexChanged += (_, _) => RebuildIdsView();

        _idsRuleFilter = new ComboBox
        {
            Location = new Point(272, 25),
            Width = 118,
            DropDownStyle = ComboBoxStyle.DropDownList,
        };
        _idsRuleFilter.Items.AddRange(new object[]
        {
            Localizer.T("全部规则"),
            Localizer.T("周期性外联"),
            Localizer.T("端口 / 主机扫描"),
            Localizer.T("内网横向"),
            Localizer.T("DNS 异常"),
        });
        _idsRuleFilter.SelectedIndex = 0;
        _idsRuleFilter.SelectedIndexChanged += (_, _) => RebuildIdsView();

        _idsRefreshButton = new Button
        {
            Location = new Point(398, 23),
            Width = 68,
            Text = "刷新",
        };
        _idsRefreshButton.Click += (_, _) => _ = RefreshIdsAsync();

        _idsAckButton = new Button
        {
            Location = new Point(474, 23),
            Width = 104,
            Text = "确认",
        };
        _idsAckButton.Click += OnIdsAckClick;

        _idsSuppressButton = new Button
        {
            Location = new Point(586, 23),
            Width = 88,
            Text = "抑制…",
        };
        _idsSuppressButton.Click += OnIdsSuppressClick;

        _idsSettingsButton = new Button
        {
            Location = new Point(682, 23),
            Width = 88,
            Text = "设置…",
        };
        _idsSettingsButton.Click += OnIdsSettingsClick;

        _idsClearButton = new Button
        {
            Location = new Point(778, 23),
            Width = 88,
            Text = "清空…",
        };
        _idsClearButton.Click += OnIdsClearClick;

        _idsSummaryLabel = new Label
        {
            Location = new Point(0, 56),
            Width = 1000,
            Height = 22,
            ForeColor = SystemColors.GrayText,
            AutoEllipsis = true,
        };

        var hint = new Label
        {
            Location = new Point(0, 80),
            Width = 1000,
            Height = 26,
            ForeColor = SystemColors.GrayText,
            Text = "可疑行为 = 周期性外联、端口/主机扫描、内网横向、DNS 异常；" +
                   "加密流量（DoH/HTTPS）只能看元数据。",
            AutoEllipsis = true,
        };

        top.Resize += (_, _) =>
        {
            var width = Math.Max(200, top.ClientSize.Width - 8);
            notice.Width = width;
            _idsSummaryLabel.Width = width;
            hint.Width = width;
        };

        top.Controls.AddRange(new Control[]
        {
            notice,
            _idsSearchBox,
            _idsSeverityFilter,
            _idsRuleFilter,
            _idsRefreshButton,
            _idsAckButton,
            _idsSuppressButton,
            _idsSettingsButton,
            _idsClearButton,
            _idsSummaryLabel,
            hint,
        });

        _idsGrid = new DataGridViewBuffered
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

        AddIdsColumn("时间", nameof(IdsRow.TimeText), 118);
        AddIdsColumn("级别", nameof(IdsRow.SeverityText), 56);
        AddIdsColumn("规则", nameof(IdsRow.RuleText), 108);
        AddIdsColumn("程序", nameof(IdsRow.ProcessName), 130);
        AddIdsColumn("目标", nameof(IdsRow.Target), 170);
        AddIdsColumn("证据", nameof(IdsRow.Evidence), 200, fill: true);
        AddIdsColumn("状态", nameof(IdsRow.StatusText), 70);

        _idsGrid.SelectionChanged += (_, _) => UpdateIdsButtons();
        _idsGrid.CellToolTipTextNeeded += OnIdsCellToolTipNeeded;
        _idsGrid.EmptyText =
            "还没有 IDS 告警。\r\n" +
            "服务本次运行以来没有发现符合规则的可疑行为。";

        _tabIds.Controls.Add(_idsGrid);
        _tabIds.Controls.Add(top);

        _tabControl.SelectedIndexChanged += (_, _) =>
        {
            if (_tabControl.SelectedTab == _tabIds)
            {
                _idsBalloonPending = false;
                _ = RefreshIdsAsync();
            }
        };

        _idsTimer = new System.Windows.Forms.Timer { Interval = IdsRefreshIntervalMs };
        _idsTimer.Tick += (_, _) =>
        {
            if (_tabControl.SelectedTab == _tabIds)
            {
                _ = RefreshIdsAsync();
            }
        };
        _idsTimer.Start();

        // 托盘提示：只在用户没看着 IDS 页时每 30 秒查一次，高危才提示。
        _idsNotifyTimer = new System.Windows.Forms.Timer { Interval = IdsNotifyIntervalMs };
        _idsNotifyTimer.Tick += (_, _) =>
        {
            if (_tabControl.SelectedTab != _tabIds)
            {
                _ = CheckIdsNotificationsAsync();
            }
        };
        _idsNotifyTimer.Start();

        // 点 IDS 高危气泡时直接打开 IDS 页；普通托盘气泡不受影响。
        _trayIcon.BalloonTipClicked += (_, _) =>
        {
            if (!_idsBalloonPending)
            {
                return;
            }

            _idsBalloonPending = false;
            ShowMainWindow();
            _tabControl.SelectedTab = _tabIds;
            _ = RefreshIdsAsync();
        };

        UpdateIdsButtons();
        UpdateIdsSummary();
    }

    private void AddIdsColumn(string header, string property, int width, bool fill = false)
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

        _idsGrid.Columns.Add(column);
    }

    // ---------------- 读取 ----------------

    private async Task RefreshIdsAsync()
    {
        if (SuppressBackgroundServices || _idsLoading || IsDisposed || Disposing)
        {
            return;
        }

        _idsLoading = true;
        UpdateIdsButtons();

        try
        {
            var result = await Task.Run(QueryIdsSnapshot);

            if (IsDisposed || Disposing)
            {
                return;
            }

            if (result is not null)
            {
                _idsServiceAvailable = true;
                _idsAlerts = result.Value.Alerts;
                _idsSuppressions = result.Value.Suppressions;
                _idsSettings = result.Value.Settings;
                _idsStatus = result.Value.Status;
                RebuildIdsView();
            }
            else
            {
                _idsServiceAvailable = false;
                UpdateIdsSummary();
            }
        }
        catch (Exception ex)
        {
            _idsServiceAvailable = false;
            LocalLog.Error(LocalLog.Pick("读取 IDS 告警失败", "Failed to read IDS alerts."), ex);
            UpdateIdsSummary();
        }
        finally
        {
            _idsLoading = false;

            if (!IsDisposed && !Disposing)
            {
                UpdateIdsButtons();
            }
        }
    }

    private static IdsSnapshot? QueryIdsSnapshot()
    {
        try
        {
            var response = ServiceClient.TryRequest(
                new ServiceRequest { Command = ServiceProtocol.Commands.QueryIdsAlerts },
                TimeSpan.FromSeconds(2),
                out _);

            return response is { Ok: true }
                ? new IdsSnapshot(
                    response.IdsAlerts ?? new List<IdsAlertDto>(),
                    response.IdsSuppressions ?? new List<IdsSuppressionDto>(),
                    response.IdsSettings,
                    response.IdsStatus)
                : null;
        }
        catch (Exception)
        {
            return null;
        }
    }

    private readonly record struct IdsSnapshot(
        List<IdsAlertDto> Alerts,
        List<IdsSuppressionDto> Suppressions,
        IdsSettingsDto? Settings,
        IdsStatusDto? Status);

    // ---------------- 托盘提示 ----------------

    private async Task CheckIdsNotificationsAsync()
    {
        if (SuppressBackgroundServices || IsDisposed || Disposing)
        {
            return;
        }

        List<IdsAlertDto> alerts;

        try
        {
            var snapshot = await Task.Run(QueryIdsSnapshot);

            if (snapshot is null || IsDisposed || Disposing)
            {
                return;
            }

            alerts = snapshot.Value.Alerts;
        }
        catch (Exception)
        {
            return;
        }

        var high = alerts
            .Where(alert => alert.Severity == IdsSeverityHigh && alert.Status == "new")
            .OrderByDescending(alert => alert.TimeUtc)
            .FirstOrDefault();

        if (high is null
            || string.Equals(high.Id, _idsLastNotifiedId, StringComparison.Ordinal)
            || DateTime.UtcNow - _idsLastNotifyUtc < IdsNotifyCooldown)
        {
            return;
        }

        _idsLastNotifiedId = high.Id;
        _idsLastNotifyUtc = DateTime.UtcNow;
        _idsBalloonPending = true;

        var process = string.IsNullOrEmpty(high.ProcessName) ? "PID " + high.Pid : high.ProcessName;

        ShowTrayBalloon(
            Localizer.T("IDS 发现高危可疑行为"),
            Localizer.F(
                "{0} → {1}\n点击打开「IDS」页查看证据（只检测，不阻断）。",
                process,
                high.Target),
            ToolTipIcon.Warning);
    }

    // ---------------- 展示 ----------------

    private void RebuildIdsView()
    {
        var keyword = _idsSearchBox.Text.Trim();

        var rows = _idsAlerts
            .Where(alert => IdsMatches(alert, keyword))
            .Select(ToIdsRow)
            .ToList();

        var signature = string.Join(
            "|",
            rows.Take(100).Select(row => $"{row.Id}/{row.Status}"));

        if (!string.Equals(signature, _idsSignature, StringComparison.Ordinal))
        {
            var selectedId = (_idsGrid.CurrentRow?.DataBoundItem as IdsRow)?.Id;

            _idsSignature = signature;
            _idsGrid.DataSource = rows;

            if (selectedId is not null)
            {
                foreach (DataGridViewRow gridRow in _idsGrid.Rows)
                {
                    if (gridRow.DataBoundItem is IdsRow row
                        && string.Equals(row.Id, selectedId, StringComparison.Ordinal))
                    {
                        gridRow.Selected = true;
                        break;
                    }
                }
            }
        }

        UpdateIdsSummary();
        UpdateIdsButtons();
    }

    private bool IdsMatches(IdsAlertDto alert, string keyword)
    {
        if (!IdsSeverityMatches(alert)
            || !IdsRuleMatches(alert))
        {
            return false;
        }

        if (keyword.Length == 0)
        {
            return true;
        }

        return alert.ProcessName.Contains(keyword, StringComparison.OrdinalIgnoreCase)
               || (alert.ProcessPath?.Contains(keyword, StringComparison.OrdinalIgnoreCase) ?? false)
               || alert.Target.Contains(keyword, StringComparison.OrdinalIgnoreCase)
               || alert.Evidence.Contains(keyword, StringComparison.OrdinalIgnoreCase);
    }

    private bool IdsSeverityMatches(IdsAlertDto alert) => _idsSeverityFilter.SelectedIndex switch
    {
        1 => alert.Severity == IdsSeverityHigh,
        2 => alert.Severity == IdsSeverityMedium,
        3 => alert.Severity == IdsSeverityLow,
        _ => true,
    };

    private bool IdsRuleMatches(IdsAlertDto alert) => _idsRuleFilter.SelectedIndex switch
    {
        1 => alert.RuleId == "beaconing",
        2 => alert.RuleId == "scan",
        3 => alert.RuleId == "lateral",
        4 => alert.RuleId == "dns",
        _ => true,
    };

    private static IdsRow ToIdsRow(IdsAlertDto alert) => new()
    {
        Id = alert.Id,
        TimeUtc = alert.TimeUtc,
        Severity = alert.Severity,
        SeverityText = Localizer.T(alert.Severity switch
        {
            IdsSeverityHigh => "高",
            IdsSeverityMedium => "中",
            _ => "低",
        }),
        RuleId = alert.RuleId,
        RuleText = Localizer.T(alert.RuleId switch
        {
            "beaconing" => "周期性外联",
            "scan" => "端口 / 主机扫描",
            "lateral" => "内网横向",
            "dns" => "DNS 异常",
            _ => alert.RuleName,
        }),
        ProcessName = string.IsNullOrEmpty(alert.ProcessName)
            ? Localizer.T("（未知程序）")
            : alert.ProcessName,
        ProcessPath = alert.ProcessPath,
        Target = alert.Target,
        Evidence = alert.Evidence,
        Status = alert.Status,
        StatusText = Localizer.T(alert.Status switch
        {
            "ack" => "已确认",
            "ignored" => "已忽略",
            _ => "新",
        }),
        ToolTip = string.IsNullOrEmpty(alert.ProcessPath)
            ? $"{alert.RuleName} · PID {alert.Pid}\n{alert.Evidence}"
            : $"{alert.ProcessPath}\n{alert.RuleName} · PID {alert.Pid}\n{alert.Evidence}",
    };

    private void OnIdsCellToolTipNeeded(object? sender, DataGridViewCellToolTipTextNeededEventArgs e)
    {
        if (e.RowIndex >= 0
            && _idsGrid.Rows[e.RowIndex].DataBoundItem is IdsRow row)
        {
            e.ToolTipText = row.ToolTip;
        }
    }

    private void UpdateIdsSummary()
    {
        var status = _idsStatus;
        var newCount = _idsAlerts.Count(alert => alert.Status == "new");
        var highCount = _idsAlerts.Count(
            alert => alert.Status == "new" && alert.Severity == IdsSeverityHigh);

        string text;

        if (status is null)
        {
            text = _idsServiceAvailable
                ? Localizer.T("IDS 状态未知（旧版服务或尚未启动）。")
                : Localizer.T("服务不可用，显示上次数据。");
        }
        else if (!status.Enabled)
        {
            text = Localizer.F(
                "IDS 已关闭 · 共 {0} 条告警 · 点「设置…」可开启（只检测，不阻断）。",
                _idsAlerts.Count);
        }
        else
        {
            var sensitivity = Localizer.T(status.Sensitivity == "conservative" ? "保守" : "标准");
            var collecting = Localizer.T(status.Collecting ? "采集中" : "采集未运行");

            text = Localizer.F(
                "IDS 已开启 · {0}敏感度 · {1} · 只检测、不阻断 · flow {2} · 事件 {3} · 未确认 {4}",
                sensitivity,
                collecting,
                status.FlowCount,
                status.EventsSeen,
                newCount);

            if (highCount > 0)
            {
                text += Localizer.F(" · 高危 {0}", highCount);
            }
        }

        if (!_idsServiceAvailable)
        {
            text = Localizer.T("服务不可用，显示上次数据") + " · " + text;
        }

        _idsSummaryLabel.Text = text;
    }

    private void UpdateIdsButtons()
    {
        var selected = SelectedIdsRow();
        var available = !_idsLoading && _idsServiceAvailable;

        _idsRefreshButton.Enabled = !_idsLoading;
        _idsAckButton.Enabled = available
                                && selected is { Status: "new" };
        _idsSuppressButton.Enabled = available && selected is not null;
        _idsSettingsButton.Enabled = available;
        _idsClearButton.Enabled = available && _idsAlerts.Count > 0;
    }

    private IdsRow? SelectedIdsRow()
        => _idsGrid.CurrentRow?.DataBoundItem as IdsRow;

    // ---------------- 操作 ----------------

    private void OnIdsAckClick(object? sender, EventArgs e)
    {
        var row = SelectedIdsRow();

        if (row is null || row.Status != "new")
        {
            return;
        }

        try
        {
            var response = CallService(
                ServiceProtocol.Commands.IdsAck,
                new ServiceRequest { IdsAlertId = row.Id },
                Localizer.T("确认 IDS 告警"));

            if (response is null)
            {
                return;
            }

            foreach (var alert in _idsAlerts)
            {
                if (string.Equals(alert.Id, row.Id, StringComparison.Ordinal))
                {
                    alert.Status = "ack";
                    break;
                }
            }

            _idsSignature = null;
            RebuildIdsView();
        }
        catch (Exception ex)
        {
            ShowError("确认 IDS 告警失败", ex, "Failed to acknowledge an IDS alert");
        }
    }

    private void OnIdsSuppressClick(object? sender, EventArgs e)
    {
        var row = SelectedIdsRow();

        if (row is null)
        {
            return;
        }

        var choice = IdsSuppressForm.Ask(
            DialogOwner,
            row.RuleText,
            row.ProcessName,
            row.Target);

        if (choice is null)
        {
            return;
        }

        var until = choice.Value.Duration is { } span ? DateTime.UtcNow.Add(span) : (DateTime?)null;

        try
        {
            var response = CallService(
                ServiceProtocol.Commands.IdsSuppress,
                new ServiceRequest
                {
                    IdsSuppression = new IdsSuppressionDto
                    {
                        RuleId = row.RuleId,
                        ProcessPath = row.ProcessPath,
                        ProcessName = row.ProcessName,
                        Target = row.Target,
                        UntilUtc = until,
                    },
                },
                Localizer.T("抑制 IDS 告警"));

            if (response is null)
            {
                return;
            }

            LocalLog.Operation(LocalLog.Pick(
                $"已抑制 IDS 告警：{row.RuleText} / {row.ProcessName} / {row.Target}",
                $"IDS alert suppressed (rule={row.RuleId}, process={row.ProcessName})."));

            ShowTrayBalloon(
                Localizer.T("已抑制这条 IDS 告警"),
                Localizer.F("{0} · {1}", row.RuleText, row.ProcessName) + "\n" +
                (until is null
                    ? Localizer.T("永久有效，可在设置里取消。")
                    : Localizer.F(
                        "有效至 {0}。", until.Value.ToLocalTime().ToString("yyyy-MM-dd HH:mm"))));

            _ = RefreshIdsAsync();
        }
        catch (Exception ex)
        {
            ShowError("抑制 IDS 告警失败", ex, "Failed to suppress an IDS alert");
        }
    }

    private void OnIdsSettingsClick(object? sender, EventArgs e)
    {
        var current = _idsSettings ?? new IdsSettingsDto();
        var result = IdsSettingsForm.Ask(DialogOwner, current, _idsSuppressions);

        if (result is null)
        {
            return;
        }

        var updated = result.Value.Settings;
        var removed = result.Value.RemovedSuppressionIds;

        try
        {
            var response = CallService(
                ServiceProtocol.Commands.IdsConfigure,
                new ServiceRequest
                {
                    IdsSettings = updated,
                    IdsRemoveSuppressionIds = removed.Count > 0 ? removed : null,
                },
                Localizer.T("修改 IDS 设置"));

            if (response is null)
            {
                return;
            }

            _idsSettings = response.IdsSettings ?? updated;
            _idsStatus = response.IdsStatus ?? _idsStatus;
            _idsSuppressions = response.IdsSuppressions ?? _idsSuppressions;
            _idsSignature = null;
            _ = RefreshIdsAsync();

            if (removed.Count > 0)
            {
                LocalLog.Operation(LocalLog.Pick(
                    $"已取消 {removed.Count} 条 IDS 抑制",
                    $"Removed {removed.Count} IDS suppression(s)."));
            }

            ShowTrayBalloon(
                Localizer.T(_idsSettings.Enabled ? "IDS 已开启" : "IDS 已关闭"),
                Localizer.T(_idsSettings.Enabled
                    ? "只检测、不阻断；发现高危可疑行为时会托盘提示。"
                    : "不再产生新的 IDS 告警，已有告警仍保留到保留期结束。"));
        }
        catch (Exception ex)
        {
            ShowError("修改 IDS 设置失败", ex, "Failed to update IDS settings");
        }
    }

    private void OnIdsClearClick(object? sender, EventArgs e)
    {
        var confirmed = ConfirmForm.Show(
            owner: DialogOwner,
            title: "清空 IDS 告警",
            question: "确定要清空全部 IDS 告警吗？",
            details: new[]
            {
                new KeyValuePair<string, string>("将要做的", "删除本机保存的 IDS 告警和确认状态"),
                new KeyValuePair<string, string>("不会影响", "规则、白名单、临时锁网和其它记录"),
            },
            warnings: new[]
            {
                "只删除告警记录，不会解除任何阻止规则。",
                "IDS 仍然只检测、不阻断。",
            },
            confirmText: "清空告警");

        if (!confirmed)
        {
            return;
        }

        try
        {
            var response = CallService(
                ServiceProtocol.Commands.IdsClear,
                new ServiceRequest(),
                Localizer.T("清空 IDS 告警"));

            if (response is null)
            {
                return;
            }

            _idsAlerts = new List<IdsAlertDto>();
            _idsSignature = null;
            _idsGrid.DataSource = new List<IdsRow>();
            RebuildIdsView();

            LocalLog.Operation(LocalLog.Pick(
                $"IDS 告警已清空：{response.Affected} 条",
                $"IDS alerts cleared ({response.Affected})."));

            ShowTrayBalloon(
                Localizer.T("IDS 告警已清空"),
                Localizer.T("已删除本机保存的告警记录；规则没有变化。"));
        }
        catch (Exception ex)
        {
            ShowError("清空 IDS 告警失败", ex, "Failed to clear IDS alerts");
        }
    }

    private const string IdsSeverityHigh = "high";
    private const string IdsSeverityMedium = "medium";
    private const string IdsSeverityLow = "low";

    private sealed class IdsRow
    {
        public string Id { get; init; } = string.Empty;

        public DateTime TimeUtc { get; init; }

        public string Severity { get; init; } = string.Empty;

        public string SeverityText { get; init; } = string.Empty;

        public string RuleId { get; init; } = string.Empty;

        public string RuleText { get; init; } = string.Empty;

        public string ProcessName { get; init; } = string.Empty;

        public string? ProcessPath { get; init; }

        public string Target { get; init; } = string.Empty;

        public string Evidence { get; init; } = string.Empty;

        public string Status { get; init; } = "new";

        public string StatusText { get; init; } = string.Empty;

        public string ToolTip { get; init; } = string.Empty;

        public string TimeText => TimeUtc.ToLocalTime().ToString("MM-dd HH:mm:ss");
    }
}
