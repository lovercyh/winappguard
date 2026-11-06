using WinAppGuard.Contracts;
using WinAppGuard.Localization;

namespace WinAppGuard.Forms;

/// <summary>
/// 5.0：网络被动检测页。
///
/// 页面只做三件事：展示 Suricata 告警、展示健康状态、让用户手动选择
/// 是否用 WFP 临时阻断。任何告警都不会自动触发过滤器。
/// </summary>
public sealed partial class MainForm
{
    private const int NetworkDetectionRefreshIntervalMs = 3000;

    private TabPage _tabNetworkDetection = null!;
    private Label _ndNoticeLabel = null!;
    private Label _ndStatusLabel = null!;
    private Button _ndRefreshButton = null!;
    private Button _ndAckButton = null!;
    private Button _ndBlockButton = null!;
    private Button _ndReleaseButton = null!;
    private Button _ndClearButton = null!;
    private Button _ndSettingsButton = null!;
    private CheckBox _ndAutoRefreshCheckBox = null!;
    private DataGridViewBuffered _ndGrid = null!;
    private ListBox _ndBlocks = null!;
    private System.Windows.Forms.Timer? _ndTimer;

    private List<NetworkAlertDto> _ndAlerts = new();
    private List<NetworkBlockDto> _ndBlockList = new();
    private NetworkDetectionSettingsDto _ndSettings = new();
    private NetworkDetectionStatusDto? _ndStatus;
    private string? _ndSignature;
    private bool _ndLoading;
    private string? _ndLastNotifiedId;
    private DateTime _ndLastNotifyUtc = DateTime.MinValue;

    private void InitializeNetworkDetectionPage()
    {
        _tabNetworkDetection = new TabPage
        {
            Name = "_tabNetworkDetection",
            Text = Localizer.T("反网络攻击"),
            Padding = new Padding(9),
            UseVisualStyleBackColor = true,
        };

        var top = new Panel
        {
            Dock = DockStyle.Top,
            Height = 132,
            Padding = new Padding(0, 4, 0, 0),
        };

        _ndNoticeLabel = new Label
        {
            AutoSize = false,
            Dock = DockStyle.Top,
            Height = 36,
            ForeColor = Color.FromArgb(191, 87, 0),
            Text = Localizer.T(
                "被动检测：只告警，不自动拦截。命中后可手动选择 WFP 临时阻断；HTTPS 正文不可见。"),
        };

        _ndStatusLabel = new Label
        {
            AutoSize = false,
            AutoEllipsis = true,
            Dock = DockStyle.Top,
            Height = 22,
            Text = Localizer.T("反网络攻击状态未知。"),
        };

        var actions = new FlowLayoutPanel
        {
            Dock = DockStyle.Top,
            Height = 62,
            FlowDirection = FlowDirection.LeftToRight,
            WrapContents = true,
            Padding = new Padding(0, 6, 0, 0),
        };

        _ndRefreshButton = new Button { Text = Localizer.T("刷新"), Width = 78 };
        _ndRefreshButton.Click += (_, _) => RefreshNetworkDetection();

        _ndAckButton = new Button { Text = Localizer.T("标记已读"), Width = 96, Enabled = false };
        _ndAckButton.Click += OnNetworkAckClick;

        _ndBlockButton = new Button { Text = Localizer.T("拦截…"), Width = 88, Enabled = false };
        _ndBlockButton.Click += OnNetworkBlockClick;

        _ndReleaseButton = new Button { Text = Localizer.T("释放选中拦截"), Width = 118, Enabled = false };
        _ndReleaseButton.Click += OnNetworkReleaseClick;

        _ndClearButton = new Button { Text = Localizer.T("清空告警"), Width = 96 };
        _ndClearButton.Click += OnNetworkClearClick;

        _ndSettingsButton = new Button { Text = Localizer.T("设置…"), Width = 84 };
        _ndSettingsButton.Click += OnNetworkSettingsClick;

        _ndAutoRefreshCheckBox = new CheckBox
        {
            AutoSize = true,
            Text = Localizer.T("每 3 秒自动刷新"),
            Checked = true,
            Margin = new Padding(12, 8, 3, 3),
        };
        _ndAutoRefreshCheckBox.CheckedChanged += OnNetworkAutoRefreshChanged;

        actions.Controls.Add(_ndRefreshButton);
        actions.Controls.Add(_ndAckButton);
        actions.Controls.Add(_ndBlockButton);
        actions.Controls.Add(_ndReleaseButton);
        actions.Controls.Add(_ndClearButton);
        actions.Controls.Add(_ndSettingsButton);
        actions.Controls.Add(_ndAutoRefreshCheckBox);

        top.Controls.Add(actions);
        top.Controls.Add(_ndStatusLabel);
        top.Controls.Add(_ndNoticeLabel);

        _ndGrid = new DataGridViewBuffered
        {
            Dock = DockStyle.Fill,
            ReadOnly = true,
            AllowUserToAddRows = false,
            AllowUserToDeleteRows = false,
            AllowUserToResizeRows = false,
            AutoGenerateColumns = false,
            MultiSelect = false,
            SelectionMode = DataGridViewSelectionMode.FullRowSelect,
            RowHeadersVisible = false,
            BackgroundColor = Color.White,
        };

        _ndGrid.Columns.Add(new DataGridViewTextBoxColumn
        {
            DataPropertyName = nameof(NdRow.TimeText),
            HeaderText = Localizer.T("时间"),
            Width = 118,
        });
        _ndGrid.Columns.Add(new DataGridViewTextBoxColumn
        {
            DataPropertyName = nameof(NdRow.SeverityText),
            HeaderText = Localizer.T("级别"),
            Width = 68,
        });
        _ndGrid.Columns.Add(new DataGridViewTextBoxColumn
        {
            DataPropertyName = nameof(NdRow.StatusText),
            HeaderText = Localizer.T("状态"),
            Width = 55,
        });
        _ndGrid.Columns.Add(new DataGridViewTextBoxColumn
        {
            DataPropertyName = nameof(NdRow.Signature),
            HeaderText = Localizer.T("规则"),
            Width = 270,
        });
        _ndGrid.Columns.Add(new DataGridViewTextBoxColumn
        {
            DataPropertyName = nameof(NdRow.TargetText),
            HeaderText = Localizer.T("远端"),
            Width = 170,
        });
        _ndGrid.Columns.Add(new DataGridViewTextBoxColumn
        {
            DataPropertyName = nameof(NdRow.ProcessText),
            HeaderText = Localizer.T("进程"),
            Width = 140,
        });
        _ndGrid.Columns.Add(new DataGridViewTextBoxColumn
        {
            DataPropertyName = nameof(NdRow.Evidence),
            HeaderText = Localizer.T("证据"),
            AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill,
        });
        _ndGrid.Columns.Add(new DataGridViewTextBoxColumn
        {
            DataPropertyName = nameof(NdRow.BlockStateText),
            HeaderText = Localizer.T("拦截状态"),
            Width = 70,
        });

        _ndGrid.SelectionChanged += (_, _) => UpdateNetworkButtons();
        _ndGrid.CellDoubleClick += (_, e) =>
        {
            if (e.RowIndex >= 0)
            {
                OnNetworkBlockClick(null, EventArgs.Empty);
            }
        };

        var bottom = new GroupBox
        {
            Dock = DockStyle.Bottom,
            Height = 150,
            Text = Localizer.T("活动拦截（服务重启自动清空）"),
            Padding = new Padding(8),
        };

        _ndBlocks = new ListBox
        {
            Dock = DockStyle.Fill,
            IntegralHeight = false,
            SelectionMode = SelectionMode.One,
        };
        _ndBlocks.SelectedIndexChanged += (_, _) => UpdateNetworkButtons();

        var releasePanel = new FlowLayoutPanel
        {
            Dock = DockStyle.Bottom,
            Height = 36,
            FlowDirection = FlowDirection.RightToLeft,
        };
        var releaseAll = new Button
        {
            Text = Localizer.T("全部释放"),
            Width = 92,
        };
        releaseAll.Click += OnNetworkReleaseAllClick;
        releasePanel.Controls.Add(releaseAll);

        bottom.Controls.Add(_ndBlocks);
        bottom.Controls.Add(releasePanel);

        _tabNetworkDetection.Controls.Add(_ndGrid);
        _tabNetworkDetection.Controls.Add(bottom);
        _tabNetworkDetection.Controls.Add(top);
        _tabControl.TabPages.Add(_tabNetworkDetection);

        _tabControl.SelectedIndexChanged += (_, _) =>
        {
            if (_tabControl.SelectedTab == _tabNetworkDetection)
            {
                RefreshNetworkDetection();
            }
        };

        // 5.6：这一页原来没有自动刷新开关，定时器一直跑，
        // 关掉别的页面的自动刷新后这里仍会每 3 秒重建表格、把滚动位置顶回顶部。
        _ndTimer = new System.Windows.Forms.Timer(components!)
        {
            Interval = NetworkDetectionRefreshIntervalMs,
            Enabled = _ndAutoRefreshCheckBox.Checked,
        };

        _ndTimer.Tick += (_, _) =>
        {
            // 只在用户真的看着这一页、且没关掉自动刷新时拉数据。
            if (_ndAutoRefreshCheckBox.Checked && _tabControl.SelectedTab == _tabNetworkDetection)
            {
                RefreshNetworkDetection();
            }
        };
    }

    private void OnNetworkAutoRefreshChanged(object? sender, EventArgs e)
    {
        if (_ndTimer is not null)
        {
            _ndTimer.Enabled = _ndAutoRefreshCheckBox.Checked;
        }

        if (_ndAutoRefreshCheckBox.Checked && _tabControl.SelectedTab == _tabNetworkDetection)
        {
            RefreshNetworkDetection();
        }
    }

    private async void RefreshNetworkDetection()
    {
        // 自检模式承诺不联网，也不启动后台查询。
        if (SuppressBackgroundServices || _ndLoading || IsDisposed || Disposing)
        {
            return;
        }

        _ndLoading = true;

        try
        {
            var snapshot = await Task.Run(QueryNetworkDetectionSnapshot);

            if (snapshot is null || IsDisposed || Disposing)
            {
                return;
            }

            _ndAlerts = snapshot.Value.Alerts;
            _ndBlockList = snapshot.Value.Blocks;
            _ndSettings = snapshot.Value.Settings;
            _ndStatus = snapshot.Value.Status;

            RebuildNetworkDetection();
        }
        finally
        {
            _ndLoading = false;
        }
    }

    private static NetworkDetectionSnapshot? QueryNetworkDetectionSnapshot()
    {
        try
        {
            var response = ServiceClient.TryRequest(
                new ServiceRequest { Command = ServiceProtocol.Commands.QueryNetworkDetection },
                TimeSpan.FromSeconds(2),
                out _);

            return response is { Ok: true }
                ? new NetworkDetectionSnapshot(
                    response.NetworkAlerts ?? new List<NetworkAlertDto>(),
                    response.NetworkBlocks ?? new List<NetworkBlockDto>(),
                    response.NetworkDetectionSettings ?? new NetworkDetectionSettingsDto(),
                    response.NetworkDetectionStatus)
                : null;
        }
        catch (Exception)
        {
            return null;
        }
    }

    private readonly record struct NetworkDetectionSnapshot(
        List<NetworkAlertDto> Alerts,
        List<NetworkBlockDto> Blocks,
        NetworkDetectionSettingsDto Settings,
        NetworkDetectionStatusDto? Status);

    private void RebuildNetworkDetection()
    {
        var rows = _ndAlerts
            .Select(alert => new NdRow
            {
                Id = alert.Id,
                TimeText = alert.TimeUtc.ToLocalTime().ToString("MM-dd HH:mm:ss"),
                SeverityText = alert.Severity,
                StatusText = Localizer.T(alert.Status switch
                {
                    "ack" => "已读",
                    "ignored" => "已忽略",
                    _ => "未读",
                }),
                Signature = alert.Signature,
                RemoteAddress = alert.RemoteAddress,
                TargetText = string.IsNullOrEmpty(alert.RemoteAddress)
                    ? string.Empty
                    : $"{alert.RemoteAddress}:{alert.RemotePort}",
                ProcessText = string.IsNullOrEmpty(alert.ProcessName)
                    ? alert.Pid > 0 ? $"PID {alert.Pid}" : Localizer.T("未知进程")
                    : alert.ProcessName,
                Evidence = alert.Evidence,
                BlockStateText = alert.BlockState == "blocked"
                    ? Localizer.T("已拦截")
                    : "—",
            })
            .ToList();

        var signature = string.Join(
            "|",
            rows.Take(100).Select(row => $"{row.Id}/{row.StatusText}/{row.BlockStateText}"));

        if (!string.Equals(signature, _ndSignature, StringComparison.Ordinal))
        {
            // 5.6：重绑前记住滚动位置，重绑后放回去。
            var firstDisplayedRow = CaptureFirstDisplayedRow(_ndGrid);
            var selectedId = (_ndGrid.CurrentRow?.DataBoundItem as NdRow)?.Id;
            _ndSignature = signature;
            _ndGrid.DataSource = rows;

            if (selectedId is not null)
            {
                foreach (DataGridViewRow gridRow in _ndGrid.Rows)
                {
                    if (gridRow.DataBoundItem is NdRow row
                        && string.Equals(row.Id, selectedId, StringComparison.Ordinal))
                    {
                        gridRow.Selected = true;
                        break;
                    }
                }
            }

            RestoreFirstDisplayedRow(_ndGrid, firstDisplayedRow);
        }

        var blocks = _ndBlockList
            .Select(block =>
                $"{block.Kind}  {block.Target}  →  {block.ExpiresUtc.ToLocalTime():HH:mm:ss}" +
                (string.IsNullOrEmpty(block.RuleName) ? string.Empty : $"  [{block.RuleName}]"))
            .ToList();

        if (!_ndBlocks.Items.Cast<string>().SequenceEqual(blocks, StringComparer.Ordinal))
        {
            var selected = _ndBlocks.SelectedIndex;
            _ndBlocks.BeginUpdate();
            _ndBlocks.Items.Clear();
            _ndBlocks.Items.AddRange(blocks.Cast<object>().ToArray());
            _ndBlocks.EndUpdate();

            if (selected >= 0 && selected < _ndBlocks.Items.Count)
            {
                _ndBlocks.SelectedIndex = selected;
            }
        }

        var status = _ndStatus;

        if (status is null)
        {
            _ndStatusLabel.Text = Localizer.T("反网络攻击状态未知：服务可能未启动或版本较旧。");
        }
        else
        {
            _ndStatusLabel.Text = Localizer.F(
                "反网络攻击：{0}；Suricata：{1}；规则：{2}（{3}）；告警：{4}（未读 {5}）；活动拦截：{6}",
                Localizer.T(status.Enabled ? "已开启" : "已关闭"),
                Localizer.T(status.Running ? "运行中" : "未运行"),
                status.RuleCount,
                Localizer.T(status.RuleProfile == "full" ? "全量" : "标准"),
                status.AlertsTotal,
                status.AlertsNew,
                status.ActiveBlocks);

            if (!string.IsNullOrWhiteSpace(status.CaptureDeviceName))
            {
                _ndStatusLabel.Text += Localizer.F(
                    "；监听：{0}", status.CaptureDeviceName);
            }

            if (status.CaptureDeviceFallback)
            {
                _ndStatusLabel.Text += "（" + Localizer.T("所选网卡不可用，已回退到自动") + "）";
            }

            if (!string.IsNullOrWhiteSpace(status.LastError))
            {
                _ndStatusLabel.Text += "；" + status.LastError;
            }
        }

        MaybeNotifyNetworkAlert();
        UpdateNetworkButtons();
        RequestNetworkOwnership();
        RefreshNetworkOwnershipTooltips();
    }

    /// <summary>5.5：把当前告警里的远程 IP 交给后台归属查询。</summary>
    private void RequestNetworkOwnership()
    {
        if (_ndGrid is null || _ndGrid.IsDisposed)
        {
            return;
        }

        RequestIpOwnership(_ndAlerts.Select(alert => alert.RemoteAddress));
    }

    /// <summary>5.5：把归属提示挂到反网络攻击表格的「远端」列。</summary>
    private void RefreshNetworkOwnershipTooltips()
    {
        if (_ndGrid is null || _ndGrid.IsDisposed)
        {
            return;
        }

        var columnIndex = _ndGrid.Columns
            .Cast<DataGridViewColumn>()
            .FirstOrDefault(column =>
                string.Equals(
                    column.DataPropertyName,
                    nameof(NdRow.TargetText),
                    StringComparison.Ordinal))?.Index ?? -1;

        if (columnIndex < 0)
        {
            return;
        }

        foreach (DataGridViewRow row in _ndGrid.Rows)
        {
            if (row.DataBoundItem is not NdRow item)
            {
                continue;
            }

            row.Cells[columnIndex].ToolTipText =
                ResolveIpOwnership(item.RemoteAddress).TooltipText;
        }
    }

    private void MaybeNotifyNetworkAlert()
    {
        if (!_ndSettings.Notify || _ndAlerts.Count == 0)
        {
            return;
        }

        var newest = _ndAlerts
            .Where(alert => alert.Status == "new" && alert.Severity == "high")
            .OrderByDescending(alert => alert.TimeUtc)
            .FirstOrDefault();

        if (newest is null)
        {
            return;
        }

        if (_ndLastNotifiedId is null)
        {
            _ndLastNotifiedId = newest.Id;
            return;
        }

        if (string.Equals(newest.Id, _ndLastNotifiedId, StringComparison.Ordinal)
            || DateTime.UtcNow - _ndLastNotifyUtc < TimeSpan.FromMinutes(5))
        {
            return;
        }

        _ndLastNotifiedId = newest.Id;
        _ndLastNotifyUtc = DateTime.UtcNow;

        ShowTrayBalloon(
            "反网络攻击高危告警",
            Localizer.F(
                "{0}\n{1}:{2}  {3}",
                newest.Signature,
                newest.RemoteAddress,
                newest.RemotePort,
                newest.ProcessName),
            ToolTipIcon.Warning);
    }

    private void UpdateNetworkButtons()
    {
        var alert = SelectedNetworkAlert();

        _ndAckButton.Enabled = alert is { Status: "new" };
        _ndBlockButton.Enabled = alert is not null;
        _ndReleaseButton.Enabled = _ndBlocks.SelectedIndex >= 0;
    }

    private NetworkAlertDto? SelectedNetworkAlert()
        => _ndGrid.CurrentRow?.DataBoundItem is NdRow row
            ? _ndAlerts.FirstOrDefault(alert => string.Equals(alert.Id, row.Id, StringComparison.Ordinal))
            : null;

    private void OnNetworkAckClick(object? sender, EventArgs e)
    {
        var alert = SelectedNetworkAlert();

        if (alert is null || alert.Status != "new")
        {
            return;
        }

        var response = CallAlertService(
            ServiceProtocol.Commands.AlertNetworkAck,
            new ServiceRequest { NetworkAlertId = alert.Id },
            Localizer.T("标记反网络攻击告警为已读"));

        if (response is null)
        {
            return;
        }

        alert.Status = "ack";
        RefreshNetworkDetection();
    }

    private void OnNetworkBlockClick(object? sender, EventArgs e)
    {
        var alert = SelectedNetworkAlert();

        if (alert is null)
        {
            return;
        }

        if (string.IsNullOrWhiteSpace(alert.RemoteAddress))
        {
            UiMessageBox.Show(
                DialogOwner,
                Localizer.T("这条告警没有远端地址，无法创建 WFP 拦截。"),
                Localizer.T("无法拦截"),
                MessageBoxButtons.OK,
                MessageBoxIcon.Warning);
            return;
        }

        var choice = NetworkBlockForm.Ask(DialogOwner, alert);

        if (choice is null)
        {
            return;
        }

        var response = ElevatedClient.TryRequest(
            new ServiceRequest
            {
                Command = ServiceProtocol.Commands.NetworkDetectionBlock,
                NetworkAlertId = alert.Id,
                NetworkBlockKind = choice.Value.Kind,
                NetworkBlockTarget = choice.Value.Target,
                NetworkBlockMinutes = choice.Value.Minutes,
            },
            out var error);

        if (response is not { Ok: true })
        {
            UiMessageBox.Show(
                DialogOwner,
                error ?? response?.Error ?? Localizer.T("拦截失败。"),
                Localizer.T("拦截失败"),
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
            return;
        }

        RefreshNetworkDetection();
    }

    private void OnNetworkReleaseClick(object? sender, EventArgs e)
    {
        if (_ndBlocks.SelectedIndex < 0
            || _ndBlocks.SelectedIndex >= _ndBlockList.Count)
        {
            return;
        }

        var block = _ndBlockList[_ndBlocks.SelectedIndex];

        var response = ElevatedClient.TryRequest(
            new ServiceRequest
            {
                Command = ServiceProtocol.Commands.NetworkDetectionRelease,
                NetworkBlockId = block.Id,
                NetworkAlertId = block.AlertId,
            },
            out var error);

        if (response is not { Ok: true })
        {
            UiMessageBox.Show(
                DialogOwner,
                error ?? response?.Error ?? Localizer.T("释放失败。"),
                Localizer.T("释放失败"),
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
            return;
        }

        RefreshNetworkDetection();
    }

    private void OnNetworkReleaseAllClick(object? sender, EventArgs e)
    {
        var confirmed = ConfirmForm.Show(
            DialogOwner,
            Localizer.T("释放全部网络拦截"),
            Localizer.T("确定要释放所有手动网络拦截吗？"),
            new[]
            {
                new KeyValuePair<string, string>("影响", "删除本次服务会话创建的全部 WFP 出站阻断"),
            },
            new[] { "不会影响防火墙规则、白名单和告警历史。" },
            Localizer.T("全部释放"));

        if (!confirmed)
        {
            return;
        }

        var response = ElevatedClient.TryRequest(
            new ServiceRequest
            {
                Command = ServiceProtocol.Commands.NetworkDetectionReleaseAll,
                NetworkBlockReleaseAll = true,
            },
            out var error);

        if (response is not { Ok: true })
        {
            UiMessageBox.Show(
                DialogOwner,
                error ?? response?.Error ?? Localizer.T("释放失败。"),
                Localizer.T("释放失败"),
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
            return;
        }

        RefreshNetworkDetection();
    }

    private void OnNetworkClearClick(object? sender, EventArgs e)
    {
        var confirmed = ConfirmForm.Show(
            DialogOwner,
            Localizer.T("清空反网络攻击告警"),
            Localizer.T("确定要清空所有反网络攻击告警吗？"),
            new[]
            {
                new KeyValuePair<string, string>("影响", "删除告警历史和未读状态，不删除活动拦截"),
            },
            new[] { "此操作不可撤销。" },
            Localizer.T("清空告警"));

        if (!confirmed)
        {
            return;
        }

        var response = CallAlertService(
            ServiceProtocol.Commands.AlertNetworkClear,
            new ServiceRequest(),
            Localizer.T("清空反网络攻击告警"));

        if (response is null)
        {
            return;
        }

        RefreshNetworkDetection();
    }

    private void OnNetworkSettingsClick(object? sender, EventArgs e)
    {
        var updated = NetworkDetectionSettingsForm.Ask(DialogOwner, _ndSettings);

        if (updated is null)
        {
            return;
        }

        var response = ElevatedClient.TryRequest(
            new ServiceRequest
            {
                Command = ServiceProtocol.Commands.NetworkDetectionConfigure,
                NetworkDetectionSettings = updated,
            },
            out var error);

        if (response is not { Ok: true })
        {
            UiMessageBox.Show(
                DialogOwner,
                error ?? response?.Error ?? Localizer.T("保存设置失败。"),
                Localizer.T("保存设置失败"),
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
            return;
        }

        RefreshNetworkDetection();
    }

    private sealed class NdRow
    {
        public string Id { get; init; } = string.Empty;
        public string TimeText { get; init; } = string.Empty;
        public string SeverityText { get; init; } = string.Empty;
        public string StatusText { get; init; } = string.Empty;
        public string Signature { get; init; } = string.Empty;
        public string RemoteAddress { get; init; } = string.Empty;
        public string TargetText { get; init; } = string.Empty;
        public string ProcessText { get; init; } = string.Empty;
        public string Evidence { get; init; } = string.Empty;
        public string BlockStateText { get; init; } = string.Empty;
    }
}

