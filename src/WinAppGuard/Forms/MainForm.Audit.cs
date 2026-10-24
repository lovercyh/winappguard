using WinAppGuard.Contracts;
using WinAppGuard.Core;
using WinAppGuard.Localization;
using WinAppGuard.Core.Audit;

namespace WinAppGuard.Forms;

/// <summary>
/// 主窗体的「审计」页 —— 所有控件在代码里构建，不放进 Designer。
///
/// 为什么这么做：这一页是一整块自包含的表格 + 工具条，
/// 代码构建比在 1000 多行的 Designer 文件里手工插控件更容易审查、也更不容易碰坏别的页。
/// </summary>
public sealed partial class MainForm
{
    private const int AuditRefreshIntervalMs = 3000;
    private const int AuditMaxDisplayedRows = 500;

    private readonly AuditStore _auditStore = new(ServicePaths.AuditDirectory);

    private TextBox _auditSearchBox = null!;
    private CheckBox _auditBlockedOnlyCheck = null!;
    private Label _auditRetentionLabel = null!;
    private ComboBox _auditRetentionCombo = null!;
    private CheckBox _auditEnabledCheck = null!;
    private CheckBox _auditDomainCheck = null!;
    private Label _auditStatusLabel = null!;
    private Label _auditDetailLabel = null!;
    private Button _auditClearButton = null!;
    private DataGridViewBuffered _auditGrid = null!;
    private ContextMenuStrip? _auditMenu;
    private System.Windows.Forms.Timer? _auditTimer;
    private bool _auditCollecting;
    private bool _loadingAuditSettings;

    /// <summary>上一次重建表格时的"数据签名"。相同就不再重建（避免每 3 秒打断用户选中/滚动）。</summary>
    private string? _auditLastSignature;

    /// <summary>
    /// 自检工具构造窗体时置 true：不启动后台服务、不写真实审计目录。
    /// （ui-check 只是量布局，不应该产生副作用。）
    /// </summary>
    internal static bool SuppressBackgroundServices { get; set; }

    private void InitializeAuditPage()
    {
        var top = new Panel
        {
            Dock = DockStyle.Top,
            Height = 72,
            Padding = new Padding(0, 4, 0, 0),
        };

        _auditSearchBox = new TextBox
        {
            Location = new Point(0, 8),
            Width = 240,
            PlaceholderText = "搜索：程序 / IP / 域名",
        };
        _auditSearchBox.TextChanged += (_, _) => RefreshAudit();

        _auditBlockedOnlyCheck = new CheckBox
        {
            Location = new Point(252, 9),
            Width = 96,
            Text = "只看拦截",
        };
        _auditBlockedOnlyCheck.CheckedChanged += (_, _) => RefreshAudit();

        var refreshButton = new Button
        {
            Location = new Point(356, 6),
            Width = 76,
            Text = "刷新",
        };
        refreshButton.Click += (_, _) => RefreshAudit();

        _auditClearButton = new Button
        {
            Location = new Point(440, 6),
            Width = 76,
            Text = "清空…",
        };
        _auditClearButton.Click += OnAuditClearClick;

        var openFolderButton = new Button
        {
            Location = new Point(524, 6),
            Width = 108,
            Text = "打开目录",
        };
        openFolderButton.Click += OnAuditOpenFolderClick;

        var blockIpButton = new Button
        {
            Location = new Point(640, 6),
            Width = 104,
            Text = "拦截此 IP…",
        };
        blockIpButton.Click += OnBlockSelectedIpClick;

        var addIpButton = new Button
        {
            Location = new Point(752, 6),
            Width = 92,
            Text = "添加 IP…",
        };
        addIpButton.Click += OnAddIpRuleClick;

        // 记录保留期：1 / 3 / 7 / 30 天。放第一行最右侧，和"清理"相关的按钮在同一行。
        _auditRetentionLabel = new Label
        {
            Location = new Point(852, 10),
            Width = 62,
            Text = "记录保留",
            ForeColor = SystemColors.GrayText,
        };

        _auditRetentionCombo = new ComboBox
        {
            Location = new Point(916, 8),
            Width = 84,
            DropDownStyle = ComboBoxStyle.DropDownList,
            Name = "_auditRetentionCombo",
        };
        _auditRetentionCombo.Items.AddRange(new object[]
        {
            Localizer.T("1 天"), Localizer.T("3 天"),
            Localizer.T("7 天"), Localizer.T("30 天"),
        });
        _auditRetentionCombo.SelectedIndex = 2;
        _auditRetentionCombo.SelectedIndexChanged += OnAuditRetentionChanged;

        _auditEnabledCheck = new CheckBox
        {
            Location = new Point(0, 42),
            Width = 110,
            Text = "记录连接",
        };
        _auditEnabledCheck.CheckedChanged += OnAuditEnabledChanged;

        _auditDomainCheck = new CheckBox
        {
            Location = new Point(118, 42),
            Width = 330,
            Text = "域名推测（会向本机 DNS 服务器发查询）",
        };
        _auditDomainCheck.CheckedChanged += OnAuditDomainChanged;

        _auditStatusLabel = new Label
        {
            Location = new Point(456, 44),
            Width = 520,
            Text = string.Empty,
            ForeColor = SystemColors.GrayText,
        };

        top.Controls.AddRange(new Control[]
        {
            _auditSearchBox,
            _auditBlockedOnlyCheck,
            refreshButton,
            _auditClearButton,
            openFolderButton,
            blockIpButton,
            addIpButton,
            _auditRetentionLabel,
            _auditRetentionCombo,
            _auditEnabledCheck,
            _auditDomainCheck,
            _auditStatusLabel,
        });

        _auditGrid = new DataGridViewBuffered
        {
            Dock = DockStyle.Fill,
            ReadOnly = true,
            AllowUserToAddRows = false,
            AllowUserToDeleteRows = false,
            AllowUserToResizeRows = false,
            RowHeadersVisible = false,
            MultiSelect = false,
            SelectionMode = DataGridViewSelectionMode.FullRowSelect,
            AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill,
            BackgroundColor = SystemColors.Window,
        };

        _auditGrid.Columns.Add(NewAuditColumn("时间", 90, 0));
        _auditGrid.Columns.Add(NewAuditColumn("类型", 60, 0));
        _auditGrid.Columns.Add(NewAuditColumn("程序", 150, 0));
        _auditGrid.Columns.Add(NewAuditColumn("远端", 160, 0));
        _auditGrid.Columns.Add(NewAuditColumn("域名（推测）", 220, 0));
        _auditGrid.Columns.Add(NewAuditColumn("命中规则", 200, 0));

        _auditGrid.SelectionChanged += (_, _) => UpdateAuditDetail();
        _auditGrid.CellFormatting += OnAuditCellFormatting;
        _auditGrid.CellMouseDown += OnAuditGridCellMouseDown;
        _auditGrid.EmptyText =
            Localizer.T("还没有记录。\r\n打开「记录连接」后，新的连接会出现在这里。");

        // 右键复制：记录页里最常想拿走的两个值（远端地址、程序路径），
        // 以前只能手抄 —— 尤其是 IPv6，手抄基本不现实。
        _auditMenu = new ContextMenuStrip();
        var copyRemoteItem = new ToolStripMenuItem(Localizer.T("复制远端地址"));
        copyRemoteItem.Click += (_, _) => CopyFromSelectedAuditRow(
            row => row.Remote, "这一行没有远端地址。");

        var copyPathItem = new ToolStripMenuItem(Localizer.T("复制程序路径"));
        copyPathItem.Click += (_, _) => CopyFromSelectedAuditRow(
            row => row.ProcessPath, "这一行没有程序路径（可能是无归属进程）。");

        var copyDomainItem = new ToolStripMenuItem(Localizer.T("复制域名"));
        copyDomainItem.Click += (_, _) => CopyFromSelectedAuditRow(
            row => row.Domain, "这一行没有推测出域名。");

        _auditMenu.Items.Add(copyRemoteItem);
        _auditMenu.Items.Add(copyPathItem);
        _auditMenu.Items.Add(copyDomainItem);
        _auditMenu.Opening += (_, _) =>
        {
            var hasRow = GetSelectedAuditRow() is not null;
            foreach (ToolStripItem item in _auditMenu.Items)
            {
                item.Enabled = hasRow;
            }
        };

        _auditGrid.ContextMenuStrip = _auditMenu;

        var bottom = new Panel
        {
            Dock = DockStyle.Bottom,
            Height = 40,
            Padding = new Padding(0, 4, 0, 0),
        };

        _auditDetailLabel = new Label
        {
            Dock = DockStyle.Fill,
            Text = Localizer.T("选中一行查看完整路径与命中规则。"),
            ForeColor = SystemColors.GrayText,
        };
        bottom.Controls.Add(_auditDetailLabel);

        // 停靠顺序：先加 Fill，再加 Top/Bottom（后加的优先占边）。
        _tabAudit.Controls.Add(_auditGrid);
        _tabAudit.Controls.Add(bottom);
        _tabAudit.Controls.Add(top);

        _tabControl.SelectedIndexChanged += (_, _) =>
        {
            if (_tabControl.SelectedTab == _tabAudit)
            {
                RefreshAudit();
            }
        };

        _auditTimer = new System.Windows.Forms.Timer { Interval = AuditRefreshIntervalMs };
        _auditTimer.Tick += (_, _) =>
        {
            if (_tabControl.SelectedTab == _tabAudit)
            {
                RefreshAudit();
            }
        };

        _loadingAuditSettings = true;
        _auditEnabledCheck.Checked = _settings.AuditEnabled;
        _auditDomainCheck.Checked = _settings.AuditDomainLookupEnabled;
        _auditDomainCheck.Enabled = _settings.AuditEnabled;
        _auditRetentionCombo.SelectedIndex = RetentionDaysToIndex(_settings.AuditRetentionDays);
        _auditRetentionCombo.Enabled = _settings.AuditEnabled;
        _loadingAuditSettings = false;

        _auditTimer.Start();
        RefreshAudit();
        UpdateAuditControlsEnabled();
    }

    private static DataGridViewTextBoxColumn NewAuditColumn(string title, int width, int fillWeight)
        => new()
        {
            HeaderText = title,
            Width = width,
            SortMode = DataGridViewColumnSortMode.NotSortable,
        };

    // ==================================================================
    // 服务与设置
    // ==================================================================

    /// <summary>
    /// 把服务返回的审计状态同步到界面控件。
    ///
    /// 只改内存里的 <c>_settings</c>（作为离线时的显示镜像），**不回写文件**：
    /// 3.0-c 起机器级设置存在 ProgramData，由服务负责持久化。
    /// </summary>
    private void ApplyAuditStatus(ServiceStatus status)
    {
        _auditCollecting = status.AuditCollecting;

        _settings.AuditEnabled = status.AuditEnabled;
        _settings.AuditDomainLookupEnabled = status.AuditDomainLookup;
        _settings.AuditRetentionDays = status.AuditRetentionDays;

        _loadingAuditSettings = true;

        try
        {
            _auditEnabledCheck.Checked = status.AuditEnabled;
            _auditDomainCheck.Checked = status.AuditDomainLookup;
            _auditRetentionCombo.SelectedIndex = RetentionDaysToIndex(status.AuditRetentionDays);
        }
        finally
        {
            _loadingAuditSettings = false;
        }

        UpdateAuditControlsEnabled();
        RefreshAudit();
    }

    /// <summary>服务不可用 / 记录关闭时，把不能用的控件灰掉（别让用户点了才发现失败）。</summary>
    private void UpdateAuditControlsEnabled()
    {
        _auditEnabledCheck.Enabled = _serviceAvailable;
        _auditDomainCheck.Enabled = _serviceAvailable && _settings.AuditEnabled;
        _auditRetentionCombo.Enabled = _serviceAvailable && _settings.AuditEnabled;
        _auditRetentionLabel.Enabled = _serviceAvailable;
        _auditClearButton.Enabled = _serviceAvailable;
    }

    private void OnAuditEnabledChanged(object? sender, EventArgs e)
    {
        if (_loadingAuditSettings)
        {
            return;
        }

        var desired = _auditEnabledCheck.Checked;

        if (SuppressBackgroundServices)
        {
            // 自检只验证控件状态，不碰服务（否则没有服务时会弹窗卡住）。
            _settings.AuditEnabled = desired;
            UpdateAuditControlsEnabled();
            return;
        }

        if (!_serviceAvailable)
        {
            RevertAuditControls();
            return;
        }

        var response = CallService(
            ServiceProtocol.Commands.AuditConfigure,
            new ServiceRequest { AuditEnabled = desired },
            "修改记录设置");

        if (response is null)
        {
            RevertAuditControls();
            return;
        }

        _settings.AuditEnabled = desired;
        _settings.Save();

        if (response.Status is not null)
        {
            ApplyAuditStatus(response.Status);
        }
        else
        {
            UpdateAuditControlsEnabled();
            RefreshAudit();
        }
    }

    /// <summary>操作失败：把控件退回服务/内存里的真实值，不留一个"看起来改了"的假开关。</summary>
    private void RevertAuditControls()
    {
        _loadingAuditSettings = true;

        try
        {
            _auditEnabledCheck.Checked = _settings.AuditEnabled;
            _auditDomainCheck.Checked = _settings.AuditDomainLookupEnabled;
            _auditRetentionCombo.SelectedIndex = RetentionDaysToIndex(_settings.AuditRetentionDays);
        }
        finally
        {
            _loadingAuditSettings = false;
        }

        UpdateAuditControlsEnabled();
        RefreshAudit();
    }

    // ==================================================================
    // 记录保留期（1 / 3 / 7 / 30 天）
    // ==================================================================

    /// <summary>下拉框 → 天数。</summary>
    private int SelectedAuditRetentionDays() => _auditRetentionCombo.SelectedIndex switch
    {
        0 => 1,
        1 => 3,
        3 => 30,
        _ => AppSettings.DefaultAuditRetentionDays,
    };

    /// <summary>天数 → 下拉框索引（设置里是 7 天时就选「7 天」）。</summary>
    private static int RetentionDaysToIndex(int days) => days switch
    {
        <= 1 => 0,
        <= 3 => 1,
        <= 7 => 2,
        _ => 3,
    };

    /// <summary>
    /// 保留期改了：交给服务重建采集。
    ///
    /// 为什么必须让服务重建：保留期是 <c>AuditService</c> 的构造参数；
    /// 不重建的话，界面显示"保留 1 天"、实际仍按 7 天清理 —— 那就是**假开关**。
    /// </summary>
    private void OnAuditRetentionChanged(object? sender, EventArgs e)
    {
        if (_loadingAuditSettings)
        {
            return;
        }

        var days = SelectedAuditRetentionDays();

        if (SuppressBackgroundServices)
        {
            _settings.AuditRetentionDays = days;
            return;
        }

        if (_settings.AuditRetentionDays == days)
        {
            return;
        }

        if (!_serviceAvailable)
        {
            RevertAuditControls();
            return;
        }

        var response = CallService(
            ServiceProtocol.Commands.AuditConfigure,
            new ServiceRequest { AuditRetentionDays = days },
            "修改记录保留期");

        if (response is null)
        {
            RevertAuditControls();
            return;
        }

        _settings.AuditRetentionDays = days;
        _settings.Save();
        LocalLog.Operation(LocalLog.Pick($"记录保留期：改为 {days} 天", $"Audit retention changed to {days} days."));

        if (response.Status is not null)
        {
            ApplyAuditStatus(response.Status);
        }
        else
        {
            UpdateAuditControlsEnabled();
            RefreshAudit();
        }
    }

    private void OnAuditDomainChanged(object? sender, EventArgs e)
    {
        if (_loadingAuditSettings)
        {
            return;
        }

        var desired = _auditDomainCheck.Checked;

        if (SuppressBackgroundServices)
        {
            _settings.AuditDomainLookupEnabled = desired;
            return;
        }

        if (!_serviceAvailable)
        {
            RevertAuditControls();
            return;
        }

        var response = CallService(
            ServiceProtocol.Commands.AuditConfigure,
            new ServiceRequest { AuditDomainLookup = desired },
            "修改域名推测设置");

        if (response is null)
        {
            RevertAuditControls();
            return;
        }

        _settings.AuditDomainLookupEnabled = desired;
        _settings.Save();

        if (response.Status is not null)
        {
            ApplyAuditStatus(response.Status);
        }
        else
        {
            UpdateAuditControlsEnabled();
        }
    }

    // ==================================================================
    // 表格
    // ==================================================================

    private sealed record AuditRow(
        DateTime TimeUtc,
        string Kind,
        string ProcessName,
        string ProcessPath,
        string Remote,
        string RemoteAddress,
        string Domain,
        string Rule,
        string Detail);

    private void RefreshAudit()
    {
        try
        {
            var events = _auditStore.ReadRecent(AuditMaxDisplayedRows);
            var idMap = TryGetFilterIdMap();

            var keyword = _auditSearchBox.Text.Trim();
            var blockedOnly = _auditBlockedOnlyCheck.Checked;

            // 数据没变就不重建：每 3 秒重建一次会把用户的选中和滚动位置打断。
            var lastTicks = events.Count > 0 ? events[^1].TimeUtc.Ticks : 0;
            var signature = $"{events.Count}|{lastTicks}|{keyword}|{blockedOnly}|{_auditCollecting}|{_serviceAvailable}";

            if (string.Equals(signature, _auditLastSignature, StringComparison.Ordinal))
            {
                return;
            }

            // 重建前记下当前选中的是哪一条（用内容做 key，行号会变）。
            var selectedKey = _auditGrid.SelectedRows.Count > 0
                              && _auditGrid.SelectedRows[0].Tag is AuditRow selectedRow
                ? selectedRow.Detail
                : null;

            var rows = new List<AuditRow>();

            // ReadRecent 返回时间正序，这里倒过来显示最新的在上面。
            for (var i = events.Count - 1; i >= 0; i--)
            {
                var item = events[i];

                if (blockedOnly && item.Kind != AuditEventKind.Blocked)
                {
                    continue;
                }

                var processName = string.IsNullOrEmpty(item.ProcessPath)
                    ? "（未知程序）"
                    : Path.GetFileName(item.ProcessPath);

                var rule = item.FilterId != 0 && idMap.TryGetValue(item.FilterId, out var name)
                    ? name
                    : item.FilterId != 0 ? $"（ID {item.FilterId}）" : string.Empty;

                var domain = string.IsNullOrEmpty(item.Domain) ? "未知" : item.Domain;

                if (keyword.Length > 0
                    && !Contains(item.ProcessPath, keyword)
                    && !Contains(processName, keyword)
                    && !Contains(item.RemoteAddress, keyword)
                    && !Contains(item.Domain, keyword))
                {
                    continue;
                }

                rows.Add(new AuditRow(
                    item.TimeUtc,
                    item.Kind == AuditEventKind.Blocked ? "拦截" : "连接",
                    processName,
                    item.ProcessPath,
                    $"{item.RemoteAddress}:{item.RemotePort}",
                    item.RemoteAddress,
                    domain,
                    rule,
                    $"{item.TimeUtc.ToLocalTime():yyyy-MM-dd HH:mm:ss}  " +
                    $"{(item.Kind == AuditEventKind.Blocked ? "拦截" : "连接")}  " +
                    $"{item.ProcessPath} → {item.RemoteAddress}:{item.RemotePort}" +
                    (string.IsNullOrEmpty(item.Domain) ? "（域名未知）" : $"（{item.Domain}，推测）") +
                    (rule.Length > 0 ? $"  命中：{rule}" : string.Empty)));
            }

            _auditGrid.SuspendLayout();
            try
            {
                _auditGrid.Rows.Clear();

                foreach (var row in rows)
                {
                    var index = _auditGrid.Rows.Add(
                        row.TimeUtc.ToLocalTime().ToString("MM-dd HH:mm:ss"),
                        row.Kind,
                        row.ProcessName,
                        row.Remote,
                        row.Domain,
                        row.Rule);

                    _auditGrid.Rows[index].Tag = row;
                }

                // 恢复之前的选中（按内容匹配）；找不到就不选，避免自动跳到第一行。
                _auditGrid.ClearSelection();

                if (selectedKey is not null)
                {
                    foreach (DataGridViewRow gridRow in _auditGrid.Rows)
                    {
                        if (gridRow.Tag is AuditRow candidate && candidate.Detail == selectedKey)
                        {
                            gridRow.Selected = true;
                            break;
                        }
                    }
                }
            }
            finally
            {
                _auditGrid.ResumeLayout();
            }

            var blocked = rows.Count(row => row.Kind == "拦截");
            var withDomain = events.Count(item => !string.IsNullOrEmpty(item.Domain));
            var total = events.Count;

            if (Localizer.IsEnglish)
            {
                var state = !_serviceAvailable
                    ? "service is not running; recording stopped"
                    : _auditCollecting
                        ? "recording"
                        : _settings.AuditEnabled
                            ? "recording is not running (see logs)"
                            : "recording is off";

                _auditStatusLabel.Text =
                    $"Showing {rows.Count} entries ({blocked} blocked) · " +
                    $"{withDomain} of the latest {total} have a domain · " +
                    $"retention {_settings.AuditRetentionDays} days · {state}";
            }
            else
            {
                _auditStatusLabel.Text =
                    $"显示 {rows.Count} 条（拦截 {blocked}）· 最近 {total} 条里有 {withDomain} 条带域名" +
                    $" · 保留 {_settings.AuditRetentionDays} 天 · " +
                    (!_serviceAvailable
                        ? "服务未运行，记录已停止"
                        : _auditCollecting
                            ? "记录中"
                            : _settings.AuditEnabled
                                ? "记录未启动（详见日志）"
                                : "记录未开启");
            }

            _auditLastSignature = signature;
            UpdateAuditDetail();
        }
        catch (Exception ex)
        {
            LocalLog.Error(LocalLog.Pick("刷新审计列表失败", "Failed to refresh the audit list."), ex);
            _auditStatusLabel.Text = Localizer.T("读取审计记录失败（详见日志）");
        }
    }

    /// <summary>右键点在哪个行上就操作哪个行（右键默认不会改变选中）。</summary>
    private void OnAuditGridCellMouseDown(object? sender, DataGridViewCellMouseEventArgs e)
    {
        if (e.Button == MouseButtons.Right && e.RowIndex >= 0 && e.RowIndex < _auditGrid.Rows.Count)
        {
            _auditGrid.CurrentCell = _auditGrid.Rows[e.RowIndex].Cells[0];
        }
    }

    /// <summary>当前选中的记录（没有选中返回 null）。</summary>
    private AuditRow? GetSelectedAuditRow()
        => _auditGrid.SelectedRows.Count > 0 && _auditGrid.SelectedRows[0].Tag is AuditRow row
            ? row
            : null;

    /// <summary>把选中行的某个字段复制到剪贴板；空值给一句明确提示，不静默失败。</summary>
    private void CopyFromSelectedAuditRow(Func<AuditRow, string> selector, string emptyMessage)
    {
        var row = GetSelectedAuditRow();

        if (row is null)
        {
            return;
        }

        var value = selector(row);

        if (string.IsNullOrWhiteSpace(value))
        {
            UiMessageBox.Show(
                this,
                emptyMessage,
                AppConstants.AppName,
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
            return;
        }

        try
        {
            Clipboard.SetText(value);
        }
        catch (Exception ex)
        {
            // 剪贴板被别的程序占用时 SetText 会抛异常，不能让它把程序带崩。
            ShowError("复制失败", ex, "Copy failed");
        }
    }

    private void UpdateAuditDetail()
    {
        if (_auditGrid.SelectedRows.Count == 0
            || _auditGrid.SelectedRows[0].Tag is not AuditRow row)
        {
            _auditDetailLabel.Text = Localizer.T("选中一行查看完整路径与命中规则。");
            return;
        }

        _auditDetailLabel.Text = row.Detail;
    }

    private void OnAuditCellFormatting(object? sender, DataGridViewCellFormattingEventArgs e)
    {
        if (e.RowIndex < 0 || _auditGrid.Rows[e.RowIndex].Tag is not AuditRow row)
        {
            return;
        }

        if (row.Kind == "拦截")
        {
            e.CellStyle.ForeColor = Color.FromArgb(180, 30, 30);
        }
    }

    private void OnAuditClearClick(object? sender, EventArgs e)
    {
        var confirmed = ConfirmForm.Show(
            owner: DialogOwner,
            title: "清空记录",
            question: "确定要删除全部记录吗？",
            details: new[]
            {
                new KeyValuePair<string, string>("将要做的", "删除本机上的全部记录文件"),
                new KeyValuePair<string, string>("不可恢复", "删除后无法找回"),
            },
            warnings: new[]
            {
                "只删除记录，不影响任何防火墙规则。",
                "以后的新连接会继续被记录（如果你没关闭「记录连接」）。",
            },
            confirmText: "清空");

        if (!confirmed)
        {
            return;
        }

        // 3.0-c：采集在服务里，删除也必须由服务做 ——
        // 它开着写入端时 Windows 不允许删除这些文件。
        var response = CallService(
            ServiceProtocol.Commands.AuditClear,
            new ServiceRequest(),
            "清空记录");

        if (response is null)
        {
            RefreshAudit();
            return;
        }

        LocalLog.Operation(LocalLog.Pick($"记录：用户清空了记录，删除 {response.Affected} 个文件", $"Audit records cleared by user: {response.Affected} files deleted."));

        RefreshAudit();

        var remaining = _auditStore.GetFiles().Count;

        if (remaining > 0)
        {
            LocalLog.Warning(LocalLog.Pick($"记录：清空后仍有 {remaining} 个文件删不掉", $"After clearing, {remaining} audit files still could not be deleted."));
            UiMessageBox.Show(
                this,
                $"有 {remaining} 个记录文件删不掉（可能正被其它程序占用）。\n" +
                $"已删除 {response.Affected} 个。\n\n" +
                $"可以稍后再试，或手动删除：\n{_auditStore.DirectoryPath}",
                AppConstants.AppName,
                MessageBoxButtons.OK,
                MessageBoxIcon.Warning);
        }
    }

    private void OnAuditOpenFolderClick(object? sender, EventArgs e)
    {
        try
        {
            Directory.CreateDirectory(_auditStore.DirectoryPath);
            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = _auditStore.DirectoryPath,
                UseShellExecute = true,
            });
        }
        catch (Exception ex)
        {
            ShowError("打开审计目录失败", ex, "Failed to open the audit folder");
        }
    }

    /// <summary>「拦截此 IP…」：取当前选中行的远端 IP。</summary>
    private void OnBlockSelectedIpClick(object? sender, EventArgs e)
    {
        if (_auditGrid.SelectedRows.Count == 0 || _auditGrid.SelectedRows[0].Tag is not AuditRow row)
        {
            UiMessageBox.Show(
                this,
                "先在上面选中一行记录，再点「拦截此 IP…」。",
                AppConstants.AppName,
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
            return;
        }

        if (string.IsNullOrWhiteSpace(row.RemoteAddress))
        {
            UiMessageBox.Show(
                this,
                "这条记录没有可用的远端 IP。",
                AppConstants.AppName,
                MessageBoxButtons.OK,
                MessageBoxIcon.Warning);
            return;
        }

        BlockIpWithConfirmation(row.RemoteAddress);
    }

    /// <summary>「添加 IP…」：手动输入一个 IP。</summary>
    private void OnAddIpRuleClick(object? sender, EventArgs e)
    {
        var input = Microsoft.VisualBasic.Interaction.InputBox(
            "输入要封禁的 IP（IPv4 或 IPv6）：",
            "封禁 IP",
            string.Empty);

        if (string.IsNullOrWhiteSpace(input))
        {
            return;
        }

        BlockIpWithConfirmation(input.Trim());
    }

    /// <summary>
    /// 确认并创建一条「封禁 IP」规则。
    ///
    /// 必须在确认框里写清"拦的是 IP，不是网站"：同一个 IP 上的其它服务会一起被拦。
    /// </summary>
    private void BlockIpWithConfirmation(string ipText)
    {
        if (!System.Net.IPAddress.TryParse(ipText, out var address))
        {
            UiMessageBox.Show(
                this,
                $"不是合法的 IP 地址：{ipText}",
                AppConstants.AppName,
                MessageBoxButtons.OK,
                MessageBoxIcon.Warning);
            return;
        }

        var normalized = address.ToString();

        var confirmed = ConfirmForm.Show(
            owner: DialogOwner,
            title: "封禁 IP",
            question: $"确定要封禁 IP「{normalized}」吗？",
            details: new[]
            {
                new KeyValuePair<string, string>("目标 IP", normalized),
                new KeyValuePair<string, string>("影响", "所有程序发往这个 IP 的新连接都会被拦"),
            },
            warnings: new[]
            {
                "拦的是 IP，不是网站：同一个 IP 上的其它服务可能一起被拦。",
                "大网站（CDN）会经常更换 IP，封禁某个 IP 不一定能封住整个网站。",
                "「记录」页里能看到它拦下了哪些连接，随时可以删除这条规则。",
            },
            confirmText: "封禁");

        if (!confirmed)
        {
            return;
        }

        try
        {
            var response = CallService(
                ServiceProtocol.Commands.AddIpRule,
                new ServiceRequest { Value = normalized },
                "封禁 IP");

            if (response is null)
            {
                return;
            }

            LocalLog.Operation(LocalLog.Pick($"封禁 IP：{normalized}", $"Block IP: {normalized}."));

            AfterRulesChanged();
            RefreshAudit();
        }
        catch (Exception ex)
        {
            ShowError("封禁 IP 失败", ex, "Failed to block the IP");
        }
    }

    private static bool Contains(string? text, string keyword)
        => !string.IsNullOrEmpty(text) && text.Contains(keyword, StringComparison.OrdinalIgnoreCase);
    /// <summary>
    /// 过滤器 ID → 规则名。3.0-b 起由服务提供（服务持有 WFP 访问权）；
    /// 服务不可用时返回空表，记录页照常显示，只是不显示规则名。
    /// </summary>
    private static Dictionary<ulong, string> TryGetFilterIdMap()
    {
        try
        {
            var response = ServiceClient.TryRequest(
                new ServiceRequest { Command = ServiceProtocol.Commands.FilterMap },
                TimeSpan.FromSeconds(2),
                out _);

            if (response is not { Ok: true, FilterMap: not null })
            {
                return new Dictionary<ulong, string>();
            }

            var map = new Dictionary<ulong, string>();

            foreach (var pair in response.FilterMap)
            {
                if (ulong.TryParse(pair.Key, out var id))
                {
                    map[id] = pair.Value;
                }
            }

            return map;
        }
        catch (Exception)
        {
            return new Dictionary<ulong, string>();
        }
    }
}
