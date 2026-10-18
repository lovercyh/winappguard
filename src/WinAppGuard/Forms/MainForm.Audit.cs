using WinAppGuard.Core;
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

    private readonly AuditStore _auditStore = new();

    private TextBox _auditSearchBox = null!;
    private CheckBox _auditBlockedOnlyCheck = null!;
    private CheckBox _auditEnabledCheck = null!;
    private CheckBox _auditDomainCheck = null!;
    private Label _auditStatusLabel = null!;
    private Label _auditDetailLabel = null!;
    private DataGridView _auditGrid = null!;
    private System.Windows.Forms.Timer? _auditTimer;
    private AuditService? _auditService;
    private bool _loadingAuditSettings;

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

        var clearButton = new Button
        {
            Location = new Point(440, 6),
            Width = 76,
            Text = "清空…",
        };
        clearButton.Click += OnAuditClearClick;

        var openFolderButton = new Button
        {
            Location = new Point(524, 6),
            Width = 108,
            Text = "打开目录",
        };
        openFolderButton.Click += OnAuditOpenFolderClick;

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
            clearButton,
            openFolderButton,
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

        var bottom = new Panel
        {
            Dock = DockStyle.Bottom,
            Height = 40,
            Padding = new Padding(0, 4, 0, 0),
        };

        _auditDetailLabel = new Label
        {
            Dock = DockStyle.Fill,
            Text = "选中一行查看完整路径与命中规则。",
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
        _loadingAuditSettings = false;

        _auditTimer.Start();
        RefreshAudit();
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

    private void StartAuditIfEnabled()
    {
        if (SuppressBackgroundServices || !_settings.AuditEnabled)
        {
            return;
        }

        try
        {
            _auditService = new AuditService(
                pollSeconds: 3,
                allowDomainLookup: _settings.AuditDomainLookupEnabled);

            _auditService.Start();
        }
        catch (Exception ex)
        {
            _auditService?.Dispose();
            _auditService = null;
            LocalLog.Error("启动审计服务失败", ex);
        }
    }

    private void StopAuditService()
    {
        try
        {
            _auditService?.Dispose();
        }
        catch (Exception ex)
        {
            LocalLog.Warning($"停止审计服务时出错：{ex.Message}");
        }

        _auditService = null;
    }

    private void OnAuditEnabledChanged(object? sender, EventArgs e)
    {
        if (_loadingAuditSettings)
        {
            return;
        }

        _settings.AuditEnabled = _auditEnabledCheck.Checked;
        _settings.Save();

        _auditDomainCheck.Enabled = _settings.AuditEnabled;

        StopAuditService();

        if (_settings.AuditEnabled)
        {
            StartAuditIfEnabled();
        }

        RefreshAudit();
    }

    private void OnAuditDomainChanged(object? sender, EventArgs e)
    {
        if (_loadingAuditSettings)
        {
            return;
        }

        _settings.AuditDomainLookupEnabled = _auditDomainCheck.Checked;
        _settings.Save();

        // 域名开关是服务构造参数：必须重建服务才能生效。
        if (_settings.AuditEnabled)
        {
            StopAuditService();
            StartAuditIfEnabled();
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
            }
            finally
            {
                _auditGrid.ResumeLayout();
            }

            var blocked = rows.Count(row => row.Kind == "拦截");
            var withDomain = events.Count(item => !string.IsNullOrEmpty(item.Domain));
            var total = events.Count;

            _auditStatusLabel.Text =
                $"显示 {rows.Count} 条（拦截 {blocked}）· 最近 {total} 条里有 {withDomain} 条带域名" +
                (_auditService is null ? " · 记录未开启" : " · 记录中");

            UpdateAuditDetail();
        }
        catch (Exception ex)
        {
            LocalLog.Error("刷新审计列表失败", ex);
            _auditStatusLabel.Text = "读取审计记录失败（详见日志）";
        }
    }

    private void UpdateAuditDetail()
    {
        if (_auditGrid.SelectedRows.Count == 0
            || _auditGrid.SelectedRows[0].Tag is not AuditRow row)
        {
            _auditDetailLabel.Text = "选中一行查看完整路径与命中规则。";
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

        // ⚠️ 必须先停掉审计服务：它开着写入端时，Windows 不允许删除这些文件。
        var wasRunning = _auditService is not null;

        if (wasRunning)
        {
            StopAuditService();
        }

        var deleted = 0;

        try
        {
            deleted = _auditStore.Clear();
            LocalLog.Operation($"记录：用户清空了记录，删除 {deleted} 个文件");
        }
        catch (Exception ex)
        {
            ShowError("清空记录失败", ex);
        }
        finally
        {
            if (wasRunning)
            {
                StartAuditIfEnabled();
            }
        }

        RefreshAudit();

        var remaining = _auditStore.GetFiles().Count;

        if (remaining > 0)
        {
            LocalLog.Warning($"记录：清空后仍有 {remaining} 个文件删不掉");
            MessageBox.Show(
                this,
                $"有 {remaining} 个记录文件删不掉（可能正被其它程序占用）。\n" +
                $"已删除 {deleted} 个。\n\n" +
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
            ShowError("打开审计目录失败", ex);
        }
    }

    private static bool Contains(string? text, string keyword)
        => !string.IsNullOrEmpty(text) && text.Contains(keyword, StringComparison.OrdinalIgnoreCase);

    /// <summary>过滤器 ID → 规则名。取不到（例如没有管理员权限）时返回空表，不影响列表显示。</summary>
    private static Dictionary<ulong, string> TryGetFilterIdMap()
    {
        try
        {
            return RuleEngine.GetFilterIdToRuleName();
        }
        catch (Exception)
        {
            return new Dictionary<ulong, string>();
        }
    }
}
