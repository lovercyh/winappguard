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
    private CheckBox _auditAlertCheck = null!;
    private CheckBox _learningCheck = null!;
    private ComboBox _learningMinutesCombo = null!;
    private Label _learningStatusLabel = null!;
    private Label _auditStatusLabel = null!;
    private Label _auditDetailLabel = null!;
    private DataGridView _auditGrid = null!;
    private System.Windows.Forms.Timer? _auditTimer;
    private System.Windows.Forms.Timer? _learningTimer;
    private AuditService? _auditService;
    private bool _loadingAuditSettings;

    /// <summary>学习模式是否正在进行（**只在本进程内**，不落盘）。</summary>
    private bool _learningActive;

    /// <summary>学习模式开始时间：用它筛出"这段时间里第一次出现的程序"。</summary>
    private DateTime _learningStartUtc;

    /// <summary>学习模式结束时间；null = 用户选择了「直到关闭」。</summary>
    private DateTime? _learningEndUtc;

    /// <summary>等待提示的程序（告警是后台线程来的，必须排队串行显示）。</summary>
    private readonly Queue<string> _pendingPrompts = new();

    /// <summary>已经在队列里的程序，避免同一个程序排两次。</summary>
    private readonly HashSet<string> _promptQueued = new(StringComparer.OrdinalIgnoreCase);

    private bool _promptActive;

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
            Height = 106,
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

        // ---- 第三行：新程序提醒 + 学习模式 ----
        _auditAlertCheck = new CheckBox
        {
            Location = new Point(0, 72),
            Width = 118,
            Text = "新程序提醒",
        };
        _auditAlertCheck.CheckedChanged += OnAuditAlertChanged;

        _learningCheck = new CheckBox
        {
            Location = new Point(126, 72),
            Width = 110,
            Text = "学习模式",
        };
        _learningCheck.CheckedChanged += OnLearningChanged;

        _learningMinutesCombo = new ComboBox
        {
            Location = new Point(240, 70),
            Width = 116,
            DropDownStyle = ComboBoxStyle.DropDownList,
        };
        _learningMinutesCombo.Items.AddRange(new object[]
        {
            "30 分钟",
            "1 小时",
            "2 小时",
            "直到关闭",
        });
        _learningMinutesCombo.SelectedIndex = 1;

        _learningStatusLabel = new Label
        {
            Location = new Point(366, 74),
            Width = 610,
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
            blockIpButton,
            addIpButton,
            _auditEnabledCheck,
            _auditDomainCheck,
            _auditStatusLabel,
            _auditAlertCheck,
            _learningCheck,
            _learningMinutesCombo,
            _learningStatusLabel,
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
        _auditAlertCheck.Checked = _settings.NewProgramAlertEnabled;
        _auditAlertCheck.Enabled = _settings.AuditEnabled;
        _loadingAuditSettings = false;

        _learningTimer = new System.Windows.Forms.Timer { Interval = 1000 };
        _learningTimer.Tick += (_, _) => UpdateLearningStatus();

        _auditTimer.Start();
        _learningTimer.Start();
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

            // 告警是后台线程发出来的：这里只做排队，弹窗一律回 UI 线程。
            _auditService.NewPrograms.NewProgramDetected += OnNewProgramDetected;

            // 服务是新建的，抑制状态要重新应用一次（否则重建服务会把学习模式/关提醒"忘掉"）。
            ApplyAlertSuppression();

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
        _auditAlertCheck.Enabled = _settings.AuditEnabled;

        StopAuditService();

        // 关掉记录就等于没有"新程序"可看：学习模式一并收尾（不再弹汇总窗）。
        if (_learningActive)
        {
            EndLearning(showSummary: false);
        }

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
    // 新程序提醒 与 学习模式
    // ==================================================================

    private void OnAuditAlertChanged(object? sender, EventArgs e)
    {
        if (_loadingAuditSettings)
        {
            return;
        }

        _settings.NewProgramAlertEnabled = _auditAlertCheck.Checked;
        _settings.Save();

        // 关掉提醒后仍然记录 —— 只是不再弹窗（"我不想知道，别打扰我"）。
        ApplyAlertSuppression();
    }

    /// <summary>是否抑制新程序提示：学习模式中，或用户关了提醒。</summary>
    private bool IsAlertSuppressed()
        => _learningActive || !_settings.NewProgramAlertEnabled;

    private void ApplyAlertSuppression()
    {
        if (_auditService is not null)
        {
            _auditService.LearningMode = IsAlertSuppressed();
        }
    }

    private void OnLearningChanged(object? sender, EventArgs e)
    {
        if (_loadingAuditSettings)
        {
            return;
        }

        if (_learningCheck.Checked)
        {
            StartLearning();
        }
        else
        {
            EndLearning(showSummary: true);
        }
    }

    /// <summary>下拉框选的时长（分钟）；0 = 直到手动关闭。</summary>
    private int SelectedLearningMinutes() => _learningMinutesCombo.SelectedIndex switch
    {
        0 => 30,
        1 => 60,
        2 => 120,
        _ => 0,
    };

    private void StartLearning()
    {
        if (_auditService is null)
        {
            _loadingAuditSettings = true;
            _learningCheck.Checked = false;
            _loadingAuditSettings = false;

            MessageBox.Show(
                this,
                "学习模式需要先打开「记录连接」。",
                AppConstants.AppName,
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
            return;
        }

        _learningActive = true;
        _learningStartUtc = DateTime.UtcNow;

        var minutes = SelectedLearningMinutes();
        _learningEndUtc = minutes > 0 ? _learningStartUtc.AddMinutes(minutes) : null;

        _learningMinutesCombo.Enabled = false;
        ApplyAlertSuppression();
        UpdateLearningStatus();

        LocalLog.Operation(minutes > 0
            ? $"学习模式：开始（{minutes} 分钟）"
            : "学习模式：开始（直到手动关闭）");
    }

    private void EndLearning(bool showSummary)
    {
        if (!_learningActive)
        {
            return;
        }

        _learningActive = false;
        _learningEndUtc = null;
        _learningMinutesCombo.Enabled = true;

        // 程序化取消勾选，别让 CheckedChanged 再进来一次。
        _loadingAuditSettings = true;
        _learningCheck.Checked = false;
        _loadingAuditSettings = false;

        ApplyAlertSuppression();
        _learningStatusLabel.Text = string.Empty;

        LocalLog.Operation("学习模式：结束");

        if (showSummary)
        {
            ShowLearningSummary();
        }
    }

    private void UpdateLearningStatus()
    {
        if (!_learningActive)
        {
            if (_learningStatusLabel.Text.Length > 0)
            {
                _learningStatusLabel.Text = string.Empty;
            }

            return;
        }

        if (_learningEndUtc is { } end && DateTime.UtcNow >= end)
        {
            EndLearning(showSummary: true);
            return;
        }

        var remaining = _learningEndUtc is { } limit
            ? $"剩余 {FormatRemaining(limit - DateTime.UtcNow)}"
            : "直到你手动关闭";

        var count = CountNewProgramsSince(_learningStartUtc);

        _learningStatusLabel.Text =
            $"学习模式：只记录、不询问 · {remaining} · 已发现新程序 {count} 个";

        // 服务可能刚被重建，顺手把抑制状态对齐。
        ApplyAlertSuppression();
    }

    private static string FormatRemaining(TimeSpan span)
    {
        if (span < TimeSpan.Zero)
        {
            span = TimeSpan.Zero;
        }

        return span.TotalHours >= 1
            ? $"{(int)span.TotalHours} 小时 {span.Minutes} 分"
            : $"{span.Minutes} 分 {span.Seconds} 秒";
    }

    private int CountNewProgramsSince(DateTime startUtc)
    {
        var store = _auditService?.NewPrograms.Store;

        return store is null
            ? 0
            : store.All().Count(program => program.FirstSeenUtc >= startUtc);
    }

    /// <summary>告警回调（**后台线程**）：只负责排队，弹窗一律回到 UI 线程。</summary>
    private void OnNewProgramDetected(string path)
    {
        if (IsDisposed || !IsHandleCreated)
        {
            return;
        }

        try
        {
            BeginInvoke(new Action(() => QueuePrompt(path)));
        }
        catch (Exception ex) when (ex is InvalidOperationException or ObjectDisposedException)
        {
            // 窗口正在关闭，丢弃这次提示即可。
        }
    }

    private void QueuePrompt(string path)
    {
        if (IsDisposed || !_promptQueued.Add(path))
        {
            return;
        }

        _pendingPrompts.Enqueue(path);
        ProcessPromptQueue();
    }

    /// <summary>
    /// 串行地弹提示：一次只显示一个。
    /// 同时来 5 个新程序就叠 5 个模态窗 —— 那不是提醒，是卡死。
    /// </summary>
    private void ProcessPromptQueue()
    {
        if (_promptActive || IsDisposed)
        {
            return;
        }

        _promptActive = true;

        try
        {
            while (_pendingPrompts.Count > 0)
            {
                var path = _pendingPrompts.Dequeue();
                _promptQueued.Remove(path);

                if (IsDisposed)
                {
                    return;
                }

                PromptForNewProgram(path);
            }
        }
        finally
        {
            _promptActive = false;
        }
    }

    private void PromptForNewProgram(string path)
    {
        var choice = NewProgramPrompt.Ask(DialogOwner, path);
        var store = _auditService?.NewPrograms.Store;

        try
        {
            switch (choice)
            {
                case NewProgramChoice.Allow:
                    store?.SetDecision(path, ProgramDecision.Allowed, DateTime.UtcNow);
                    LocalLog.Operation($"新程序：允许联网 {path}");
                    break;

                case NewProgramChoice.Ignore:
                    store?.SetDecision(path, ProgramDecision.Ignored, DateTime.UtcNow);
                    LocalLog.Operation($"新程序：忽略 {path}");
                    break;

                case NewProgramChoice.Block:
                    store?.SetDecision(path, ProgramDecision.Blocked, DateTime.UtcNow);

                    var ruleName = RuleEngine.CreateBlockRule(path);
                    LocalLog.Operation($"新程序：阻止联网 {path}（规则 {ruleName}）");

                    AfterRulesChanged();
                    break;

                default:
                    // 「稍后」= 忘掉它，下次联网再问（不是"永不询问"）。
                    store?.Forget(path);
                    break;
            }

            store?.Save();
        }
        catch (Exception ex)
        {
            ShowError("处理新程序失败", ex);
        }
    }

    /// <summary>学习模式结束：列出这段时间新出现的程序，一次决定阻止/允许。</summary>
    private void ShowLearningSummary()
    {
        var store = _auditService?.NewPrograms.Store;

        if (store is null)
        {
            return;
        }

        var programs = store.All()
            .Where(program => program.FirstSeenUtc >= _learningStartUtc)
            .ToList();

        if (programs.Count == 0)
        {
            MessageBox.Show(
                this,
                "学习期间没有新程序联网。",
                AppConstants.AppName,
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
            return;
        }

        var toBlock = LearningSummaryForm.Ask(DialogOwner, programs);

        if (toBlock is null)
        {
            // 取消 = 什么都不改（不会把程序静默标成"允许"）。
            return;
        }

        var blocked = new HashSet<string>(toBlock, StringComparer.OrdinalIgnoreCase);
        var now = DateTime.UtcNow;
        var failed = 0;

        foreach (var program in programs)
        {
            var shouldBlock = blocked.Contains(program.Path);

            store.SetDecision(
                program.Path,
                shouldBlock ? ProgramDecision.Blocked : ProgramDecision.Allowed,
                now);

            if (!shouldBlock)
            {
                continue;
            }

            try
            {
                RuleEngine.CreateBlockRule(program.Path);
            }
            catch (Exception ex)
            {
                failed++;
                LocalLog.Error($"学习模式：阻止 {program.Path} 失败", ex);
            }
        }

        store.Save();
        AfterRulesChanged();
        RefreshAudit();

        LocalLog.Operation($"学习模式：处理 {programs.Count} 个新程序，阻止 {blocked.Count} 个");

        if (failed > 0)
        {
            MessageBox.Show(
                this,
                $"有 {failed} 个程序没能阻止（详情见日志）。\n其余已处理。",
                AppConstants.AppName,
                MessageBoxButtons.OK,
                MessageBoxIcon.Warning);
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
            var signature = $"{events.Count}|{lastTicks}|{keyword}|{blockedOnly}|{_auditService is null}";

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

            _auditStatusLabel.Text =
                $"显示 {rows.Count} 条（拦截 {blocked}）· 最近 {total} 条里有 {withDomain} 条带域名" +
                (_auditService is null ? " · 记录未开启" : " · 记录中");

            _auditLastSignature = signature;
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

    /// <summary>「拦截此 IP…」：取当前选中行的远端 IP。</summary>
    private void OnBlockSelectedIpClick(object? sender, EventArgs e)
    {
        if (_auditGrid.SelectedRows.Count == 0 || _auditGrid.SelectedRows[0].Tag is not AuditRow row)
        {
            MessageBox.Show(
                this,
                "先在上面选中一行记录，再点「拦截此 IP…」。",
                AppConstants.AppName,
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
            return;
        }

        if (string.IsNullOrWhiteSpace(row.RemoteAddress))
        {
            MessageBox.Show(
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
            MessageBox.Show(
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
            var created = RuleEngine.CreateIpBlockRule(normalized);
            LocalLog.Operation($"封禁 IP：{normalized}（规则 {created}）");

            AfterRulesChanged();
            RefreshAudit();
        }
        catch (Exception ex)
        {
            ShowError("封禁 IP 失败", ex);
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
