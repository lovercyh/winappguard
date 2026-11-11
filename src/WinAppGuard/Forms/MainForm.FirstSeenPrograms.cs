using WinAppGuard.Contracts;
using WinAppGuard.Core;
using WinAppGuard.Localization;
using WinAppGuard.Models;

namespace WinAppGuard.Forms;

/// <summary>
/// 5.8：新程序联网提醒。
///
/// 独立页面，不放在设置页里：
///   - 模式默认关闭，只有用户明确开启后才记录；
///   - 只记录本模式开启后看到的程序路径和联网时间；
///   - 只在本机保存，不记录 IP / 域名 / 端口，不上传；
///   - 不自动拦截，用户可从这里阻止或加入严格模式白名单。
/// </summary>
public sealed partial class MainForm
{
    private static readonly TimeSpan FirstSeenBalloonCooldown = TimeSpan.FromSeconds(10);
    private const int FirstSeenRefreshIntervalMs = 3000;

    private readonly BindingSource _firstSeenSource = new();
    private readonly List<FirstSeenProgramRecord> _firstSeenView = new();

    private TabPage _tabFirstSeenPrograms = null!;
    private Button _firstSeenModeButton = null!;
    private CheckBox _firstSeenBalloonCheckBox = null!;
    private CheckBox _firstSeenDefaultBlockCheckBox = null!;
    private CheckBox _firstSeenOnlyNewCheckBox = null!;
    private TextBox _firstSeenSearchBox = null!;
    private Button _firstSeenRefreshButton = null!;
    private Button _firstSeenBlockButton = null!;
    private Button _firstSeenReleaseGuardButton = null!;
    private Button _firstSeenWhitelistButton = null!;
    private Button _firstSeenKnownButton = null!;
    private Button _firstSeenAckAllButton = null!;
    private Button _firstSeenDeleteButton = null!;
    private Button _firstSeenClearButton = null!;
    private Button _firstSeenExportButton = null!;
    private Label _firstSeenStatusLabel = null!;
    private DataGridViewBuffered _firstSeenGrid = null!;
    private ContextMenuStrip _firstSeenMenu = null!;

    private FirstSeenProgramStore _firstSeenStore = null!;
    private System.Windows.Forms.Timer? _firstSeenTimer;
    private bool _firstSeenLoading;
    private bool _firstSeenBaselinePending;
    private DateTime _lastFirstSeenBalloonUtc = DateTime.MinValue;

    private readonly Queue<(FirstSeenProgramRecord Record, bool Guarded)> _firstSeenPromptQueue = new();
    private readonly HashSet<string> _firstSeenPrompted = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> _firstSeenGuardedPaths = new(StringComparer.OrdinalIgnoreCase);
    private bool _firstSeenPromptShowing;

    private void InitializeFirstSeenProgramsPage()
    {
        // 自检工具不应该读写用户的真实程序记录。
        _firstSeenStore = SuppressBackgroundServices
            ? new FirstSeenProgramStore(Path.Combine(
                Path.GetTempPath(), $"wag-first-seen-{Guid.NewGuid():N}.json"))
            : new FirstSeenProgramStore();

        _tabFirstSeenPrograms = new TabPage
        {
            Text = Localizer.T("新程序联网提醒"),
            Padding = new Padding(9),
            UseVisualStyleBackColor = true,
        };

        var top = new Panel
        {
            Dock = DockStyle.Top,
            Height = 200,
            Padding = new Padding(0, 4, 0, 0),
        };

        var modeRow = new FlowLayoutPanel
        {
            Dock = DockStyle.Top,
            Height = 38,
            FlowDirection = FlowDirection.LeftToRight,
            WrapContents = false,
            Padding = new Padding(0, 0, 0, 4),
        };

        _firstSeenModeButton = new Button
        {
            Text = Localizer.T("开启新程序联网提醒"),
            AutoSize = false,
            Size = new Size(200, 32),
            Margin = new Padding(0, 0, 14, 0),
            UseVisualStyleBackColor = true,
            TabIndex = 0,
        };
        _firstSeenModeButton.Click += OnFirstSeenModeButtonClick;

        _firstSeenBalloonCheckBox = new CheckBox
        {
            AutoSize = true,
            Text = Localizer.T("发现新程序时显示托盘提示"),
            Margin = new Padding(0, 8, 0, 0),
        };
        _firstSeenBalloonCheckBox.CheckedChanged += OnFirstSeenBalloonChanged;

        modeRow.Controls.Add(_firstSeenModeButton);
        modeRow.Controls.Add(_firstSeenBalloonCheckBox);

        var defaultBlockRow = new FlowLayoutPanel
        {
            Dock = DockStyle.Top,
            Height = 28,
            FlowDirection = FlowDirection.LeftToRight,
            WrapContents = false,
            Padding = new Padding(0, 0, 0, 4),
        };

        _firstSeenDefaultBlockCheckBox = new CheckBox
        {
            AutoSize = true,
            Text = Localizer.T("新程序默认阻止并弹窗询问（高风险）"),
            ForeColor = Color.FromArgb(180, 30, 30),
            Margin = new Padding(0, 3, 0, 0),
        };
        _firstSeenDefaultBlockCheckBox.CheckedChanged += OnFirstSeenDefaultBlockChanged;
        defaultBlockRow.Controls.Add(_firstSeenDefaultBlockCheckBox);

        var description = new Label
        {
            AutoSize = false,
            Dock = DockStyle.Top,
            Height = 38,
            ForeColor = Color.FromArgb(191, 87, 0),
            Text = Localizer.T(
                "只记录本模式开启后的程序路径和联网时间；开启前已联网的程序记为「启用时已在线」。" +
                "不记录 IP、域名或连接内容，不会上传。"),
        };

        var toolbar = new FlowLayoutPanel
        {
            Dock = DockStyle.Top,
            Height = 66,
            FlowDirection = FlowDirection.LeftToRight,
            WrapContents = true,
            Padding = new Padding(0, 4, 0, 4),
        };

        _firstSeenSearchBox = new TextBox
        {
            Width = 220,
            PlaceholderText = Localizer.T("搜索：程序 / 路径"),
            Margin = new Padding(0, 2, 8, 0),
        };
        _firstSeenSearchBox.TextChanged += (_, _) => RebuildFirstSeenView();

        _firstSeenOnlyNewCheckBox = new CheckBox
        {
            AutoSize = true,
            Text = Localizer.T("只看新程序"),
            Margin = new Padding(0, 6, 8, 0),
        };
        _firstSeenOnlyNewCheckBox.CheckedChanged += (_, _) => RebuildFirstSeenView();

        _firstSeenRefreshButton = CreateFirstSeenButton("刷新", OnFirstSeenRefreshClick);
        _firstSeenBlockButton = CreateFirstSeenButton("阻止联网", OnFirstSeenBlockClick);
        _firstSeenReleaseGuardButton = CreateFirstSeenButton("释放临时阻止", OnFirstSeenReleaseGuardClick);
        _firstSeenWhitelistButton = CreateFirstSeenButton("加入白名单", OnFirstSeenWhitelistClick);
        _firstSeenKnownButton = CreateFirstSeenButton("标记为已知", OnFirstSeenKnownClick);
        _firstSeenAckAllButton = CreateFirstSeenButton("全部已读", OnFirstSeenAckAllClick);
        _firstSeenDeleteButton = CreateFirstSeenButton("删除记录", OnFirstSeenDeleteClick);
        _firstSeenClearButton = CreateFirstSeenButton("清空记录…", OnFirstSeenClearClick);
        _firstSeenExportButton = CreateFirstSeenButton("导出…", (_, _) => ExportFirstSeenProgramsView());

        toolbar.Controls.Add(_firstSeenSearchBox);
        toolbar.Controls.Add(_firstSeenOnlyNewCheckBox);
        toolbar.Controls.Add(_firstSeenRefreshButton);
        toolbar.Controls.Add(_firstSeenBlockButton);
        toolbar.Controls.Add(_firstSeenReleaseGuardButton);
        toolbar.Controls.Add(_firstSeenWhitelistButton);
        toolbar.Controls.Add(_firstSeenKnownButton);
        toolbar.Controls.Add(_firstSeenAckAllButton);
        toolbar.Controls.Add(_firstSeenDeleteButton);
        toolbar.Controls.Add(_firstSeenClearButton);
        toolbar.Controls.Add(_firstSeenExportButton);

        _firstSeenStatusLabel = new Label
        {
            AutoSize = false,
            Dock = DockStyle.Top,
            Height = 22,
            ForeColor = SystemColors.GrayText,
            AutoEllipsis = true,
        };

        // Dock=Top 时后加的控件先占顶部；按显示顺序反着加：
        // 状态栏 → 工具条 → 说明 → 模式行，最终从上到下是模式行、说明、工具条、状态栏。
        top.Controls.Add(_firstSeenStatusLabel);
        top.Controls.Add(toolbar);
        top.Controls.Add(description);
        top.Controls.Add(defaultBlockRow);
        top.Controls.Add(modeRow);

        _firstSeenGrid = new DataGridViewBuffered
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

        AddColumn(_firstSeenGrid, "进程名", nameof(FirstSeenProgramRecord.ProcessNameText), 150);
        AddColumn(_firstSeenGrid, "完整路径", nameof(FirstSeenProgramRecord.Path), 300, fill: true, minWidth: 220);
        AddColumn(_firstSeenGrid, "首次联网时间", nameof(FirstSeenProgramRecord.FirstSeenText), 145);
        AddColumn(_firstSeenGrid, "最近联网时间", nameof(FirstSeenProgramRecord.LastSeenText), 145);
        AddColumn(_firstSeenGrid, "状态", nameof(FirstSeenProgramRecord.StatusText), 70);
        AddColumn(_firstSeenGrid, "处理状态", nameof(FirstSeenProgramRecord.ProcessingText), 100);
        AddColumn(_firstSeenGrid, "来源", nameof(FirstSeenProgramRecord.SourceText), 140);

        _firstSeenGrid.EmptyText = BuildFirstSeenEmptyText();
        _firstSeenGrid.SelectionChanged += (_, _) => UpdateFirstSeenButtons();
        _firstSeenGrid.CellMouseDown += OnFirstSeenGridCellMouseDown;

        _firstSeenMenu = new ContextMenuStrip();
        AddFirstSeenMenuItem("阻止该程序联网", OnFirstSeenBlockClick);
        AddFirstSeenMenuItem("释放临时阻止", OnFirstSeenReleaseGuardClick);
        AddFirstSeenMenuItem("加入 / 移出严格模式白名单", OnFirstSeenWhitelistClick);
        AddFirstSeenMenuItem("标记为已知", OnFirstSeenKnownClick);
        _firstSeenMenu.Items.Add(new ToolStripSeparator());
        AddFirstSeenMenuItem("复制程序路径", OnFirstSeenCopyPathClick);
        AddFirstSeenMenuItem("删除记录", OnFirstSeenDeleteClick);
        _firstSeenGrid.ContextMenuStrip = _firstSeenMenu;

        _firstSeenSource.DataSource = _firstSeenView;
        _firstSeenGrid.DataSource = _firstSeenSource;

        _tabFirstSeenPrograms.Controls.Add(_firstSeenGrid);
        _tabFirstSeenPrograms.Controls.Add(top);

        var settingsIndex = _tabControl.TabPages.IndexOf(_tabSettings);
        if (settingsIndex >= 0)
        {
            _tabControl.TabPages.Insert(settingsIndex, _tabFirstSeenPrograms);
        }
        else
        {
            _tabControl.TabPages.Add(_tabFirstSeenPrograms);
        }

        _tabControl.SelectedIndexChanged += (_, _) =>
        {
            if (_tabControl.SelectedTab == _tabFirstSeenPrograms)
            {
                // 切回本页时重新读一次规则阻止状态和临时阻止状态。
                RebuildFirstSeenView();
            }
        };

        _firstSeenLoading = true;
        _firstSeenModeButton.Text = Localizer.T(
            _settings.NewProgramAlertsEnabled ? "关闭新程序联网提醒" : "开启新程序联网提醒");
        _firstSeenBalloonCheckBox.Checked = _settings.NewProgramBalloonEnabled;
        _firstSeenDefaultBlockCheckBox.Checked = _settings.NewProgramDefaultBlockEnabled;
        _firstSeenLoading = false;

        _firstSeenBalloonCheckBox.Enabled = _settings.NewProgramAlertsEnabled;
        _firstSeenDefaultBlockCheckBox.Enabled = _settings.NewProgramAlertsEnabled;

        _firstSeenTimer = new System.Windows.Forms.Timer(components!)
        {
            Interval = FirstSeenRefreshIntervalMs,
            Enabled = _settings.NewProgramAlertsEnabled,
        };
        _firstSeenTimer.Tick += (_, _) =>
        {
            if (SuppressBackgroundServices || !_settings.NewProgramAlertsEnabled)
            {
                return;
            }

            // 5.8：只在模式开启时定时扫描；关闭时完全停止。
            _ = RefreshConnectionsAsync();
        };

        RebuildFirstSeenView();
    }

    private static Button CreateFirstSeenButton(string text, EventHandler handler)
    {
        var button = new Button
        {
            Text = Localizer.T(text),
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            MinimumSize = new Size(84, 27),
            Margin = new Padding(0, 2, 8, 0),
        };

        button.Click += handler;
        return button;
    }

    private void AddFirstSeenMenuItem(string text, EventHandler handler)
    {
        var item = new ToolStripMenuItem(Localizer.T(text));
        item.Click += handler;
        _firstSeenMenu.Items.Add(item);
    }

    private void OnFirstSeenModeButtonClick(object? sender, EventArgs e)
    {
        if (_firstSeenLoading)
        {
            return;
        }

        var enabled = !_settings.NewProgramAlertsEnabled;
        _settings.NewProgramAlertsEnabled = enabled;
        _settings.Save();

        _firstSeenModeButton.Text = Localizer.T(
            enabled ? "关闭新程序联网提醒" : "开启新程序联网提醒");
        _firstSeenBalloonCheckBox.Enabled = enabled;
        _firstSeenDefaultBlockCheckBox.Enabled = enabled;
        _firstSeenBaselinePending = false;

        if (!enabled)
        {
            _firstSeenPromptQueue.Clear();
            _firstSeenPrompted.Clear();
            ReleaseAllGuardedPrograms();
        }

        if (_firstSeenTimer is not null)
        {
            _firstSeenTimer.Enabled = enabled;
        }

        if (enabled)
        {
            if (_scannedConnections.Count > 0)
            {
                BaselineFirstSeenPrograms();
            }
            else
            {
                _firstSeenBaselinePending = true;
                _firstSeenStatusLabel.Text = Localizer.T(
                    "模式已开启；正在扫描当前程序并建立「启用时已在线」基线。");
                _ = RefreshConnectionsAsync();
            }
        }

        RebuildFirstSeenView();
    }

    private async void OnFirstSeenRefreshClick(object? sender, EventArgs e)
    {
        _firstSeenRefreshButton.Enabled = false;

        try
        {
            await RefreshConnectionsAsync();
            RebuildFirstSeenView();
        }
        finally
        {
            _firstSeenRefreshButton.Enabled = true;
        }
    }

    private void OnFirstSeenBalloonChanged(object? sender, EventArgs e)
    {
        if (_firstSeenLoading)
        {
            return;
        }

        _settings.NewProgramBalloonEnabled = _firstSeenBalloonCheckBox.Checked;
        _settings.Save();
    }

    /// <summary>
    /// 5.8：新程序默认阻止（高风险）。开启前必须明确确认；
    /// 关闭时释放所有由本功能创建的临时阻止。
    /// </summary>
    private void OnFirstSeenDefaultBlockChanged(object? sender, EventArgs e)
    {
        if (_firstSeenLoading)
        {
            return;
        }

        if (!_firstSeenDefaultBlockCheckBox.Checked)
        {
            _settings.NewProgramDefaultBlockEnabled = false;
            _settings.Save();
            _firstSeenPromptQueue.Clear();
            _firstSeenPrompted.Clear();
            ReleaseAllGuardedPrograms();
            RebuildFirstSeenView();
            return;
        }

        if (!_settings.NewProgramAlertsEnabled)
        {
            _firstSeenLoading = true;
            _firstSeenDefaultBlockCheckBox.Checked = false;
            _firstSeenLoading = false;
            return;
        }

        var confirmed = ConfirmForm.Show(
            owner: DialogOwner,
            title: "开启新程序默认阻止",
            question: "开启后，新程序会被临时阻止并弹出居中确认框。确定继续吗？",
            details: new[]
            {
                new KeyValuePair<string, string>(
                    "将做的",
                    "发现新程序联网时，由服务创建临时 WFP 阻止过滤器，再弹窗询问是否允许"),
                new KeyValuePair<string, string>(
                    "你的选择",
                    "「允许联网」立即释放；「保持阻止」继续阻止；关闭弹窗也保持阻止"),
                new KeyValuePair<string, string>(
                    "生效范围",
                    "只限本功能的临时阻止，不写永久规则；服务停止或重启后自动清空"),
            },
            warnings: new[]
            {
                "这是高风险功能：新程序的第一条连接可能已经建立，只能阻止它后续的连接。",
                "当前只检测 TCP；只使用 UDP 的程序可能不会触发这个弹窗。",
                "受保护进程（本程序、svchost / lsass 等系统关键进程）不会被阻止。",
                "临时阻止只在本功能运行期间有效；关闭默认阻止或主模式会立即释放。",
            },
            confirmText: "开启默认阻止");

        if (!confirmed)
        {
            _firstSeenLoading = true;
            _firstSeenDefaultBlockCheckBox.Checked = false;
            _firstSeenLoading = false;
            return;
        }

        _settings.NewProgramDefaultBlockEnabled = true;
        _settings.Save();
    }

    /// <summary>模式开启时，把当前程序静默记为基线，不弹气泡。</summary>
    private void BaselineFirstSeenPrograms()
    {
        var programs = CurrentFirstSeenPrograms().ToList();

        if (programs.Count == 0)
        {
            _firstSeenBaselinePending = true;
            return;
        }

        var added = _firstSeenStore.Baseline(programs, DateTime.UtcNow);
        _firstSeenBaselinePending = false;
        _firstSeenStatusLabel.Text = Localizer.F(
            "已把当前 {0} 个程序记为已知；之后第一次联网的新程序会出现在列表里。",
            added);
    }

    /// <summary>连接扫描完成 / 路径回填后调用。模式关闭时什么都不做。</summary>
    private void UpdateFirstSeenPrograms()
    {
        if (SuppressBackgroundServices || !_settings.NewProgramAlertsEnabled)
        {
            return;
        }

        var programs = CurrentFirstSeenPrograms().ToList();

        if (programs.Count == 0)
        {
            return;
        }

        var now = DateTime.UtcNow;

        if (_firstSeenBaselinePending)
        {
            _firstSeenStore.Baseline(programs, now);
            _firstSeenBaselinePending = false;
        }
        else
        {
            var added = _firstSeenStore.Observe(programs, now);

            if (added.Count > 0)
            {
                if (_settings.NewProgramDefaultBlockEnabled)
                {
                    QueueDefaultBlockPrompts(added);
                }
                else
                {
                    NotifyNewPrograms(added);
                }
            }
        }


        if (_tabControl.SelectedTab == _tabFirstSeenPrograms)
        {
            RebuildFirstSeenView();
        }
    }

    private IEnumerable<(string Path, string ProcessName)> CurrentFirstSeenPrograms()
        => _scannedConnections
            .Where(item => !string.IsNullOrEmpty(item.ProcessPath))
            .GroupBy(item => item.ProcessPath, StringComparer.OrdinalIgnoreCase)
            .Select(group => (group.Key, group.First().ProcessName));

    private void NotifyNewPrograms(IReadOnlyList<FirstSeenProgramRecord> added)
    {
        if (!_settings.NewProgramBalloonEnabled || added.Count == 0)
        {
            return;
        }

        var now = DateTime.UtcNow;

        // 10 秒全局冷却：同一批新程序合并成一条，下一批至少等 10 秒。
        if (now - _lastFirstSeenBalloonUtc < FirstSeenBalloonCooldown)
        {
            return;
        }

        var candidates = added
            .Where(record => _firstSeenStore.ShouldNotify(record, now))
            .ToList();

        if (candidates.Count == 0)
        {
            return;
        }

        _lastFirstSeenBalloonUtc = now;
        _firstSeenStore.MarkNotified(
            candidates.Select(record => record.Path),
            now);

        var names = string.Join(
            "、",
            candidates.Take(5).Select(record => record.ProcessNameText));

        var text = candidates.Count == 1
            ? Localizer.F("{0} 首次联网。打开「新程序联网提醒」查看。", names)
            : Localizer.F(
                "发现 {0} 个新程序联网：{1}。打开「新程序联网提醒」查看。",
                candidates.Count,
                names);

        ShowTrayBalloon(Localizer.T("发现新程序联网"), text, ToolTipIcon.Info);
    }

    /// <summary>
    /// 5.8：默认阻止模式。先由服务创建临时阻止，再逐个弹出居中确认框。
    /// </summary>
    private void QueueDefaultBlockPrompts(IReadOnlyList<FirstSeenProgramRecord> added)
    {
        foreach (var record in added)
        {
            if (_firstSeenPrompted.Contains(record.Path))
            {
                continue;
            }

            if (ProtectedProcesses.IsProtected(record.Path, out _))
            {
                // 系统关键进程不允许阻止，直接当作已知，避免反复出现在“新”里。
                _firstSeenStore.MarkKnown(record.Path);
                continue;
            }

            var guarded = TryGuardNewProgram(record.Path);
            _firstSeenPrompted.Add(record.Path);
            _firstSeenPromptQueue.Enqueue((record, guarded));
        }

        ShowNextFirstSeenPrompt();
    }

    private void ShowNextFirstSeenPrompt()
    {
        if (_firstSeenPromptShowing || _firstSeenPromptQueue.Count == 0 || IsDisposed || Disposing)
        {
            return;
        }

        _firstSeenPromptShowing = true;

        try
        {
            while (_firstSeenPromptQueue.Count > 0 && !IsDisposed && !Disposing)
            {
                var item = _firstSeenPromptQueue.Dequeue();
                var remote = FirstSeenRemoteEndpoint(item.Record);

                using var form = new NewProgramPromptForm(item.Record, remote, item.Guarded);
                var result = form.ShowDialog();

                if (result == DialogResult.Yes)
                {
                    if (item.Guarded)
                    {
                        if (TryReleaseGuardedProgram(item.Record.Path))
                        {
                            _firstSeenStore.SetDecision(item.Record.Path, FirstSeenDecision.Allowed);
                        }
                        else
                        {
                            _firstSeenStore.SetDecision(item.Record.Path, FirstSeenDecision.Blocked);
                            UiMessageBox.Show(
                                this,
                                Localizer.T(
                                    "释放临时阻止失败。程序可能仍然无法联网，请到「联网连接」或规则页检查，或重启防护服务。"),
                                AppConstants.AppName,
                                MessageBoxButtons.OK,
                                MessageBoxIcon.Warning);
                        }
                    }
                    else
                    {
                        _firstSeenStore.SetDecision(item.Record.Path, FirstSeenDecision.Allowed);
                    }
                }
                else
                {
                    // 关闭窗口 / Esc / 保持阻止：临时阻止继续有效。
                    _firstSeenStore.SetDecision(item.Record.Path, FirstSeenDecision.Blocked);
                }
            }
        }
        catch (Exception ex)
        {
            LocalLog.Error(
                LocalLog.Pick("显示新程序确认框失败", "Failed to show the new-program prompt."),
                ex);
        }
        finally
        {
            _firstSeenPromptShowing = false;
        }

        RebuildFirstSeenView();
    }

    private string FirstSeenRemoteEndpoint(FirstSeenProgramRecord record)
    {
        var connection = _scannedConnections.FirstOrDefault(
            item => PathsEqual(item.ProcessPath, record.Path) && item.RemotePort != 0);

        return connection is null
            ? string.Empty
            : $"{connection.RemoteAddressText}:{connection.RemotePortText}";
    }

    /// <summary>
    /// 5.8：调用服务创建“只在本功能里使用”的临时 WFP 阻止。
    /// 故意不走 CallService —— 那会为每个新程序弹 UAC。
    /// </summary>
    private bool TryGuardNewProgram(string path)
    {
        try
        {
            var response = Gateway.TryRequest(
                new ServiceRequest
                {
                    Command = ServiceProtocol.Commands.GuardNewProgramBlock,
                    Value = path,
                },
                TimeSpan.FromSeconds(3),
                out var error);

            if (response is { Ok: true })
            {
                _firstSeenGuardedPaths.Add(path);
                return true;
            }

            LocalLog.Warning(LocalLog.Pick(
                $"创建新程序临时阻止失败：{path}（{response?.Error ?? error}）",
                $"Failed to quarantine a new program: {path} ({response?.Error ?? error})."));
            return false;
        }
        catch (Exception ex)
        {
            LocalLog.Error(
                LocalLog.Pick("创建新程序临时阻止失败", "Failed to quarantine a new program."),
                ex);
            return false;
        }
    }

    private bool TryReleaseGuardedProgram(string path)
    {
        try
        {
            var response = Gateway.TryRequest(
                new ServiceRequest
                {
                    Command = ServiceProtocol.Commands.GuardNewProgramRelease,
                    Value = path,
                },
                TimeSpan.FromSeconds(3),
                out var error);

            if (response is { Ok: true })
            {
                _firstSeenGuardedPaths.Remove(path);
                return true;
            }

            LocalLog.Warning(LocalLog.Pick(
                $"释放新程序临时阻止失败：{path}（{response?.Error ?? error}）",
                $"Failed to release a new-program quarantine: {path} ({response?.Error ?? error})."));
            return false;
        }
        catch (Exception ex)
        {
            LocalLog.Error(
                LocalLog.Pick("释放新程序临时阻止失败", "Failed to release a new-program quarantine."),
                ex);
            return false;
        }
    }

    private void ReleaseAllGuardedPrograms()
    {
        foreach (var path in _firstSeenGuardedPaths.ToList())
        {
            if (TryReleaseGuardedProgram(path))
            {
                _firstSeenStore.SetDecision(path, FirstSeenDecision.Allowed);
            }
        }

        _firstSeenGuardedPaths.Clear();
    }


    private void RebuildFirstSeenView()
    {
        if (_firstSeenGrid is null)
        {
            return;
        }

        var selectedPath = SelectedFirstSeenRecord()?.Path;
        var firstDisplayedRow = CaptureFirstDisplayedRow(_firstSeenGrid);
        var keyword = _firstSeenSearchBox.Text.Trim();
        var onlyNew = _firstSeenOnlyNewCheckBox.Checked;

        var view = _firstSeenStore.Snapshot()
            .Where(record => !onlyNew || record.IsNew)
            .Where(record => FirstSeenMatches(record, keyword))
            .ToList();

        foreach (var record in view)
        {
            record.IsBlockedByRule = _blockedPaths.Contains(record.Path);
            record.IsGuarded = _firstSeenGuardedPaths.Contains(record.Path);
        }

        _firstSeenView.Clear();
        _firstSeenView.AddRange(view);

        _firstSeenSource.ResetBindings(metadataChanged: false);

        var restored = false;

        if (!string.IsNullOrEmpty(selectedPath))
        {
            foreach (DataGridViewRow row in _firstSeenGrid.Rows)
            {
                if (row.DataBoundItem is FirstSeenProgramRecord record
                    && string.Equals(record.Path, selectedPath, StringComparison.OrdinalIgnoreCase))
                {
                    _firstSeenGrid.CurrentCell = row.Cells[0];
                    restored = true;
                    break;
                }
            }
        }

        if (!restored)
        {
            _firstSeenGrid.CurrentCell = null;
        }

        RestoreFirstDisplayedRow(_firstSeenGrid, firstDisplayedRow);
        UpdateFirstSeenStatus();
        UpdateFirstSeenButtons();
    }

    private static bool FirstSeenMatches(FirstSeenProgramRecord record, string keyword)
        => keyword.Length == 0
           || record.ProcessNameText.Contains(keyword, StringComparison.OrdinalIgnoreCase)
           || record.Path.Contains(keyword, StringComparison.OrdinalIgnoreCase);

    private FirstSeenProgramRecord? SelectedFirstSeenRecord()
        => _firstSeenGrid.CurrentRow?.DataBoundItem as FirstSeenProgramRecord;

    private void OnFirstSeenGridCellMouseDown(object? sender, DataGridViewCellMouseEventArgs e)
    {
        if (e.Button != MouseButtons.Right
            || e.RowIndex < 0
            || e.RowIndex >= _firstSeenGrid.Rows.Count)
        {
            return;
        }

        _firstSeenGrid.CurrentCell = _firstSeenGrid.Rows[e.RowIndex].Cells[0];
        UpdateFirstSeenButtons();
    }

    private void UpdateFirstSeenStatus()
    {
        var mode = _settings.NewProgramAlertsEnabled
            ? Localizer.T("正在记录")
            : Localizer.T("模式未开启，已停止记录");

        var text = Localizer.F(
            "{0} · 已记录 {1} 个程序 · 新程序 {2} 个",
            mode,
            _firstSeenStore.Count,
            _firstSeenStore.NewCount);

        if (_firstSeenStore.LastError is { Length: > 0 } error)
        {
            text += " · " + Localizer.F("记录文件不可写：{0}", error);
        }

        _firstSeenStatusLabel.Text = text;
        _firstSeenGrid.EmptyText = BuildFirstSeenEmptyText();
    }

    private string BuildFirstSeenEmptyText()
        => _settings.NewProgramAlertsEnabled
            ? Localizer.T("还没有记录。新程序联网后会出现在这里。")
            : Localizer.T("模式未开启。开启后才会记录新程序；已有历史记录仍可查看。");

    private void UpdateFirstSeenButtons()
    {
        var record = SelectedFirstSeenRecord();
        var hasPath = record is not null && !string.IsNullOrEmpty(record.Path);
        var isProtected = hasPath
                          && ProtectedProcesses.IsProtected(record!.Path, out _);
        var isBlocked = hasPath && _blockedPaths.Contains(record!.Path);
        var isWhitelisted = hasPath && _whitelistedPaths.Contains(record!.Path);

        _firstSeenBlockButton.Enabled = _serviceAvailable && hasPath && !isProtected && !isBlocked;
        _firstSeenReleaseGuardButton.Enabled = hasPath
                                               && _firstSeenGuardedPaths.Contains(record!.Path);
        _firstSeenWhitelistButton.Enabled = _serviceAvailable && hasPath;
        _firstSeenWhitelistButton.Text = Localizer.T(isWhitelisted ? "移出白名单" : "加入白名单");
        _firstSeenKnownButton.Enabled = record is { IsNew: true };
        _firstSeenAckAllButton.Enabled = _firstSeenStore.NewCount > 0;
        _firstSeenDeleteButton.Enabled = record is not null;
        _firstSeenClearButton.Enabled = _firstSeenStore.Count > 0;
        _firstSeenExportButton.Enabled = _firstSeenView.Count > 0;
    }

    private void OnFirstSeenBlockClick(object? sender, EventArgs e)
    {
        var record = SelectedFirstSeenRecord();

        if (record is null || string.IsNullOrEmpty(record.Path))
        {
            return;
        }

        var connectionCount = _scannedConnections.Count(
            item => PathsEqual(item.ProcessPath, record.Path));

        BlockProgramWithConfirmation(record.Path, record.ProcessNameText, connectionCount);
        RebuildFirstSeenView();
    }

    private void OnFirstSeenWhitelistClick(object? sender, EventArgs e)
    {
        var record = SelectedFirstSeenRecord();

        if (record is null || string.IsNullOrEmpty(record.Path))
        {
            return;
        }

        if (_whitelistedPaths.Contains(record.Path))
        {
            RemoveFromWhitelist(record.Path, record.ProcessNameText);
        }
        else
        {
            AddToWhitelist(record.Path, record.ProcessNameText);
        }

        UpdateFirstSeenButtons();
    }

    private void OnFirstSeenReleaseGuardClick(object? sender, EventArgs e)
    {
        var record = SelectedFirstSeenRecord();

        if (record is null || string.IsNullOrEmpty(record.Path))
        {
            return;
        }

        if (!TryReleaseGuardedProgram(record.Path))
        {
            UiMessageBox.Show(
                this,
                Localizer.T("释放临时阻止失败，请确认防护服务正在运行。"),
                AppConstants.AppName,
                MessageBoxButtons.OK,
                MessageBoxIcon.Warning);
        }
        else
        {
            _firstSeenStore.SetDecision(record.Path, FirstSeenDecision.Allowed);
        }

        RebuildFirstSeenView();
    }

    private void OnFirstSeenKnownClick(object? sender, EventArgs e)
    {
        var record = SelectedFirstSeenRecord();

        if (record is null)
        {
            return;
        }

        _firstSeenStore.MarkKnown(record.Path);
        RebuildFirstSeenView();
    }

    private void OnFirstSeenAckAllClick(object? sender, EventArgs e)
    {
        var changed = _firstSeenStore.MarkAllKnown();

        if (changed > 0)
        {
            LocalLog.Operation(LocalLog.Pick(
                $"新程序提醒：全部标记为已知（{changed} 条）",
                $"New-program reminders: marked all as known ({changed})."));
        }

        RebuildFirstSeenView();
    }

    private void OnFirstSeenDeleteClick(object? sender, EventArgs e)
    {
        var record = SelectedFirstSeenRecord();

        if (record is null)
        {
            return;
        }

        var path = record.Path;
        var online = _scannedConnections.Any(
            item => PathsEqual(item.ProcessPath, path));
        var guarded = _firstSeenGuardedPaths.Contains(path);

        // 默认阻止开启且程序还在联网（或仍被本功能临时阻止）：删除后立刻重新当作新程序处理，
        // 不释放现有临时阻止，避免出现“删掉记录就等于放行”的空窗。
        if (_settings.NewProgramDefaultBlockEnabled && (online || guarded))
        {
            _firstSeenStore.Delete(path);
            _firstSeenPrompted.Remove(path);

            var added = _firstSeenStore.Observe(
                new[] { (path, record.ProcessNameText) },
                DateTime.UtcNow);

            QueueDefaultBlockPrompts(added);
            RebuildFirstSeenView();
            return;
        }

        if (_firstSeenGuardedPaths.Contains(path) && !TryReleaseGuardedProgram(path))
        {
            UiMessageBox.Show(
                this,
                Localizer.T("释放临时阻止失败，未删除记录。请确认防护服务正在运行。"),
                AppConstants.AppName,
                MessageBoxButtons.OK,
                MessageBoxIcon.Warning);
            return;
        }

        _firstSeenStore.Delete(path);
        _firstSeenPrompted.Remove(path);
        _firstSeenGuardedPaths.Remove(path);
        RebuildFirstSeenView();
    }

    private void OnFirstSeenClearClick(object? sender, EventArgs e)
    {
        if (_firstSeenStore.Count == 0)
        {
            return;
        }

        var confirmed = ConfirmForm.Show(
            owner: DialogOwner,
            title: "清空新程序记录",
            question: "确定要清空全部新程序记录吗？",
            details: new[]
            {
                new KeyValuePair<string, string>("将要做的", "删除本机保存的全部程序首次联网记录"),
                new KeyValuePair<string, string>(
                    "影响",
                    _settings.NewProgramAlertsEnabled
                        ? "当前已联网程序会重新记为已知基线，不会立刻全部标成新程序"
                        : "只删除历史记录；模式仍然关闭"),
            },
            warnings: new[]
            {
                "只影响「新程序联网提醒」的本地记录，不会删除防火墙规则或连接记录。",
                "不会上传任何数据。",
            },
            confirmText: "清空记录");

        if (!confirmed)
        {
            return;
        }

        _firstSeenStore.Clear();
        _firstSeenBaselinePending = false;
        _firstSeenPromptQueue.Clear();
        _firstSeenPrompted.Clear();
        ReleaseAllGuardedPrograms();

        if (_settings.NewProgramAlertsEnabled)
        {
            BaselineFirstSeenPrograms();
        }

        RebuildFirstSeenView();
    }

    private void OnFirstSeenCopyPathClick(object? sender, EventArgs e)
    {
        var record = SelectedFirstSeenRecord();

        if (record is null || string.IsNullOrEmpty(record.Path))
        {
            return;
        }

        try
        {
            Clipboard.SetText(record.Path);
        }
        catch (Exception)
        {
            // 剪贴板被占用时静默失败。
        }
    }

    private void ExportFirstSeenProgramsView()
    {
        var columns = new[]
        {
            Column("processName", "进程名"),
            Column("processPath", "完整路径"),
            Column("firstSeenUtc", "首次联网时间（UTC）"),
            Column("lastSeenUtc", "最近联网时间（UTC）"),
            Column("status", "状态"),
            Column("processing", "处理状态"),
            Column("source", "来源"),
        };

        var rows = _firstSeenView
            .Select(record => Row(
                ("processName", record.ProcessNameText),
                ("processPath", record.Path),
                ("firstSeenUtc", record.FirstSeenUtc),
                ("lastSeenUtc", record.LastSeenUtc),
                ("status", record.StatusText),
                ("processing", record.ProcessingText),
                ("source", record.SourceText)))
            .ToList();

        ExportTable(
            "new-programs",
            "新程序联网提醒",
            "WinAppGuard-新程序联网提醒",
            columns,
            rows);
    }
}
