// 该文件被编译器视为「自动生成的代码」，必须显式声明可空引用类型上下文，
// 否则 IContainer? 这类批注会产生 CS8669 警告。
#nullable enable

namespace WinAppGuard.Forms;

/// <summary>
/// MainForm 的界面布局代码。
///
/// 这里没有使用可视化设计器生成，而是全部手写，
/// 好处是布局逻辑可以直接在代码评审里看明白，不依赖 .resx 里的隐藏信息。
///
/// 例外：两个表格的「列」不在这里定义，而在 MainForm.cs 的 SetupConnectionGrid /
/// SetupRulesGrid 里。原因是列和数据字段是一一对应的，
/// 放在一起看更清楚，改起来也不容易漏。
/// </summary>
partial class MainForm
{
    /// <summary>设计器要求的组件容器。</summary>
    private System.ComponentModel.IContainer? components = null;

    private Label _titleLabel = null!;
    private Label _descriptionLabel = null!;
    private Label _safetyNoticeLabel = null!;

    // ================= 标签页 =================
    private TabControl _tabControl = null!;

    // ---------- 页一：联网连接 ----------
    private TabPage _tabConnections = null!;

    private Panel _toolPanel = null!;
    private Button _refreshButton = null!;
    private CheckBox _autoRefreshCheckBox = null!;
    private CheckBox _showListenCheckBox = null!;
    private CheckBox _showClosedCheckBox = null!;
    private CheckBox _showOwnerlessCheckBox = null!;
    private CheckBox _hideLoopbackCheckBox = null!;
    private Button _blockButton = null!;
    private Button _allowButton = null!;
    private Button _refreshRulesButton = null!;
    private Label _selectionHintLabel = null!;

    private DataGridViewBuffered _connectionGrid = null!;

    private ContextMenuStrip _gridContextMenu = null!;
    private ToolStripMenuItem _menuBlock = null!;
    private ToolStripMenuItem _menuAllow = null!;
    private ToolStripSeparator _menuSeparator = null!;
    private ToolStripMenuItem _menuCopyPath = null!;

    // ---------- 页二：已阻止的程序（规则管理）----------
    private TabPage _tabRules = null!;

    private Label _rulesNoticeLabel = null!;
    private Panel _rulesToolPanel = null!;
    private Button _rulesRefreshButton = null!;
    private Label _rulesSummaryLabel = null!;
    private Button _rulesAllowButton = null!;
    private Button _rulesDeleteButton = null!;
    private Button _rulesDeleteAllButton = null!;
    private Label _rulesHintLabel = null!;

    private DataGridViewBuffered _rulesGrid = null!;

    // ---------- 页三：设置 ----------
    private TabPage _tabSettings = null!;

    private Label _settingsNoticeLabel = null!;
    private GroupBox _autostartPanel = null!;
    private Label _autostartStatusLabel = null!;
    private Panel _autostartDetailHost = null!;
    private Label _autostartDetailLabel = null!;
    private Panel _autostartButtons = null!;
    private Button _enableAutostartButton = null!;
    private Button _disableAutostartButton = null!;
    private Button _refreshAutostartButton = null!;

    private GroupBox _taskXmlPanel = null!;
    private TextBox _taskXmlBox = null!;

    private GroupBox _privacyPanel = null!;
    private Label _privacyLabel = null!;
    private Label _logPathLabel = null!;
    private Button _openLogFolderButton = null!;

    // ---------- 其它 ----------
    private Button _exitButton = null!;

    private StatusStrip _statusStrip = null!;
    private ToolStripStatusLabel _adminStatusLabel = null!;
    private ToolStripStatusLabel _springLabel = null!;
    private ToolStripStatusLabel _startModeLabel = null!;
    private ToolStripStatusLabel _statusRulesLabel = null!;
    private ToolStripStatusLabel _summaryLabel = null!;
    private ToolStripStatusLabel _versionLabel = null!;

    private System.Windows.Forms.Timer _autoRefreshTimer = null!;
    private ToolTip _toolTip = null!;

    // ---------- 系统托盘 ----------
    private NotifyIcon _trayIcon = null!;
    private ContextMenuStrip _trayMenu = null!;
    private ToolStripMenuItem _trayShowItem = null!;
    private ToolStripMenuItem _trayDeleteAllItem = null!;
    private ToolStripSeparator _traySeparator = null!;
    private ToolStripMenuItem _trayExitItem = null!;

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            components?.Dispose();
        }

        base.Dispose(disposing);
    }

    private void InitializeComponent()
    {
        components = new System.ComponentModel.Container();

        _titleLabel = new Label();
        _descriptionLabel = new Label();
        _safetyNoticeLabel = new Label();
        _tabControl = new TabControl();
        _tabConnections = new TabPage();
        _tabRules = new TabPage();
        _toolPanel = new Panel();
        _refreshButton = new Button();
        _autoRefreshCheckBox = new CheckBox();
        _showListenCheckBox = new CheckBox();
        _showClosedCheckBox = new CheckBox();
        _showOwnerlessCheckBox = new CheckBox();
        _hideLoopbackCheckBox = new CheckBox();
        _blockButton = new Button();
        _allowButton = new Button();
        _refreshRulesButton = new Button();
        _selectionHintLabel = new Label();
        _connectionGrid = new DataGridViewBuffered();
        _gridContextMenu = new ContextMenuStrip(components);
        _menuBlock = new ToolStripMenuItem();
        _menuAllow = new ToolStripMenuItem();
        _menuSeparator = new ToolStripSeparator();
        _menuCopyPath = new ToolStripMenuItem();
        _rulesNoticeLabel = new Label();
        _rulesToolPanel = new Panel();
        _rulesRefreshButton = new Button();
        _rulesSummaryLabel = new Label();
        _rulesAllowButton = new Button();
        _rulesDeleteButton = new Button();
        _rulesDeleteAllButton = new Button();
        _rulesHintLabel = new Label();
        _rulesGrid = new DataGridViewBuffered();
        _tabSettings = new TabPage();
        _settingsNoticeLabel = new Label();
        _autostartPanel = new GroupBox();
        _autostartStatusLabel = new Label();
        _autostartDetailHost = new Panel();
        _autostartDetailLabel = new Label();
        _autostartButtons = new Panel();
        _enableAutostartButton = new Button();
        _disableAutostartButton = new Button();
        _refreshAutostartButton = new Button();
        _taskXmlPanel = new GroupBox();
        _taskXmlBox = new TextBox();
        _privacyPanel = new GroupBox();
        _privacyLabel = new Label();
        _logPathLabel = new Label();
        _openLogFolderButton = new Button();
        _exitButton = new Button();
        _statusStrip = new StatusStrip();
        _adminStatusLabel = new ToolStripStatusLabel();
        _springLabel = new ToolStripStatusLabel();
        _startModeLabel = new ToolStripStatusLabel();
        _statusRulesLabel = new ToolStripStatusLabel();
        _summaryLabel = new ToolStripStatusLabel();
        _versionLabel = new ToolStripStatusLabel();
        _autoRefreshTimer = new System.Windows.Forms.Timer(components);
        _toolTip = new ToolTip(components);
        _trayIcon = new NotifyIcon(components);
        _trayMenu = new ContextMenuStrip(components);
        _trayShowItem = new ToolStripMenuItem();
        _trayDeleteAllItem = new ToolStripMenuItem();
        _traySeparator = new ToolStripSeparator();
        _trayExitItem = new ToolStripMenuItem();

        _trayMenu.SuspendLayout();

        _tabControl.SuspendLayout();
        _tabConnections.SuspendLayout();
        _tabRules.SuspendLayout();
        _tabSettings.SuspendLayout();
        _autostartPanel.SuspendLayout();
        _autostartDetailHost.SuspendLayout();
        _autostartButtons.SuspendLayout();
        _taskXmlPanel.SuspendLayout();
        _privacyPanel.SuspendLayout();
        _toolPanel.SuspendLayout();
        _rulesToolPanel.SuspendLayout();
        _gridContextMenu.SuspendLayout();
        _statusStrip.SuspendLayout();
        SuspendLayout();

        // ---------- 标题 ----------
        _titleLabel.AutoSize = true;
        _titleLabel.Font = new Font("Microsoft YaHei UI", 15.75F, FontStyle.Bold, GraphicsUnit.Point);
        _titleLabel.Location = new Point(24, 16);
        _titleLabel.Name = "_titleLabel";
        _titleLabel.Size = new Size(213, 28);
        _titleLabel.TabIndex = 0;
        _titleLabel.Text = "WinAppGuard";

        // ---------- 一句话说明 ----------
        _descriptionLabel.AutoSize = true;
        _descriptionLabel.ForeColor = SystemColors.GrayText;
        _descriptionLabel.Location = new Point(27, 52);
        _descriptionLabel.MaximumSize = new Size(1120, 0);
        _descriptionLabel.Name = "_descriptionLabel";
        _descriptionLabel.Size = new Size(700, 17);
        _descriptionLabel.TabIndex = 1;
        _descriptionLabel.Text = "Windows 程序联网控制工具。它本身不拦截任何流量，真正生效的是 Windows 防火墙规则，" +
                                 "本工具只负责按你的选择创建和清理这些规则。";

        // ---------- 当前阶段提示 ----------
        // ---------- 安全约定（常驻说明，不再是「当前阶段」）----------
        //
        // 刻意关掉 AutoSize 并写死高度：这段文字是固定长度的常驻说明，
        // 万一以后有人把它改长了、换行了，也只会被裁掉一点，绝不会往下长出去压住标签页。
        _safetyNoticeLabel.AutoSize = false;
        _safetyNoticeLabel.ForeColor = Color.FromArgb(191, 87, 0);
        _safetyNoticeLabel.Location = new Point(27, 74);
        _safetyNoticeLabel.Name = "_safetyNoticeLabel";
        _safetyNoticeLabel.Size = new Size(1120, 20);
        _safetyNoticeLabel.TabIndex = 2;
        _safetyNoticeLabel.Text =
            "安全约定：只创建和删除以 AppGuard_ 开头的防火墙规则，从不修改全局防火墙策略；" +
            "本程序不访问网络、不上传任何数据。";

        // ==================================================================
        // 标签页容器
        // ==================================================================
        _tabControl.Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;
        _tabControl.Controls.Add(_tabConnections);
        _tabControl.Controls.Add(_tabRules);
        _tabControl.Controls.Add(_tabSettings);
        _tabControl.Location = new Point(24, 104);
        _tabControl.Name = "_tabControl";
        _tabControl.SelectedIndex = 0;
        _tabControl.Size = new Size(1132, 522);
        _tabControl.TabIndex = 3;
        _tabControl.SelectedIndexChanged += OnTabControlSelectedIndexChanged;

        // ==================================================================
        // 页一：联网连接
        // ==================================================================
        _tabConnections.Padding = new Padding(9);
        _tabConnections.Name = "_tabConnections";
        _tabConnections.Text = "联网连接";
        _tabConnections.UseVisualStyleBackColor = true;

        // 工具条第一行：过滤
        _toolPanel.Dock = DockStyle.Top;
        _toolPanel.Height = 76;
        _toolPanel.Name = "_toolPanel";
        _toolPanel.Controls.Add(_refreshButton);
        _toolPanel.Controls.Add(_autoRefreshCheckBox);
        _toolPanel.Controls.Add(_showListenCheckBox);
        _toolPanel.Controls.Add(_showClosedCheckBox);
        _toolPanel.Controls.Add(_showOwnerlessCheckBox);
        _toolPanel.Controls.Add(_hideLoopbackCheckBox);
        _toolPanel.Controls.Add(_blockButton);
        _toolPanel.Controls.Add(_allowButton);
        _toolPanel.Controls.Add(_refreshRulesButton);
        _toolPanel.Controls.Add(_selectionHintLabel);

        _refreshButton.Location = new Point(0, 4);
        _refreshButton.Name = "_refreshButton";
        _refreshButton.Size = new Size(90, 28);
        _refreshButton.TabIndex = 0;
        _refreshButton.Text = "刷新";
        _refreshButton.UseVisualStyleBackColor = true;
        _refreshButton.Click += OnRefreshButtonClick;

        _autoRefreshCheckBox.AutoSize = true;
        _autoRefreshCheckBox.Location = new Point(104, 10);
        _autoRefreshCheckBox.Name = "_autoRefreshCheckBox";
        _autoRefreshCheckBox.Size = new Size(130, 21);
        _autoRefreshCheckBox.TabIndex = 1;
        _autoRefreshCheckBox.Text = "每 3 秒自动刷新";
        _autoRefreshCheckBox.UseVisualStyleBackColor = true;
        _autoRefreshCheckBox.CheckedChanged += OnAutoRefreshCheckedChanged;

        _showListenCheckBox.AutoSize = true;
        _showListenCheckBox.Location = new Point(250, 10);
        _showListenCheckBox.Name = "_showListenCheckBox";
        _showListenCheckBox.Size = new Size(150, 21);
        _showListenCheckBox.TabIndex = 2;
        _showListenCheckBox.Text = "显示监听中(LISTEN)";
        _showListenCheckBox.UseVisualStyleBackColor = true;
        _showListenCheckBox.CheckedChanged += OnScanOptionChanged;

        _showClosedCheckBox.AutoSize = true;
        _showClosedCheckBox.Location = new Point(412, 10);
        _showClosedCheckBox.Name = "_showClosedCheckBox";
        _showClosedCheckBox.Size = new Size(170, 21);
        _showClosedCheckBox.TabIndex = 3;
        _showClosedCheckBox.Text = "显示已结束(TIME_WAIT 等)";
        _showClosedCheckBox.UseVisualStyleBackColor = true;
        _showClosedCheckBox.CheckedChanged += OnScanOptionChanged;

        _showOwnerlessCheckBox.AutoSize = true;
        _showOwnerlessCheckBox.Location = new Point(596, 10);
        _showOwnerlessCheckBox.Name = "_showOwnerlessCheckBox";
        _showOwnerlessCheckBox.Size = new Size(170, 21);
        _showOwnerlessCheckBox.TabIndex = 4;
        _showOwnerlessCheckBox.Text = "显示无进程归属的连接";
        _showOwnerlessCheckBox.UseVisualStyleBackColor = true;
        _showOwnerlessCheckBox.CheckedChanged += OnScanOptionChanged;

        _hideLoopbackCheckBox.AutoSize = true;
        _hideLoopbackCheckBox.Checked = true;
        _hideLoopbackCheckBox.CheckState = CheckState.Checked;
        _hideLoopbackCheckBox.Location = new Point(780, 10);
        _hideLoopbackCheckBox.Name = "_hideLoopbackCheckBox";
        _hideLoopbackCheckBox.Size = new Size(150, 21);
        _hideLoopbackCheckBox.TabIndex = 5;
        _hideLoopbackCheckBox.Text = "隐藏本机回环连接";
        _hideLoopbackCheckBox.UseVisualStyleBackColor = true;
        _hideLoopbackCheckBox.CheckedChanged += OnScanOptionChanged;

        _blockButton.Enabled = false;
        _blockButton.Location = new Point(0, 42);
        _blockButton.Name = "_blockButton";
        _blockButton.Size = new Size(160, 28);
        _blockButton.TabIndex = 10;
        _blockButton.Text = "阻止选中程序联网";
        _blockButton.UseVisualStyleBackColor = true;
        _blockButton.Click += OnBlockButtonClick;

        _allowButton.Enabled = false;
        _allowButton.Location = new Point(168, 42);
        _allowButton.Name = "_allowButton";
        _allowButton.Size = new Size(160, 28);
        _allowButton.TabIndex = 11;
        _allowButton.Text = "允许选中程序联网";
        _allowButton.UseVisualStyleBackColor = true;
        _allowButton.Click += OnAllowButtonClick;

        _refreshRulesButton.Location = new Point(336, 42);
        _refreshRulesButton.Name = "_refreshRulesButton";
        _refreshRulesButton.Size = new Size(130, 28);
        _refreshRulesButton.TabIndex = 12;
        _refreshRulesButton.Text = "同步规则状态";
        _refreshRulesButton.UseVisualStyleBackColor = true;
        _refreshRulesButton.Click += OnRefreshRulesButtonClick;

        _selectionHintLabel.AutoSize = true;
        _selectionHintLabel.ForeColor = SystemColors.GrayText;
        _selectionHintLabel.Location = new Point(480, 47);
        _selectionHintLabel.Name = "_selectionHintLabel";
        _selectionHintLabel.Size = new Size(300, 17);
        _selectionHintLabel.TabIndex = 13;
        _selectionHintLabel.Text = "未选中任何连接";

        _connectionGrid.Dock = DockStyle.Fill;
        _connectionGrid.AllowUserToAddRows = false;
        _connectionGrid.AllowUserToDeleteRows = false;
        _connectionGrid.AllowUserToResizeRows = false;
        _connectionGrid.AlternatingRowsDefaultCellStyle = new DataGridViewCellStyle
        {
            BackColor = Color.FromArgb(245, 247, 250),
        };
        _connectionGrid.AutoGenerateColumns = false;
        _connectionGrid.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.None;
        _connectionGrid.BackgroundColor = SystemColors.Window;
        _connectionGrid.BorderStyle = BorderStyle.Fixed3D;
        _connectionGrid.ColumnHeadersHeightSizeMode = DataGridViewColumnHeadersHeightSizeMode.DisableResizing;
        _connectionGrid.ContextMenuStrip = _gridContextMenu;
        _connectionGrid.EditMode = DataGridViewEditMode.EditProgrammatically;
        _connectionGrid.MultiSelect = false;
        _connectionGrid.Name = "_connectionGrid";
        _connectionGrid.ReadOnly = true;
        _connectionGrid.RowHeadersVisible = false;
        _connectionGrid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
        _connectionGrid.TabIndex = 1;
        _connectionGrid.CellMouseDown += OnGridCellMouseDown;
        _connectionGrid.KeyDown += OnGridKeyDown;
        _connectionGrid.SelectionChanged += OnGridSelectionChanged;

        // 先加 Fill 的控件，再加 Dock=Top 的控件，这样 Top 的占上面一条、Fill 的占剩下的。
        _tabConnections.Controls.Add(_connectionGrid);
        _tabConnections.Controls.Add(_toolPanel);

        // ---------- 右键菜单 ----------
        _gridContextMenu.Items.AddRange(new ToolStripItem[] { _menuBlock, _menuAllow, _menuSeparator, _menuCopyPath });
        _gridContextMenu.Name = "_gridContextMenu";
        _gridContextMenu.Size = new Size(220, 76);

        _menuBlock.Name = "_menuBlock";
        _menuBlock.Size = new Size(219, 22);
        _menuBlock.Text = "阻止该程序联网";
        _menuBlock.Click += OnBlockButtonClick;

        _menuAllow.Name = "_menuAllow";
        _menuAllow.Size = new Size(219, 22);
        _menuAllow.Text = "允许该程序联网";
        _menuAllow.Click += OnAllowButtonClick;

        _menuSeparator.Name = "_menuSeparator";
        _menuSeparator.Size = new Size(216, 6);

        _menuCopyPath.Name = "_menuCopyPath";
        _menuCopyPath.Size = new Size(219, 22);
        _menuCopyPath.Text = "复制程序路径";
        _menuCopyPath.Click += OnCopyPathClick;

        // ==================================================================
        // 页二：已阻止的程序（规则管理）
        // ==================================================================
        _tabRules.Padding = new Padding(9);
        _tabRules.Name = "_tabRules";
        _tabRules.Text = "已阻止的程序";
        _tabRules.UseVisualStyleBackColor = true;

        // 这一段说明是专门为了回答「我阻止了 chrome，为什么列表里找不到它了」。
        _rulesNoticeLabel.Dock = DockStyle.Top;
        _rulesNoticeLabel.ForeColor = Color.FromArgb(191, 87, 0);
        _rulesNoticeLabel.Height = 46;
        _rulesNoticeLabel.Name = "_rulesNoticeLabel";
        _rulesNoticeLabel.Padding = new Padding(0, 2, 0, 0);
        _rulesNoticeLabel.Text = "被阻止的程序不会出现在「联网连接」页里 —— 它连不上网，自然也就没有连接。\r\n" +
                                 "所以恢复联网请一定在这一页操作：选中要恢复的程序，点「允许选中程序联网」。";
        _rulesNoticeLabel.TextAlign = ContentAlignment.TopLeft;

        _rulesToolPanel.Dock = DockStyle.Top;
        _rulesToolPanel.Height = 76;
        _rulesToolPanel.Name = "_rulesToolPanel";
        _rulesToolPanel.Controls.Add(_rulesRefreshButton);
        _rulesToolPanel.Controls.Add(_rulesSummaryLabel);
        _rulesToolPanel.Controls.Add(_rulesAllowButton);
        _rulesToolPanel.Controls.Add(_rulesDeleteButton);
        _rulesToolPanel.Controls.Add(_rulesDeleteAllButton);
        _rulesToolPanel.Controls.Add(_rulesHintLabel);

        _rulesRefreshButton.Location = new Point(0, 4);
        _rulesRefreshButton.Name = "_rulesRefreshButton";
        _rulesRefreshButton.Size = new Size(110, 28);
        _rulesRefreshButton.TabIndex = 0;
        _rulesRefreshButton.Text = "重新读取规则";
        _rulesRefreshButton.UseVisualStyleBackColor = true;
        _rulesRefreshButton.Click += OnRefreshRulesButtonClick;

        _rulesSummaryLabel.AutoSize = true;
        _rulesSummaryLabel.ForeColor = SystemColors.GrayText;
        _rulesSummaryLabel.Location = new Point(124, 10);
        _rulesSummaryLabel.Name = "_rulesSummaryLabel";
        _rulesSummaryLabel.Size = new Size(300, 17);
        _rulesSummaryLabel.TabIndex = 1;
        _rulesSummaryLabel.Text = "规则共 0 条";

        _rulesAllowButton.Enabled = false;
        _rulesAllowButton.Location = new Point(0, 42);
        _rulesAllowButton.Name = "_rulesAllowButton";
        _rulesAllowButton.Size = new Size(160, 28);
        _rulesAllowButton.TabIndex = 2;
        _rulesAllowButton.Text = "允许选中程序联网";
        _rulesAllowButton.UseVisualStyleBackColor = true;
        _rulesAllowButton.Click += OnRulesAllowButtonClick;

        _rulesDeleteButton.Enabled = false;
        _rulesDeleteButton.Location = new Point(168, 42);
        _rulesDeleteButton.Name = "_rulesDeleteButton";
        _rulesDeleteButton.Size = new Size(130, 28);
        _rulesDeleteButton.TabIndex = 3;
        _rulesDeleteButton.Text = "删除选中规则";
        _rulesDeleteButton.UseVisualStyleBackColor = true;
        _rulesDeleteButton.Click += OnRulesDeleteButtonClick;

        _rulesDeleteAllButton.Location = new Point(306, 42);
        _rulesDeleteAllButton.Name = "_rulesDeleteAllButton";
        _rulesDeleteAllButton.Size = new Size(180, 28);
        _rulesDeleteAllButton.TabIndex = 4;
        _rulesDeleteAllButton.Text = "删除全部 AppGuard 规则";
        _rulesDeleteAllButton.UseVisualStyleBackColor = true;
        _rulesDeleteAllButton.Click += OnRulesDeleteAllButtonClick;

        _rulesHintLabel.AutoSize = true;
        _rulesHintLabel.ForeColor = SystemColors.GrayText;
        _rulesHintLabel.Location = new Point(500, 47);
        _rulesHintLabel.Name = "_rulesHintLabel";
        _rulesHintLabel.Size = new Size(300, 17);
        _rulesHintLabel.TabIndex = 5;
        _rulesHintLabel.Text = "未选中任何规则";

        _rulesGrid.Dock = DockStyle.Fill;
        _rulesGrid.AllowUserToAddRows = false;
        _rulesGrid.AllowUserToDeleteRows = false;
        _rulesGrid.AllowUserToResizeRows = false;
        _rulesGrid.AlternatingRowsDefaultCellStyle = new DataGridViewCellStyle
        {
            BackColor = Color.FromArgb(245, 247, 250),
        };
        _rulesGrid.AutoGenerateColumns = false;
        _rulesGrid.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.None;
        _rulesGrid.BackgroundColor = SystemColors.Window;
        _rulesGrid.BorderStyle = BorderStyle.Fixed3D;
        _rulesGrid.ColumnHeadersHeightSizeMode = DataGridViewColumnHeadersHeightSizeMode.DisableResizing;
        _rulesGrid.EditMode = DataGridViewEditMode.EditProgrammatically;
        _rulesGrid.MultiSelect = false;
        _rulesGrid.Name = "_rulesGrid";
        _rulesGrid.ReadOnly = true;
        _rulesGrid.RowHeadersVisible = false;
        _rulesGrid.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
        _rulesGrid.TabIndex = 1;
        _rulesGrid.CellMouseDown += OnRulesGridCellMouseDown;
        _rulesGrid.KeyDown += OnRulesGridKeyDown;
        _rulesGrid.SelectionChanged += OnRulesGridSelectionChanged;

        // 先加 Fill，再加 Dock=Top 的，顺序决定谁占外面一条：最后加的最靠外。
        _tabRules.Controls.Add(_rulesGrid);
        _tabRules.Controls.Add(_rulesToolPanel);
        _tabRules.Controls.Add(_rulesNoticeLabel);

        // ==================================================================
        // 页三：设置
        // ==================================================================
        _tabSettings.AutoScroll = true;
        _tabSettings.Padding = new Padding(9);
        _tabSettings.Name = "_tabSettings";
        _tabSettings.Text = "设置";
        _tabSettings.UseVisualStyleBackColor = true;
        _tabSettings.Resize += OnSettingsTabResize;

        // 这一页有四个分区，竖向放不下，所以标签页开了 AutoScroll。
        //
        // 这里用绝对坐标是可以的，因为**每个分区的高度都是写死的**，
        // 不存在「内容把容器撑大」的情况 —— 那正是之前压住按钮的 bug 根因。
        // 分区内部仍然全部用 Dock 布局（见下面「开机自启」面板的说明）。
        _settingsNoticeLabel.AutoSize = true;
        _settingsNoticeLabel.Anchor = AnchorStyles.Top | AnchorStyles.Left;
        _settingsNoticeLabel.ForeColor = Color.FromArgb(191, 87, 0);
        _settingsNoticeLabel.Location = new Point(6, 6);
        _settingsNoticeLabel.MaximumSize = new Size(1060, 0);
        _settingsNoticeLabel.Name = "_settingsNoticeLabel";
        _settingsNoticeLabel.Size = new Size(900, 60);
        _settingsNoticeLabel.TabIndex = 0;
        _settingsNoticeLabel.Text =
            "开机自启的原理：在 Windows「任务计划程序」里创建一条名为 WinAppGuard 的任务，" +
            "让你每次登录 Windows 时自动启动本程序并最小化到托盘。" +
            "它使用「最高权限运行」，所以开机启动时不会弹出 UAC 确认框。\r\n" +
            "这是本程序唯一一处会写入系统持久化配置的地方 —— 你可以随时在下面关掉，" +
            "也可以自己打开 taskschd.msc 手动删除。";

        _autostartPanel.Anchor = AnchorStyles.Top | AnchorStyles.Left;
        _autostartPanel.Location = new Point(6, 84);
        _autostartPanel.Name = "_autostartPanel";
        _autostartPanel.Size = new Size(1060, 248);
        _autostartPanel.TabIndex = 1;
        _autostartPanel.Text = "开机自启";

        // 面板内一律用 Dock 排版，不用绝对坐标。
        //
        // 为什么：这里的「任务详情」字数随状态变化很大（未开启 1 行 / 已开启 6 行 / 配置不符 8 行）。
        // 之前用「AutoSize 标签 + 绝对坐标 + 固定高度的容器」，内容一长就往下长出去盖住了下面的按钮 ——
        // 这是真实发生过的 bug。停靠布局从结构上就不可能重叠：
        // 按钮钉死在底部，状态钉死在顶部，详情占中间剩下的地方，装不下就自己出滚动条。
        _autostartPanel.Controls.Add(_autostartDetailHost);
        _autostartPanel.Controls.Add(_autostartStatusLabel);
        _autostartPanel.Controls.Add(_autostartButtons);

        _autostartStatusLabel.Dock = DockStyle.Top;
        _autostartStatusLabel.Font = new Font("Microsoft YaHei UI", 11F, FontStyle.Bold, GraphicsUnit.Point);
        _autostartStatusLabel.Height = 32;
        _autostartStatusLabel.Name = "_autostartStatusLabel";
        _autostartStatusLabel.Padding = new Padding(12, 0, 0, 0);
        _autostartStatusLabel.TabIndex = 0;
        _autostartStatusLabel.Text = "当前状态：检测中…";
        _autostartStatusLabel.TextAlign = ContentAlignment.MiddleLeft;

        // 详情区开了 AutoScroll：内容装不下时出滚动条，而不是溢出去压住别的控件。
        _autostartDetailHost.AutoScroll = true;
        _autostartDetailHost.Dock = DockStyle.Fill;
        _autostartDetailHost.Name = "_autostartDetailHost";
        _autostartDetailHost.TabIndex = 1;
        _autostartDetailHost.Controls.Add(_autostartDetailLabel);

        _autostartDetailLabel.AutoSize = true;
        _autostartDetailLabel.ForeColor = SystemColors.GrayText;
        _autostartDetailLabel.Location = new Point(14, 0);
        _autostartDetailLabel.MaximumSize = new Size(1040, 0);
        _autostartDetailLabel.Name = "_autostartDetailLabel";
        _autostartDetailLabel.Size = new Size(400, 60);
        _autostartDetailLabel.TabIndex = 0;
        _autostartDetailLabel.Text = "";

        _autostartButtons.Dock = DockStyle.Bottom;
        _autostartButtons.Height = 48;
        _autostartButtons.Name = "_autostartButtons";
        _autostartButtons.TabIndex = 2;
        _autostartButtons.Controls.Add(_enableAutostartButton);
        _autostartButtons.Controls.Add(_disableAutostartButton);
        _autostartButtons.Controls.Add(_refreshAutostartButton);

        _enableAutostartButton.Location = new Point(14, 8);
        _enableAutostartButton.Name = "_enableAutostartButton";
        _enableAutostartButton.Size = new Size(180, 32);
        _enableAutostartButton.TabIndex = 0;
        _enableAutostartButton.Text = "开启开机自启";
        _enableAutostartButton.UseVisualStyleBackColor = true;
        _enableAutostartButton.Click += OnEnableAutoStartClick;

        _disableAutostartButton.Location = new Point(204, 8);
        _disableAutostartButton.Name = "_disableAutostartButton";
        _disableAutostartButton.Size = new Size(180, 32);
        _disableAutostartButton.TabIndex = 1;
        _disableAutostartButton.Text = "关闭开机自启";
        _disableAutostartButton.UseVisualStyleBackColor = true;
        _disableAutostartButton.Click += OnDisableAutoStartClick;

        _refreshAutostartButton.Location = new Point(394, 8);
        _refreshAutostartButton.Name = "_refreshAutostartButton";
        _refreshAutostartButton.Size = new Size(150, 32);
        _refreshAutostartButton.TabIndex = 2;
        _refreshAutostartButton.Text = "重新读取状态";
        _refreshAutostartButton.UseVisualStyleBackColor = true;
        _refreshAutostartButton.Click += OnRefreshAutoStartClick;

        // 直接把任务计划程序里的原始定义摆出来给用户看，这是最彻底的透明。
        _taskXmlPanel.Anchor = AnchorStyles.Top | AnchorStyles.Left;
        _taskXmlPanel.Location = new Point(6, 486);
        _taskXmlPanel.Name = "_taskXmlPanel";
        _taskXmlPanel.Size = new Size(1060, 220);
        _taskXmlPanel.TabIndex = 3;
        _taskXmlPanel.Text = "任务计划程序里的原始定义（只读，实时读取）";
        _taskXmlPanel.Controls.Add(_taskXmlBox);

        _taskXmlBox.Dock = DockStyle.Fill;
        _taskXmlBox.Font = new Font("Consolas", 9F, FontStyle.Regular, GraphicsUnit.Point);
        _taskXmlBox.Location = new Point(3, 19);
        _taskXmlBox.Multiline = true;
        _taskXmlBox.Name = "_taskXmlBox";
        _taskXmlBox.ReadOnly = true;
        _taskXmlBox.ScrollBars = ScrollBars.Both;
        _taskXmlBox.TabIndex = 0;
        _taskXmlBox.WordWrap = false;

        // ---------- 数据与隐私 ----------
        // 单独做一块，是为了正面回答「这工具会不会偷偷把我的数据传出去」。
        _privacyPanel.Anchor = AnchorStyles.Top | AnchorStyles.Left;
        _privacyPanel.Location = new Point(6, 342);
        _privacyPanel.Name = "_privacyPanel";
        _privacyPanel.Size = new Size(1060, 132);
        _privacyPanel.TabIndex = 2;
        _privacyPanel.Text = "数据与隐私";

        _privacyLabel.AutoSize = true;
        _privacyLabel.Location = new Point(14, 24);
        _privacyLabel.MaximumSize = new Size(1030, 0);
        _privacyLabel.Name = "_privacyLabel";
        _privacyLabel.Size = new Size(600, 40);
        _privacyLabel.TabIndex = 0;
        _privacyLabel.Text =
            "本程序运行期间不访问网络、不上传任何数据、不调用任何在线服务。" +
            "日志只写在本机下面这一个目录里，不会发送到任何地方，你可以随时查看或删除：";

        _logPathLabel.AutoSize = true;
        _logPathLabel.ForeColor = SystemColors.GrayText;
        _logPathLabel.Location = new Point(14, 68);
        _logPathLabel.Name = "_logPathLabel";
        _logPathLabel.Size = new Size(600, 17);
        _logPathLabel.TabIndex = 1;
        _logPathLabel.Text = "";

        _openLogFolderButton.Location = new Point(14, 90);
        _openLogFolderButton.Name = "_openLogFolderButton";
        _openLogFolderButton.Size = new Size(160, 30);
        _openLogFolderButton.TabIndex = 2;
        _openLogFolderButton.Text = "打开日志目录";
        _openLogFolderButton.UseVisualStyleBackColor = true;
        _openLogFolderButton.Click += OnOpenLogFolderClick;

        _privacyPanel.Controls.Add(_privacyLabel);
        _privacyPanel.Controls.Add(_logPathLabel);
        _privacyPanel.Controls.Add(_openLogFolderButton);

        _tabSettings.Controls.Add(_taskXmlPanel);
        _tabSettings.Controls.Add(_privacyPanel);
        _tabSettings.Controls.Add(_autostartPanel);
        _tabSettings.Controls.Add(_settingsNoticeLabel);

        // ---------- 退出按钮 ----------
        _exitButton.Anchor = AnchorStyles.Bottom | AnchorStyles.Left;
        _exitButton.Location = new Point(24, 638);
        _exitButton.Name = "_exitButton";
        _exitButton.Size = new Size(120, 34);
        _exitButton.TabIndex = 4;
        _exitButton.Text = "最小化到托盘";
        _exitButton.UseVisualStyleBackColor = true;
        _exitButton.Click += OnExitButtonClick;

        // ---------- 底部状态栏 ----------
        _statusStrip.Items.AddRange(new ToolStripItem[]
        {
            _adminStatusLabel, _springLabel, _startModeLabel, _statusRulesLabel, _summaryLabel, _versionLabel,
        });
        _statusStrip.Location = new Point(0, 678);
        _statusStrip.Name = "_statusStrip";
        _statusStrip.Size = new Size(1180, 22);
        _statusStrip.TabIndex = 5;

        _adminStatusLabel.Name = "_adminStatusLabel";
        _adminStatusLabel.Size = new Size(150, 17);
        _adminStatusLabel.Text = "管理员权限：检测中…";

        // 中间弹簧，把后面的信息挤到最右侧
        _springLabel.Name = "_springLabel";
        _springLabel.Size = new Size(0, 17);
        _springLabel.Spring = true;

        _startModeLabel.ForeColor = SystemColors.GrayText;
        _startModeLabel.Name = "_startModeLabel";
        _startModeLabel.Size = new Size(160, 17);
        _startModeLabel.Text = "启动模式：手动启动";

        _statusRulesLabel.Name = "_statusRulesLabel";
        _statusRulesLabel.Size = new Size(180, 17);
        _statusRulesLabel.Text = "已阻止程序：0 个";

        _summaryLabel.Name = "_summaryLabel";
        _summaryLabel.Size = new Size(200, 17);
        _summaryLabel.Text = "最后刷新：--:--:--    共 0 条";

        _versionLabel.Name = "_versionLabel";
        _versionLabel.Size = new Size(60, 17);
        _versionLabel.Text = "版本 v0.0.0";

        // ---------- 自动刷新定时器 ----------
        // 间隔在 MainForm 构造函数中统一设置，避免同一个数值出现在两个文件里。
        _autoRefreshTimer.Tick += OnAutoRefreshTick;

        // ---------- 系统托盘 ----------
        // 托盘是本工具「一直可用」的保障：用户点 X 只是收起来，规则仍在生效，
        // 想恢复被拦的程序随时能找到入口。
        _trayMenu.Items.AddRange(new ToolStripItem[] { _trayShowItem, _trayDeleteAllItem, _traySeparator, _trayExitItem });
        _trayMenu.Name = "_trayMenu";
        _trayMenu.Size = new Size(260, 92);

        _trayShowItem.Name = "_trayShowItem";
        _trayShowItem.Size = new Size(259, 22);
        _trayShowItem.Text = "显示主界面";
        _trayShowItem.Font = new Font(_trayShowItem.Font, FontStyle.Bold);
        _trayShowItem.Click += OnTrayShowClick;

        _trayDeleteAllItem.Name = "_trayDeleteAllItem";
        _trayDeleteAllItem.Size = new Size(259, 22);
        _trayDeleteAllItem.Text = "删除全部 AppGuard 规则…";
        _trayDeleteAllItem.Click += OnRulesDeleteAllButtonClick;

        _traySeparator.Name = "_traySeparator";
        _traySeparator.Size = new Size(256, 6);

        _trayExitItem.Name = "_trayExitItem";
        _trayExitItem.Size = new Size(259, 22);
        _trayExitItem.Text = "退出";
        _trayExitItem.Click += OnTrayExitClick;

        // NotifyIcon.Text 有 63 个字符的上限，别写太长。
        // 这里用 Core.AppIcon 全限定名，是因为 Designer 文件不写 using，保持和自动生成代码一致的风格。
        _trayIcon.ContextMenuStrip = _trayMenu;
        _trayIcon.Icon = Core.AppIcon.Load(SystemInformation.SmallIconSize);
        _trayIcon.Text = "WinAppGuard — 程序联网控制";
        _trayIcon.Visible = true;
        _trayIcon.DoubleClick += OnTrayShowClick;

        // ---------- 鼠标悬停说明 ----------
        // 默认会隐藏掉一部分连接，必须在界面上说清楚隐藏了什么，不能静默过滤。
        _toolTip.SetToolTip(_showListenCheckBox,
            "监听状态表示程序开着端口等待别人来连，并不代表它正在联网。\n默认不显示。");
        _toolTip.SetToolTip(_showClosedCheckBox,
            "TIME_WAIT / CLOSED 表示连接已经结束，只是还没被系统回收。\n" +
            "这类记录的归属进程通常已经退出，既看不出是哪个程序，也没法用来创建防火墙规则。\n默认不显示。");
        _toolTip.SetToolTip(_showOwnerlessCheckBox,
            "没有归属进程（PID 为 0）的连接无法显示程序名，也无法为它创建防火墙规则。\n默认不显示。");
        _toolTip.SetToolTip(_autoRefreshCheckBox,
            "每 3 秒自动重新扫描一次。勾选后会立刻先刷新一次。");
        _toolTip.SetToolTip(_connectionGrid,
            "默认只显示「有归属进程、还活着、且不是本机回环」的连接。\n" +
            "在行上点右键可以直接阻止或允许该程序联网。\n" +
            "注意：被阻止的程序连不上网，所以不会出现在这里 —— 去「已阻止的程序」页恢复它。");
        _toolTip.SetToolTip(_refreshRulesButton,
            "重新从 Windows 防火墙读取本工具创建的规则。\n" +
            "如果你在 wf.msc 里手动改过规则，点这里同步。");
        _toolTip.SetToolTip(_rulesDeleteAllButton,
            "删除本工具创建的全部规则，相当于一次「全部放行」。\n" +
            "只会删除 AppGuard 开头的规则，其他软件和系统自带的规则一律不动。\n" +
            "需要连续确认两次。");
        // 注意：ToolTip 只接受 Control，托盘图标不能设，它自带 Text 悬停提示。

        // ---------- 窗体 ----------
        AutoScaleDimensions = new SizeF(7F, 17F);
        AutoScaleMode = AutoScaleMode.Font;
        ClientSize = new Size(1180, 700);
        Controls.Add(_tabControl);
        Controls.Add(_safetyNoticeLabel);
        Controls.Add(_descriptionLabel);
        Controls.Add(_titleLabel);
        Controls.Add(_exitButton);
        Controls.Add(_statusStrip);
        MinimumSize = new Size(980, 640);
        Name = "MainForm";
        StartPosition = FormStartPosition.CenterScreen;
        Text = "WinAppGuard — Windows 程序联网控制工具";

        _tabControl.ResumeLayout(false);
        _tabConnections.ResumeLayout(false);
        _tabRules.ResumeLayout(false);
        _tabSettings.ResumeLayout(false);
        _autostartPanel.ResumeLayout(false);
        _autostartDetailHost.ResumeLayout(false);
        _autostartDetailHost.PerformLayout();
        _autostartButtons.ResumeLayout(false);
        _autostartButtons.PerformLayout();
        _taskXmlPanel.ResumeLayout(false);
        _taskXmlPanel.PerformLayout();
        _privacyPanel.ResumeLayout(false);
        _privacyPanel.PerformLayout();
        _toolPanel.ResumeLayout(false);
        _toolPanel.PerformLayout();
        _rulesToolPanel.ResumeLayout(false);
        _rulesToolPanel.PerformLayout();
        _gridContextMenu.ResumeLayout(false);
        _trayMenu.ResumeLayout(false);
        _statusStrip.ResumeLayout(false);
        _statusStrip.PerformLayout();
        ResumeLayout(false);
        PerformLayout();
    }
}
