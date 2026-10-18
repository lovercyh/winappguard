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
    private Label _safetyNoticeLabel = null!;

    // ================= 标签页 =================
    private TabControl _tabControl = null!;

    // ---------- 页一：联网连接 ----------
    private TabPage _tabConnections = null!;

    private Panel _toolPanel = null!;
    private FlowLayoutPanel _toolRowFilters = null!;
    private FlowLayoutPanel _toolRowActions = null!;
    private FlowLayoutPanel _toolRowSearch = null!;
    private Label _searchLabel = null!;
    private TextBox _searchBox = null!;
    private Button _clearSearchButton = null!;
    private Button _refreshButton = null!;
    private CheckBox _autoRefreshCheckBox = null!;
    private CheckBox _showListenCheckBox = null!;
    private CheckBox _showClosedCheckBox = null!;
    private CheckBox _showOwnerlessCheckBox = null!;
    private CheckBox _hideLoopbackCheckBox = null!;
    private Button _blockButton = null!;
    private Button _allowButton = null!;
    private Button _whitelistButton = null!;
    private Button _refreshRulesButton = null!;
    private Label _selectionHintLabel = null!;

    private DataGridViewBuffered _connectionGrid = null!;

    private ContextMenuStrip _gridContextMenu = null!;
    private ToolStripMenuItem _menuBlock = null!;
    private ToolStripMenuItem _menuAllow = null!;
    private ToolStripSeparator _menuSeparator = null!;
    private ToolStripMenuItem _menuCopyPath = null!;
    private ToolStripMenuItem _menuWhitelistAdd = null!;
    private ToolStripMenuItem _menuWhitelistRemove = null!;

    // ---------- 页二：规则（本工具建的防火墙规则）----------
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
    private TabPage _tabAudit = null!;

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
    private CheckBox _checkRevocationCheckBox = null!;
    private CheckBox _checkIpOwnershipCheckBox = null!;
    private Panel _privacyScrollHost = null!;
    private Panel _privacyBottomPanel = null!;

    // ---------- 严格模式（高级）----------
    private GroupBox _strictModePanel = null!;
    private Label _strictModeStatusLabel = null!;
    private Label _strictModeDetailLabel = null!;
    private Panel _strictModeButtons = null!;
    private Button _strictModeToggleButton = null!;
    private Button _refreshStrictModeButton = null!;

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

    /// <summary>
    /// 检查「临时阻断」是否到期的独立定时器。
    ///
    /// 刻意**不**复用上面那个自动刷新定时器：自动刷新的开关默认是关的，
    /// 复用的话没勾开关的用户就永远等不到临时阻断自动解除。
    /// </summary>
    private System.Windows.Forms.Timer _expiryTimer = null!;
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
            // 先停掉归属查询的后台调度，再释放控件。
            // Dispose 不等待正在飞的查询 —— 那会让退出卡住；
            // 后台线程是线程池线程，不会阻止进程退出。
            _ipOwnershipService.Dispose();

            components?.Dispose();
        }

        base.Dispose(disposing);
    }

    private void InitializeComponent()
    {
        components = new System.ComponentModel.Container();

        _titleLabel = new Label();
        _safetyNoticeLabel = new Label();
        _tabControl = new TabControl();
        _tabConnections = new TabPage();
        _tabRules = new TabPage();
        _toolPanel = new Panel();
        _toolRowFilters = new FlowLayoutPanel();
        _toolRowActions = new FlowLayoutPanel();
        _toolRowSearch = new FlowLayoutPanel();
        _searchLabel = new Label();
        _searchBox = new TextBox();
        _clearSearchButton = new Button();
        _refreshButton = new Button();
        _autoRefreshCheckBox = new CheckBox();
        _showListenCheckBox = new CheckBox();
        _showClosedCheckBox = new CheckBox();
        _showOwnerlessCheckBox = new CheckBox();
        _hideLoopbackCheckBox = new CheckBox();
        _blockButton = new Button();
        _allowButton = new Button();
        _whitelistButton = new Button();
        _refreshRulesButton = new Button();
        _selectionHintLabel = new Label();
        _connectionGrid = new DataGridViewBuffered();
        _gridContextMenu = new ContextMenuStrip(components);
        _menuBlock = new ToolStripMenuItem();
        _menuAllow = new ToolStripMenuItem();
        _menuSeparator = new ToolStripSeparator();
        _menuCopyPath = new ToolStripMenuItem();
        _menuWhitelistAdd = new ToolStripMenuItem();
        _menuWhitelistRemove = new ToolStripMenuItem();
        _rulesNoticeLabel = new Label();
        _rulesToolPanel = new Panel();
        _rulesRefreshButton = new Button();
        _rulesSummaryLabel = new Label();
        _rulesAllowButton = new Button();
        _rulesDeleteButton = new Button();
        _rulesDeleteAllButton = new Button();
        _rulesHintLabel = new Label();
        _rulesGrid = new DataGridViewBuffered();
        _tabAudit = new TabPage();
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
        _checkRevocationCheckBox = new CheckBox();
        _checkIpOwnershipCheckBox = new CheckBox();
        _privacyScrollHost = new Panel();
        _privacyBottomPanel = new Panel();
        _strictModePanel = new GroupBox();
        _strictModeStatusLabel = new Label();
        _strictModeDetailLabel = new Label();
        _strictModeButtons = new Panel();
        _strictModeToggleButton = new Button();
        _refreshStrictModeButton = new Button();
        _exitButton = new Button();
        _statusStrip = new StatusStrip();
        _adminStatusLabel = new ToolStripStatusLabel();
        _springLabel = new ToolStripStatusLabel();
        _startModeLabel = new ToolStripStatusLabel();
        _statusRulesLabel = new ToolStripStatusLabel();
        _summaryLabel = new ToolStripStatusLabel();
        _versionLabel = new ToolStripStatusLabel();
        _autoRefreshTimer = new System.Windows.Forms.Timer(components);
        _expiryTimer = new System.Windows.Forms.Timer(components);
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
        _privacyScrollHost.SuspendLayout();
        _privacyBottomPanel.SuspendLayout();
        _strictModePanel.SuspendLayout();
        _strictModeButtons.SuspendLayout();
        _toolPanel.SuspendLayout();
        _toolRowFilters.SuspendLayout();
        _toolRowActions.SuspendLayout();
        _toolRowSearch.SuspendLayout();
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

        // ---------- 说明（常驻）----------
        //
        // 刻意关掉 AutoSize 并写死高度：这段文字是固定长度的常驻说明，
        // 万一以后有人把它改长了、换行了，也只会被裁掉一点，绝不会往下长出去压住标签页。
        _safetyNoticeLabel.AutoSize = false;
        _safetyNoticeLabel.ForeColor = Color.FromArgb(191, 87, 0);
        _safetyNoticeLabel.Location = new Point(27, 52);
        _safetyNoticeLabel.Name = "_safetyNoticeLabel";
        _safetyNoticeLabel.Size = new Size(1120, 20);
        _safetyNoticeLabel.TabIndex = 1;
        // ⚠️ 这里的措辞必须和实际行为一致。
        // 有两处会联网：IP 归属查询（本程序自己的代码）和证书吊销检查
        // （Windows 证书服务代表程序发起）。不能写「本程序不访问网络」，那是在骗用户。
        //
        // 2.0 起工具不再使用 Windows 防火墙，规则全部落在 WFP 的专属子层里；
        // 严格模式也只是在自己的动态会话里生效，**不修改任何系统设置**。
        // 所以这里既不能说「Windows 防火墙规则」，也不能再留「除严格模式外」的例外。
        //
        // ⚠️ 这个标签是**固定宽高、不换行**的（AutoSize=false, 1120×20），
        // 所以文案**必须放得下** —— 加长之后后半句会被直接裁掉，而且不报错。
        // 自检里有一条断言专门量它（--ui-check 的「顶部安全横幅放得下」）。
        _safetyNoticeLabel.Text =
            "说明：只在专属子层里创建和删除本工具的过滤器，不修改 Windows 防火墙的任何设置" +
            "（严格模式只在本进程内生效）；默认会联网查 IP 归属与证书吊销，都能在「设置」页关闭。";

        _tabAudit.Name = "_tabAudit";
        _tabAudit.Padding = new Padding(3);
        _tabAudit.Text = "审计";
        _tabAudit.UseVisualStyleBackColor = true;

        // ==================================================================
        // 标签页容器
        // ==================================================================
        _tabControl.Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;
        _tabControl.Controls.Add(_tabConnections);
        _tabControl.Controls.Add(_tabRules);
        _tabControl.Controls.Add(_tabSettings);
        _tabControl.Controls.Add(_tabAudit);
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
        // ---------- 工具栏 ----------
        //
        // 排版原则（踩过坑，见 docs 里的「界面布局铁律」）：
        //   这里以前是「绝对坐标 + 固定高度 76」，每个控件写死 Location。
        //   结果窗口一缩到最小尺寸，第一行最右边的「隐藏本机回环连接」就被裁掉 ——
        //   实测该开关右边界 902 > 工具栏宽度 890，被 SelfCheck --ui-check 抓了出来。
        //
        //   现在改成「三层流式布局」：控件从左往右排，装不下自动换行，
        //   整块工具栏的高度跟着内容长。结构上不可能被裁掉。
        _toolPanel.AutoSize = true;
        _toolPanel.AutoSizeMode = AutoSizeMode.GrowAndShrink;
        _toolPanel.Dock = DockStyle.Top;
        _toolPanel.Name = "_toolPanel";

        // 停靠顺序是从后往前解析的：最后加的排最上面。
        // 所以按「搜索行 → 操作行 → 筛选行」加入，显示出来就是「筛选 / 操作 / 搜索」三行。
        _toolPanel.Controls.Add(_toolRowSearch);
        _toolPanel.Controls.Add(_toolRowActions);
        _toolPanel.Controls.Add(_toolRowFilters);

        // 每一行都是一个流式布局：从左往右排，装不下自动换行。
        _toolRowFilters.AutoSize = true;
        _toolRowFilters.AutoSizeMode = AutoSizeMode.GrowAndShrink;
        _toolRowFilters.Dock = DockStyle.Top;
        _toolRowFilters.FlowDirection = FlowDirection.LeftToRight;
        _toolRowFilters.Name = "_toolRowFilters";
        _toolRowFilters.Padding = new Padding(0, 2, 0, 2);

        _toolRowActions.AutoSize = true;
        _toolRowActions.AutoSizeMode = AutoSizeMode.GrowAndShrink;
        _toolRowActions.Dock = DockStyle.Top;
        _toolRowActions.FlowDirection = FlowDirection.LeftToRight;
        _toolRowActions.Name = "_toolRowActions";
        _toolRowActions.Padding = new Padding(0, 2, 0, 2);

        _toolRowSearch.AutoSize = true;
        _toolRowSearch.AutoSizeMode = AutoSizeMode.GrowAndShrink;
        _toolRowSearch.Dock = DockStyle.Top;
        _toolRowSearch.FlowDirection = FlowDirection.LeftToRight;
        _toolRowSearch.Name = "_toolRowSearch";
        _toolRowSearch.Padding = new Padding(0, 2, 0, 4);

        _toolRowFilters.Controls.Add(_refreshButton);
        _toolRowFilters.Controls.Add(_autoRefreshCheckBox);
        _toolRowFilters.Controls.Add(_showListenCheckBox);
        _toolRowFilters.Controls.Add(_showClosedCheckBox);
        _toolRowFilters.Controls.Add(_showOwnerlessCheckBox);
        _toolRowFilters.Controls.Add(_hideLoopbackCheckBox);

        _toolRowActions.Controls.Add(_blockButton);
        _toolRowActions.Controls.Add(_allowButton);
        _toolRowActions.Controls.Add(_whitelistButton);
        _toolRowActions.Controls.Add(_refreshRulesButton);
        _toolRowActions.Controls.Add(_selectionHintLabel);

        _toolRowSearch.Controls.Add(_searchLabel);
        _toolRowSearch.Controls.Add(_searchBox);
        _toolRowSearch.Controls.Add(_clearSearchButton);

        _refreshButton.Name = "_refreshButton";
        _refreshButton.Size = new Size(90, 28);
        _refreshButton.TabIndex = 0;
        _refreshButton.Text = "刷新";
        _refreshButton.UseVisualStyleBackColor = true;
        _refreshButton.Click += OnRefreshButtonClick;

        // 注意：下面这些控件都开了 AutoSize，所以**不再写死 Size** ——
        // 写了也会被忽略（原来的代码里写了 Size，实际宽度却由文字决定，很容易误判）。
        _autoRefreshCheckBox.AutoSize = true;
        _autoRefreshCheckBox.Name = "_autoRefreshCheckBox";
        _autoRefreshCheckBox.TabIndex = 1;
        _autoRefreshCheckBox.Text = "每 3 秒自动刷新";
        _autoRefreshCheckBox.UseVisualStyleBackColor = true;
        _autoRefreshCheckBox.CheckedChanged += OnAutoRefreshCheckedChanged;

        _showListenCheckBox.AutoSize = true;
        _showListenCheckBox.Name = "_showListenCheckBox";
        _showListenCheckBox.TabIndex = 2;
        _showListenCheckBox.Text = "显示监听中(LISTEN)";
        _showListenCheckBox.UseVisualStyleBackColor = true;
        _showListenCheckBox.CheckedChanged += OnScanOptionChanged;

        _showClosedCheckBox.AutoSize = true;
        _showClosedCheckBox.Name = "_showClosedCheckBox";
        _showClosedCheckBox.TabIndex = 3;
        _showClosedCheckBox.Text = "显示已结束(TIME_WAIT 等)";
        _showClosedCheckBox.UseVisualStyleBackColor = true;
        _showClosedCheckBox.CheckedChanged += OnScanOptionChanged;

        _showOwnerlessCheckBox.AutoSize = true;
        _showOwnerlessCheckBox.Name = "_showOwnerlessCheckBox";
        _showOwnerlessCheckBox.TabIndex = 4;
        _showOwnerlessCheckBox.Text = "显示无进程归属的连接";
        _showOwnerlessCheckBox.UseVisualStyleBackColor = true;
        _showOwnerlessCheckBox.CheckedChanged += OnScanOptionChanged;

        _hideLoopbackCheckBox.AutoSize = true;
        _hideLoopbackCheckBox.Checked = true;
        _hideLoopbackCheckBox.CheckState = CheckState.Checked;
        _hideLoopbackCheckBox.Name = "_hideLoopbackCheckBox";
        _hideLoopbackCheckBox.TabIndex = 5;
        _hideLoopbackCheckBox.Text = "隐藏本机回环连接";
        _hideLoopbackCheckBox.UseVisualStyleBackColor = true;
        _hideLoopbackCheckBox.CheckedChanged += OnScanOptionChanged;

        _blockButton.Enabled = false;
        _blockButton.Name = "_blockButton";
        _blockButton.Size = new Size(160, 28);
        _blockButton.TabIndex = 10;
        _blockButton.Text = "阻止选中程序联网";
        _blockButton.UseVisualStyleBackColor = true;
        _blockButton.Click += OnBlockButtonClick;

        _allowButton.Enabled = false;
        _allowButton.Name = "_allowButton";
        _allowButton.Size = new Size(160, 28);
        _allowButton.TabIndex = 11;
        _allowButton.Text = "允许选中程序联网";
        _allowButton.UseVisualStyleBackColor = true;
        _allowButton.Click += OnAllowButtonClick;

        // 白名单按钮的文字会**跟着选中行变化**（加入 / 移出），所以这里只给个初值。
        _whitelistButton.Enabled = false;
        _whitelistButton.Name = "_whitelistButton";
        _whitelistButton.Size = new Size(120, 28);
        _whitelistButton.TabIndex = 12;
        _whitelistButton.Text = "加入白名单";
        _whitelistButton.UseVisualStyleBackColor = true;
        _whitelistButton.Click += OnWhitelistButtonClick;

        _refreshRulesButton.Name = "_refreshRulesButton";
        _refreshRulesButton.Size = new Size(130, 28);
        _refreshRulesButton.TabIndex = 12;
        _refreshRulesButton.Text = "同步规则状态";
        _refreshRulesButton.UseVisualStyleBackColor = true;
        _refreshRulesButton.Click += OnRefreshRulesButtonClick;

        _selectionHintLabel.AutoSize = true;
        _selectionHintLabel.ForeColor = SystemColors.GrayText;
        _selectionHintLabel.Name = "_selectionHintLabel";
        _selectionHintLabel.TabIndex = 13;
        _selectionHintLabel.Text = "未选中任何连接";

        // 搜索框。
        //
        // 刻意**不做 placeholder**：那要调 user32 的 EM_SETCUEBANNER，
        // 会新增一个 P/Invoke，把「16 个原生调用」变成 17 个，还要改审计和文档。
        // 不值当 —— 用左边这个标签把用途写清楚就够了。
        _searchLabel.AutoSize = true;
        _searchLabel.ForeColor = SystemColors.GrayText;
        _searchLabel.Margin = new Padding(0, 7, 4, 0);
        _searchLabel.Name = "_searchLabel";
        _searchLabel.Text = "搜索（程序名 / PID / 远程 IP / 远程端口）：";

        _searchBox.Name = "_searchBox";
        _searchBox.Size = new Size(220, 23);
        _searchBox.TabIndex = 20;
        _searchBox.TextChanged += OnSearchTextChanged;
        _searchBox.KeyDown += OnSearchBoxKeyDown;

        _clearSearchButton.Name = "_clearSearchButton";
        _clearSearchButton.Size = new Size(70, 26);
        _clearSearchButton.TabIndex = 21;
        _clearSearchButton.Text = "清除";
        _clearSearchButton.UseVisualStyleBackColor = true;
        _clearSearchButton.Click += OnClearSearchClick;

        _connectionGrid.Dock = DockStyle.Fill;
        _connectionGrid.AllowUserToAddRows = false;
        _connectionGrid.AllowUserToDeleteRows = false;
        // 关掉自带的「实时改列宽」：它每移动一次鼠标就把整表重画一遍，慢机器上明显卡。
        // 改用 GridColumnResizer 的「预览线」方式（见那个类的说明）。
        _connectionGrid.AllowUserToResizeColumns = false;
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
        _connectionGrid.ColumnHeaderMouseClick += OnConnectionGridColumnHeaderMouseClick;
        _connectionGrid.KeyDown += OnGridKeyDown;
        _connectionGrid.SelectionChanged += OnGridSelectionChanged;

        // 先加 Fill 的控件，再加 Dock=Top 的控件，这样 Top 的占上面一条、Fill 的占剩下的。
        _tabConnections.Controls.Add(_connectionGrid);
        _tabConnections.Controls.Add(_toolPanel);

        // ---------- 右键菜单 ----------
        _gridContextMenu.Items.AddRange(new ToolStripItem[] { _menuBlock, _menuAllow, _menuWhitelistAdd, _menuWhitelistRemove, _menuSeparator, _menuCopyPath });
        _gridContextMenu.Name = "_gridContextMenu";
        _gridContextMenu.Size = new Size(220, 120);

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

        _menuWhitelistAdd.Name = "_menuWhitelistAdd";
        _menuWhitelistAdd.Size = new Size(219, 22);
        _menuWhitelistAdd.Text = "加入白名单";
        _menuWhitelistAdd.Click += OnWhitelistAddClick;

        _menuWhitelistRemove.Name = "_menuWhitelistRemove";
        _menuWhitelistRemove.Size = new Size(219, 22);
        _menuWhitelistRemove.Text = "移出白名单";
        _menuWhitelistRemove.Click += OnWhitelistRemoveClick;

        _menuCopyPath.Name = "_menuCopyPath";
        _menuCopyPath.Size = new Size(219, 22);
        _menuCopyPath.Text = "复制程序路径";
        _menuCopyPath.Click += OnCopyPathClick;

        // ==================================================================
        // 页二：规则（本工具建的防火墙规则 —— 阻止规则和允许规则都在这里）
        // ==================================================================
        _tabRules.Padding = new Padding(9);
        _tabRules.Name = "_tabRules";
        _tabRules.Text = "规则";
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
        // ---------- 严格模式（高级）----------
        //
        // 刻意**不用复选框**当开关：复选框一点就生效，而这个开关会把「默认出站动作」
        // 改成「阻止」—— 误触的代价是整台机器上不了网。按钮点击天然会走到确认框。
        _strictModePanel.Location = new Point(6, 630);
        _strictModePanel.Name = "_strictModePanel";
        _strictModePanel.Size = new Size(1060, 230);
        _strictModePanel.TabIndex = 4;
        _strictModePanel.TabStop = false;
        _strictModePanel.Text = "严格模式（高级）";
        _strictModePanel.Controls.Add(_strictModeDetailLabel);
        _strictModePanel.Controls.Add(_strictModeStatusLabel);
        _strictModePanel.Controls.Add(_strictModeButtons);

        _strictModeStatusLabel.Dock = DockStyle.Top;
        _strictModeStatusLabel.Name = "_strictModeStatusLabel";
        _strictModeStatusLabel.Size = new Size(1054, 22);
        _strictModeStatusLabel.TabIndex = 0;
        _strictModeStatusLabel.Text = "当前状态：检测中…";

        _strictModeDetailLabel.Dock = DockStyle.Fill;
        _strictModeDetailLabel.Name = "_strictModeDetailLabel";
        _strictModeDetailLabel.Padding = new Padding(8, 4, 8, 0);
        _strictModeDetailLabel.Size = new Size(1054, 160);
        _strictModeDetailLabel.TabIndex = 1;

        _strictModeButtons.Dock = DockStyle.Bottom;
        _strictModeButtons.Name = "_strictModeButtons";
        _strictModeButtons.Size = new Size(1054, 44);
        _strictModeButtons.TabIndex = 2;
        _strictModeButtons.Controls.Add(_strictModeToggleButton);
        _strictModeButtons.Controls.Add(_refreshStrictModeButton);

        _strictModeToggleButton.Location = new Point(14, 8);
        _strictModeToggleButton.Name = "_strictModeToggleButton";
        _strictModeToggleButton.Size = new Size(200, 32);
        _strictModeToggleButton.TabIndex = 0;
        _strictModeToggleButton.Text = "开启严格模式…";
        _strictModeToggleButton.UseVisualStyleBackColor = true;
        _strictModeToggleButton.Click += OnStrictModeToggleClick;

        _refreshStrictModeButton.Location = new Point(224, 8);
        _refreshStrictModeButton.Name = "_refreshStrictModeButton";
        _refreshStrictModeButton.Size = new Size(150, 32);
        _refreshStrictModeButton.TabIndex = 1;
        _refreshStrictModeButton.Text = "重新读取状态";
        _refreshStrictModeButton.UseVisualStyleBackColor = true;
        _refreshStrictModeButton.Click += OnRefreshStrictModeClick;

        // 因为上面插了一整块，任务定义面板整体往下挪。
        _taskXmlPanel.Location = new Point(6, 872);
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
        //
        // 排版说明（踩过坑的，见 docs 里的「界面布局铁律」）：
        //   这块上面的说明文字比较长，而下面那两行开关是固定高度。
        //   以前用「AutoSize 标签 + 绝对坐标 + 固定高度容器」，文字一长就会压住下面的控件。
        //   现在改成停靠布局：文字区 Dock=Fill 且开 AutoScroll（装不下就出滚动条，不会溢出去），
        //   日志和开关一起钉在底部（Dock=Bottom）。从结构上不可能重叠。
        _privacyPanel.Anchor = AnchorStyles.Top | AnchorStyles.Left;
        _privacyPanel.Location = new Point(6, 342);
        _privacyPanel.Name = "_privacyPanel";
        _privacyPanel.Size = new Size(1060, 280);
        _privacyPanel.TabIndex = 2;
        _privacyPanel.Text = "数据与隐私";

        // 先加 Fill 的、再加 Bottom 的：停靠顺序是从后往前解析，
        // 所以后加的 Bottom 先拿走底部，先加的 Fill 拿剩下中间的区域。
        _privacyPanel.Controls.Add(_privacyScrollHost);
        _privacyPanel.Controls.Add(_privacyBottomPanel);

        _privacyScrollHost.AutoScroll = true;
        _privacyScrollHost.Dock = DockStyle.Fill;
        _privacyScrollHost.Name = "_privacyScrollHost";
        _privacyScrollHost.TabIndex = 0;
        _privacyScrollHost.Controls.Add(_privacyLabel);

        // ⚠️ 措辞必须和实际行为一致：现在有两处会联网，不能再写「本程序不含网络代码」。
        // 一处是本程序自己的代码（IP 归属查询），一处是 Windows 证书服务代表程序发起的
        // （证书吊销检查）。写含糊了就是在骗用户。
        _privacyLabel.AutoSize = true;
        _privacyLabel.Location = new Point(14, 8);
        _privacyLabel.MaximumSize = new Size(1010, 0);
        _privacyLabel.Name = "_privacyLabel";
        _privacyLabel.Size = new Size(600, 60);
        _privacyLabel.TabIndex = 0;
        _privacyLabel.Text =
            "本程序有且只有两处会联网，两者都可以关掉：\r\n" +
            "· IP 归属查询（默认开启）：把连接的远程 IP 发送到 whois.cymru.com 查询归属，" +
            "用来判断「这个连接在跟谁通信」。只发远程 IP，不发进程名、路径、端口或任何其它本机信息；" +
            "局域网和本机地址根本不会发出去。\r\n" +
            "· 证书吊销检查（默认开启）：Windows 的证书服务会代表本程序去查询 CA 服务器。\r\n" +
            "两处都关掉之后，本程序不再产生任何网络流量。\r\n" +
            "日志只写在本机下面这一个目录里，不会发送到任何地方，你可以随时查看或删除：";

        _privacyBottomPanel.Dock = DockStyle.Bottom;
        _privacyBottomPanel.Height = 138;
        _privacyBottomPanel.Name = "_privacyBottomPanel";
        _privacyBottomPanel.TabIndex = 1;
        _privacyBottomPanel.Controls.Add(_logPathLabel);
        _privacyBottomPanel.Controls.Add(_openLogFolderButton);
        _privacyBottomPanel.Controls.Add(_checkRevocationCheckBox);
        _privacyBottomPanel.Controls.Add(_checkIpOwnershipCheckBox);

        _logPathLabel.AutoSize = true;
        _logPathLabel.ForeColor = SystemColors.GrayText;
        _logPathLabel.Location = new Point(14, 4);
        _logPathLabel.Name = "_logPathLabel";
        _logPathLabel.Size = new Size(600, 17);
        _logPathLabel.TabIndex = 0;
        _logPathLabel.Text = "";

        _openLogFolderButton.Location = new Point(14, 26);
        _openLogFolderButton.Name = "_openLogFolderButton";
        _openLogFolderButton.Size = new Size(160, 30);
        _openLogFolderButton.TabIndex = 1;
        _openLogFolderButton.Text = "打开日志目录";
        _openLogFolderButton.UseVisualStyleBackColor = true;
        _openLogFolderButton.Click += OnOpenLogFolderClick;

        // 默认勾选：吊销状态查得准。代价是会有网络流量，界面上已经说清楚了。
        _checkRevocationCheckBox.AutoSize = true;
        _checkRevocationCheckBox.Checked = true;
        _checkRevocationCheckBox.CheckState = CheckState.Checked;
        _checkRevocationCheckBox.Location = new Point(16, 66);
        _checkRevocationCheckBox.Name = "_checkRevocationCheckBox";
        _checkRevocationCheckBox.Size = new Size(400, 21);
        _checkRevocationCheckBox.TabIndex = 2;
        _checkRevocationCheckBox.Text = "检查证书吊销状态（会联网查询 CA 服务器，取消勾选则完全零网络）";
        _checkRevocationCheckBox.UseVisualStyleBackColor = true;
        _checkRevocationCheckBox.CheckedChanged += OnRevocationModeChanged;

        // IP 归属查询开关。
        // 这里先把默认值摆上（默认开启），真实值随后由 settings.json 覆盖（见 MainForm.cs）。
        // 文案必须写清楚「会把远程 IP 发到哪里」，只写「查询归属」是不够的。
        _checkIpOwnershipCheckBox.AutoSize = true;
        _checkIpOwnershipCheckBox.Checked = true;
        _checkIpOwnershipCheckBox.CheckState = CheckState.Checked;
        _checkIpOwnershipCheckBox.Location = new Point(16, 96);
        _checkIpOwnershipCheckBox.Name = "_checkIpOwnershipCheckBox";
        _checkIpOwnershipCheckBox.Size = new Size(400, 21);
        _checkIpOwnershipCheckBox.TabIndex = 3;
        _checkIpOwnershipCheckBox.Text =
            "查询 IP 归属（会把远程 IP 发送到 whois.cymru.com，取消勾选则完全不发）";
        _checkIpOwnershipCheckBox.UseVisualStyleBackColor = true;
        _checkIpOwnershipCheckBox.CheckedChanged += OnIpOwnershipChanged;

        _tabSettings.Controls.Add(_taskXmlPanel);
        _tabSettings.Controls.Add(_strictModePanel);
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
        _expiryTimer.Tick += OnExpiryTimerTick;

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
            "注意：被阻止的程序连不上网，所以不会出现在这里 —— 去「规则」页恢复它。\n" +
            "\n" +
            "行底色的含义（按优先级）：\n" +
            "  淡红 = 签名被篡改 / 证书异常 / 证书链不受信任（真有问题）\n" +
            "  淡黄 = 该程序没有数字签名（需要留意，但不代表一定有问题，\n" +
            "         很多正经的免费和开源工具都没买签名证书）\n" +
            "  淡蓝 = 已被本工具阻止（这是你自己的操作，不是风险）\n" +
            "\n" +
            "把鼠标停在「数字签名」那一格上可以看到完整结论。");
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
        _privacyScrollHost.ResumeLayout(false);
        _privacyScrollHost.PerformLayout();
        _privacyBottomPanel.ResumeLayout(false);
        _strictModePanel.ResumeLayout(false);
        _strictModeButtons.ResumeLayout(false);
        _privacyBottomPanel.PerformLayout();
        _toolPanel.ResumeLayout(false);
        _toolPanel.PerformLayout();
        _toolRowFilters.ResumeLayout(false);
        _toolRowFilters.PerformLayout();
        _toolRowActions.ResumeLayout(false);
        _toolRowActions.PerformLayout();
        _toolRowSearch.ResumeLayout(false);
        _toolRowSearch.PerformLayout();
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
