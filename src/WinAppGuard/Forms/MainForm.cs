using WinAppGuard.Core;
using WinAppGuard.Models;

namespace WinAppGuard.Forms;

/// <summary>
/// 主窗体。
///
/// 界面分两页，这个划分是刻意的：
///   「联网连接」页  —— 基于**实时连接**，用来发现「谁正在联网」。
///   「已阻止的程序」页 —— 基于**防火墙规则**，用来管理已经建好的规则。
///
/// 为什么要分成两页：被阻止的程序连不上网，所以它不会出现在连接列表里。
/// 如果恢复入口也放在连接列表上，就会出现「拦截越成功越无法恢复」的死结。
/// 规则是持久存在的，恢复入口必须挂在规则上，而不是挂在实时连接上。
///
/// 分工说明（很重要）：
///   本文件只负责「显示状态」和「弹确认框」。
///   真正的安全边界全部在 <see cref="FirewallManager"/> 里 ——
///   这里把按钮置灰只是体验优化，就算置灰逻辑写错了，
///   底层照样会拒绝非法操作。不要把安全检查只写在这一层。
/// </summary>
public partial class MainForm : Form
{
    /// <summary>自动刷新间隔（毫秒）。</summary>
    private const int AutoRefreshIntervalMs = 3000;

    /// <summary>被阻止的行用淡红色底，扫一眼就能看出来。</summary>
    private static readonly Color BlockedRowColor = Color.FromArgb(255, 236, 236);

    /// <summary>
    /// 本次启动是否由「开机自启」拉起（命令行带 --autostart）。
    /// 阶段 5 起会据此直接最小化到系统托盘。
    /// </summary>
    private readonly bool _isAutostart;

    // ---------- 联网连接页的数据 ----------

    /// <summary>连接列表的数据源。</summary>
    private readonly BindingSource _connectionSource = new();

    /// <summary>
    /// 当前表格里显示的全部连接，供选中操作时查找和统计。
    ///
    /// 注意：这个列表实例**只创建一次**，之后一律用 Clear + AddRange 原地更新，绝不能重新赋值。
    /// 因为 <see cref="_connectionSource"/> 绑定的是这个实例本身，
    /// 一旦把字段指向新的 List，数据源还留在旧列表上，表格就会永远是空的。
    /// </summary>
    private readonly List<TcpConnectionItem> _connections = new();

    // ---------- 规则管理页的数据 ----------

    /// <summary>规则列表的数据源。</summary>
    private readonly BindingSource _rulesSource = new();

    /// <summary>规则列表的数据。同样只创建一次、原地更新，理由见 <see cref="_connections"/>。</summary>
    private readonly List<FirewallRuleItem> _rules = new();

    /// <summary>
    /// 本工具创建的全部防火墙规则（内存缓存）。
    ///
    /// 为什么缓存而不是每次用到就去读：系统里可能有几百上千条规则，
    /// 通过 COM 全量枚举很慢，放在每 3 秒的自动刷新里会把界面拖卡。
    /// 只在真正需要时（启动、操作之后、用户手动点「同步规则状态」）才去同步。
    /// </summary>
    private List<FirewallRuleItem> _appGuardRules = new();

    /// <summary>当前处于「已阻止」状态的程序路径集合，由 <see cref="_appGuardRules"/> 推导。</summary>
    private readonly HashSet<string> _blockedPaths = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// 是否正在扫描。
    /// 自动刷新和手动刷新有可能撞在一起，用这个标志保证同一时刻只跑一次扫描，
    /// 否则任务会不断堆积。
    /// </summary>
    private bool _isScanning;

    /// <summary>
    /// 用户是否主动点选过「联网连接」表格里的某一行。
    ///
    /// 为什么需要这个标志：DataGridView 会在数据绑定后、以及**标签页重新显示时**
    /// 自己把第一行设成「当前行」。也就是说「当前行」并不等于「用户选中的行」。
    /// 实测把 CurrentCell 设成 null 也没用 —— 切一次标签页再切回来，它又自己选上了。
    /// 而 DataGridView 没有提供「禁用自动选中」的开关。
    ///
    /// 所以不去和控件较劲，而是自己记录「用户到底点没点过」：
    /// 没点过就当成没选中，操作按钮一律置灰。
    /// 宁可让用户多点一下，也不要在用户没看清要操作谁的时候就动手。
    /// </summary>
    private bool _connectionSelectionConfirmed;

    /// <summary>用户是否主动点选过「已阻止的程序」表格里的某一条规则。理由同上一项。</summary>
    private bool _ruleSelectionConfirmed;

    /// <summary>
    /// 是否正在重新绑定连接表格。
    ///
    /// 重新绑定期间，表格会短暂处于「当前行指向的数据已经不在」的中间状态，
    /// 这时如果 SelectionChanged 去读选中项，会抛 IndexOutOfRangeException。
    /// 用这个标志把这段窗口内的 SelectionChanged 挡掉。
    /// </summary>
    private bool _isRebindingGrid;

    /// <summary>是否正在重新绑定规则表格。理由同上。</summary>
    private bool _isRebindingRules;

    /// <summary>
    /// 启动时先不显示主窗口（用于 --autostart）。只会生效一次。
    /// </summary>
    private bool _suppressInitialShow;

    /// <summary>运行期初始化是否已经做过。窗口显示和不显示两条路径都可能会调用它，用它保证只做一次。</summary>
    private bool _runtimeInitialized;

    /// <summary>是否已经提示过「程序收进托盘了」。只在第一次提示，不要每收一次都弹。</summary>
    private bool _trayHintShown;

    /// <summary>
    /// 是否真的要退出程序。
    /// 只有托盘的「退出」菜单会把它置为 true —— 那是一条用户明确选择的路。
    /// 其它任何关闭动作（点 X、Alt+F4）都只是收进托盘。
    /// </summary>
    private bool _reallyExit;

    /// <summary>
    /// 弹对话框时用的父窗口。
    ///
    /// 窗口隐藏时传 null：否则对话框会以一个看不见的窗口为基准去居中，位置会很奇怪。
    /// </summary>
    private IWin32Window? DialogOwner => Visible ? this : null;

    /// <summary>供设计器/调试使用的默认构造函数。</summary>
    public MainForm() : this(isAutostart: false)
    {
    }

    public MainForm(bool isAutostart)
    {
        _isAutostart = isAutostart;
        _suppressInitialShow = isAutostart;

        InitializeComponent();

        _autoRefreshTimer.Interval = AutoRefreshIntervalMs;
        SetupConnectionGrid();
        SetupRulesGrid();
    }

    /// <summary>
    /// 控制窗口是否显示。
    ///
    /// 开机自启时不希望窗口闪一下再消失，所以在这里就把第一次显示挡掉，
    /// 而不是先显示再 Hide()。要先把窗口句柄建出来，否则后面的异步扫描拿不到 Handle。
    /// </summary>
    protected override void SetVisibleCore(bool value)
    {
        if (_suppressInitialShow)
        {
            _suppressInitialShow = false;

            if (!IsHandleCreated)
            {
                CreateHandle();
            }

            base.SetVisibleCore(false);
            InitializeRuntime();
            return;
        }

        base.SetVisibleCore(value);
    }

    /// <summary>窗口加载完成后启动运行期逻辑。</summary>
    protected override void OnLoad(EventArgs e)
    {
        base.OnLoad(e);
        InitializeRuntime();
    }

    /// <summary>
    /// 运行期初始化：显示状态、同步防火墙规则、开始首次扫描。
    /// 窗口显示与否都会走到这里，用标志保证只执行一次。
    /// </summary>
    private void InitializeRuntime()
    {
        if (_runtimeInitialized)
        {
            return;
        }

        _runtimeInitialized = true;

        ShowRuntimeStatus();

        // 把日志目录直接摆在界面上，用户不用去猜日志藏在哪。
        _logPathLabel.Text = LocalLog.LogDirectory;

        // 设置页的分区宽度是手动算的，先按当前尺寸摆一次。
        LayoutSettingsSections();

        // 先把防火墙规则读进来，这样第一屏就能正确显示「已阻止 / 未阻止」。
        RefreshRulesFromFirewall();

        // 读一次开机自启的真实状态。
        RefreshAutoStartStatus();

        // 首次扫描。RefreshConnectionsAsync 内部已经处理了所有异常，
        // 这里可以安全地「发射后不管」，不会因为后台异常导致进程崩溃。
        _ = RefreshConnectionsAsync();

        if (_isAutostart)
        {
            // 开机自启必须让用户看得见 —— 静默出现一个常驻进程而不告诉用户是不对的。
            ShowTrayBalloon(
                "WinAppGuard 已随开机启动",
                "程序正在后台运行，托盘图标就是它。双击图标可以打开主界面，右键可以退出。");
        }
    }

    /// <summary>
    /// 关闭窗口时收进托盘，而不是退出程序。
    ///
    /// 为什么要这样：本工具的价值在于「随时能恢复被拦的程序」。
    /// 如果点 X 就退出，用户会以为自己已经把工具关掉了，实际上防火墙规则还在生效，
    /// 回头想恢复的时候满桌面找不到入口。收进托盘可以让它一直可用。
    /// 真正退出只能走托盘的「退出」菜单。
    /// </summary>
    protected override void OnFormClosing(FormClosingEventArgs e)
    {
        // 关机 / 注销 / 任务管理器结束进程时不要拦，该退就退。
        if (!_reallyExit && e.CloseReason == CloseReason.UserClosing)
        {
            e.Cancel = true;
            HideToTray();
            return;
        }

        base.OnFormClosing(e);
    }

    // ==================================================================
    // 界面初始化
    // ==================================================================

    /// <summary>
    /// 定义「联网连接」表格的列。
    ///
    /// 放在这里而不是设计器文件里，是因为每一列都直接对应
    /// <see cref="TcpConnectionItem"/> 的一个属性，两者对着看才不容易写错。
    /// </summary>
    private void SetupConnectionGrid()
    {
        AddConnectionColumn("程序名", nameof(TcpConnectionItem.ProcessName), 150);
        AddConnectionColumn("程序路径", nameof(TcpConnectionItem.ProcessPathText), 300, fill: true);
        AddConnectionColumn("PID", nameof(TcpConnectionItem.Pid), 70);
        AddConnectionColumn("本地端口", nameof(TcpConnectionItem.LocalPortText), 90);
        AddConnectionColumn("远程 IP", nameof(TcpConnectionItem.RemoteAddressText), 170);
        AddConnectionColumn("远程端口", nameof(TcpConnectionItem.RemotePortText), 90);
        AddConnectionColumn("状态", nameof(TcpConnectionItem.StateText), 100);
        AddConnectionColumn("协议", nameof(TcpConnectionItem.Protocol), 70);
        AddConnectionColumn("阻止状态", nameof(TcpConnectionItem.BlockStateText), 90);

        _connectionSource.DataSource = _connections;
        _connectionGrid.DataSource = _connectionSource;
    }

    /// <summary>
    /// 定义「已阻止的程序」表格的列。
    /// 这一页的数据来自防火墙规则本身，与实时连接无关。
    /// </summary>
    private void SetupRulesGrid()
    {
        AddRuleColumn("程序名", nameof(FirewallRuleItem.ApplicationNameText), 170);
        AddRuleColumn("程序路径", nameof(FirewallRuleItem.ApplicationPath), 280, fill: true);
        AddRuleColumn("动作", nameof(FirewallRuleItem.ActionText), 60);
        AddRuleColumn("方向", nameof(FirewallRuleItem.DirectionText), 60);
        AddRuleColumn("协议", nameof(FirewallRuleItem.ProtocolText), 60);
        AddRuleColumn("启用", nameof(FirewallRuleItem.EnabledText), 70);
        AddRuleColumn("规则名", nameof(FirewallRuleItem.Name), 290);

        _rulesSource.DataSource = _rules;
        _rulesGrid.DataSource = _rulesSource;
    }

    /// <summary>给「联网连接」表格添加一个只读文本列。</summary>
    private void AddConnectionColumn(string header, string propertyName, int width, bool fill = false)
        => AddColumn(_connectionGrid, header, propertyName, width, fill);

    /// <summary>给「已阻止的程序」表格添加一个只读文本列。</summary>
    private void AddRuleColumn(string header, string propertyName, int width, bool fill = false)
        => AddColumn(_rulesGrid, header, propertyName, width, fill);

    /// <summary>添加一个只读的文本列。</summary>
    /// <param name="grid">目标表格。</param>
    /// <param name="header">列标题。</param>
    /// <param name="propertyName">绑定的属性名，必须与数据模型的属性名完全一致。</param>
    /// <param name="width">列宽（像素）。</param>
    /// <param name="fill">为 true 时该列自动占满剩余宽度（通常给路径列）。</param>
    private static void AddColumn(DataGridView grid, string header, string propertyName, int width, bool fill = false)
    {
        var column = new DataGridViewTextBoxColumn
        {
            HeaderText = header,
            DataPropertyName = propertyName,
            Name = propertyName,
            ReadOnly = true,
            SortMode = DataGridViewColumnSortMode.NotSortable,
        };

        if (fill)
        {
            column.AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill;
            column.MinimumWidth = 200;
        }
        else
        {
            column.Width = width;
        }

        grid.Columns.Add(column);
    }

    /// <summary>把运行期才能确定的信息填到界面上。</summary>
    private void ShowRuntimeStatus()
    {
        _versionLabel.Text = $"版本 v{Application.ProductVersion}";

        _startModeLabel.Text = _isAutostart
            ? $"启动模式：开机自启（{AppConstants.AutostartArgument}）"
            : "启动模式：手动启动";

        var isAdmin = AdminHelper.IsRunningAsAdmin();
        _adminStatusLabel.Text = isAdmin
            ? "管理员权限：已获得"
            : "管理员权限：未获得（防火墙功能不可用）";
        _adminStatusLabel.ForeColor = isAdmin ? Color.FromArgb(0, 120, 0) : Color.Firebrick;
    }

    // ==================================================================
    // 防火墙规则状态同步
    // ==================================================================

    /// <summary>
    /// 从 Windows 防火墙重新读取本工具创建的规则，刷新内存缓存和规则列表页。
    /// 读取失败时不改变已有缓存，只提示用户。
    /// </summary>
    private void RefreshRulesFromFirewall()
    {
        try
        {
            _appGuardRules = FirewallManager.GetAppGuardRules();

            _blockedPaths.Clear();
            var allowRuleCount = 0;
            foreach (var rule in _appGuardRules)
            {
                if (rule.Action == FirewallAction.Block && !string.IsNullOrEmpty(rule.ApplicationPath))
                {
                    _blockedPaths.Add(rule.ApplicationPath);
                }
                else
                {
                    allowRuleCount++;
                }
            }

            // 原地更新规则列表。
            // 注意顺序：必须**先**抓取选中的规则名，再动 _rules ——
            // 列表变短之后，表格里旧索引对应的数据就不存在了，那时再去读会越界崩溃。
            var selectedRuleName = CaptureRuleSelection();
            _rules.Clear();
            _rules.AddRange(_appGuardRules);
            RebindRules(selectedRuleName);

            // 让用户一眼看到有几条规则被阻止，也顺便回答「为什么连接页里找不到它」。
            _tabRules.Text = $"已阻止的程序（{_blockedPaths.Count}）";
            _statusRulesLabel.Text = $"已阻止程序：{_blockedPaths.Count} 个";
            _rulesSummaryLabel.Text = allowRuleCount > 0
                ? $"规则共 {_appGuardRules.Count} 条（阻止 {_appGuardRules.Count - allowRuleCount} 条，允许 {allowRuleCount} 条）"
                : $"规则共 {_appGuardRules.Count} 条";

            UpdateRulesActionState();
        }
        catch (Exception ex)
        {
            _statusRulesLabel.Text = "读取防火墙规则失败";
            _rulesSummaryLabel.Text = "读取防火墙规则失败";

            ShowError("读取 Windows 防火墙规则失败", ex);
        }
    }

    /// <summary>
    /// 规则发生变化后的统一收尾：重新读规则，并刷新连接页的阻止状态显示。
    /// 任何修改规则的操作都应该以调用这个方法结束。
    /// </summary>
    private void AfterRulesChanged()
    {
        RefreshRulesFromFirewall();

        // 先抓选中，再重绑 —— 顺序理由见 RebindGrid 的说明。
        RebindGrid(CaptureSelection());
    }

    /// <summary>把「已阻止」状态写到当前这批连接数据上，并刷新表格。</summary>
    private void ApplyBlockedState()
    {
        foreach (var item in _connections)
        {
            item.IsBlocked = !string.IsNullOrEmpty(item.ProcessPath)
                             && _blockedPaths.Contains(item.ProcessPath);
        }
    }

    /// <summary>
    /// 重新绑定连接表格，并尽量保持用户的选中状态。
    ///
    /// 参数 selectedKey 必须是**在修改 _connections 之前**抓下来的！
    /// 原因：列表一旦变短，表格里那个旧行的索引就会越界，
    /// 这时候再去读 CurrentRow.DataBoundItem 会直接抛 IndexOutOfRangeException 把程序搞崩。
    /// （这个坑是实测踩出来的：连接数从 100 条掉到 50 条时，表格还挂着索引 90 的旧行。）
    /// </summary>
    private void RebindGrid(RowKey? selectedKey)
    {
        // 重新绑定期间表格会短暂处于「当前行指向的数据已经不在了」的中间状态，
        // 这时候不能让 SelectionChanged 去读选中项，否则同样会越界。
        _isRebindingGrid = true;
        try
        {
            ApplyBlockedState();
            _connectionSource.ResetBindings(metadataChanged: false);
        }
        finally
        {
            _isRebindingGrid = false;
        }

        // 恢复原来选中的那一行；恢复不了就明确清空选中，并取消「已确认选中」。
        //
        // 为什么要清空，而不是让表格自己落到第一行：表格绑定数据后会自动选中第一行。
        // 如果原来选中的那条连接已经消失（程序关了、连接断了），
        // 用户点「阻止」时操作的就不是他以为的那一行了。
        // 宁可让按钮灰着、让他重新选一行，也不要冒险操作错对象。
        if (selectedKey is null || !TryRestoreSelection(selectedKey))
        {
            _connectionGrid.CurrentCell = null;
            _connectionSelectionConfirmed = false;
        }

        ShadeBlockedRows();
        UpdateActionState();
    }

    /// <summary>给被阻止的行刷上底色。</summary>
    private void ShadeBlockedRows()
    {
        foreach (DataGridViewRow row in _connectionGrid.Rows)
        {
            if (row.DataBoundItem is TcpConnectionItem { IsBlocked: true })
            {
                row.DefaultCellStyle.BackColor = BlockedRowColor;
            }
        }
    }

    /// <summary>
    /// 重新绑定规则表格，并尽量保住用户的选中状态。
    ///
    /// 和连接页一样：恢复不了原选中就明确清空，不让表格自动落到第一行。
    /// 否则用户点「允许选中程序联网」时，操作的可能是他并没有看过的那一条规则。
    /// </summary>
    private void RebindRules(string? selectedRuleName)
    {
        _isRebindingRules = true;
        try
        {
            _rulesSource.ResetBindings(metadataChanged: false);
        }
        finally
        {
            _isRebindingRules = false;
        }

        if (selectedRuleName is null || !TryRestoreRuleSelection(selectedRuleName))
        {
            _rulesGrid.CurrentCell = null;
            _ruleSelectionConfirmed = false;
        }

        UpdateRulesActionState();
    }

    /// <summary>按规则名找回原来选中的那一条，找到返回 true。</summary>
    private bool TryRestoreRuleSelection(string? ruleName)
    {
        if (string.IsNullOrEmpty(ruleName))
        {
            return false;
        }

        for (var i = 0; i < _rules.Count && i < _rulesGrid.Rows.Count; i++)
        {
            if (string.Equals(_rules[i].Name, ruleName, StringComparison.OrdinalIgnoreCase))
            {
                _rulesGrid.CurrentCell = _rulesGrid.Rows[i].Cells[0];
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// 抓取当前选中的规则名。和 <see cref="CaptureSelection"/> 一样，
    /// 没被用户主动点选过时返回 null，避免把表格自动选中的第一条当成用户的选择。
    /// </summary>
    private string? CaptureRuleSelection()
        => _ruleSelectionConfirmed ? GetSelectedRule()?.Name : null;

    // ==================================================================
    // 选中状态
    // ==================================================================

    /// <summary>当前选中的连接。注意：没被用户主动点选过时，这个值不可信，见 <see cref="_connectionSelectionConfirmed"/>。</summary>
    private TcpConnectionItem? GetSelectedConnection()
        => _connectionGrid.CurrentRow?.DataBoundItem as TcpConnectionItem;

    /// <summary>当前选中的规则。注意：没被用户主动点选过时，这个值不可信，见 <see cref="_ruleSelectionConfirmed"/>。</summary>
    private FirewallRuleItem? GetSelectedRule()
        => _rulesGrid.CurrentRow?.DataBoundItem as FirewallRuleItem;

    /// <summary>「用户真正选中的连接」—— 没主动点过就返回 null。</summary>
    private TcpConnectionItem? GetConfirmedConnection()
        => _connectionSelectionConfirmed ? GetSelectedConnection() : null;

    /// <summary>「用户真正选中的规则」—— 没主动点过就返回 null。</summary>
    private FirewallRuleItem? GetConfirmedRule()
        => _ruleSelectionConfirmed ? GetSelectedRule() : null;

    /// <summary>
    /// 选中行的「身份」。
    ///
    /// 重新绑定数据源会清空选中状态，而每 3 秒的自动刷新会不断重新绑定 ——
    /// 如果不管这件事，用户根本没法稳定地选中一行去点右键。
    /// 所以刷新前后按这个身份把原来选中的那一行找回来。
    /// PID + 本地端口 + 远端 合起来足以唯一确定一条连接。
    /// </summary>
    private readonly record struct RowKey(int Pid, string LocalPort, string RemoteAddress, string RemotePort);

    private RowKey? CaptureSelection()
    {
        if (!_connectionSelectionConfirmed)
        {
            return null;
        }

        var item = GetConfirmedConnection();
        return item is null
            ? null
            : new RowKey(item.Pid, item.LocalPortText, item.RemoteAddressText, item.RemotePortText);
    }

    /// <summary>按身份找回原来选中的那一行，找到返回 true。</summary>
    private bool TryRestoreSelection(RowKey? key)
    {
        if (key is null)
        {
            return false;
        }

        for (var i = 0; i < _connections.Count && i < _connectionGrid.Rows.Count; i++)
        {
            var c = _connections[i];
            if (c.Pid == key.Value.Pid
                && c.LocalPortText == key.Value.LocalPort
                && c.RemoteAddressText == key.Value.RemoteAddress
                && c.RemotePortText == key.Value.RemotePort)
            {
                _connectionGrid.CurrentCell = _connectionGrid.Rows[i].Cells[0];
                return true;
            }
        }

        return false;
    }

    /// <summary>根据当前选中行，决定哪些操作可用，并给出文字说明。</summary>
    private void UpdateActionState()
    {
        // 用 GetConfirmedConnection 而不是 GetSelectedConnection：
        // 表格自动选中的第一行不算「用户选中」。
        var item = GetConfirmedConnection();

        var hasPath = item is not null && !string.IsNullOrEmpty(item.ProcessPath);
        var isBlocked = hasPath && _blockedPaths.Contains(item!.ProcessPath);
        var isProtected = hasPath && ProtectedProcesses.IsProtected(item!.ProcessPath, out _);

        // 只有「有路径、当前没被阻止、且不是系统关键进程」才允许阻止。
        var canBlock = hasPath && !isBlocked && !isProtected;

        // 只有已经处于阻止状态，才有东西可以「允许」。
        var canAllow = hasPath && isBlocked;

        _blockButton.Enabled = canBlock;
        _allowButton.Enabled = canAllow;
        _menuBlock.Enabled = canBlock;
        _menuAllow.Enabled = canAllow;
        _menuCopyPath.Enabled = hasPath;

        _selectionHintLabel.Text = BuildSelectionHint(item, hasPath, isBlocked);
    }

    /// <summary>根据当前选中的规则，决定规则页哪些操作可用。</summary>
    private void UpdateRulesActionState()
    {
        var rule = GetConfirmedRule();

        _rulesAllowButton.Enabled = rule is not null;
        _rulesDeleteButton.Enabled = rule is not null;

        // 按「表格里实际显示了几条」来判断，而不是按内存缓存 ——
        // 按钮状态应该和用户看到的东西一致。
        _rulesDeleteAllButton.Enabled = _rules.Count > 0;

        if (rule is null)
        {
            _rulesHintLabel.Text = _rules.Count == 0
                ? "当前没有任何 AppGuard 规则"
                : "点击一条规则来选择要操作的程序";
            return;
        }

        _rulesHintLabel.Text = $"已选中 {rule.ApplicationNameText} —— {rule.ActionText}，规则名 {rule.Name}";
    }

    /// <summary>构造「已选中 xxx —— ……」这行说明，让用户知道按钮为什么灰着。</summary>
    private string BuildSelectionHint(TcpConnectionItem? item, bool hasPath, bool isBlocked)
    {
        if (item is null)
        {
            // 表格里可能有高亮的行，但那不算用户选中，这里要说清楚，否则按钮灰着很莫名其妙。
            return _connectionGrid.CurrentRow is null
                ? "未选中任何连接"
                : "点击一行来选择要操作的程序";
        }

        if (!hasPath)
        {
            return $"已选中 {item.ProcessName}，但拿不到程序路径，无法设置规则";
        }

        if (ProtectedProcesses.IsProtected(item.ProcessPath, out var reason))
        {
            return $"已选中 {item.ProcessName} —— {reason}";
        }

        var connectionCount = _connections.Count(c => PathsEqual(c.ProcessPath, item.ProcessPath));
        var state = isBlocked ? "已阻止" : "未阻止";

        return $"已选中 {item.ProcessName}（共 {connectionCount} 条连接）—— 当前状态：{state}";
    }

    // ==================================================================
    // 扫描逻辑
    // ==================================================================

    /// <summary>
    /// 扫描一次 TCP 连接并刷新列表。
    ///
    /// 扫描在后台线程执行：连接表可能有几百行，还要逐个反查进程路径，
    /// 放在界面线程会明显卡顿。
    /// </summary>
    private async Task RefreshConnectionsAsync()
    {
        if (_isScanning)
        {
            return;
        }

        _isScanning = true;
        _refreshButton.Enabled = false;

        try
        {
            var options = new ConnectionScanOptions
            {
                IncludeListening = _showListenCheckBox.Checked,
                IncludeClosed = _showClosedCheckBox.Checked,
                IncludeOwnerless = _showOwnerlessCheckBox.Checked,
                HideLoopback = _hideLoopbackCheckBox.Checked,
            };

            var connections = await Task.Run(() => ConnectionScanner.Scan(options));

            // 扫描期间窗口可能已经被关闭，此时再碰控件会抛 ObjectDisposedException。
            if (IsDisposed || Disposing)
            {
                return;
            }

            // 连接表本身是按本地端口排序的，看不出「哪个程序连得多」。
            // 按程序名排一下，同一个程序的连接就会聚在一起。
            connections.Sort(static (a, b) =>
            {
                var byName = string.Compare(a.ProcessName, b.ProcessName, StringComparison.OrdinalIgnoreCase);
                return byName != 0
                    ? byName
                    : string.Compare(a.RemoteAddressText, b.RemoteAddressText, StringComparison.OrdinalIgnoreCase);
            });

            // 关键顺序：先在旧数据还在的时候抓取选中项，再替换列表。
            // 反过来的话，列表一旦变短就会越界崩溃。
            var selectedKey = CaptureSelection();

            _connections.Clear();
            _connections.AddRange(connections);

            // 用上面抓好的 selectedKey 重绑，绝对不能在这之后再重新抓一次。
            RebindGrid(selectedKey);

            _summaryLabel.Text = $"最后刷新：{DateTime.Now:HH:mm:ss}    共 {connections.Count} 条";
        }
        catch (Exception ex)
        {
            if (IsDisposed || Disposing)
            {
                return;
            }

            _summaryLabel.Text = "扫描失败";

            // 关掉自动刷新，否则会每隔 3 秒弹一次错误框，把界面顶死。
            _autoRefreshCheckBox.Checked = false;

            ShowError("扫描 TCP 连接失败", ex);
        }
        finally
        {
            _isScanning = false;
            _refreshButton.Enabled = true;
        }
    }

    // ==================================================================
    // 阻止 / 允许
    // ==================================================================

    private void OnBlockButtonClick(object? sender, EventArgs e)
    {
        var item = GetConfirmedConnection();
        if (item is null || string.IsNullOrEmpty(item.ProcessPath))
        {
            return;
        }

        // 界面上按钮已经置灰了，这里再挡一次，好给出一句人话而不是让它静默无反应。
        // 真正的安全边界在 FirewallManager.ValidateProgramPath 里，不在这里。
        if (ProtectedProcesses.IsProtected(item.ProcessPath, out var reason))
        {
            MessageBox.Show(this, reason, AppConstants.AppName, MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        var connectionCount = _connections.Count(c => PathsEqual(c.ProcessPath, item.ProcessPath));
        var ruleName = FirewallManager.BuildBlockRuleName(item.ProcessPath);

        var confirmed = ConfirmForm.Show(
            owner: DialogOwner,
            title: "阻止程序联网",
            question: $"确定要阻止「{item.ProcessName}」联网吗？",
            details: new[]
            {
                new KeyValuePair<string, string>("程序名", item.ProcessName),
                new KeyValuePair<string, string>("完整路径", item.ProcessPath),
                new KeyValuePair<string, string>("当前连接", $"{connectionCount} 条"),
                new KeyValuePair<string, string>("生效范围", "出站方向的 TCP 和 UDP 全部阻止"),
                new KeyValuePair<string, string>("将创建规则", ruleName),
            },
            warnings: new[]
            {
                $"确认后该程序会立刻无法联网；实测中它当前正在进行中的 {connectionCount} 条连接也会马上断开（浏览器会立刻掉线）。",
                "如果你发现它仍然能联网，重启该程序再试一次即可。",
                "拦截按「可执行文件路径」生效：同一个程序换到别的目录运行不受影响，但同一目录下的所有实例会一起被拦掉。",
                "阻止之后这个程序会从「联网连接」页消失（它连不上，自然没有连接）。" +
                "要恢复它，请到「已阻止的程序」页操作。",
            },
            confirmText: "阻止联网");

        if (!confirmed)
        {
            return;
        }

        try
        {
            var createdRuleName = FirewallManager.CreateBlockRule(item.ProcessPath);
            LocalLog.Operation($"阻止联网：{item.ProcessPath}（规则 {createdRuleName}）");
            AfterRulesChanged();
        }
        catch (Exception ex)
        {
            ShowError("阻止失败", ex);
        }
    }

    private void OnAllowButtonClick(object? sender, EventArgs e)
    {
        var item = GetConfirmedConnection();
        if (item is null || string.IsNullOrEmpty(item.ProcessPath))
        {
            return;
        }

        ConfirmAndAllowProgram(item.ProcessPath, item.ProcessName);
    }

    /// <summary>「已阻止的程序」页：允许选中的规则对应的程序联网。</summary>
    private void OnRulesAllowButtonClick(object? sender, EventArgs e)
    {
        var rule = GetConfirmedRule();
        if (rule is null || string.IsNullOrEmpty(rule.ApplicationPath))
        {
            return;
        }

        ConfirmAndAllowProgram(rule.ApplicationPath, rule.ApplicationNameText);
    }

    /// <summary>
    /// 弹出确认框，删除某个程序的全部 AppGuard 规则（即「允许它联网」）。
    /// 两个页面共用这一份逻辑，避免两处各写一遍、将来改一处漏一处。
    /// </summary>
    /// <returns>确实执行了删除返回 true；用户取消或无事可做返回 false。</returns>
    private bool ConfirmAndAllowProgram(string programPath, string programName)
    {
        var rulesForProgram = _appGuardRules
            .Where(rule => PathsEqual(rule.ApplicationPath, programPath))
            .ToList();

        if (rulesForProgram.Count == 0)
        {
            // 可能是规则被人在 wf.msc 里删掉了，缓存过期。同步一次再说。
            AfterRulesChanged();

            MessageBox.Show(
                this,
                $"「{programName}」当前没有被 WinAppGuard 阻止，不需要允许。\n\n" +
                "已重新同步防火墙规则状态。",
                AppConstants.AppName,
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
            return false;
        }

        var ruleList = string.Join(Environment.NewLine, rulesForProgram.Select(r => "    " + r.Name));

        var confirmed = ConfirmForm.Show(
            owner: DialogOwner,
            title: "允许程序联网",
            question: $"确定要允许「{programName}」联网吗？",
            details: new[]
            {
                new KeyValuePair<string, string>("程序名", programName),
                new KeyValuePair<string, string>("完整路径", programPath),
                new KeyValuePair<string, string>("将删除规则", $"{rulesForProgram.Count} 条"),
            },
            warnings: new[]
            {
                "只会删除下面这些由 WinAppGuard 创建的规则：",
                ruleList,
                "其他程序、以及系统和其他软件设置的防火墙规则一律不受影响。",
                "删除后该程序可以立刻重新联网；如果它没有自己恢复，重启该程序即可。",
            },
            confirmText: "允许联网");

        if (!confirmed)
        {
            return false;
        }

        try
        {
            var deletedCount = FirewallManager.DeleteRulesForProgram(programPath);
            LocalLog.Operation($"允许联网：{programPath}（删除 {deletedCount} 条规则）");
            AfterRulesChanged();
            return true;
        }
        catch (Exception ex)
        {
            ShowError("允许失败", ex);
            return false;
        }
    }

    /// <summary>「已阻止的程序」页：只删除选中的那一条规则。</summary>
    private void OnRulesDeleteButtonClick(object? sender, EventArgs e)
    {
        var rule = GetConfirmedRule();
        if (rule is null)
        {
            return;
        }

        var confirmed = ConfirmForm.Show(
            owner: DialogOwner,
            title: "删除单条规则",
            question: "确定要删除这条规则吗？",
            details: new[]
            {
                new KeyValuePair<string, string>("规则名", rule.Name),
                new KeyValuePair<string, string>("程序", rule.ApplicationPath),
                new KeyValuePair<string, string>("动作", rule.ActionText),
            },
            warnings: new[]
            {
                "删除后该程序可以立刻重新联网。",
                "只会删除这一条规则，其他规则不受影响。",
            },
            confirmText: "删除规则");

        if (!confirmed)
        {
            return;
        }

        try
        {
            FirewallManager.DeleteRule(rule.Name);
            LocalLog.Operation($"删除规则：{rule.Name}（程序 {rule.ApplicationPath}）");
            AfterRulesChanged();
        }
        catch (Exception ex)
        {
            ShowError("删除规则失败", ex);
        }
    }

    /// <summary>
    /// 「已阻止的程序」页：删除全部 AppGuard 规则。
    /// 这是不可撤销的批量操作，所以需要**连续确认两次**。
    /// </summary>
    private void OnRulesDeleteAllButtonClick(object? sender, EventArgs e)
    {
        var rules = _appGuardRules;

        if (rules.Count == 0)
        {
            AfterRulesChanged();
            MessageBox.Show(
                this,
                "当前没有任何 AppGuard 规则，无需清理。",
                AppConstants.AppName,
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
            return;
        }

        var ruleList = string.Join(
            Environment.NewLine,
            rules.Select(r => $"    {r.Name}  →  {r.ApplicationPath}"));

        // ---------------- 第一次确认：说明清楚要删什么 ----------------
        var firstConfirmed = ConfirmForm.Show(
            owner: DialogOwner,
            title: "删除全部 AppGuard 规则",
            question: $"确定要删除全部 {rules.Count} 条由 WinAppGuard 创建的规则吗？",
            details: new[]
            {
                new KeyValuePair<string, string>("规则条数", $"{rules.Count} 条"),
                new KeyValuePair<string, string>("影响", "这些程序将立刻恢复联网"),
            },
            warnings: new[]
            {
                "将要删除的规则如下：",
                ruleList,
                "其他软件和系统自带的防火墙规则一律不受影响。",
            },
            confirmText: "继续");

        if (!firstConfirmed)
        {
            return;
        }

        // ---------------- 第二次确认：不可撤销，再问一次 ----------------
        var secondConfirmed = ConfirmForm.Show(
            owner: DialogOwner,
            title: "最后确认",
            question: "这一步不可撤销，确定要删除全部规则吗？",
            details: new[]
            {
                new KeyValuePair<string, string>("规则条数", $"{rules.Count} 条"),
            },
            warnings: new[]
            {
                "删除后这些程序会立刻恢复联网。",
                "如果你只是想放行某一个程序，请用「允许选中程序联网」，不要用这个按钮。",
            },
            confirmText: "确认删除");

        if (!secondConfirmed)
        {
            return;
        }

        try
        {
            var deleted = FirewallManager.DeleteAllAppGuardRules();
            LocalLog.Operation($"删除全部 AppGuard 规则：实际删除 {deleted} 条");
            AfterRulesChanged();

            MessageBox.Show(
                this,
                $"已删除 {deleted} 条 AppGuard 规则。\n\n" +
                "其他软件和系统自带的防火墙规则没有受到影响。",
                AppConstants.AppName,
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
        }
        catch (Exception ex)
        {
            ShowError("批量删除失败", ex);
        }
    }

    // ==================================================================
    // 事件处理
    // ==================================================================

    private async void OnRefreshButtonClick(object? sender, EventArgs e)
    {
        await RefreshConnectionsAsync();
    }

    private async void OnAutoRefreshTick(object? sender, EventArgs e)
    {
        await RefreshConnectionsAsync();
    }

    /// <summary>重新从防火墙读取规则状态。用于在 wf.msc 里手动改过规则之后同步。</summary>
    private void OnRefreshRulesButtonClick(object? sender, EventArgs e)
    {
        AfterRulesChanged();
    }

    /// <summary>勾选/取消「每 3 秒自动刷新」。</summary>
    private void OnAutoRefreshCheckedChanged(object? sender, EventArgs e)
    {
        _autoRefreshTimer.Enabled = _autoRefreshCheckBox.Checked;

        // 刚勾上时立刻刷新一次，不用干等 3 秒
        if (_autoRefreshCheckBox.Checked)
        {
            _ = RefreshConnectionsAsync();
        }
    }

    /// <summary>扫描过滤开关共用：任意一个发生变化，立刻按新条件重新扫描。</summary>
    private void OnScanOptionChanged(object? sender, EventArgs e)
    {
        _ = RefreshConnectionsAsync();
    }

    private void OnGridSelectionChanged(object? sender, EventArgs e)
    {
        // 重新绑定过程中的选中变化不算数，而且这时候读选中项会越界崩溃。
        // RebindGrid 收尾时会自己调一次 UpdateActionState。
        if (_isRebindingGrid)
        {
            return;
        }

        UpdateActionState();
    }

    private void OnRulesGridSelectionChanged(object? sender, EventArgs e)
    {
        if (_isRebindingRules)
        {
            return;
        }

        UpdateRulesActionState();
    }

    /// <summary>
    /// 右键点击某一行时先把那一行选中，否则菜单操作的会是上一次选中的行，
    /// 这种「点 A 却操作了 B」的行为在管理防火墙时非常危险。
    ///
    /// 同时标记「用户主动点过了」，这是操作按钮能变得可用的唯一途径。
    /// </summary>
    private void OnGridCellMouseDown(object? sender, DataGridViewCellMouseEventArgs e)
    {
        if (e.RowIndex < 0 || e.RowIndex >= _connectionGrid.Rows.Count)
        {
            return;
        }

        _connectionGrid.CurrentCell = _connectionGrid.Rows[e.RowIndex].Cells[0];
        _connectionSelectionConfirmed = true;

        // SelectionChanged 有可能先于本事件触发，那时按钮还是灰的，所以这里要再刷新一次。
        UpdateActionState();
    }

    /// <summary>用键盘在表格里移动，同样算「用户主动选择」。</summary>
    private void OnGridKeyDown(object? sender, KeyEventArgs e)
    {
        if (_connectionGrid.CurrentRow is null)
        {
            return;
        }

        _connectionSelectionConfirmed = true;
        UpdateActionState();
    }

    /// <summary>「已阻止的程序」表格：用户主动点了某一行。</summary>
    private void OnRulesGridCellMouseDown(object? sender, DataGridViewCellMouseEventArgs e)
    {
        if (e.RowIndex < 0 || e.RowIndex >= _rulesGrid.Rows.Count)
        {
            return;
        }

        _rulesGrid.CurrentCell = _rulesGrid.Rows[e.RowIndex].Cells[0];
        _ruleSelectionConfirmed = true;
        UpdateRulesActionState();
    }

    /// <summary>「已阻止的程序」表格：用键盘移动。</summary>
    private void OnRulesGridKeyDown(object? sender, KeyEventArgs e)
    {
        if (_rulesGrid.CurrentRow is null)
        {
            return;
        }

        _ruleSelectionConfirmed = true;
        UpdateRulesActionState();
    }

    /// <summary>
    /// 切换标签页时把「表格自己选中的第一行」清掉。
    ///
    /// DataGridView 在标签页重新显示时会自动把第一行设成当前行。
    /// 这里用 BeginInvoke 排到消息队列末尾，等控件把这一轮布局和自动选中都干完之后再清，
    /// 界面上才不会出现「高亮着但按钮是灰的」这种看不懂的状态。
    /// 用户自己点过的选择（Confirmed 为 true）不受影响。
    /// </summary>
    private void OnTabControlSelectedIndexChanged(object? sender, EventArgs e)
    {
        BeginInvoke(new Action(() =>
        {
            if (IsDisposed || Disposing)
            {
                return;
            }

            if (!_connectionSelectionConfirmed && ReferenceEquals(_tabControl.SelectedTab, _tabConnections))
            {
                _connectionGrid.CurrentCell = null;
            }

            if (!_ruleSelectionConfirmed && ReferenceEquals(_tabControl.SelectedTab, _tabRules))
            {
                _rulesGrid.CurrentCell = null;
            }

            UpdateActionState();
            UpdateRulesActionState();
        }));
    }

    private void OnCopyPathClick(object? sender, EventArgs e)
    {
        var item = GetConfirmedConnection();
        if (item is null || string.IsNullOrEmpty(item.ProcessPath))
        {
            return;
        }

        try
        {
            Clipboard.SetText(item.ProcessPath);
        }
        catch (Exception)
        {
            // 剪贴板偶尔会被别的程序占用，失败就算了，不值得弹框打断用户。
        }
    }

    /// <summary>
    /// 「最小化到托盘」按钮。
    /// 这个按钮**不是**退出 —— 真正的退出在托盘右键菜单里。
    /// 按钮上写清楚去向，比写一个行为不符的「退出」要诚实。
    /// </summary>
    private void OnExitButtonClick(object? sender, EventArgs e)
    {
        HideToTray();
    }

    // ==================================================================
    // 开机自启
    // ==================================================================

    /// <summary>
    /// 重新从任务计划程序读取开机自启状态。
    ///
    /// 每次都是真读系统，不缓存 —— 用户完全可能在 taskschd.msc 里手动删掉任务，
    /// 界面必须如实反映，不能一直显示一个过期的「已开启」骗人。
    /// </summary>
    private void RefreshAutoStartStatus()
    {
        try
        {
            var status = AutoStartManager.GetStatus();

            switch (status.State)
            {
                case AutoStartState.Enabled:
                    _autostartStatusLabel.Text = "当前状态：已开启";
                    _autostartStatusLabel.ForeColor = Color.FromArgb(0, 120, 0);
                    break;

                case AutoStartState.Misconfigured:
                    _autostartStatusLabel.Text = "当前状态：已开启，但任务指向的不是当前程序";
                    _autostartStatusLabel.ForeColor = Color.FromArgb(191, 87, 0);
                    break;

                default:
                    _autostartStatusLabel.Text = "当前状态：未开启";
                    _autostartStatusLabel.ForeColor = SystemColors.ControlText;
                    break;
            }

            _autostartDetailLabel.Text = BuildAutoStartDetail(status);
            _taskXmlBox.Text = status.Exists
                ? status.RawXml
                : "（系统里没有名为 WinAppGuard 的计划任务）";

            // 已经正确开启时不需要再点「开启」；没有任务时没什么可关的。
            _enableAutostartButton.Enabled = status.State != AutoStartState.Enabled;
            _disableAutostartButton.Enabled = status.Exists;
        }
        catch (Exception ex)
        {
            LocalLog.Error("读取开机自启状态失败", ex);
            _autostartStatusLabel.Text = "当前状态：读取失败";
            _autostartStatusLabel.ForeColor = Color.Firebrick;
            _autostartDetailLabel.Text = ex.Message;
            _taskXmlBox.Text = string.Empty;
            _enableAutostartButton.Enabled = true;
            _disableAutostartButton.Enabled = false;
        }
    }

    /// <summary>把任务详情拼成给用户看的多行文本。</summary>
    private static string BuildAutoStartDetail(AutoStartStatus status)
    {
        if (!status.Exists)
        {
            return "系统里没有这个任务。点「开启开机自启」会创建它。";
        }

        var runLevel = string.Equals(status.RunLevel, "HighestAvailable", StringComparison.OrdinalIgnoreCase)
            ? "最高权限（HighestAvailable，开机启动时不会弹 UAC 确认框）"
            : status.RunLevel;

        var lines = new List<string>
        {
            $"任务名：{AppConstants.ScheduledTaskName}",
            $"执行的程序：{status.ExecutablePath}",
            $"参数：{status.Arguments}",
            $"运行级别：{runLevel}",
            $"触发器：{status.Trigger}",
            $"任务状态：{status.TaskState}",
        };

        if (status.State == AutoStartState.Misconfigured)
        {
            lines.Add(
                $"当前程序实际位置：{Environment.ProcessPath}");
            lines.Add(
                "↑ 与任务里配置的不一致，通常是程序被挪动了。重新点一次「开启开机自启」即可修正。");
        }

        return string.Join(Environment.NewLine, lines);
    }

    private void OnEnableAutoStartClick(object? sender, EventArgs e)
    {
        var exePath = Environment.ProcessPath;
        if (string.IsNullOrEmpty(exePath))
        {
            MessageBox.Show(
                this,
                "拿不到当前程序的完整路径，无法设置开机自启。",
                AppConstants.AppName,
                MessageBoxButtons.OK,
                MessageBoxIcon.Warning);
            return;
        }

        var confirmed = ConfirmForm.Show(
            owner: DialogOwner,
            title: "开启开机自启",
            question: "确定要让 WinAppGuard 随 Windows 开机自动启动吗？",
            details: new[]
            {
                new KeyValuePair<string, string>("任务名", AppConstants.ScheduledTaskName),
                new KeyValuePair<string, string>("位置", @"任务计划程序库 → 根目录"),
                new KeyValuePair<string, string>("执行的程序", exePath),
                new KeyValuePair<string, string>("参数", AppConstants.AutostartArgument),
                new KeyValuePair<string, string>("运行级别", "最高权限"),
                new KeyValuePair<string, string>("触发器", "当前用户登录时"),
            },
            warnings: new[]
            {
                "这会在 Windows 任务计划程序里创建一条真实的计划任务。",
                "它会在你每次登录 Windows 时自动启动本程序，并直接最小化到系统托盘，不会弹窗打扰你。",
                "它使用「最高权限运行」，所以开机启动时不会弹出 UAC 确认框。",
                "这属于「提权持久化」行为，个别安全软件可能会给出提示，属于已知现象。",
                "随时可以在本页点「关闭开机自启」删除它，也可以自己打开 taskschd.msc 手动删除。",
            },
            confirmText: "开启");

        if (!confirmed)
        {
            return;
        }

        try
        {
            AutoStartManager.Enable(exePath);
            LocalLog.Operation($"开启开机自启：任务名 {AppConstants.ScheduledTaskName}，执行的程序 {exePath}");
            RefreshAutoStartStatus();

            MessageBox.Show(
                this,
                "开机自启已开启。\n\n" +
                $"任务名：{AppConstants.ScheduledTaskName}\n" +
                "你可以在「任务计划程序」(taskschd.msc) 里看到它，下面也显示了它的完整定义。",
                AppConstants.AppName,
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
        }
        catch (Exception ex)
        {
            RefreshAutoStartStatus();

            ShowError("开启开机自启失败", ex);
        }
    }

    private void OnDisableAutoStartClick(object? sender, EventArgs e)
    {
        var status = AutoStartManager.GetStatus();

        var confirmed = ConfirmForm.Show(
            owner: DialogOwner,
            title: "关闭开机自启",
            question: "确定要删除开机自启任务吗？",
            details: new[]
            {
                new KeyValuePair<string, string>("任务名", status.Exists ? AppConstants.ScheduledTaskName : "（不存在）"),
                new KeyValuePair<string, string>("当前程序", status.ExecutablePath),
            },
            warnings: new[]
            {
                "将删除 Windows 任务计划程序里名为 WinAppGuard 的这条任务。",
                "只删除这一个任务，系统和其他软件的计划任务一律不受影响。",
                "删除后本程序不再随开机自动启动。",
                "正在运行的这个实例不受影响，已创建的防火墙规则也依然有效。",
            },
            confirmText: "关闭开机自启");

        if (!confirmed)
        {
            return;
        }

        try
        {
            var deleted = AutoStartManager.Disable();
            LocalLog.Operation($"关闭开机自启：删除任务 {AppConstants.ScheduledTaskName}，实际删除={(deleted ? "是" : "任务本来就不存在")}");
            RefreshAutoStartStatus();

            MessageBox.Show(
                this,
                deleted ? "开机自启已关闭，任务已从任务计划程序里删除。" : "系统里本来就没有这个任务，无需删除。",
                AppConstants.AppName,
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
        }
        catch (Exception ex)
        {
            RefreshAutoStartStatus();

            ShowError("关闭开机自启失败", ex);
        }
    }

    /// <summary>
    /// 「重新读取状态」。
    /// 主要用于用户在 taskschd.msc 里手动增删过任务之后，让界面跟系统对齐。
    /// </summary>
    private void OnRefreshAutoStartClick(object? sender, EventArgs e)
    {
        RefreshAutoStartStatus();
    }

    // ==================================================================
    // 系统托盘
    // ==================================================================

    /// <summary>把主窗口收进托盘。</summary>
    private void HideToTray()
    {
        Hide();

        // 第一次收进托盘时给个气泡提示。
        // 不提示的话用户会以为程序被关掉了，而其实防火墙规则还在生效 ——
        // 尤其在有开机自启的时候，这种误解代价很大。
        if (!_trayHintShown)
        {
            _trayHintShown = true;
            ShowTrayBalloon(
                "WinAppGuard 仍在后台运行",
                "防火墙规则依然有效。双击托盘图标可以重新打开；要真正退出，请右键托盘图标选「退出」。");
        }
    }

    /// <summary>
    /// 处理窗口消息。
    ///
    /// 这里只接一件事：第二个进程启动时会广播一条自定义消息请我们把主窗口显示出来。
    /// 收到就把窗口拉回前台 —— 用户看到的效果就是「点第二下，窗口回来了」。
    /// </summary>
    protected override void WndProc(ref Message m)
    {
        if (SingleInstance.ShowWindowMessage != 0 && (uint)m.Msg == SingleInstance.ShowWindowMessage)
        {
            LocalLog.Info("收到另一个实例的请求，把主窗口显示出来。");
            ShowMainWindow();
            return;
        }

        base.WndProc(ref m);
    }

    /// <summary>
    /// 重新显示主窗口。
    /// </summary>
    private void ShowMainWindow()
    {
        Show();

        if (WindowState == FormWindowState.Minimized)
        {
            WindowState = FormWindowState.Normal;
        }

        Activate();
        BringToFront();
    }

    /// <summary>弹一个托盘气泡。系统通知被关掉时它不显示，但不影响功能，所以不用管返回值。</summary>
    private void ShowTrayBalloon(string title, string text)
    {
        _trayIcon.ShowBalloonTip(5000, title, text, ToolTipIcon.Info);
    }

    private void OnTrayShowClick(object? sender, EventArgs e)
    {
        ShowMainWindow();
    }

    /// <summary>
    /// 托盘的「退出」。这是唯一一条真正结束进程的路，所以必须把后果说清楚。
    /// </summary>
    private void OnTrayExitClick(object? sender, EventArgs e)
    {
        var blockedCount = _blockedPaths.Count;

        var warnings = blockedCount > 0
            ? new[]
            {
                "退出只是关掉这个界面程序。它创建的防火墙规则依然生效，被阻止的程序仍然上不了网。",
                $"当前被阻止的 {blockedCount} 个程序会继续保持被阻止状态。",
                "如果想让它们恢复联网，请先回到主界面用「允许选中程序联网」，或用「删除全部 AppGuard 规则」。",
            }
            : new[]
            {
                "退出只是关掉这个界面程序。它创建的防火墙规则依然生效。",
            };

        var confirmed = ConfirmForm.Show(
            owner: DialogOwner,
            title: "退出 WinAppGuard",
            question: "确定要退出 WinAppGuard 吗？",
            details: new[]
            {
                new KeyValuePair<string, string>("当前被阻止的程序", $"{blockedCount} 个"),
            },
            warnings: warnings,
            confirmText: "退出");

        if (!confirmed)
        {
            return;
        }

        LocalLog.Info($"用户从托盘退出程序。退出时被阻止的程序数={blockedCount}，规则依然生效。");
        _reallyExit = true;
        Close();
    }

    // ==================================================================
    // 内部工具
    // ==================================================================

    /// <summary>
    /// 统一的错误出口：先写日志，再弹一个用户能看懂的框。
    ///
    /// 收成一处的好处：以后新增操作时不会再有人忘记写日志，
    /// 而且日志里的记录和用户看到的提示永远是同一句话。
    /// </summary>
    private void ShowError(string what, Exception ex)
    {
        LocalLog.Error(what, ex);

        MessageBox.Show(
            this,
            $"{what}：\n\n{ex.Message}",
            AppConstants.AppName,
            MessageBoxButtons.OK,
            MessageBoxIcon.Error);
    }

    /// <summary>
    /// 设置页尺寸变化时，手动把各分区的宽度对齐可视宽度。
    ///
    /// 为什么不用 Anchor=Right：设置页开了 AutoScroll，而「AutoScroll + Anchor=Right」两者会互相打架 ——
    /// 竖向滚动条一出现，客户区宽度就变，锚定右边缘的控件跟着变宽，下一次布局再变，
    /// 结果是控件一次比一次宽（实测从 1361 涨到 2532），右边直接跑出画面。
    /// 手动设宽度行为确定、可预测，也不会出现这种累积漂移。
    /// </summary>
    private void OnSettingsTabResize(object? sender, EventArgs e)
    {
        LayoutSettingsSections();
    }

    private void LayoutSettingsSections()
    {
        // 留出竖向滚动条和一点边距的位置。
        var width = _tabSettings.ClientSize.Width - 14;
        if (width < 600)
        {
            // 太窄时不再压缩，交给横向滚动条处理，总比把内容挤成一列强。
            width = 600;
        }

        _autostartPanel.Width = width;
        _privacyPanel.Width = width;
        _taskXmlPanel.Width = width;
    }

    /// <summary>打开日志目录。打不开就如实告诉用户路径，不要静默失败。</summary>
    private void OnOpenLogFolderClick(object? sender, EventArgs e)
    {
        if (!LocalLog.OpenLogDirectory())
        {
            MessageBox.Show(
                this,
                $"打不开日志目录，你可以手动复制下面这个路径：\n\n{LocalLog.LogDirectory}",
                AppConstants.AppName,
                MessageBoxButtons.OK,
                MessageBoxIcon.Warning);
        }
    }

    /// <summary>比较两个程序路径是否指向同一个文件。</summary>
    private static bool PathsEqual(string? left, string? right)
        => !string.IsNullOrEmpty(left)
           && !string.IsNullOrEmpty(right)
           && string.Equals(left, right, StringComparison.OrdinalIgnoreCase);
}
