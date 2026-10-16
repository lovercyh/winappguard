using WinAppGuard.Core;
using WinAppGuard.Models;

namespace WinAppGuard.Forms;

/// <summary>
/// 主窗体。
///
/// 界面分两页，这个划分是刻意的：
///   「联网连接」页  —— 基于**实时连接**，用来发现「谁正在联网」。
///   「规则」页 —— 基于**防火墙规则**，用来管理已经建好的规则。
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

    /// <summary>
    /// 签名有严重问题的行底色：签名被篡改、证书已过期/被吊销、证书链不受信任。
    /// 这些都是「真有问题」，用红色。
    /// </summary>
    private static readonly Color SignatureProblemRowColor = Color.FromArgb(255, 212, 212);

    /// <summary>
    /// 未签名程序的行底色：黄色。
    /// 黄色表示「需要留意」，不是「有错误」—— 很多正经的免费/开源工具都没买签名证书。
    /// </summary>
    private static readonly Color UnsignedRowColor = Color.FromArgb(255, 240, 184);

    /// <summary>已被本工具阻止的行底色。蓝色表示「你的操作」，不是风险。</summary>
    private static readonly Color BlockedRowColor = Color.FromArgb(221, 234, 251);

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

    /// <summary>
    /// 本次扫描的**全部**连接（未经搜索过滤）。
    ///
    /// 为什么要和 <see cref="_connections"/> 分开：
    ///   `_connections` 放的是「当前显示」的那些；搜索词一改，只需要按它重新过滤 + 重绑，
    ///   **不必重新扫描**（扫描要几百毫秒，还会打断用户正在看的列表）。
    /// 同样只创建一次、原地更新（理由见上面 <see cref="_connections"/> 的说明）。
    /// </summary>
    private readonly List<TcpConnectionItem> _scannedConnections = new();

    /// <summary>当前搜索关键词。空字符串表示不过滤。</summary>
    private string _searchKeyword = string.Empty;

    /// <summary>当前排序列（界面接线在 1.3-D；这里先由重建显示列表的逻辑使用）。</summary>
    private ConnectionSortColumn _sortColumn = ConnectionSortColumn.None;

    /// <summary>当前排序方向：true 为升序。</summary>
    private bool _sortAscending = true;

    /// <summary>上一次扫描完成的时刻，用于状态栏显示。</summary>
    private DateTime _lastScanTime = DateTime.MinValue;

    /// <summary>
    /// 是否正在清理到期的临时阻断规则。
    /// 定时器和「手动刷新」有可能撞在一起，用这个标志保证同一时刻只跑一次。
    /// </summary>
    private bool _isPurging;

    /// <summary>
    /// 列宽的「预览线」拖动器。
    ///
    /// 为什么不用 DataGridView 自带的实时拖动：它每移动一次鼠标就把整表重画一遍，
    /// 实测在 1920×1080、20 个可见行时单帧要 33~40ms（25~30fps），拖起来跟不上鼠标。
    /// 详见 <see cref="GridColumnResizer"/> 的类说明。
    /// </summary>
    private readonly GridColumnResizer _columnResizer;

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
    /// 严格模式白名单：被**本工具**建的允许规则（<c>AppGuard_Allow_*</c>）覆盖的程序路径。
    /// 它不是从 <see cref="_appGuardRules"/> 推导的，而是 <see cref="RefreshAllowTargets"/> 读回来的。
    /// </summary>
    private readonly HashSet<string> _whitelistedPaths = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// 被**系统或其它软件**建的允许规则覆盖的程序路径。
    ///
    /// 为什么要单独存：严格模式**挡不住**这些程序（我们的边界是不碰别人的规则），
    /// 界面上必须把它们和"我们自己放行的"区分开 —— 否则用户会以为
    /// "严格模式 = 只有我放行的能上网"，而事实不是。
    /// </summary>
    private readonly HashSet<string> _otherAllowPaths = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>「不限程序」的允许规则条数（系统自带的多是这类）。只用于如实说明。</summary>
    private int _programlessAllowRuleCount;

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

    /// <summary>用户是否主动点选过「规则」表格里的某一条规则。理由同上一项。</summary>
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

    /// <summary>
    /// 证书吊销检查方式。
    ///
    /// 默认 <see cref="RevocationMode.Online"/>：吊销状态查得准。
    /// 代价是 **Windows 的证书服务会代表本程序去查询 CA 服务器**，
    /// 在资源监视器里会看到 WinAppGuard.exe 有对外连接。
    /// 用户可以在「设置」页取消勾选，那样就完全不留网络流量。
    /// </summary>
    private RevocationMode _revocationMode = RevocationMode.Online;

    /// <summary>
    /// 是否正在后台检查数字签名。
    /// 检查很慢（目录签名要哈希整个文件、还要验证证书链），
    /// 用这个标志保证同一时刻只跑一轮，否则每 3 秒刷新一次会堆积任务。
    /// </summary>
    private bool _isCheckingSignatures;

    // ---------- IP 归属查询 ----------

    /// <summary>
    /// 本机设置。默认 IP 归属查询是**开启**的（见 <see cref="AppSettings"/>）。
    /// 这个文件只写本机，不参与任何联网。
    /// </summary>
    private readonly AppSettings _settings = AppSettings.Load();

    /// <summary>
    /// IP 归属查询的调度器。
    /// 联网动作全在它内部的 <see cref="IpOwnershipLookup"/> 里 ——
    /// 界面这一层只负责「要查哪些地址」和「把结果挂到表格上」，不直接碰网络。
    /// </summary>
    private readonly IpOwnershipService _ipOwnershipService = new();

    /// <summary>
    /// 是否正在把设置里的值填到界面控件上。
    ///
    /// 为什么需要：给 CheckBox.Checked 赋值会触发 CheckedChanged，
    /// 那本来代表「用户切换了开关」。不加这个标志的话，启动时的一次填充
    /// 会被当成用户操作，白白写一次设置文件、还记一条日志。
    /// </summary>
    private bool _loadingSettings;

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

        // 到期检查用独立定时器（理由见字段说明）。
        _expiryTimer.Interval = AppConstants.ExpiredRuleCheckIntervalMs;
        SetupConnectionGrid();
        SetupRulesGrid();

        // 列宽用「预览线」拖动（自带的实时拖动在慢机器上会卡，见 GridColumnResizer）。
        _columnResizer = new GridColumnResizer(_connectionGrid);

        // IP 归属查询：把后台结果接回界面，并按设置决定要不要开启。
        // 开启只是「允许查询」，真正的网络请求要等扫描完成后才会发起。
        _ipOwnershipService.ResultsUpdated += OnOwnershipResultsUpdated;
        _ipOwnershipService.IsEnabled = _settings.IpOwnershipEnabled;

        // 把设置里的开关状态填到界面上。
        // 用 _loadingSettings 挡住 CheckedChanged —— 那是给「用户操作」用的，
        // 启动时的一次填充不该写文件、也不该记日志。
        _loadingSettings = true;
        _checkIpOwnershipCheckBox.Checked = _settings.IpOwnershipEnabled;
        _loadingSettings = false;
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

        // 严格模式是**会话级**的：如果上次没有正常退出（崩溃 / 被强杀 / 断电），
        // 它留下的「默认阻止出站」必须在这一刻还原 —— 否则用户开机即断网。
        // 放在最前面：连规则都还没读，先把网络救回来。
        RecoverStrictModeIfLeftOn();

        // 启动时先把**已经到期**的临时阻断清掉，再读规则 ——
        // 这样第一屏显示的就是清理后的状态，不会先闪一下旧数据。
        // 这一步在界面线程上同步做（实测约 45ms，只在启动时一次）；
        // 之后的周期性检查都放后台线程（见 CheckExpiredBlocksAsync）。
        PurgeExpiredBlocksAtStartup();

        // 先把防火墙规则读进来，这样第一屏就能正确显示「已阻止 / 未阻止」。
        // 放行状态（严格模式白名单）要在这之前读：它会让「放行」列第一屏就是对的。
        RefreshAllowTargets();
        RefreshRulesFromFirewall();

        // 严格模式分区也要有个初值（它读的就是上面刚缓存好的白名单）。
        RefreshStrictModeStatus();

        // 启动「临时阻断」到期检查：独立定时器，**不受**「每 3 秒自动刷新」那个开关影响。
        _expiryTimer.Start();

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
        else
        {
            // IP 归属查询默认开启，也就是第一次运行就会联网，必须主动告知一次。
            // 用 BeginInvoke 延后到窗口画完之后再弹，避免对话框出现在还没画完的窗口前面。
            // （开机自启那条路不在这里弹，会在用户真正打开窗口时弹 —— 见 ShowMainWindow。）
            BeginInvoke(ShowIpOwnershipNoticeIfNeeded);
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
        // 列变多了（加了「数字签名」），所以每一列都适当收窄了一点，
        // 否则 1180 宽的窗口里会出现横向滚动条。
        //
        // 末尾的 sortable: true 表示「允许点击表头排序」。只给排序真正有意义、
        // 且能按**值**正确排的列开（见 ConnectionFilter 的说明）：
        // 程序路径太长不必排；数字签名/阻止状态排起来没什么意义。
        //
        // ⚠️ Fill 列刻意放在**最后一列**（数字签名），不放在程序路径上：
        //    Fill 列的宽度是自动算出来的，**它右边那条分隔线天生不可拖**。
        //    放在中间就会出现「别的线都能拖、唯独那条拖不动」的怪现象
        //    （用户实际报过这个 bug）。放在最后一列只影响表格最右边缘，没人会去拖那里。
        AddConnectionColumn("程序名", nameof(TcpConnectionItem.ProcessName), 115, sortable: true);
        AddConnectionColumn("程序路径", nameof(TcpConnectionItem.ProcessPathText), 135);
        AddConnectionColumn("PID", nameof(TcpConnectionItem.Pid), 60, sortable: true);
        AddConnectionColumn("本地端口", nameof(TcpConnectionItem.LocalPortText), 80, sortable: true);
        AddConnectionColumn("远程 IP", nameof(TcpConnectionItem.RemoteAddressText), 130, sortable: true);
        AddConnectionColumn("远程端口", nameof(TcpConnectionItem.RemotePortText), 80, sortable: true);
        AddConnectionColumn("状态", nameof(TcpConnectionItem.StateText), 90, sortable: true);
        AddConnectionColumn("协议", nameof(TcpConnectionItem.Protocol), 60);
        AddConnectionColumn("阻止状态", nameof(TcpConnectionItem.BlockStateText), 80);
        AddConnectionColumn("放行", nameof(TcpConnectionItem.WhitelistText), 140);
        AddConnectionColumn("数字签名", nameof(TcpConnectionItem.SignatureText), 130, fill: true, minWidth: 80);

        _connectionSource.DataSource = _connections;
        _connectionGrid.DataSource = _connectionSource;
    }

    /// <summary>
    /// 定义「规则」表格的列。
    /// 这一页的数据来自防火墙规则本身，与实时连接无关。
    /// </summary>
    private void SetupRulesGrid()
    {
        AddRuleColumn("程序名", nameof(FirewallRuleItem.ApplicationNameText), 150);
        AddRuleColumn("程序路径", nameof(FirewallRuleItem.ApplicationPath), 280, fill: true);
        AddRuleColumn("自动解除", nameof(FirewallRuleItem.ExpiryText), 120);
        AddRuleColumn("动作", nameof(FirewallRuleItem.ActionText), 60);
        AddRuleColumn("方向", nameof(FirewallRuleItem.DirectionText), 60);
        AddRuleColumn("协议", nameof(FirewallRuleItem.ProtocolText), 60);
        AddRuleColumn("启用", nameof(FirewallRuleItem.EnabledText), 70);
        AddRuleColumn("规则名", nameof(FirewallRuleItem.Name), 180);

        _rulesSource.DataSource = _rules;
        _rulesGrid.DataSource = _rulesSource;
    }

    /// <summary>给「联网连接」表格添加一个只读文本列。</summary>
    private void AddConnectionColumn(
        string header, string propertyName, int width,
        bool fill = false, bool sortable = false, int minWidth = 200)
        => AddColumn(_connectionGrid, header, propertyName, width, fill, sortable, minWidth);

    /// <summary>给「规则」表格添加一个只读文本列。</summary>
    private void AddRuleColumn(string header, string propertyName, int width, bool fill = false)
        => AddColumn(_rulesGrid, header, propertyName, width, fill);

    /// <summary>添加一个只读的文本列。</summary>
    /// <param name="grid">目标表格。</param>
    /// <param name="header">列标题。</param>
    /// <param name="propertyName">绑定的属性名，必须与数据模型的属性名完全一致。</param>
    /// <param name="width">列宽（像素）。</param>
    /// <param name="fill">为 true 时该列自动占满剩余宽度（通常给路径列）。</param>
    /// <param name="sortable">
    /// 这一列是否允许点击表头排序。
    ///
    /// 用 <see cref="DataGridViewColumnSortMode.Programmatic"/> 而不是 Automatic：
    /// 表格绑的是 BindingSource + List&lt;T&gt;，**不支持** IBindingList 排序，
    /// 交给控件自己排会没反应甚至抛异常；而且每 3 秒重绑一次也会把它的排序冲掉。
    /// 所以排序由我们自己算（见 ConnectionFilter），控件只负责画那个小箭头。
    /// </param>
    /// <param name="minWidth">Fill 列的最小宽度（非 Fill 列忽略这个参数）。</param>
    private static void AddColumn(
        DataGridView grid, string header, string propertyName, int width,
        bool fill = false, bool sortable = false, int minWidth = 200)
    {
        var column = new DataGridViewTextBoxColumn
        {
            HeaderText = header,
            DataPropertyName = propertyName,
            Name = propertyName,
            ReadOnly = true,
            SortMode = sortable
                ? DataGridViewColumnSortMode.Programmatic
                : DataGridViewColumnSortMode.NotSortable,
        };

        if (fill)
        {
            column.AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill;
            column.MinimumWidth = minWidth;
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
        _versionLabel.Text = $"版本 v{BuildVersionText()}";

        _startModeLabel.Text = _isAutostart
            ? $"启动模式：开机自启（{AppConstants.AutostartArgument}）"
            : "启动模式：手动启动";

        var isAdmin = AdminHelper.IsRunningAsAdmin();
        _adminStatusLabel.Text = isAdmin
            ? "管理员权限：已获得"
            : "管理员权限：未获得（防火墙功能不可用）";
        _adminStatusLabel.ForeColor = isAdmin ? Color.FromArgb(0, 120, 0) : Color.Firebrick;
    }

    /// <summary>
    /// 状态栏上显示的版本文字。
    ///
    /// .NET SDK 会把 git 提交号附加在版本后面（形如 1.1.0+5a7219c22e75…），
    /// 这是标准行为，而且对排查问题很有用 —— 用户报 bug 时能定位到具体那次提交。
    /// 但完整 SHA 太长，所以这里截成短号显示成「1.1.0 · 5a7219c」。
    /// </summary>
    private static string BuildVersionText()
    {
        var version = Application.ProductVersion;

        var plusIndex = version.IndexOf('+');
        if (plusIndex <= 0)
        {
            // 不在 git 仓库里构建时就没有提交号后缀，直接用版本号。
            return version;
        }

        var number = version[..plusIndex];
        var revision = version[(plusIndex + 1)..];

        if (revision.Length > 7)
        {
            revision = revision[..7];
        }

        return $"{number} · {revision}";
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

            // 页签上挂**规则总数**（而不是"被阻止的程序数"）：
            // 这一页现在同时装着阻止规则和允许规则（白名单），
            // 挂规则数才和用户在这个页面里看到的东西一致。
            _tabRules.Text = $"规则（{_appGuardRules.Count}）";
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

        // 规则变了，白名单也可能变了（加入/移出白名单、删除规则、严格模式开关）。
        // 必须在 RebindGrid 之前刷新 —— RebindGrid 里要用它算「放行」列。
        RefreshAllowTargets();

        // 先抓选中，再重绑 —— 顺序理由见 RebindGrid 的说明。
        RebindGrid(CaptureSelection());
    }

    // ==================================================================
    // 临时阻断的到期清理
    //
    // 什么时候检查：程序启动时（同步一次）、一个 30 秒的独立定时器、
    // 以及用户手动点「刷新」时。
    // **刻意不搭在「每 3 秒自动刷新」上** —— 那个开关默认是关的，
    // 搭上去的话没勾开关的用户就永远等不到临时阻断自动解除。
    //
    // 为什么放后台线程：读一遍防火墙规则要把系统里**全部**规则枚举一遍
    // （本机 735 条，实测约 45ms）。挂在界面线程上，每 30 秒就会有一次可见的卡顿。
    // ==================================================================

    /// <summary>
    /// 启动时的到期清理：**同步**做一次（约 45ms，只在启动时一次），
    /// 这样紧接着读出来的规则就已经是清理后的状态，不会先闪一下旧数据。
    /// </summary>
    private void PurgeExpiredBlocksAtStartup()
    {
        try
        {
            // 把开机时刻和「是不是自启动」记进日志：这一类问题（重启了却没解除）
            // 下次一看日志就能定位，不用再猜。
            LocalLog.Info(
                $"启动清理：开机时刻 = {SystemUptime.BootTimeUtc:yyyy-MM-dd HH:mm:ss} UTC，" +
                $"本次是否由登录触发的开机自启拉起 = {_isAutostart}");

            // freshLogonSession 传 _isAutostart：登录触发说明刚刚发生过一次登录，
            // 「直到下次重启」那类规则就该在这一刻解除（快速启动会让开机时长不归零，
            // 光靠开机时刻判断会漏掉，详见 RuleExpiry.IsExpired 的说明）。
            var removed = FirewallManager.PurgeExpiredRules(
                DateTime.UtcNow, SystemUptime.BootTimeUtc, freshLogonSession: _isAutostart);

            NotifyExpiredBlocks(removed);
        }
        catch (Exception ex)
        {
            LocalLog.Error("启动时清理到期的临时阻断规则失败", ex);
        }
    }

    /// <summary>
    /// 严格模式的启动兜底：上次没正常退出（崩溃 / 被强杀 / 断电）时，
    /// 把残留的「默认阻止出站」还原成「允许」。
    ///
    /// 为什么必须做：默认出站动作**不随程序退出而恢复**。
    /// 漏掉这一步，用户下次开机就是"所有程序都上不了网"，
    /// 而他很可能正是不敢碰 wf.msc 的那类人。
    /// </summary>
    private void RecoverStrictModeIfLeftOn()
    {
        try
        {
            var result = StrictModeManager.RecoverIfLeftOn();

            if (!result.WasLeftOn)
            {
                // 绝大多数情况：上次正常退出，什么都没留下。
                return;
            }

            if (result.Restored)
            {
                ShowTrayBalloon(
                    "严格模式已被自动还原",
                    "上次没有正常退出，严格模式留下的「默认阻止出站」已经还原成「允许」，网络应该恢复正常了。");
                return;
            }

            // 还原失败是最严重的情况之一，必须明确告诉用户怎么手工救回来。
            MessageBox.Show(
                this,
                result.Message + "\n\n请手工恢复：Win+R 输入 wf.msc → 右键「属性」→ " +
                "三套配置文件（域 / 专用 / 公用）标签页的「出站连接」都改成「允许」。",
                AppConstants.AppName,
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
        }
        catch (Exception ex)
        {
            // 这里失败不能影响程序启动；标志还在，下次启动会再试一次。
            LocalLog.Error("启动时还原严格模式失败", ex);
        }
    }

    /// <summary>定时器到点、或用户手动刷新时调用。放后台线程做，不卡界面。</summary>
    private async void CheckExpiredBlocksAsync()
    {
        if (_isPurging || IsDisposed || Disposing)
        {
            return;
        }

        _isPurging = true;

        try
        {
            var removed = await Task.Run(() =>
                FirewallManager.PurgeExpiredRules(DateTime.UtcNow, SystemUptime.BootTimeUtc));

            // await 期间窗口可能已经被关了。
            if (IsDisposed || Disposing)
            {
                return;
            }

            NotifyExpiredBlocks(removed);

            // 什么时候需要重刷界面：
            //   1. 真的删掉了规则 —— 规则页和连接页的「已阻止」显示都要跟着更新；
            //   2. 内存里还有**临时**规则 —— 重刷一次能让「剩余 X 分钟」这个倒计时保持新鲜。
            //      （规则页那列显示的是读取那一刻的快照，不重刷就会一直停在旧数字上。）
            if (removed.Count > 0 || _appGuardRules.Any(rule => !rule.Expiry.IsPermanent))
            {
                AfterRulesChanged();
            }
        }
        catch (Exception ex)
        {
            LocalLog.Error("清理到期的临时阻断规则失败", ex);
        }
        finally
        {
            _isPurging = false;
        }
    }

    /// <summary>
    /// 有一条或多条临时阻断到期被解除：记日志 + 弹一次托盘气泡。
    ///
    /// 为什么要弹气泡（产品负责人定的）：不声不响地解除会让人困惑 ——
    /// 「这程序怎么又能联网了」。多条一起到期时只弹一个，把数量说清楚。
    /// </summary>
    private void NotifyExpiredBlocks(IReadOnlyList<(string RuleName, string ProgramPath)> removed)
    {
        if (removed.Count == 0)
        {
            return;
        }

        foreach (var (ruleName, programPath) in removed)
        {
            LocalLog.Operation($"临时阻断到期，已自动解除：{programPath}（规则 {ruleName}）");
        }

        var names = removed
            .Select(item => Path.GetFileName(item.ProgramPath))
            .Where(name => !string.IsNullOrEmpty(name))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var text = removed.Count == 1
            ? $"「{names.FirstOrDefault() ?? "该程序"}」的临时阻断已到期，已自动解除，它现在可以重新联网了。"
            : $"{removed.Count} 个程序的临时阻断已到期，已自动解除：{string.Join("、", names)}";

        ShowTrayBalloon("临时阻断已自动解除", text);
    }

    private void OnExpiryTimerTick(object? sender, EventArgs e) => CheckExpiredBlocksAsync();

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
    /// 重新读一遍「哪些程序已经被放行」（严格模式白名单 + 别的来源的允许规则）。
    ///
    /// 为什么必须缓存：这一读要把系统里**全部**防火墙规则枚举一遍，还要逐条读
    /// ApplicationName（比单纯数条数贵得多，耗时记进日志便于观察）。
    /// 所以只在**规则可能变化**的时候刷新：启动时、规则增删之后、切回本页时。
    /// **刻意不搭在「每 3 秒自动刷新」上** —— 白名单不会每 3 秒变一次，
    /// 但会因此每 3 秒枚举一遍全部规则。
    /// </summary>
    private void RefreshAllowTargets()
    {
        try
        {
            var started = Environment.TickCount64;
            var targets = FirewallManager.GetOutboundAllowTargets();

            _whitelistedPaths.Clear();
            _whitelistedPaths.UnionWith(targets.OurAllowRulePrograms);

            _otherAllowPaths.Clear();
            _otherAllowPaths.UnionWith(targets.OtherSoftwareAllowRulePrograms);

            _programlessAllowRuleCount = targets.ProgramlessAllowRuleCount;

            // 耗时写进日志：这条路径的开销是本功能唯一的性能风险点，
            // 真机上一旦变慢，日志里就能直接看到。
            LocalLog.Info(
                $"放行状态：本工具白名单 {_whitelistedPaths.Count} 个程序、" +
                $"系统/其它软件放行 {_otherAllowPaths.Count} 个程序、" +
                $"不限程序的允许规则 {_programlessAllowRuleCount} 条、" +
                $"耗时 {Environment.TickCount64 - started}ms");
        }
        catch (Exception ex)
        {
            LocalLog.Error("读取放行状态失败", ex);
        }
    }

    /// <summary>把白名单状态写到当前这批连接数据上。</summary>
    private void ApplyWhitelistState()
    {
        foreach (var item in _connections)
        {
            item.Whitelist =
                string.IsNullOrEmpty(item.ProcessPath) ? WhitelistState.NotApplicable
                : _whitelistedPaths.Contains(item.ProcessPath) ? WhitelistState.Ours
                : _otherAllowPaths.Contains(item.ProcessPath) ? WhitelistState.OtherSource
                : WhitelistState.NotWhitelisted;
        }
    }

    /// <summary>
    /// 按「当前搜索词 + 当前排序」重建显示列表。
    ///
    /// 关键约定：**原地更新 <see cref="_connections"/>**（Clear + AddRange），
    /// 绝不重新赋值 —— BindingSource 绑的是这个实例本身，
    /// 一换实例表格就永远是空的（见该字段的注释）。
    /// </summary>
    private void RebuildView()
    {
        var view = ConnectionFilter.Apply(_scannedConnections, _searchKeyword, _sortColumn, _sortAscending);

        _connections.Clear();
        _connections.AddRange(view);
    }

    /// <summary>
    /// 刷新状态栏的计数。
    ///
    /// 为什么必须区分「显示」和「共」：过滤之后如果只显示一个数字，
    /// 用户会以为连接变少了（可能误判成程序出了问题）。把总数摆出来才不会误导。
    /// </summary>
    private void UpdateSummary()
    {
        var shown = _connections.Count;
        var total = _scannedConnections.Count;
        var time = _lastScanTime == DateTime.MinValue ? "--:--:--" : _lastScanTime.ToString("HH:mm:ss");

        _summaryLabel.Text = shown == total
            ? $"最后刷新：{time}    共 {total} 条"
            : $"最后刷新：{time}    显示 {shown} / 共 {total} 条";
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
            ApplyOwnership();
            ApplyWhitelistState();
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

        ColorizeRows();
        UpdateSortGlyphs();
        UpdateActionState();
    }

    /// <summary>
    /// 给每一行上色，并给签名列挂上悬停提示。
    ///
    /// 行底色的优先级（高到低）：
    ///   1. 签名被篡改 / 证书异常 / 证书链不受信任 → 淡红
    ///   2. 未签名                                  → 淡黄
    ///   3. 已阻止                                  → 淡蓝
    ///
    /// 为什么把签名风险排在「已阻止」前面：
    ///   签名问题是你**还不知道、需要被提醒**的信息；
    ///   而「已阻止」是你自己刚才做的操作，状态在专门的列里写着，不必再用行底色重复强调。
    ///   两者冲突时让「新信息」胜出。
    ///   另外被阻止的程序连不上网，会从连接列表里消失，所以这里的「已阻止」行本来就很少，
    ///   把行底色让给签名信息损失很小。
    /// </summary>
    private void ColorizeRows()
    {
        // 签名列的列名，用于定位单元格。用列名而不是硬编码索引，列顺序变了也不会错。
        var signatureColumnIndex = _connectionGrid.Columns[nameof(TcpConnectionItem.SignatureText)]?.Index ?? -1;
        var whitelistColumnIndex = _connectionGrid.Columns[nameof(TcpConnectionItem.WhitelistText)]?.Index ?? -1;

        foreach (DataGridViewRow row in _connectionGrid.Rows)
        {
            if (row.DataBoundItem is not TcpConnectionItem item)
            {
                continue;
            }

            var background = GetRowColor(item);
            if (background is { } color)
            {
                row.DefaultCellStyle.BackColor = color;
            }

            // 签名列只显示短名字，完整结论（含签名来源和错误码）放悬停提示里。
            if (signatureColumnIndex >= 0 && !string.IsNullOrEmpty(item.SignatureTooltip))
            {
                row.Cells[signatureColumnIndex].ToolTipText = item.SignatureTooltip;
            }

            // 「放行」列同理：单元格里只放得下短文本，三档的**完整含义**放悬停提示里。
            // 这一列尤其不能只写"已放行"了事 —— 必须让用户看清"这不是我放行的"。
            if (whitelistColumnIndex >= 0)
            {
                row.Cells[whitelistColumnIndex].ToolTipText = BuildWhitelistTooltip(item);
            }
        }

        // 归属信息挂在「远程 IP」列上，和签名提示一样只在有内容时才显示。
        RefreshOwnershipTooltips();
    }

    /// <summary>
    /// 「放行」列的悬停提示：把三档含义说全。
    ///
    /// 之所以要写这么细：这一列的全部价值就在于"如实"——
    /// 用户必须能看出「已放行·其它来源」**不是他放行的**，也能看出
    /// 「未放行」在严格模式下到底会发生什么（以及已有连接会怎样）。
    /// </summary>
    private static string BuildWhitelistTooltip(TcpConnectionItem item) => item.Whitelist switch
    {
        WhitelistState.Ours =>
            "已加入白名单：本工具为它建了一条「允许出站」的防火墙规则。\n" +
            "严格模式生效时，它能正常上网。",

        WhitelistState.OtherSource =>
            "它并不在本工具的白名单里，但「系统或其它软件」为它建了允许规则。\n" +
            "严格模式挡不住这一类 —— 本工具的边界是不碰别人的规则，所以只能如实显示。",

        WhitelistState.NotWhitelisted =>
            "本工具没有为它建允许规则。\n" +
            "严格模式生效时，它无法建立新的出站连接（已经连上的要等它自己断开）。",

        _ => "拿不到这个程序的完整路径，无法判断它在不在白名单里。",
    };

    /// <summary>按优先级决定一行的底色；不需要特殊着色时返回 null。</summary>
    private static Color? GetRowColor(TcpConnectionItem item)
    {
        switch (item.Signature.State)
        {
            case SignatureState.Tampered:
            case SignatureState.CertificateProblem:
            case SignatureState.Untrusted:
                return SignatureProblemRowColor;

            case SignatureState.Unsigned:
                return UnsignedRowColor;

            default:
                // 签名正常（或者还没查出来）时，才轮到「已阻止」占用行底色。
                return item.IsBlocked ? BlockedRowColor : null;
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

        // 白名单状态：只认**本工具建的**允许规则。
        // 「已放行（系统/其它软件）」那种不是我们建的，我们也不会去删别人的规则，
        // 所以它不参与这两个动作的启用判断。
        var isWhitelistedByUs = hasPath && _whitelistedPaths.Contains(item!.ProcessPath);

        _blockButton.Enabled = canBlock;
        _allowButton.Enabled = canAllow;
        _menuBlock.Enabled = canBlock;
        _menuAllow.Enabled = canAllow;
        _menuCopyPath.Enabled = hasPath;

        // 白名单按钮/菜单项：文字跟着选中行走，两个菜单项按状态各自启用。
        _whitelistButton.Enabled = hasPath;
        _whitelistButton.Text = isWhitelistedByUs ? "移出白名单" : "加入白名单";
        _menuWhitelistAdd.Enabled = hasPath && !isWhitelistedByUs;
        _menuWhitelistRemove.Enabled = isWhitelistedByUs;

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

        // 白名单状态放在提示里，因为「放行」列只显示得下短文本。
        var whitelist = item.Whitelist switch
        {
            WhitelistState.Ours => "白名单：已放行",
            WhitelistState.OtherSource => "白名单：未放行（但系统或其它软件的规则放行了它）",
            _ => "白名单：未放行",
        };

        // 签名是「按程序」的属性，放在这里显示比在每一行重复一列更省地方。
        var signature = string.IsNullOrEmpty(item.SignatureText) ? "" : $"　签名：{item.SignatureText}";

        return $"已选中 {item.ProcessName}（共 {connectionCount} 条连接）—— 当前状态：{state}；{whitelist}{signature}";
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
            // 这是「不点任何列排序」时的默认顺序。
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

            // 扫描结果存**全集**；显示列表由它按「当前搜索词 + 当前排序」推出来。
            _scannedConnections.Clear();
            _scannedConnections.AddRange(connections);
            RebuildView();

            _lastScanTime = DateTime.Now;

            // 用上面抓好的 selectedKey 重绑，绝对不能在这之后再重新抓一次。
            RebindGrid(selectedKey);
            UpdateSummary();

            // 列表已经显示出来了，签名在后台慢慢补。
            // 放最后调用是为了不让它拖慢"列表出现"这件事。
            _ = CheckSignaturesAsync();

            // 归属信息同样在后台补：Request 立即返回，不阻塞界面。
            RequestOwnershipForVisibleConnections();
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
    // 数字签名
    // ==================================================================

    /// <summary>
    /// 在后台把当前这批连接的签名补齐，补完再刷新一次表格。
    ///
    /// 为什么不跟扫描放在同一步：目录签名验证要把**整个文件哈希一遍**，
    /// 实测首次要 87 ms（加上证书链验证），几十个程序加起来界面会明显卡住。
    /// 所以列表先出来（签名列暂时是空的），结果随后补上。
    /// </summary>
    private async Task CheckSignaturesAsync()
    {
        if (_isCheckingSignatures)
        {
            return;
        }

        _isCheckingSignatures = true;

        try
        {
            var mode = _revocationMode;

            // 选中状态要在界面线程上先抓下来 —— 重绑表格会清空选中，
            // 抓晚了（比如 await 之后）用户的选择就丢了。
            var selectedKey = CaptureSelection();

            // 在界面线程上先做快照。
            // 不能在后台线程里直接遍历 _connections —— 界面线程每 3 秒就会
            // Clear + AddRange 一次，两个线程同时动同一个 List 会出问题。
            //
            // 这里用**扫描结果全集**而不是显示列表：这样搜索条件变化后新露出来的行
            // 也已经带着签名结论，不会出现「刚显示出来还是空的、过几秒才补上」。
            var items = _scannedConnections
                .Where(item => !string.IsNullOrEmpty(item.ProcessPath))
                .ToArray();

            if (items.Length == 0)
            {
                return;
            }

            await Task.Run(() =>
            {
                foreach (var item in items)
                {
                    // Check 内部有缓存，所以只有「第一次见到的程序」才会真的去验证。
                    item.Signature = DigitalSignature.Check(item.ProcessPath, mode);
                }
            });

            if (IsDisposed || Disposing)
            {
                return;
            }

            RebindGrid(selectedKey);
        }
        catch (Exception ex)
        {
            LocalLog.Error("检查数字签名失败", ex);
        }
        finally
        {
            _isCheckingSignatures = false;
        }
    }

    /// <summary>
    /// 用户切换了「检查证书吊销状态」。
    ///
    /// 切换后必须清空缓存重新判定 —— 两种模式下「证书是否被吊销」的结论可能不一样，
    /// 不清缓存就会把上一轮的结论继续显示出来，等于开关没生效。
    /// </summary>
    private void OnRevocationModeChanged(object? sender, EventArgs e)
    {
        _revocationMode = _checkRevocationCheckBox.Checked
            ? RevocationMode.Online
            : RevocationMode.CacheOnly;

        DigitalSignature.ClearCache();

        LocalLog.Info(_revocationMode == RevocationMode.Online
            ? "已开启证书吊销检查：Windows 证书服务会联网查询 CA 服务器。"
            : "已关闭证书吊销检查：只读本地缓存，本程序完全不留网络流量。");

        _ = CheckSignaturesAsync();
    }

    // ==================================================================
    // IP 归属查询
    //
    // 界面这一层的分工很明确：
    //   它只负责「要查哪些地址」和「把结果挂到表格上」；
    //   真正的联网在 Core/IpOwnershipLookup.cs（唯一联网出口），
    //   排队/缓存/后台调度在 Core/IpOwnershipService.cs。
    // 这里绝不直接碰网络 —— 这样「程序会不会偷偷联网」只需要审那两个文件。
    // ==================================================================

    /// <summary>
    /// 把缓存里已有的归属信息填到连接项上。
    ///
    /// 只在界面线程调用，而且只读内存缓存 —— 不联网、不阻塞。
    /// 真正确立结论的后台查询在 <see cref="IpOwnershipService"/> 里。
    /// </summary>
    private void ApplyOwnership()
    {
        var enabled = _ipOwnershipService.IsEnabled;

        foreach (var item in _connections)
        {
            if (!enabled)
            {
                // 功能关闭时一律不显示归属 —— 让「关闭」这件事在观感上也是干净的。
                item.IpOwnership = IpOwnershipInfo.None;
                continue;
            }

            if (!IpOwnershipLookup.IsQueryable(item.RemoteAddress))
            {
                // 私有 / 回环地址：明确告诉用户「没有往外查」，
                // 而不是留一片空白让人以为功能坏了。
                item.IpOwnership = IpOwnershipInfo.LocalOnly;
                continue;
            }

            var key = IpOwnershipLookup.ToKey(item.RemoteAddress);
            item.IpOwnership = _ipOwnershipService.TryGet(key, out var info)
                ? info
                : IpOwnershipInfo.None;
        }
    }

    /// <summary>
    /// 把归属提示挂到「远程 IP」列上。
    /// 空字符串会让单元格不显示提示，所以不需要额外清除逻辑。
    /// </summary>
    private void RefreshOwnershipTooltips()
    {
        // 用列名定位而不是硬编码索引，列顺序变了也不会挂错格子。
        var columnIndex = _connectionGrid.Columns[nameof(TcpConnectionItem.RemoteAddressText)]?.Index ?? -1;
        if (columnIndex < 0)
        {
            return;
        }

        foreach (DataGridViewRow row in _connectionGrid.Rows)
        {
            if (row.DataBoundItem is not TcpConnectionItem item)
            {
                continue;
            }

            row.Cells[columnIndex].ToolTipText = item.IpOwnershipTooltip;
        }
    }

    /// <summary>
    /// 请后台把当前列表里的远程地址查一遍归属。
    /// 入参在这里就做成快照 —— 后台线程绝不能去遍历界面线程每 3 秒就会改一次的集合。
    /// </summary>
    private void RequestOwnershipForVisibleConnections()
    {
        if (!_ipOwnershipService.IsEnabled)
        {
            return;
        }

        var addresses = _connections.Select(item => item.RemoteAddress).ToArray();
        _ipOwnershipService.Request(addresses);
    }

    /// <summary>
    /// 后台查完一批归属后的回调。
    ///
    /// 注意：**这个方法在后台线程上被调用**，所以第一件事就是切回界面线程，
    /// 绝不能在这里直接碰控件。
    /// </summary>
    private void OnOwnershipResultsUpdated(IReadOnlyDictionary<string, IpOwnershipInfo> results)
    {
        if (IsDisposed || Disposing || !IsHandleCreated)
        {
            return;
        }

        try
        {
            BeginInvoke(() =>
            {
                if (IsDisposed || Disposing)
                {
                    return;
                }

                ApplyOwnership();

                // 只重挂悬停提示，不做整表重绑 ——
                // 归属信息不影响行底色，重绑反而会让用户的选中闪一下。
                RefreshOwnershipTooltips();
            });
        }
        catch (InvalidOperationException)
        {
            // 窗口正在销毁、句柄已失效。丢掉这一次刷新即可，不需要报错。
        }
    }

    /// <summary>
    /// 用户切换了「查询 IP 归属」。
    ///
    /// 三件事缺一不可：
    ///   1. 落盘 —— 否则重启后用户的「关闭」会被静默回滚（这正是加 settings.json 的原因）；
    ///   2. 立刻作用于调度器 —— 关闭之后不能再有任何网络请求；
    ///   3. 刷新界面 —— 关闭时清掉已显示的归属，开启时立刻补查。
    /// </summary>
    private void OnIpOwnershipChanged(object? sender, EventArgs e)
    {
        if (_loadingSettings)
        {
            // 启动时把设置填到控件上，不是用户操作。
            return;
        }

        var enabled = _checkIpOwnershipCheckBox.Checked;

        _settings.IpOwnershipEnabled = enabled;
        _settings.Save();

        _ipOwnershipService.IsEnabled = enabled;

        LocalLog.Info(enabled
            ? $"已开启 IP 归属查询：会把远程 IP 发送到 {AppConstants.OwnershipLookupHost}:{AppConstants.OwnershipLookupPort} 查询归属。"
            : "已关闭 IP 归属查询：此后不再产生任何相关网络请求。");

        ApplyOwnership();
        RefreshOwnershipTooltips();

        if (enabled)
        {
            // 先讲清楚会发生什么，再开始查。
            ShowIpOwnershipNoticeIfNeeded();
            RequestOwnershipForVisibleConnections();
        }
    }

    /// <summary>
    /// IP 归属查询的一次性告知。
    ///
    /// 为什么要有它：这个功能**默认开启**，也就是第一次运行就会把远程 IP 发到外部服务。
    /// 项目对「会对外通信的行为」要求透明可见，所以必须主动说一次，
    /// 而不是把说明埋在设置页里让用户自己去发现。
    /// 告知过就记进 settings.json，不再重复打扰。
    /// </summary>
    private void ShowIpOwnershipNoticeIfNeeded()
    {
        // 功能关闭时不弹 —— 那时「默认会联网」这句话对用户来说是错的。
        if (_settings.IpOwnershipNoticeShown || !_ipOwnershipService.IsEnabled)
        {
            return;
        }

        _settings.IpOwnershipNoticeShown = true;
        _settings.Save();

        MessageBox.Show(
            DialogOwner,
            BuildIpOwnershipNoticeText(),
            AppConstants.AppName,
            MessageBoxButtons.OK,
            MessageBoxIcon.Information);
    }

    /// <summary>
    /// 一次性告知的正文。
    ///
    /// 单独抽成一个方法，是为了让这段文案**可以被断言**：
    /// 模态对话框在无头环境里没法自动点掉，但「它到底说了什么」必须能验。
    /// </summary>
    private static string BuildIpOwnershipNoticeText()
        // 注意：MessageBox 不解析 Markdown，不要写 ** 之类的标记，会原样显示。
        => "WinAppGuard 会查询每条连接的目标归属，让你一眼看出「这个连接在跟谁通信」。\n\n" +
           $"为此它会把远程 IP 发送到外部服务 {AppConstants.OwnershipLookupHost}" +
           $"（端口 {AppConstants.OwnershipLookupPort}）。\n\n" +
           "只会发送远程 IP：不会发送进程名、程序路径、端口，也不会发送局域网和本机地址。\n\n" +
           "不想要的话，可以在「设置 → 数据与隐私」里取消勾选「查询 IP 归属」，" +
           "之后不会有任何相关网络请求。";

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
                "要恢复它，请到「规则」页操作。",
            },
            confirmText: "阻止联网",
            offerDuration: true,
            out var chosenExpiry);

        if (!confirmed)
        {
            return;
        }

        try
        {
            var createdRuleName = FirewallManager.CreateBlockRule(item.ProcessPath, chosenExpiry);

            LocalLog.Operation(
                $"阻止联网：{item.ProcessPath}（规则 {createdRuleName}，时长：{chosenExpiry.DescribeSchedule()}）");

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

    /// <summary>「规则」页：允许选中的规则对应的程序联网。</summary>
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

    // ==================================================================
    // 严格模式白名单（加入 / 移出）
    //
    // 为什么需要这两个动作：严格模式下"没被阻止"**不再等于**"能上网" ——
    // 必须有一条允许规则（白名单）才能出网。所以放行是一个**独立的用户动作**，
    // 不能和"允许程序联网"（= 删掉我们的阻止规则）混为一谈。
    // ==================================================================

    /// <summary>
    /// 工具栏那个白名单按钮：文字会跟着选中行变（加入 / 移出），
    /// 所以点击时要**重新看一眼当前状态**再决定做什么，
    /// 不能依赖按钮上的文字（那可能是上一次刷新时设的）。
    /// </summary>
    private void OnWhitelistButtonClick(object? sender, EventArgs e)
    {
        var item = GetConfirmedConnection();
        if (item is null || string.IsNullOrEmpty(item.ProcessPath))
        {
            return;
        }

        if (_whitelistedPaths.Contains(item.ProcessPath))
        {
            RemoveFromWhitelist(item.ProcessPath, item.ProcessName);
        }
        else
        {
            AddToWhitelist(item.ProcessPath, item.ProcessName);
        }
    }

    private void OnWhitelistAddClick(object? sender, EventArgs e)
    {
        var item = GetConfirmedConnection();
        if (item is null || string.IsNullOrEmpty(item.ProcessPath))
        {
            return;
        }

        AddToWhitelist(item.ProcessPath, item.ProcessName);
    }

    private void OnWhitelistRemoveClick(object? sender, EventArgs e)
    {
        var item = GetConfirmedConnection();
        if (item is null || string.IsNullOrEmpty(item.ProcessPath))
        {
            return;
        }

        RemoveFromWhitelist(item.ProcessPath, item.ProcessName);
    }

    /// <summary>把程序加入白名单 —— 为它建一条「允许出站」的防火墙规则。</summary>
    private void AddToWhitelist(string programPath, string programName)
    {
        var ruleName = FirewallManager.BuildAllowRuleName(programPath);

        var warnings = new List<string>
        {
            $"会创建一条「允许出站」的防火墙规则：{ruleName}",
            "严格模式生效时，只有加了白名单的程序才能上网；没加的一律上不了网。",
            "放行不会影响其它程序，也永远不会把谁锁在外面。",
            "「规则」页里能看到这条规则，随时可以删掉（那就是移出白名单）。",
        };

        if (!StrictModeManager.IsEnabled)
        {
            // 如实说明：严格模式没开时，这条规则暂时不改变什么。
            // 但**仍然允许**现在加 —— 「先加白名单、再开严格模式」正是推荐的用法。
            warnings.Add("注意：严格模式当前没开，所以这条规则暂时不改变什么；开启严格模式后它才会生效。");
        }

        var confirmed = ConfirmForm.Show(
            owner: DialogOwner,
            title: "加入白名单",
            question: $"确定要把「{programName}」加入白名单吗？",
            details: new[]
            {
                new KeyValuePair<string, string>("程序名", programName),
                new KeyValuePair<string, string>("完整路径", programPath),
                new KeyValuePair<string, string>("将创建规则", ruleName),
            },
            warnings: warnings.ToArray(),
            confirmText: "加入白名单");

        if (!confirmed)
        {
            return;
        }

        try
        {
            var created = FirewallManager.CreateAllowRule(programPath);
            LocalLog.Operation($"加入白名单：{programPath}（规则 {created}）");
            AfterRulesChanged();
        }
        catch (Exception ex)
        {
            ShowError("加入白名单失败", ex);
        }
    }

    /// <summary>
    /// 把程序移出白名单 —— 删掉**本工具为它建的那条**允许规则。
    ///
    /// 只会删以 AppGuard_Allow_ 开头、且属于这个程序的那一条：
    /// 别人的规则我们碰都不碰（<see cref="FirewallManager.DeleteRule"/> 在底层就会拒）。
    /// </summary>
    private void RemoveFromWhitelist(string programPath, string programName)
    {
        var ruleName = FirewallManager.BuildAllowRuleName(programPath);

        var warnings = new List<string>
        {
            $"会删掉这条「允许出站」规则：{ruleName}",
        };

        if (StrictModeManager.IsEnabled)
        {
            // 这句必须在严格模式下说清楚：删掉白名单和"允许联网"是**相反**的效果。
            warnings.Add("⚠ 严格模式正在生效：删掉之后这个程序会立刻上不了网（新连接会被拦）。");
        }
        else
        {
            warnings.Add("严格模式当前没开，所以删掉它暂时不改变什么。");
        }

        warnings.Add("只会删掉这一条规则，其它规则不受影响。");

        var confirmed = ConfirmForm.Show(
            owner: DialogOwner,
            title: "移出白名单",
            question: $"确定要把「{programName}」移出白名单吗？",
            details: new[]
            {
                new KeyValuePair<string, string>("程序名", programName),
                new KeyValuePair<string, string>("完整路径", programPath),
                new KeyValuePair<string, string>("将删除规则", ruleName),
            },
            warnings: warnings.ToArray(),
            confirmText: "移出白名单");

        if (!confirmed)
        {
            return;
        }

        try
        {
            var deleted = FirewallManager.DeleteRule(ruleName);

            if (!deleted)
            {
                // 规则已经不在了（可能在别处删过），缓存过期。同步一次再说。
                AfterRulesChanged();
                MessageBox.Show(
                    this,
                    $"「{programName}」的白名单规则已经不在了（可能已在别处删掉）。\n\n已重新同步防火墙规则状态。",
                    AppConstants.AppName,
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
                return;
            }

            LocalLog.Operation($"移出白名单：{programPath}（规则 {ruleName}）");
            AfterRulesChanged();
        }
        catch (Exception ex)
        {
            ShowError("移出白名单失败", ex);
        }
    }

    /// <summary>「规则」页：只删除选中的那一条规则。</summary>
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
            warnings: rule.Action == FirewallAction.Allow
                ? new[]
                {
                    StrictModeManager.IsEnabled
                        ? "⚠ 严格模式正在生效：删掉这条「允许」规则之后，该程序会立刻上不了网（新连接会被拦）。"
                        : "这是一条「允许」规则（白名单）。严格模式当前没开，所以删掉它暂时不改变什么。",
                    "只会删除这一条规则，其他规则不受影响。",
                }
                : new[]
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
    /// 「规则」页：删除全部 AppGuard 规则。
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

        // 严格模式生效时，这一步会把**白名单一起删光** —— 那等于把所有程序都断网。
        // 所以必须同时关闭严格模式（还原默认放行）。这件事必须写在确认框里，
        // 不能在代码里悄悄做。
        var strictModeEnabled = StrictModeManager.IsEnabled;

        var deleteWarnings = new List<string>
        {
            "将要删除的规则如下：",
            ruleList,
            "其他软件和系统自带的防火墙规则一律不受影响。",
        };

        if (strictModeEnabled)
        {
            deleteWarnings.Insert(0, "⚠ 严格模式正在生效：下面这些规则里有白名单，删光之后所有程序都上不了网。");
            deleteWarnings.Insert(1, "所以这一步会同时关闭严格模式（把默认出站动作还原成「允许」）。");
        }

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
            warnings: deleteWarnings.ToArray(),
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
            }.Concat(strictModeEnabled
                ? new[] { "⚠ 严格模式会同时被关闭（默认出站动作还原成「允许」），因为白名单马上就不在了。" }
                : Array.Empty<string>()).ToArray(),
            confirmText: "确认删除");

        if (!secondConfirmed)
        {
            return;
        }

        try
        {
            // ⚠ 顺序不能反：**先**关严格模式（还原默认放行），**再**删规则。
            // 反过来的话，中间那一瞬间是「默认阻止 + 白名单已被删光」= 整台机器断网。
            if (strictModeEnabled)
            {
                var disableResult = StrictModeManager.Disable();
                LocalLog.Operation($"删除全部规则前先关闭严格模式：{disableResult.Message}");
            }

            var deleted = FirewallManager.DeleteAllAppGuardRules();
            LocalLog.Operation($"删除全部 AppGuard 规则：实际删除 {deleted} 条");
            AfterRulesChanged();
            RefreshStrictModeStatus();

            MessageBox.Show(
                this,
                $"已删除 {deleted} 条 AppGuard 规则。\n\n" +
                "其他软件和系统自带的防火墙规则没有受到影响。" +
                (strictModeEnabled
                    ? "\n\n严格模式已同时关闭，默认出站动作已还原成「允许」。"
                    : string.Empty),
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
        // 顺手检查一次到期的临时阻断（产品负责人定的时机之一）。
        // 它自己在后台线程跑，不会拖慢这次刷新。
        CheckExpiredBlocksAsync();

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

    // ==================================================================
    // 搜索（只过滤当前扫描结果，不重新扫描）
    // ==================================================================

    /// <summary>
    /// 搜索框内容变化 —— 立刻按新关键词重滤一遍。
    ///
    /// 注意这里**不重新扫描**：扫描结果已经在 _scannedConnections 里，
    /// 只需要重新过滤 + 重绑。几百行数据在内存里过滤是微秒级的，
    /// 所以每敲一个字都来得及。
    /// </summary>
    private void OnSearchTextChanged(object? sender, EventArgs e)
    {
        var keyword = _searchBox.Text;

        // 文本没变就不用做事（Clear() 之类也会触发这个事件）。
        if (string.Equals(keyword, _searchKeyword, StringComparison.Ordinal))
        {
            return;
        }

        _searchKeyword = keyword;

        // 顺序仍然是「先抓选中 → 再换数据 → 最后重绑」，不能反（见 RebindGrid 的说明）。
        var selectedKey = CaptureSelection();
        RebuildView();
        RebindGrid(selectedKey);
        UpdateSummary();

        // 过滤后新露出来的地址可能还没查过归属，补一次请求（内部会去重，不会重复查）。
        RequestOwnershipForVisibleConnections();
    }

    /// <summary>在搜索框里按 Esc 清空。</summary>
    private void OnSearchBoxKeyDown(object? sender, KeyEventArgs e)
    {
        if (e.KeyCode != Keys.Escape)
        {
            return;
        }

        // 别让 Esc 继续冒泡（否则可能被窗体当成「关闭」之类处理）。
        e.Handled = true;
        e.SuppressKeyPress = true;
        ClearSearch();
    }

    private void OnClearSearchClick(object? sender, EventArgs e) => ClearSearch();

    /// <summary>
    /// 清空搜索并立刻恢复完整列表。
    ///
    /// 这里刻意不直接改 _searchKeyword，而是交给 TextChanged 去处理 ——
    /// 只留一条路径，避免「两处各自重建一次」这种重复刷新。
    /// </summary>
    private void ClearSearch()
    {
        if (_searchBox.Text.Length == 0)
        {
            return;
        }

        _searchBox.Clear();
        _searchBox.Focus();
    }

    // ==================================================================
    // 按列排序
    //
    // 排序**由我们自己算**（ConnectionFilter），不交给 DataGridView：
    //   表格绑的是 BindingSource + List<T>，不支持 IBindingList 排序；
    //   而且每 3 秒重绑一次会把控件自己的排序冲掉。
    // 控件只负责把那个小箭头画出来（SortMode = Programmatic）。
    // ==================================================================

    /// <summary>
    /// 用户点了表头。
    ///
    /// 行为：点同一列 → 切换升降序；点另一列 → 该列升序（箭头跟着挪过去）。
    /// </summary>
    private void OnConnectionGridColumnHeaderMouseClick(object? sender, DataGridViewCellMouseEventArgs e)
    {
        // 刚刚那一下如果是「拖列宽」（在分隔线上按下并松开），就不是点表头排序，
        // 必须吃掉，否则拖完列宽会顺手把排序也切了。
        if (_columnResizer.ConsumeHeaderClickSuppression())
        {
            return;
        }

        if (e.ColumnIndex < 0 || e.ColumnIndex >= _connectionGrid.Columns.Count)
        {
            return;
        }

        var target = ColumnToSortColumn(_connectionGrid.Columns[e.ColumnIndex].Name);
        if (target == ConnectionSortColumn.None)
        {
            // 这一列没开排序（例如「程序路径」「数字签名」）。
            return;
        }

        if (_sortColumn == target)
        {
            _sortAscending = !_sortAscending;
        }
        else
        {
            _sortColumn = target;
            _sortAscending = true;
        }

        // 顺序照旧：先抓选中 → 再重建显示列表 → 最后重绑。
        var selectedKey = CaptureSelection();
        RebuildView();
        RebindGrid(selectedKey);
    }

    /// <summary>列名（= 绑定的属性名）→ 排序列；不支持的列返回 None。</summary>
    private static ConnectionSortColumn ColumnToSortColumn(string? columnName) => columnName switch
    {
        nameof(TcpConnectionItem.ProcessName) => ConnectionSortColumn.ProcessName,
        nameof(TcpConnectionItem.Pid) => ConnectionSortColumn.Pid,
        nameof(TcpConnectionItem.LocalPortText) => ConnectionSortColumn.LocalPort,
        nameof(TcpConnectionItem.RemoteAddressText) => ConnectionSortColumn.RemoteAddress,
        nameof(TcpConnectionItem.RemotePortText) => ConnectionSortColumn.RemotePort,
        nameof(TcpConnectionItem.StateText) => ConnectionSortColumn.State,
        _ => ConnectionSortColumn.None,
    };

    /// <summary>排序列 → 列名（用来把箭头画到正确的列上）。</summary>
    private static string? SortColumnToColumnName(ConnectionSortColumn column) => column switch
    {
        ConnectionSortColumn.ProcessName => nameof(TcpConnectionItem.ProcessName),
        ConnectionSortColumn.Pid => nameof(TcpConnectionItem.Pid),
        ConnectionSortColumn.LocalPort => nameof(TcpConnectionItem.LocalPortText),
        ConnectionSortColumn.RemoteAddress => nameof(TcpConnectionItem.RemoteAddressText),
        ConnectionSortColumn.RemotePort => nameof(TcpConnectionItem.RemotePortText),
        ConnectionSortColumn.State => nameof(TcpConnectionItem.StateText),
        _ => null,
    };

    /// <summary>
    /// 更新表头上的排序箭头。
    ///
    /// 既然控件自带的排序被关掉了（Programmatic），箭头也得自己画 ——
    /// 否则用户点了表头会觉得「毫无反应」，不知道到底排了没有。
    /// </summary>
    private void UpdateSortGlyphs()
    {
        foreach (DataGridViewColumn column in _connectionGrid.Columns)
        {
            column.HeaderCell.SortGlyphDirection = SortOrder.None;
        }

        var name = SortColumnToColumnName(_sortColumn);
        if (name is null)
        {
            return;
        }

        if (_connectionGrid.Columns[name] is { } target)
        {
            target.HeaderCell.SortGlyphDirection = _sortAscending ? SortOrder.Ascending : SortOrder.Descending;
        }
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

    /// <summary>「规则」表格：用户主动点了某一行。</summary>
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

    /// <summary>「规则」表格：用键盘移动。</summary>
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

            if (ReferenceEquals(_tabControl.SelectedTab, _tabConnections))
            {
                // 切回本页时刷一次白名单状态：别的软件也可能在后台改自己的允许规则，
                // 而这件事**只**影响这一页的显示（规则页看的是我们自己的规则）。
                RefreshAllowTargets();
                RebindGrid(CaptureSelection());
            }

            if (!_ruleSelectionConfirmed && ReferenceEquals(_tabControl.SelectedTab, _tabRules))
            {
                _rulesGrid.CurrentCell = null;
            }

            if (ReferenceEquals(_tabControl.SelectedTab, _tabSettings))
            {
                // 切到设置页时刷一次严格模式状态：用户可能刚在 wf.msc 里手工改过默认动作，
                // 界面必须跟着说实话，不能一直显示内存里那个旧状态。
                RefreshAllowTargets();
                RefreshStrictModeStatus();
                LayoutSettingsSections();
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

        // 开机自启起来的实例，一次性告知会推迟到用户第一次打开窗口时再弹。
        BeginInvoke(ShowIpOwnershipNoticeIfNeeded);
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

        // 说明类文字要跟着可视宽度重新换行。
        // 不设的话，窗口变窄时这些文字会一直保持旧宽度，右边被裁掉。
        _settingsNoticeLabel.MaximumSize = new Size(width - 20, 0);
        _privacyLabel.MaximumSize = new Size(width - 60, 0);
        _strictModeDetailLabel.MaximumSize = new Size(width - 60, 0);

        _autostartPanel.Width = width;
        _privacyPanel.Width = width;
        _strictModePanel.Width = width;
        _taskXmlPanel.Width = width;
    }

    // ==================================================================
    // 严格模式（设置页）
    //
    // 这是本工具**唯一**会修改全局防火墙策略的功能，所以这一块代码的规矩是：
    //   1. 开启前必须二次确认，并且**如实列出**会影响哪些程序；
    //   2. 状态显示一律**以实际读回来的值为准**，不信内存里的标志
    //      （用户可能在 wf.msc 里手工改过，那就得让状态文字跟着变）；
    //   3. 每个出口都留了"恢复默认放行"的路（还有启动兜底，见 StrictModeManager）。
    // ==================================================================

    /// <summary>本工具自己现在是否在白名单里（用界面缓存，不重新枚举全部规则）。</summary>
    private bool SelfIsWhitelisted()
    {
        var selfPath = Environment.ProcessPath;
        return !string.IsNullOrEmpty(selfPath) && _whitelistedPaths.Contains(selfPath);
    }

    private void OnRefreshStrictModeClick(object? sender, EventArgs e)
    {
        RefreshAllowTargets();
        RefreshStrictModeStatus();
    }

    /// <summary>
    /// 生成严格模式说明文字。
    ///
    /// **纯函数**：不读防火墙、不改任何东西 —— 所以界面自检可以直接拿它来断言
    /// "该说清的都说了"（这类"如实说明"的文字一旦被改掉，必须有人立刻发现）。
    /// </summary>
    /// <param name="enabled">严格模式当前是否生效。</param>
    /// <param name="actual">**实际读回来**的三套配置文件默认出站动作。</param>
    private string BuildStrictModeDetailText(bool enabled, OutboundDefaultState actual)
    {
        var lines = new List<string>();

        if (enabled)
        {
            lines.Add("现在：只有白名单里的程序能上网，其它程序的新连接会被拦掉。");
            lines.Add("程序退出（或崩溃后下次启动）时会自动还原 —— 严格模式是「会话级」的。");
        }
        else
        {
            lines.Add("开启后：所有没加白名单的程序都上不了网（新连接会被拦掉），只放行白名单。");
            lines.Add("它改的是 Windows 的「默认出站动作」，三套网络配置文件一起改。");
            lines.Add("这是本工具唯一会修改全局防火墙策略的地方。它是「会话级」的：" +
                      "程序退出（或崩溃后下次启动）时会自动还原。");
        }

        lines.Add(string.Empty);

        lines.Add($"本工具白名单：{_whitelistedPaths.Count} 个程序" +
                  (SelfIsWhitelisted() ? "（含本工具自己，否则它查不了 IP 归属）" : string.Empty));
        lines.Add($"系统/其它软件为具体程序建的允许规则：{_otherAllowPaths.Count} 个程序" +
                  "（严格模式挡不住这些 —— 本工具不碰别人的规则，只能如实显示）");
        lines.Add($"另有 {_programlessAllowRuleCount} 条「不限程序」的允许规则（系统自带的多是这类），" +
                  "它们也会放行一部分流量。");

        lines.Add(string.Empty);

        if (!enabled && !actual.AllAllowed)
        {
            lines.Add($"⚠ 现在不能开启：三套配置文件的默认出站动作是 {actual.Describe()}，" +
                      "不是全部「允许」。这说明机器上已经有别的「默认阻止出站」策略" +
                      "（可能是别的安全软件），本工具不会去覆盖它。");
        }
        else
        {
            lines.Add($"三套配置文件的默认出站动作：{actual.Describe()}");
        }

        return string.Join(Environment.NewLine, lines);
    }

    /// <summary>
    /// 刷新严格模式分区：状态文字、说明文字、按钮文字。
    ///
    /// 状态一律**实际读回来**，不只看内存标志 —— 严格模式改的是系统级设置，
    /// 用户在 wf.msc 里改过之后，界面必须跟着说实话。
    /// </summary>
    private void RefreshStrictModeStatus()
    {
        try
        {
            var actual = FirewallManager.GetOutboundDefaultAllowed();
            var enabled = StrictModeManager.IsEnabled;

            _strictModeStatusLabel.Text = enabled
                ? "当前状态：严格模式生效中（本次会话）"
                : "当前状态：未开启，默认放行";

            _strictModeToggleButton.Text = enabled ? "恢复默认放行" : "开启严格模式…";

            // 没开、而且当前状态不是「三套全允许」时，开启必然会被拒绝（不能覆盖别人的策略），
            // 那就别让按钮看起来可点 —— 但说明里会写清"为什么不能开"。
            _strictModeToggleButton.Enabled = enabled || actual.AllAllowed;

            _strictModeDetailLabel.Text = BuildStrictModeDetailText(enabled, actual);
        }
        catch (Exception ex)
        {
            LocalLog.Error("刷新严格模式状态失败", ex);
            _strictModeStatusLabel.Text = "当前状态：读取失败（详见日志）";
        }
    }

    private void OnStrictModeToggleClick(object? sender, EventArgs e)
    {
        if (StrictModeManager.IsEnabled)
        {
            DisableStrictMode();
        }
        else
        {
            EnableStrictModeWithConfirmation();
        }
    }

    /// <summary>关闭严格模式。这是"安全方向"的操作，所以只要一次确认。</summary>
    private void DisableStrictMode()
    {
        var selfWasWhitelisted = SelfIsWhitelisted();

        var confirmed = ConfirmForm.Show(
            owner: DialogOwner,
            title: "恢复默认放行",
            question: "确定要关闭严格模式吗？",
            details: new[]
            {
                new KeyValuePair<string, string>("将要做的", "把三套配置文件的默认出站动作还原成「允许」"),
                new KeyValuePair<string, string>("影响", "所有程序恢复联网（白名单规则本身保留）"),
            },
            warnings: new[]
            {
                "严格模式本来就是「会话级」的：程序退出时也会自动还原，这一步只是提前做而已。",
                "白名单（AppGuard_Allow_ 规则）不会被删，下次开启严格模式时直接生效。",
                selfWasWhitelisted
                    ? "本程序自己那条由严格模式自动加的白名单规则会被删掉。"
                    : "本程序自己本来就在白名单里（是你自己加的），不会被删。",
            },
            confirmText: "恢复默认放行");

        if (!confirmed)
        {
            return;
        }

        try
        {
            var result = StrictModeManager.Disable();
            LocalLog.Operation($"严格模式已关闭：{result.Message}");

            AfterRulesChanged();
            RefreshStrictModeStatus();

            ShowTrayBalloon("严格模式已关闭", "默认出站动作已还原成「允许」，所有程序恢复联网。");
        }
        catch (Exception ex)
        {
            ShowError("关闭严格模式失败", ex);
            RefreshStrictModeStatus();
        }
    }

    /// <summary>
    /// 开启严格模式：**两次确认**。
    ///
    /// 为什么要两次：这一步会把"没有白名单的程序全部断网"，
    /// 而用户手上可能正开着浏览器、正连着 VPN。第一次讲清后果，
    /// 第二次把**会被影响的具体程序清单**摊开，让他有机会先去放行。
    /// </summary>
    private void EnableStrictModeWithConfirmation()
    {
        // 先把"会影响哪些程序"算出来 —— 两次确认都要用。
        var affected = BuildProgramsThatWillLoseAccess();

        const string howToWhitelist =
            "想先放行某些程序：取消这个对话框 → 到「联网连接」页选中它 → 右键「加入白名单」→ 再回来开启。";

        // ---------------- 第一次确认：讲清后果 ----------------
        var firstConfirmed = ConfirmForm.Show(
            owner: DialogOwner,
            title: "开启严格模式（第 1/2 步）",
            question: "开启后，没有加入白名单的程序将无法上网。确定继续吗？",
            details: new[]
            {
                new KeyValuePair<string, string>(
                    "将要做的", "把 Windows 的「默认出站动作」改成「阻止」（三套网络配置文件）"),
                new KeyValuePair<string, string>(
                    "将会放行", $"本工具白名单里的 {_whitelistedPaths.Count} 个程序"),
                new KeyValuePair<string, string>(
                    "会被影响", $"{affected.Count} 个正在联网、但没加白名单的程序"),
            },
            warnings: new[]
            {
                "这是本工具唯一会修改全局防火墙策略的地方。",
                "程序退出（或崩溃后下次启动）时会自动还原成「允许」—— 严格模式是会话级的。",
                "Windows 自带的允许规则、以及别的软件为某些程序建的允许规则仍然会放行；" +
                "本工具不碰别人的规则，所以严格模式不是绝对白名单。",
                howToWhitelist,
            },
            confirmText: "下一步");

        if (!firstConfirmed)
        {
            return;
        }

        // ---------------- 第二次确认：把清单摊开 ----------------
        var details = new List<KeyValuePair<string, string>>
        {
            new(
                "开启后会上不了网的程序",
                affected.Count == 0
                    ? "（没有 —— 当前联网的程序都已经在白名单里）"
                    : $"{affected.Count} 个"),
        };

        var warnings = new List<string>();

        if (affected.Count > 0)
        {
            warnings.Add("这些程序会立刻无法建立新的出站连接：");
            warnings.Add("    " + string.Join("、", affected.Take(20)));

            if (affected.Count > 20)
            {
                warnings.Add($"    …… 以及另外 {affected.Count - 20} 个");
            }

            warnings.Add("（已经连上的连接要等它自己断开，不会被立刻掐断。）");
            warnings.Add("注意：系统或其它软件的「不限程序」允许规则也会放行一部分流量，实际影响可能比这个清单小。");
        }

        warnings.Add(howToWhitelist);

        var secondConfirmed = ConfirmForm.Show(
            owner: DialogOwner,
            title: "开启严格模式（第 2/2 步）",
            question: "上面的清单确认过了吗？现在就开启吗？",
            details: details.ToArray(),
            warnings: warnings.ToArray(),
            confirmText: "确认开启");

        if (!secondConfirmed)
        {
            return;
        }

        try
        {
            var result = StrictModeManager.Enable();

            if (!result.Success)
            {
                // 例如：机器上已经有别人的「默认阻止出站」策略 —— 如实说明，不覆盖。
                MessageBox.Show(
                    this, result.Message, AppConstants.AppName, MessageBoxButtons.OK, MessageBoxIcon.Warning);
                RefreshStrictModeStatus();
                return;
            }

            LocalLog.Operation($"严格模式已开启：{result.Message}");

            // 规则变了（多了本程序自己那条白名单规则），两个页面都要跟上。
            AfterRulesChanged();
            RefreshStrictModeStatus();

            ShowTrayBalloon(
                "严格模式已开启",
                $"只有白名单里的 {_whitelistedPaths.Count} 个程序能上网，其它程序的新连接会被拦掉。" +
                "程序退出时会自动还原。");
        }
        catch (Exception ex)
        {
            ShowError("开启严格模式失败", ex);
            RefreshStrictModeStatus();
        }
    }

    /// <summary>
    /// 列出「开启严格模式后会上不了网」的程序：当前正在联网、拿得到路径、
    /// 且既不在我们的白名单里、也没有别的软件为它建过允许规则。
    ///
    /// 用**当前扫描到的连接**来算 —— 那是用户此刻屏幕上能看到的东西，
    /// 比去猜"这台机器装了哪些程序"可靠得多。
    /// </summary>
    private List<string> BuildProgramsThatWillLoseAccess()
    {
        var names = new List<string>();

        foreach (var item in _scannedConnections)
        {
            if (string.IsNullOrEmpty(item.ProcessPath)
                || _whitelistedPaths.Contains(item.ProcessPath)
                || _otherAllowPaths.Contains(item.ProcessPath))
            {
                continue;
            }

            names.Add(item.ProcessName);
        }

        return names
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(name => name, StringComparer.OrdinalIgnoreCase)
            .ToList();
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
