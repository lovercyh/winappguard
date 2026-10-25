using System.Diagnostics;
using System.Text;
using WinAppGuard.Contracts;
using WinAppGuard.Core;
using WinAppGuard.Core.ProtectedMode;
using WinAppGuard.Localization;
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

    /// <summary>3.5：服务端流量快照，按完整路径索引（程序已知时优先用这个）。</summary>
    private readonly Dictionary<string, TrafficDto> _trafficByPath =
        new(StringComparer.OrdinalIgnoreCase);

    /// <summary>3.5：服务端流量快照，按 PID 索引（只装拿不到路径的程序）。</summary>
    private readonly Dictionary<int, TrafficDto> _trafficByPid = new();

    /// <summary>3.5：服务是否支持 query.traffic（旧服务返回“未知命令”时隐藏三列）。</summary>
    private bool _trafficSupported = true;

    /// <summary>3.5：列可见性是否已经按服务能力设置过（避免每次刷新都碰控件）。</summary>
    private bool _trafficColumnVisibilityApplied;

    /// <summary>当前搜索关键词。空字符串表示不过滤。</summary>
    private string _searchKeyword = string.Empty;

    /// <summary>当前排序列（界面接线在 1.3-D；这里先由重建显示列表的逻辑使用）。</summary>
    private ConnectionSortColumn _sortColumn = ConnectionSortColumn.None;

    /// <summary>当前排序方向：true 为升序。</summary>
    private bool _sortAscending = true;

    /// <summary>上一次扫描完成的时刻，用于状态栏显示。</summary>
    private DateTime _lastScanTime = DateTime.MinValue;

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

    /// <summary>规则页的**筛选后**视图（绑定到表格）。<_rules> 始终是完整列表。</summary>
    private readonly List<FirewallRuleItem> _rulesView = new();

    /// <summary>规则页搜索词；空字符串表示不过滤。</summary>
    private string _rulesKeyword = string.Empty;

    /// <summary>规则摘要的"未筛选"版本，搜索时在它后面追加筛选结果数。</summary>
    private string _rulesSummaryBase = "规则共 0 条";

    /// <summary>规则列表的数据。同样只创建一次、原地更新，理由见 <see cref="_connections"/>。</summary>
    private readonly List<FirewallRuleItem> _rules = new();

    // ---------- 严格模式下白名单页的数据 ----------

    private readonly BindingSource _whitelistSource = new();

    /// <summary>白名单页的**筛选后**视图（绑定到表格）；<_whitelistRules> 始终是完整列表。</summary>
    private readonly List<FirewallRuleItem> _whitelistView = new();

    private readonly List<FirewallRuleItem> _whitelistRules = new();

    private string _whitelistKeyword = string.Empty;
    private string _whitelistSummaryBase = "白名单共 0 个程序";

    // ---------- 2.4：规则分组（3.0-b 起由服务持有，界面不再直接读写文件）----------

    /// <summary>服务是否可用（可用 = 规则页可读写；不可用 = 只读）。</summary>
    private bool _serviceAvailable;

    /// <summary>每 5 秒探测一次服务状态（独立于"自动刷新连接"，关掉那个也要能发现服务停了）。</summary>
    private System.Windows.Forms.Timer? _serviceProbeTimer;

    /// <summary>严格模式状态（由服务状态快照更新；3.0-c 起会话在服务里）。</summary>
    private bool _strictModeEnabled;

    /// <summary>严格模式当前放行的程序数（服务状态快照）。</summary>
    private int _strictModePermittedCount;

    /// <summary>3.5：当前严格模式是否由临时锁网建立（用于显示倒计时和到期提示）。</summary>
    private bool _lockdownActive;

    /// <summary>3.5：临时锁网到期时间（UTC，服务给的时间；界面只用来算倒计时）。</summary>
    private DateTime? _lockdownExpiresUtc;

    /// <summary>上次看到的"自动重建规则"计数（用于弹一次托盘提示）。-1 = 还没同步过。</summary>
    private int _lastTamperRebuilt = -1;

    /// <summary>上次看到的"到期自动解除"计数（用于弹一次托盘提示）。-1 = 还没同步过。</summary>
    private int _lastExpiredPurged = -1;

    /// <summary>本次运行是否已经尝试过"自动拉起服务"（只试一次，避免反复弹 UAC）。</summary>
    private bool _triedAutoStartService;

    /// <summary>黑名单页的原始提示文案（离线时会被替换，恢复后还原）。</summary>
    private string _rulesNoticeDefault = string.Empty;

    /// <summary>黑名单分组筛选：null = 全部；"" = 未分组；其它 = 具体分组。</summary>
    private string? _blockGroupFilter;

    /// <summary>白名单分组筛选，语义同上。</summary>
    private string? _allowGroupFilter;

    /// <summary>重建分组下拉框时抑制事件，避免来回触发筛选。</summary>
    private bool _suppressGroupFilterEvents;

    /// <summary>白名单页是否"用户真的点选过"某一行（理由同 <see cref="_ruleSelectionConfirmed"/>）。</summary>
    private bool _whitelistSelectionConfirmed;

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

    private ToolStripStatusLabel? _languageStatusLabel;
    private ContextMenuStrip? _languageMenu;

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

    /// <summary>窗口大小/位置与列宽（本机状态，存在 ui-state.json；不含任何隐私数据）。</summary>
    private UiState _uiState = new();

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
        SetupWhitelistGrid();
        InitializeAuditPage();
        InitializeDnsPage();

        // 3.2：把 Designer 里的中文静态文案换成英文（如果当前语言是英文）。
        ControlLocalizer.Apply(this);
        ControlLocalizer.ApplyTray(_trayMenu, _trayIcon);

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

            // 开机自启不会走 OnLoad：这里也要读一次状态并同步 AppliedLanguage，
            // 否则「自启后从未打开过窗口」时，CLI 永远读不到 GUI 已生效的语言。
            _uiState = UiState.Load();
            SyncAppliedLanguage();

            InitializeRuntime();
            return;
        }

        base.SetVisibleCore(value);
    }

    /// <summary>窗口加载完成后启动运行期逻辑。</summary>
    protected override void OnLoad(EventArgs e)
    {
        base.OnLoad(e);

        // 先恢复上次的窗口大小/列宽，再初始化运行期（首屏就是用户熟悉的样子）。
        RestoreUiState();

        SyncAppliedLanguage();

        Localizer.Initialize(_uiState.Language);
        LocalLog.English = Localizer.IsEnglish;
        ControlLocalizer.Apply(this);
        ControlLocalizer.ApplyTray(_trayMenu, _trayIcon);
        SetupLanguageSwitch();

        InitializeRuntime();
    }

    /// <summary>
    /// 3.3：把用户选择的语言记为「本次真正生效」，CLI 默认读这个值。
    /// 放在 OnLoad 与自启隐藏路径都会经过的地方，保证两种启动方式行为一致。
    /// </summary>
    private void SyncAppliedLanguage()
    {
        if (!string.Equals(
                _uiState.AppliedLanguage, _uiState.Language,
                StringComparison.OrdinalIgnoreCase))
        {
            _uiState.AppliedLanguage = _uiState.Language;
            _uiState.Save();
        }
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

        KeyDown += OnMainFormKeyDown;

        ShowRuntimeStatus();

        // 状态栏在"服务未运行"时是可点的：点一下启动服务（否则用户只能去装服务）。
        _serviceStatusLabel.Click += OnServiceStatusLabelClick;

        _rulesNoticeDefault = _rulesNoticeLabel.Text;

        // 探测防护服务（异步：服务没装/没起时不能拖慢启动）。
        ProbeServiceStatus();

        // 服务状态要持续更新：只探一次的话，服务停了界面会永远停在"运行中"。
        // 用独立定时器，不跟「每 3 秒自动刷新连接」绑在一起（那个可以被用户关掉）。
        if (!SuppressBackgroundServices)
        {
            _serviceProbeTimer = new System.Windows.Forms.Timer(components!)
            {
                Interval = 5000,
            };

            _serviceProbeTimer.Tick += (_, _) => ProbeServiceStatus();
            _serviceProbeTimer.Start();
        }

        // 把日志目录直接摆在界面上，用户不用去猜日志藏在哪。
        _logPathLabel.Text = LocalLog.LogDirectory;

        // 设置页的分区宽度是手动算的，先按当前尺寸摆一次。
        LayoutSettingsSections();

        // 到期清理、1.x 迁移、旧分组/审计设置迁移都归服务 / 安装器：
        // 3.0-c 起界面可能以普通权限运行，启动阶段不再触发任何写操作。

        // 先把防火墙规则读进来，这样第一屏就能正确显示「已阻止 / 未阻止」。
        // 放行状态（严格模式白名单）要在这之前读：它会让「放行」列第一屏就是对的。
        RefreshAllowTargets();
        RefreshRulesFromFirewall();

        // 严格模式会话在服务里：先同步取一次状态，避免第一屏把"正在生效"显示成"未开启"。
        if (_serviceAvailable)
        {
            var strictStatus = ServiceClient.TryGetStatus(TimeSpan.FromSeconds(2));

            if (strictStatus is not null)
            {
                _strictModeEnabled = strictStatus.StrictModeActive;
                _strictModePermittedCount = strictStatus.StrictModePermittedCount;
                _lockdownActive = strictStatus.StrictModeLockdownActive;
                _lockdownExpiresUtc = strictStatus.StrictModeLockdownExpiresUtc;

                // 顺带把审计设置/采集状态同步到记录页（服务是唯一来源）。
                ApplyAuditStatus(strictStatus);
            }
        }

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

        // 真正退出：停掉审计刷新定时器（采集在服务里，不随界面退出停止）。
        _auditTimer?.Stop();
        _auditTimer?.Dispose();
        _auditStore.Dispose();

        // 记住窗口位置/大小与列宽，下次打开还是原样（自检模式不写，免得污染本机状态）。
        CaptureAndSaveUiState();

        base.OnFormClosing(e);
    }

    // ==================================================================
    // 界面状态（窗口大小/位置、列宽）与快捷键
    // ==================================================================

    /// <summary>3.2：状态栏语言入口。切换保存后提示重启，避免运行中重排所有控件。</summary>
    private void SetupLanguageSwitch()
    {
        _languageStatusLabel = new ToolStripStatusLabel
        {
            IsLink = true,
            Margin = new Padding(8, 3, 0, 2),
        };

        _languageStatusLabel.Click += (_, _) => ShowLanguageMenu();
        _statusStrip.Items.Add(_languageStatusLabel);
        UpdateLanguageStatusLabel();
    }

    private void UpdateLanguageStatusLabel()
    {
        if (_languageStatusLabel is null)
        {
            return;
        }

        _languageStatusLabel.Text = Localizer.IsEnglish
            ? "Language: English"
            : "语言：简体中文";

        _languageStatusLabel.ToolTipText = Localizer.IsEnglish
            ? "Switch the GUI language (restart required)."
            : "切换界面语言（需要重启）。";
    }

    private void ShowLanguageMenu()
    {
        _languageMenu?.Dispose();
        _languageMenu = new ContextMenuStrip();

        var follow = new ToolStripMenuItem(
            Localizer.IsEnglish ? "Follow system" : "跟随系统")
        {
            Tag = "auto",
            Checked = _uiState.Language == "auto",
        };

        var chinese = new ToolStripMenuItem("简体中文")
        {
            Tag = "zh",
            Checked = _uiState.Language == "zh",
        };

        var english = new ToolStripMenuItem("English")
        {
            Tag = "en",
            Checked = _uiState.Language == "en",
        };

        foreach (var item in new[] { follow, chinese, english })
        {
            item.Click += (_, _) => SelectLanguage((string)item.Tag!);
            _languageMenu.Items.Add(item);
        }

        _languageMenu.Show(_statusStrip, new Point(
            Math.Max(0, _languageStatusLabel?.Bounds.Left ?? 0), -8));
    }

    private void SelectLanguage(string language)
    {
        if (_uiState.Language == language)
        {
            return;
        }

        _uiState.Language = language;
        _uiState.Save();

        // 立即按新语言更新“重启提示”的语言；其它控件等重启后再刷新。
        Localizer.Initialize(language);
        UpdateLanguageStatusLabel();

        var prompt = Localizer.IsEnglish
            ? "The language will take effect after WinAppGuard restarts.\n\nRestart now?"
            : "界面语言将在重启 WinAppGuard 后生效。\n\n现在重启吗？";

        var result = UiMessageBox.Show(
            prompt,
            AppConstants.AppName,
            MessageBoxButtons.YesNo,
            MessageBoxIcon.Question);

        if (result == DialogResult.Yes)
        {
            RestartForLanguage();
        }
    }

    private void RestartForLanguage()
    {
        var exe = Environment.ProcessPath;

        if (string.IsNullOrEmpty(exe))
        {
            UiMessageBox.Show(
                Localizer.IsEnglish
                    ? "Could not determine the executable path. Please restart manually."
                    : "无法确定程序路径，请手动重启。",
                AppConstants.AppName,
                MessageBoxButtons.OK,
                MessageBoxIcon.Warning);
            return;
        }

        try
        {
            // 必须先释放单实例互斥体，否则新进程会被旧进程挡掉。
            SingleInstance.Release();
            Process.Start(new ProcessStartInfo(exe) { UseShellExecute = true });
            _reallyExit = true;
            Application.Exit();
        }
        catch (Exception ex)
        {
            UiMessageBox.Show(
                (Localizer.IsEnglish
                    ? "Restart failed: "
                    : "重启失败：") + ex.Message,
                AppConstants.AppName,
                MessageBoxButtons.OK,
                MessageBoxIcon.Error);
        }
    }

    /// <summary>恢复上次的窗口位置/大小与列宽；没有记录或记录不可用就保持默认。</summary>
    private void RestoreUiState()
    {
        // 自检里固定用默认布局：否则开发机上保存过的窗口大小会让布局断言时好时坏。
        if (SuppressBackgroundServices)
        {
            return;
        }

        _uiState = UiState.Load();

        if (_uiState.HasUsableBounds())
        {
            StartPosition = FormStartPosition.Manual;
            Bounds = new Rectangle(_uiState.X, _uiState.Y, _uiState.Width, _uiState.Height);

            if (_uiState.Maximized)
            {
                WindowState = FormWindowState.Maximized;
            }
        }

        ApplyColumnWidths(_connectionGrid);
        ApplyColumnWidths(_rulesGrid);
        ApplyColumnWidths(_whitelistGrid);
    }

    /// <summary>把当前窗口位置/大小和两处列宽写回 ui-state.json。</summary>
    private void CaptureAndSaveUiState()
    {
        if (SuppressBackgroundServices)
        {
            return;
        }

        // 最大化时 Bounds 是屏幕大小，用户真正想要的"还原尺寸"在 RestoreBounds 里。
        var bounds = WindowState == FormWindowState.Normal ? Bounds : RestoreBounds;

        _uiState.X = bounds.X;
        _uiState.Y = bounds.Y;
        _uiState.Width = bounds.Width;
        _uiState.Height = bounds.Height;
        _uiState.Maximized = WindowState == FormWindowState.Maximized;

        CaptureColumnWidths(_connectionGrid);
        CaptureColumnWidths(_rulesGrid);
        CaptureColumnWidths(_whitelistGrid);

        _uiState.Save();
    }

    private void ApplyColumnWidths(DataGridView grid)
    {
        foreach (DataGridViewColumn column in grid.Columns)
        {
            // Fill 列的宽度由表格自己算，记下来也没用。
            if (column.AutoSizeMode == DataGridViewAutoSizeColumnMode.Fill)
            {
                continue;
            }

            if (_uiState.ColumnWidths.TryGetValue($"{grid.Name}.{column.Name}", out var width)
                && width >= column.MinimumWidth)
            {
                column.Width = width;
            }
        }
    }

    private void CaptureColumnWidths(DataGridView grid)
    {
        foreach (DataGridViewColumn column in grid.Columns)
        {
            if (column.AutoSizeMode == DataGridViewAutoSizeColumnMode.Fill)
            {
                continue;
            }

            _uiState.ColumnWidths[$"{grid.Name}.{column.Name}"] = column.Width;
        }
    }

    /// <summary>
    /// 全局快捷键（KeyPreview）：
    ///   F5        刷新当前页
    ///   Ctrl+F    跳到当前页的搜索框
    ///   Esc       清空当前页的搜索（光标不在输入框里时）
    ///   Delete    删除选中的规则（光标不在输入框里时；仍会弹确认框）
    /// </summary>
    private void OnMainFormKeyDown(object? sender, KeyEventArgs e)
    {
        if (e.KeyCode == Keys.F5)
        {
            e.Handled = true;
            e.SuppressKeyPress = true;

            if (_tabControl.SelectedTab == _tabAudit)
            {
                RefreshAudit();
            }
            else if (_tabControl.SelectedTab == _tabRules
                     || _tabControl.SelectedTab == _tabWhitelist)
            {
                OnRefreshRulesButtonClick(this, EventArgs.Empty);
            }
            else
            {
                OnRefreshButtonClick(this, EventArgs.Empty);
            }

            return;
        }

        if (e.Control && e.KeyCode == Keys.F)
        {
            e.Handled = true;
            e.SuppressKeyPress = true;

            var box = _tabControl.SelectedTab == _tabRules
                ? _rulesSearchBox
                : _tabControl.SelectedTab == _tabWhitelist
                    ? _whitelistSearchBox
                    : _tabControl.SelectedTab == _tabAudit
                        ? _auditSearchBox
                        : _searchBox;

            box.Focus();
            box.SelectAll();
            return;
        }

        // 下面两个键在输入框里必须保持原义（删字、取消输入）。
        if (ActiveControl is TextBoxBase)
        {
            return;
        }

        if (e.KeyCode == Keys.Escape)
        {
            if (_tabControl.SelectedTab == _tabRules && _rulesKeyword.Length > 0)
            {
                _rulesSearchBox.Clear();
                e.Handled = true;
            }
            else if (_tabControl.SelectedTab == _tabWhitelist && _whitelistKeyword.Length > 0)
            {
                _whitelistSearchBox.Clear();
                e.Handled = true;
            }
            else if (_tabControl.SelectedTab == _tabConnections && _searchKeyword.Length > 0)
            {
                ClearSearch();
                e.Handled = true;
            }

            return;
        }

        if (e.KeyCode == Keys.Delete && _tabControl.SelectedTab == _tabRules
            && _rulesDeleteButton.Enabled)
        {
            e.Handled = true;
            e.SuppressKeyPress = true;
            OnRulesDeleteButtonClick(this, EventArgs.Empty);
            return;
        }

        if (e.KeyCode == Keys.Delete && _tabControl.SelectedTab == _tabWhitelist
            && _whitelistRemoveButton.Enabled)
        {
            e.Handled = true;
            e.SuppressKeyPress = true;
            OnWhitelistRemoveButtonClick(this, EventArgs.Empty);
        }
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
        // 列变多了（3.5 加了「上传 / 下载 / 总计」），每一列都适当收窄了一点，
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
        // 3.5：加了「上传 / 下载 / 总计」三列，其它列再收窄一点，
        // 保证 1180 宽的默认窗口仍然放得下（流量是本次运行的近似值，列头保持短）。
        AddConnectionColumn("程序名", nameof(TcpConnectionItem.ProcessName), 110, sortable: true);
        AddConnectionColumn("程序路径", nameof(TcpConnectionItem.ProcessPathText), 110);
        AddConnectionColumn("PID", nameof(TcpConnectionItem.Pid), 55, sortable: true);
        AddConnectionColumn("本地端口", nameof(TcpConnectionItem.LocalPortText), 70, sortable: true);
        AddConnectionColumn("远程 IP", nameof(TcpConnectionItem.RemoteAddressText), 120, sortable: true);
        AddConnectionColumn("远程端口", nameof(TcpConnectionItem.RemotePortText), 70, sortable: true);
        AddConnectionColumn("状态", nameof(TcpConnectionItem.StateText), 80, sortable: true);
        AddConnectionColumn("协议", nameof(TcpConnectionItem.Protocol), 55);
        AddConnectionColumn("上传", nameof(TcpConnectionItem.TrafficOutText), 65, sortable: true);
        AddConnectionColumn("下载", nameof(TcpConnectionItem.TrafficInText), 65, sortable: true);
        AddConnectionColumn("总计", nameof(TcpConnectionItem.TrafficTotalText), 70, sortable: true);
        AddConnectionColumn("阻止状态", nameof(TcpConnectionItem.BlockStateText), 75);
        AddConnectionColumn("放行", nameof(TcpConnectionItem.WhitelistText), 120);
        AddConnectionColumn("数字签名", nameof(TcpConnectionItem.SignatureText), 70, fill: true, minWidth: 70);

        // 流量列的悬停提示：必须写明「仅 TCP / 近似值」，不能让人当精确账单。
        var trafficTip = Localizer.T("本次运行累计，仅统计 TCP；短连接和 UDP 可能漏计。");

        foreach (var columnName in new[]
                 {
                     nameof(TcpConnectionItem.TrafficOutText),
                     nameof(TcpConnectionItem.TrafficInText),
                     nameof(TcpConnectionItem.TrafficTotalText),
                 })
        {
            if (_connectionGrid.Columns[columnName] is { } column)
            {
                column.ToolTipText = trafficTip;
            }
        }

        // 状态栏也挂一条：用户没注意到列头悬停时，至少还有一个地方能看到这个边界。
        _summaryLabel.ToolTipText = trafficTip;

        _connectionSource.DataSource = _connections;
        _connectionGrid.DataSource = _connectionSource;
        _connectionGrid.EmptyText =
            "没有匹配的连接。\r\n可以清除搜索，或勾选上面被隐藏的连接类型。";
    }

    /// <summary>
    /// 定义「规则」表格的列。
    /// 这一页的数据来自防火墙规则本身，与实时连接无关。
    /// </summary>
    private void SetupRulesGrid()
    {
        // 黑名单只装「阻止」类规则（程序阻止 + 封禁 IP）。
        // 不再放 动作/方向/协议 三列：这里每一条都是「阻止 / 出站 / 任意」，
        // 三列都只有一个值，除了占地方没有任何信息量。
        AddRuleColumn("类型", nameof(FirewallRuleItem.RuleKindText), 60);
        AddRuleColumn("分组", nameof(FirewallRuleItem.Group), 90);
        AddRuleColumn("范围", nameof(FirewallRuleItem.ScopeText), 150);
        AddRuleColumn("程序名 / IP", nameof(FirewallRuleItem.ApplicationNameText), 160);
        AddRuleColumn("程序路径", nameof(FirewallRuleItem.ApplicationPath), 280, fill: true);
        AddRuleColumn("自动解除", nameof(FirewallRuleItem.ExpiryText), 120);
        AddRuleColumn("启用", nameof(FirewallRuleItem.EnabledText), 70);
        AddRuleColumn("规则名", nameof(FirewallRuleItem.Name), 200);

        _rulesSource.DataSource = _rulesView;
        _rulesGrid.DataSource = _rulesSource;
        _rulesGrid.EmptyText =
            "黑名单是空的。\r\n在「联网连接」页选中程序后点「阻止选中程序联网」，或在「记录」页封禁某个 IP。";
    }

    /// <summary>「严格模式下白名单」表格的列。</summary>
    private void SetupWhitelistGrid()
    {
        AddColumn(_whitelistGrid, "分组", nameof(FirewallRuleItem.Group), 90);
        AddColumn(_whitelistGrid, "范围", nameof(FirewallRuleItem.ScopeText), 150);
        AddColumn(_whitelistGrid, "程序名", nameof(FirewallRuleItem.ApplicationNameText), 160);
        AddColumn(_whitelistGrid, "程序路径", nameof(FirewallRuleItem.ApplicationPath), 280, fill: true);
        AddColumn(_whitelistGrid, "启用", nameof(FirewallRuleItem.EnabledText), 70);
        AddColumn(_whitelistGrid, "规则名", nameof(FirewallRuleItem.Name), 200);

        _whitelistSource.DataSource = _whitelistView;
        _whitelistGrid.DataSource = _whitelistSource;
        _whitelistGrid.EmptyText =
            "白名单是空的。\r\n严格模式开启后，没有任何程序能上网（系统必需程序除外）。\r\n" +
            "在「联网连接」页选中程序，点「加入白名单」。";
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
        _versionLabel.Text = Localizer.F("版本 v{0}", BuildVersionText());

        _startModeLabel.Text = _isAutostart
            ? Localizer.F("启动模式：开机自启（{0}）", AppConstants.AutostartArgument)
            : Localizer.T("启动模式：手动启动");

        var isAdmin = AdminHelper.IsRunningAsAdmin();
        _adminStatusLabel.Text = isAdmin
            ? Localizer.T("管理员权限：已获得")
            : Localizer.T("管理员权限：按需提权（修改规则 / 严格模式时弹一次 UAC）");
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
    /// 重新读取本工具创建的规则（2.0：来自 WFP），刷新内存缓存和规则列表页。
    /// 读取失败时不改变已有缓存，只提示用户。
    /// </summary>
    private void RefreshRulesFromFirewall()
    {
        try
        {
            var response = ServiceClient.TryRequest(
                new ServiceRequest { Command = ServiceProtocol.Commands.ListRules },
                TimeSpan.FromSeconds(3),
                out var error);

            var fromSnapshot = false;
            DateTime? snapshotTime = null;

            if (response is not { Ok: true, Rules: not null })
            {
                // 服务不可用：规则页只读（3.0-b 起唯一写入路径是服务）。
                _serviceAvailable = false;
                LocalLog.Warning(LocalLog.Pick($"读取规则失败（服务不可用）：{error ?? response?.Error}", "Failed to read rules (service unavailable)."));

                // 3.0-c：服务每次写入后都会留一份权威副本（rules.json）。
                // 离线时读它，让用户至少能看到"上次已知状态"，而不是一片空白。
                var snapshot = RuleSnapshotFile.TryRead(ServicePaths.RulesSnapshotFile);

                if (snapshot is null || snapshot.Rules.Count == 0)
                {
                    _statusRulesLabel.Text = Localizer.T("防护服务未运行（规则只读）");
                    _rulesSummaryLabel.Text = Localizer.T("读取规则失败：服务不可用");
                    _whitelistSummaryLabel.Text = Localizer.T("读取规则失败：服务不可用");
                    MarkRulesReadOnly("防护服务未运行");
                    return;
                }

                _appGuardRules = snapshot.Rules.Select(ToRuleItem).ToList();
                snapshotTime = snapshot.SavedUtc.ToLocalTime();
                fromSnapshot = true;

                // 离线时"谁在白名单里"也要从快照补上，否则连接页会把已放行的程序标成"未放行"。
                // 别的软件/系统的放行规则离线时不知道，保持为空（并明确是"上次已知状态"）。
                _whitelistedPaths.Clear();
                _whitelistedPaths.UnionWith(_appGuardRules
                    .Where(rule => rule.Action == FirewallAction.Allow
                                   && !string.IsNullOrEmpty(rule.ApplicationPath))
                    .Select(rule => rule.ApplicationPath));
            }
            else
            {
                _serviceAvailable = true;
                _appGuardRules = response.Rules.Select(ToRuleItem).ToList();

                // 旧分组 / 审计设置 / 1.x 严格模式兜底都改由安装器在安装/修复时处理：
                // 界面可能以普通权限运行，不应在刷新时触发提权。
            }

            _blockedPaths.Clear();

            foreach (var rule in _appGuardRules)
            {
                if (rule.Action == FirewallAction.Block && !string.IsNullOrEmpty(rule.ApplicationPath))
                {
                    _blockedPaths.Add(rule.ApplicationPath);
                }
            }

            // 原地更新两份列表。注意顺序：必须**先**抓取选中项，再动列表 ——
            // 列表变短之后，表格里旧索引对应的数据就不存在了，那时再去读会越界崩溃。
            var selectedRuleName = CaptureRuleSelection();
            var selectedWhitelistName = CaptureWhitelistSelection();

            _rules.Clear();
            _rules.AddRange(_appGuardRules.Where(rule => rule.Action == FirewallAction.Block));

            _whitelistRules.Clear();
            _whitelistRules.AddRange(_appGuardRules.Where(rule => rule.Action == FirewallAction.Allow));

            RefreshGroupFilters();

            // 绑定到表格的是**筛选后**的视图：搜索时只显示匹配项，
            // 但 _rules / _whitelistRules 始终完整（清空与摘要统计都按完整列表算）。
            ApplyRulesFilter(selectedRuleName);
            ApplyWhitelistFilter(selectedWhitelistName);

            // 页签上挂数量：用户不用点进去就知道每一类有多少条。
            _tabRules.Text = Localizer.F("黑名单（{0}）", _rules.Count);
            _tabWhitelist.Text = Localizer.F("严格模式下白名单（{0}）", _whitelistRules.Count);

            _statusRulesLabel.Text = fromSnapshot
                ? Localizer.F("已阻止程序：{0} 个（上次已知）", _blockedPaths.Count)
                : Localizer.F("已阻止程序：{0} 个", _blockedPaths.Count);

            if (fromSnapshot)
            {
                // 离线快照：状态栏按离线处理，页首写明"这是什么时候的状态"。
                UpdateServiceStatusLabel(null);
                MarkRulesReadOnly(
                    $"防护服务未运行（上次已知状态：{snapshotTime:MM-dd HH:mm}）");
            }
            else
            {
                // 状态栏的规则条数也要跟着走：以前只在启动时探一次，新建规则后一直显示旧数字。
                _serviceStatusLabel.Text = Localizer.F("服务：运行中 · {0} 条规则", _appGuardRules.Count);
                _serviceStatusLabel.ForeColor = Color.FromArgb(0, 120, 0);
                _serviceStatusLabel.IsLink = false;
            }

            _rulesSummaryBase = Localizer.F("黑名单共 {0} 条", _rules.Count);
            _whitelistSummaryBase = Localizer.F("白名单共 {0} 个程序", _whitelistRules.Count);

            UpdateRulesSummaryText();
            UpdateWhitelistSummaryText();

            // 白名单页顶部直接写清"现在白名单到底生不生效"，用户不用去设置页找严格模式开关。
            _whitelistNoticeLabel.Text = BuildWhitelistNotice(_strictModeEnabled);
            _whitelistNoticeLabel.Height = Localizer.IsEnglish ? 100 : 64;

            if (!fromSnapshot)
            {
                RestoreRulesPageWritable();
            }

            UpdateRulesActionState();
            UpdateWhitelistActionState();
        }
        catch (Exception ex)
        {
            _statusRulesLabel.Text = Localizer.T("读取规则失败");
            _rulesSummaryLabel.Text = Localizer.T("读取规则失败");
            _whitelistSummaryLabel.Text = Localizer.T("读取规则失败");

            ShowError("读取规则失败", ex, "Failed to read rules");
        }
    }

    /// <summary>把服务返回的 DTO 映射成界面用的规则项。</summary>
    private static FirewallRuleItem ToRuleItem(RuleDto dto)
    {
        var isIp = string.Equals(dto.Kind, "ip", StringComparison.OrdinalIgnoreCase);

        return new FirewallRuleItem
        {
            Name = dto.Name,
            ApplicationPath = dto.Value,
            IpAddress = isIp ? dto.Value : null,
            Description = string.Empty,
            Grouping = AppConstants.RuleGroupingName,
            Enabled = dto.Enabled,
            Action = string.Equals(dto.Action, "block", StringComparison.OrdinalIgnoreCase)
                ? FirewallAction.Block
                : FirewallAction.Allow,
            Direction = FirewallDirection.Outbound,
            Protocol = 256,
            Expiry = RuleExpiry.Parse(dto.Expiry),
            Scope = RuleScope.TryParse(dto.Scope, out var scope) ? scope : RuleScope.Any,
            Group = dto.Group,
        };
    }

    /// <summary>
    /// 服务不可用：规则页只读。按钮全部禁用，并把原因写在页首。
    /// 注意：**不做本地回退写入** —— 3.0 起规则的唯一写入路径是服务。
    /// </summary>
    private void MarkRulesReadOnly(string reason)
    {
        _rulesNoticeLabel.Text = Localizer.IsEnglish
            ? $"⚠ {Localizer.T(reason)}\r\nRules are read-only; start or repair the protection service to edit them. Export still works."
            : $"⚠ {reason}\r\n规则页面只读；启动或修复防护服务后即可恢复编辑，导出仍可使用。";

        _rulesAddButton.Enabled = false;
        _rulesGroupButton.Enabled = false;
        _rulesImportButton.Enabled = false;
        _rulesDeleteButton.Enabled = false;
        _rulesDeleteAllButton.Enabled = false;

        _whitelistAddButton.Enabled = false;
        _whitelistGroupButton.Enabled = false;
        _whitelistRemoveButton.Enabled = false;
        _whitelistClearButton.Enabled = false;

        _rulesHintLabel.Text = Localizer.T("服务未运行：规则只读");
        _whitelistHintLabel.Text = Localizer.T("服务未运行：规则只读");
    }

    /// <summary>服务恢复后，把规则页的提示与按钮恢复（选中相关的状态由 Update*ActionState 负责）。</summary>
    private void RestoreRulesPageWritable()
    {
        _rulesNoticeLabel.Text = _rulesNoticeDefault;
        _rulesAddButton.Enabled = true;
        _rulesImportButton.Enabled = true;
        _whitelistAddButton.Enabled = true;
    }

    /// <summary>
    /// 发一条写命令；失败时弹出原因并返回 null。
    /// 统一在这里处理"服务没起 / 未提权 / 服务拒绝"，避免每个调用点各写一遍。
    /// </summary>
    private ServiceResponse? CallService(string command, ServiceRequest request, string actionName)
    {
        request.Command = command;

        ServiceResponse? response;
        string? error;

        if (AdminHelper.IsRunningAsAdmin())
        {
            response = ServiceClient.TryRequest(
                request, TimeSpan.FromSeconds(5), out error);
        }
        else
        {
            // 普通权限：写操作走一次 UAC（提权助手 = WinAppGuardSvc.exe --elevated-ipc）。
            response = ElevatedClient.TryRequest(request, out error);
        }

        if (response is { Ok: true })
        {
            return response;
        }

        if (response is null && string.Equals(error, ElevatedClient.CancelledMessage, StringComparison.Ordinal))
        {
            LocalLog.Info(LocalLog.Pick($"{actionName}：用户取消了管理员授权。", $"User cancelled the elevation prompt (command={command})."));
            return null;
        }

        var reason = response?.Error ?? error ?? "防护服务没有响应。";
        LocalLog.Warning(LocalLog.Pick($"{actionName}失败：{reason}", $"Service request failed (command={command})."));

        UiMessageBox.Show(
            this,
            $"{actionName}失败：\n\n{reason}\n\n" +
            (response is null
                ? "连接不上防护服务或提权失败：请确认服务已安装并正在运行" +
                  "（安装目录里的 WinAppGuardSetup.exe --repair）。"
                : "服务拒绝了这次操作。如果是权限问题，请确认提权没有被安全软件拦截。"),
            AppConstants.AppName,
            MessageBoxButtons.OK,
            MessageBoxIcon.Warning);

        return null;
    }

    /// <summary>
    /// 规则发生变化后的统一收尾：重新读规则，并刷新连接页的阻止状态显示。
    /// 任何修改规则的操作都应该以调用这个方法结束。
    /// </summary>
    private void AfterRulesChanged()
    {
        // 3.0-c：严格模式会话由服务持有，服务在写规则时会自己重建会话
        // （见 RuleHandlers 里的 StrictModeHost.RefreshIfEnabled）。
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

    // 到期清理与 1.x 迁移都归服务 / 安装器：
    // 3.0-c 起界面可能以普通权限运行，启动和定时都不再触发任何写操作。
    // 到期解除通过 ServiceStatus.ExpiredPurgedCount 感知（见 UpdateServiceStatusLabel）。
    private void OnExpiryTimerTick(object? sender, EventArgs e) => ProbeServiceStatus();

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

            // 3.0-c：界面不再枚举防火墙规则，两类信息都由服务一次读齐。
            var response = ServiceClient.TryRequest(
                new ServiceRequest { Command = ServiceProtocol.Commands.AllowTargets },
                TimeSpan.FromSeconds(5),
                out var error);

            if (response is not { Ok: true })
            {
                // 服务不可用：保留上一次的缓存（不要清空 —— 清空会让所有程序都显示"未放行"）。
                LocalLog.Warning(LocalLog.Pick($"读取放行状态失败（保留上次缓存）：{response?.Error ?? error}", "Failed to read the allow state; keeping the previous cache."));
                return;
            }

            _whitelistedPaths.Clear();
            _whitelistedPaths.UnionWith(response.Programs ?? new List<string>());

            _otherAllowPaths.Clear();
            _otherAllowPaths.UnionWith(response.OtherPrograms ?? new List<string>());

            _programlessAllowRuleCount = response.ProgramlessRuleCount;

            // 耗时写进日志：这条路径的开销是本功能唯一的性能风险点，
            // 真机上一旦变慢，日志里就能直接看到。
            LocalLog.Info(LocalLog.Pick(
                $"放行状态：本工具白名单 {_whitelistedPaths.Count} 个程序、系统/其它软件放行 {_otherAllowPaths.Count} 个程序、不限程序的允许规则 {_programlessAllowRuleCount} 条、耗时 {Environment.TickCount64 - started}ms",
                $"Allow state: our whitelist {_whitelistedPaths.Count} programs, system/other allow rules {_otherAllowPaths.Count} programs, programless allow rules {_programlessAllowRuleCount}, took {Environment.TickCount64 - started}ms."));
        }
        catch (Exception ex)
        {
            LocalLog.Error(LocalLog.Pick("读取放行状态失败", "Failed to read the allow state."), ex);
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
    /// <summary>
    /// 3.5：界面是普通权限，读不到提权/受保护进程的路径；让服务代查并回填。
    /// 只查当前扫描结果里路径为空的 PID，最多 64 个，失败静默（不打扰用户）。
    /// </summary>
    private async Task ResolveMissingProcessPathsAsync()
    {
        var targets = _scannedConnections
            .Where(item => string.IsNullOrEmpty(item.ProcessPath))
            .Where(item => item.Pid > 4)
            .ToList();

        if (targets.Count == 0)
        {
            return;
        }

        var pids = targets
            .Select(item => item.Pid)
            .Distinct()
            .Take(64)
            .ToList();

        var response = await Task.Run(() =>
        {
            try
            {
                return ServiceClient.TryRequest(
                    new ServiceRequest
                    {
                        Command = ServiceProtocol.Commands.QueryProcessPaths,
                        Pids = pids,
                    },
                    TimeSpan.FromSeconds(3),
                    out _);
            }
            catch (Exception)
            {
                return null;
            }
        });

        if (response is not { Ok: true, ProcessPaths: not null }
            || IsDisposed
            || Disposing)
        {
            return;
        }

        var paths = response.ProcessPaths
            .Where(item => !string.IsNullOrEmpty(item.Path))
            .GroupBy(item => item.Pid)
            .ToDictionary(group => group.Key, group => group.First().Path!);

        if (paths.Count == 0)
        {
            return;
        }

        // 扫描可能在这期间又跑了一轮：只回填仍然在列表里的对象。
        var active = new HashSet<TcpConnectionItem>(_scannedConnections);
        var changed = false;

        foreach (var item in targets)
        {
            if (active.Contains(item) && paths.TryGetValue(item.Pid, out var path))
            {
                item.ApplyResolvedPath(path);
                ApplyTrafficTo(item);
                changed = true;
            }
        }

        if (!changed)
        {
            return;
        }

        var selectedKey = CaptureSelection();
        RebuildView();
        RebindGrid(selectedKey);
    }
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
            ? Localizer.F("最后刷新：{0}    共 {1} 条", time, total)
            : Localizer.F("最后刷新：{0}    显示 {1} / 共 {2} 条", time, shown, total);
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
        var pathColumnIndex = _connectionGrid.Columns[nameof(TcpConnectionItem.ProcessPathText)]?.Index ?? -1;

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

            // 路径列一定会被截断（列宽就那么大），悬停给出完整路径。
            if (pathColumnIndex >= 0 && !string.IsNullOrEmpty(item.ProcessPath))
            {
                row.Cells[pathColumnIndex].ToolTipText = item.ProcessPath;
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
    /// 否则用户点「解除阻止（允许联网）」时，操作的可能是他并没有看过的那一条规则。
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

        for (var i = 0; i < _rulesView.Count && i < _rulesGrid.Rows.Count; i++)
        {
            if (string.Equals(_rulesView[i].Name, ruleName, StringComparison.OrdinalIgnoreCase))
            {
                _rulesGrid.CurrentCell = _rulesGrid.Rows[i].Cells[0];
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// 按搜索词重建「筛选后的规则视图」，然后重新绑定表格。
    /// </summary>
    /// <remarks>
    /// 为什么要单独一个视图：表格如果直接绑 <see cref="_rules"/>，
    /// 搜索就只能在**刷新时**过滤，而每 3 秒/每次操作都会重新绑定，
    /// 用户的搜索结果会被无声地冲掉。分成"完整列表 + 视图"两层就没有这个问题。
    /// 删除全部、摘要统计仍然按完整列表算，不受搜索影响。
    /// </remarks>
    private void ApplyRulesFilter(string? selectedRuleName = null)
    {
        var keyword = _rulesKeyword.Trim();

        _rulesView.Clear();

        if (keyword.Length == 0)
        {
            _rulesView.AddRange(_rules.Where(rule => MatchesGroup(rule, _blockGroupFilter)));
        }
        else
        {
            _rulesView.AddRange(_rules.Where(rule =>
                MatchesGroup(rule, _blockGroupFilter) && MatchesRule(rule, keyword)));
        }

        // 复用 RebindRules：它负责 ResetBindings + 恢复选中 + 刷新按钮状态。
        RebindRules(selectedRuleName);

        ApplyRuleTooltips();
        UpdateRulesSummaryText();
    }

    /// <summary>规则是否匹配搜索词（程序名 / 路径 / 规则名 / 到期文本）。</summary>
    private static bool MatchesRule(FirewallRuleItem rule, string keyword)
        => Contains(rule.ApplicationNameText, keyword)
           || Contains(rule.ApplicationPath, keyword)
           || Contains(rule.Name, keyword)
           || Contains(rule.ExpiryText, keyword);

    /// <summary>
    /// 分组筛选：null = 全部；"" = 未分组；其它 = 精确匹配（不区分大小写）。
    /// </summary>
    private static bool MatchesGroup(FirewallRuleItem rule, string? groupFilter)
        => groupFilter is null
           || string.Equals(rule.Group, groupFilter, StringComparison.OrdinalIgnoreCase);

    /// <summary>摘要文字：没有搜索时就是总数；搜索时追加「筛选出 N 条」。</summary>
    private void UpdateRulesSummaryText()
        => _rulesSummaryLabel.Text = _rulesKeyword.Trim().Length == 0
            ? _rulesSummaryBase
            : Localizer.F("{0} ｜ 筛选出 {1} 条", _rulesSummaryBase, _rulesView.Count);

    private void OnRulesSearchTextChanged(object? sender, EventArgs e)
    {
        var keyword = _rulesSearchBox.Text.Trim();

        if (string.Equals(keyword, _rulesKeyword, StringComparison.Ordinal))
        {
            return;
        }

        _rulesKeyword = keyword;
        ApplyRulesFilter(CaptureRuleSelection());
    }

    // ==================================================================
    // 分组筛选（2.4）
    // ==================================================================

    /// <summary>重建两个分组下拉框（保留用户当前的选择）。</summary>
    private void RefreshGroupFilters()
    {
        // 3.0-b：分组随规则一起从服务来 —— 去重后即为当前可用的分组清单。
        var groups = _appGuardRules
            .Select(rule => rule.Group)
            .Where(group => !string.IsNullOrWhiteSpace(group))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(group => group, StringComparer.OrdinalIgnoreCase)
            .ToList();

        RebuildGroupCombo(_rulesGroupCombo, ref _blockGroupFilter, groups);
        RebuildGroupCombo(_whitelistGroupCombo, ref _allowGroupFilter, groups);
    }

    /// <summary>
    /// 下拉项固定是「全部分组 / 未分组 / 各分组」。
    /// 当前选中的分组如果已经不存在了（比如规则全被删掉），自动回到「全部分组」——
    /// 否则界面会停在一个空列表上，用户以为规则丢了。
    /// </summary>
    private void RebuildGroupCombo(
        ComboBox combo, ref string? filter, IReadOnlyList<string> groups)
    {
        _suppressGroupFilterEvents = true;

        try
        {
            combo.Items.Clear();
            combo.Items.Add(Localizer.T("全部分组"));
            combo.Items.Add(Localizer.T("未分组"));

            foreach (var group in groups)
            {
                combo.Items.Add(group);
            }

            var index = 0;

            if (filter is not null)
            {
                if (filter.Length == 0)
                {
                    index = 1;
                }
                else
                {
                    var found = combo.Items.IndexOf(filter);

                    if (found >= 0)
                    {
                        index = found;
                    }
                    else
                    {
                        filter = null;
                    }
                }
            }

            combo.SelectedIndex = index;
        }
        finally
        {
            _suppressGroupFilterEvents = false;
        }
    }

    private void OnBlockGroupFilterChanged(object? sender, EventArgs e)
    {
        if (_suppressGroupFilterEvents)
        {
            return;
        }

        _blockGroupFilter = _rulesGroupCombo.SelectedIndex switch
        {
            0 => null,
            1 => string.Empty,
            _ => _rulesGroupCombo.SelectedItem as string,
        };

        ApplyRulesFilter(CaptureRuleSelection());
    }

    private void OnAllowGroupFilterChanged(object? sender, EventArgs e)
    {
        if (_suppressGroupFilterEvents)
        {
            return;
        }

        _allowGroupFilter = _whitelistGroupCombo.SelectedIndex switch
        {
            0 => null,
            1 => string.Empty,
            _ => _whitelistGroupCombo.SelectedItem as string,
        };

        ApplyWhitelistFilter(CaptureWhitelistSelection());
    }

    /// <summary>规则表格：路径和规则名经常显示不全，悬停给完整内容。</summary>
    private void ApplyRuleTooltips()
    {
        var pathIndex = _rulesGrid.Columns[nameof(FirewallRuleItem.ApplicationPath)]?.Index ?? -1;
        var nameIndex = _rulesGrid.Columns[nameof(FirewallRuleItem.Name)]?.Index ?? -1;

        foreach (DataGridViewRow row in _rulesGrid.Rows)
        {
            if (row.DataBoundItem is not FirewallRuleItem rule)
            {
                continue;
            }

            if (pathIndex >= 0 && !string.IsNullOrEmpty(rule.ApplicationPath))
            {
                row.Cells[pathIndex].ToolTipText = rule.ApplicationPath;
            }

            if (nameIndex >= 0 && !string.IsNullOrEmpty(rule.Name))
            {
                row.Cells[nameIndex].ToolTipText = rule.Name;
            }
        }
    }

    // ==================================================================
    // 严格模式下白名单页
    // ==================================================================

    /// <summary>按搜索词重建白名单视图并重新绑定。</summary>
    private void ApplyWhitelistFilter(string? selectedRuleName = null)
    {
        var keyword = _whitelistKeyword.Trim();

        _whitelistView.Clear();

        if (keyword.Length == 0)
        {
            _whitelistView.AddRange(_whitelistRules.Where(rule => MatchesGroup(rule, _allowGroupFilter)));
        }
        else
        {
            _whitelistView.AddRange(_whitelistRules.Where(rule =>
                MatchesGroup(rule, _allowGroupFilter) && MatchesRule(rule, keyword)));
        }

        RebindWhitelist(selectedRuleName);
        ApplyWhitelistTooltips();
        UpdateWhitelistSummaryText();
    }

    private void RebindWhitelist(string? selectedRuleName)
    {
        _isRebindingRules = true;
        try
        {
            _whitelistSource.ResetBindings(metadataChanged: false);
        }
        finally
        {
            _isRebindingRules = false;
        }

        if (selectedRuleName is null || !TryRestoreWhitelistSelection(selectedRuleName))
        {
            _whitelistGrid.CurrentCell = null;
            _whitelistSelectionConfirmed = false;
        }

        UpdateWhitelistActionState();
    }

    private bool TryRestoreWhitelistSelection(string? ruleName)
    {
        if (string.IsNullOrEmpty(ruleName))
        {
            return false;
        }

        for (var i = 0; i < _whitelistView.Count && i < _whitelistGrid.Rows.Count; i++)
        {
            if (string.Equals(_whitelistView[i].Name, ruleName, StringComparison.OrdinalIgnoreCase))
            {
                _whitelistGrid.CurrentCell = _whitelistGrid.Rows[i].Cells[0];
                return true;
            }
        }

        return false;
    }

    private void UpdateWhitelistSummaryText()
        => _whitelistSummaryLabel.Text = _whitelistKeyword.Trim().Length == 0
            ? _whitelistSummaryBase
            : Localizer.F("{0} ｜ 筛选出 {1} 个", _whitelistSummaryBase, _whitelistView.Count);

    private void OnWhitelistSearchTextChanged(object? sender, EventArgs e)
    {
        var keyword = _whitelistSearchBox.Text.Trim();

        if (string.Equals(keyword, _whitelistKeyword, StringComparison.Ordinal))
        {
            return;
        }

        _whitelistKeyword = keyword;
        ApplyWhitelistFilter(CaptureWhitelistSelection());
    }

    private void ApplyWhitelistTooltips()
    {
        var pathIndex = _whitelistGrid.Columns[nameof(FirewallRuleItem.ApplicationPath)]?.Index ?? -1;
        var nameIndex = _whitelistGrid.Columns[nameof(FirewallRuleItem.Name)]?.Index ?? -1;

        foreach (DataGridViewRow row in _whitelistGrid.Rows)
        {
            if (row.DataBoundItem is not FirewallRuleItem rule)
            {
                continue;
            }

            if (pathIndex >= 0 && !string.IsNullOrEmpty(rule.ApplicationPath))
            {
                row.Cells[pathIndex].ToolTipText = rule.ApplicationPath;
            }

            if (nameIndex >= 0 && !string.IsNullOrEmpty(rule.Name))
            {
                row.Cells[nameIndex].ToolTipText = rule.Name;
            }
        }
    }

    private FirewallRuleItem? GetSelectedWhitelistRule()
        => _whitelistGrid.CurrentRow?.DataBoundItem as FirewallRuleItem;

    private FirewallRuleItem? GetConfirmedWhitelistRule()
        => _whitelistSelectionConfirmed ? GetSelectedWhitelistRule() : null;

    private string? CaptureWhitelistSelection()
        => _whitelistSelectionConfirmed ? GetSelectedWhitelistRule()?.Name : null;

    private void UpdateWhitelistActionState()
    {
        if (!_serviceAvailable)
        {
            _whitelistRemoveButton.Enabled = false;
            _whitelistGroupButton.Enabled = false;
            _whitelistClearButton.Enabled = false;
            _whitelistHintLabel.Text = Localizer.T("服务未运行：规则只读");
            return;
        }

        var rule = GetConfirmedWhitelistRule();

        _whitelistRemoveButton.Enabled = rule is not null;
        _whitelistGroupButton.Enabled = rule is not null;
        _whitelistClearButton.Enabled = _whitelistRules.Count > 0;

        // 空状态/长文本交给表格自己的 EmptyText 和分组列，这里只留最短的选中提示，
        // 否则在最小窗口宽度下这行会被截断。
        _whitelistHintLabel.Text = rule is null
            ? Localizer.T("未选中任何程序")
            : Localizer.F("已选中 {0}", rule.ApplicationNameText);
    }

    private void OnWhitelistGridCellMouseDown(object? sender, DataGridViewCellMouseEventArgs e)
    {
        if (e.RowIndex < 0 || e.RowIndex >= _whitelistGrid.Rows.Count)
        {
            return;
        }

        _whitelistGrid.CurrentCell = _whitelistGrid.Rows[e.RowIndex].Cells[0];
        _whitelistSelectionConfirmed = true;
        UpdateWhitelistActionState();
    }

    private void OnWhitelistGridKeyDown(object? sender, KeyEventArgs e)
    {
        if (_whitelistGrid.CurrentRow is null)
        {
            return;
        }

        _whitelistSelectionConfirmed = true;
        UpdateWhitelistActionState();
    }

    private void OnWhitelistGridSelectionChanged(object? sender, EventArgs e)
    {
        if (_isRebindingRules)
        {
            return;
        }

        _whitelistSelectionConfirmed = true;
        UpdateWhitelistActionState();
    }

    /// <summary>
    /// 「添加程序…」：按路径把程序加入白名单。
    ///
    /// 为什么必须有这个入口：严格模式开启后，没进白名单的程序**连不上网**，
    /// 因此也不会出现在「联网连接」页里 —— 用户会被"想加白名单却找不到它"卡死。
    /// </summary>
    private void OnWhitelistAddButtonClick(object? sender, EventArgs e)
    {
        using var dialog = new OpenFileDialog
        {
            Title = "选择要加入白名单的程序",
            Filter = "程序 (*.exe)|*.exe",
            CheckFileExists = true,
            Multiselect = false,
        };

        if (dialog.ShowDialog(this) != DialogResult.OK)
        {
            return;
        }

        var path = dialog.FileName;
        var name = Path.GetFileName(path);
        var strictModeOn = _strictModeEnabled;

        var scope = RuleScopeForm.Ask(DialogOwner, RuleScope.Any);

        if (scope is null)
        {
            return;
        }

        var confirmed = ConfirmForm.Show(
            owner: DialogOwner,
            title: "加入白名单",
            question: $"确定要把「{name}」加入白名单吗？",
            details: new[]
            {
                new KeyValuePair<string, string>("程序名", name),
                new KeyValuePair<string, string>("完整路径", path),
                new KeyValuePair<string, string>("生效条件", "只在严格模式下有意义"),
                new KeyValuePair<string, string>("作用范围", scope.Describe()),
            },
            warnings: new[]
            {
                strictModeOn
                    ? "严格模式正在生效：确认后它立刻就能联网。"
                    : "严格模式当前没有开启，所以加进去暂时不会有任何变化。",
                "这**不是**阻止规则：它只是允许该程序上网，不影响其它程序。",
                "如果把同一个程序也放进了黑名单，黑名单优先 —— 它仍然上不了网。",
            },
            confirmText: "加入");

        if (!confirmed)
        {
            return;
        }

        try
        {
            var response = CallService(
                ServiceProtocol.Commands.AddProgramRule,
                new ServiceRequest
                {
                    Value = path,
                    Action = "allow",
                    Expiry = RuleExpiry.Never.Encode(),
                    Scope = scope.Encode(),
                },
                "加入白名单");

            if (response is null)
            {
                return;
            }

            LocalLog.Operation(LocalLog.Pick($"加入白名单：{path}（范围 {scope.Describe()}）", $"Add to allowlist: {path} (scope {DescribeScopeEnglish(scope)})."));
            AfterRulesChanged();
        }
        catch (Exception ex)
        {
            ShowError("加入白名单失败", ex, "Failed to add to the allowlist");
        }
    }

    /// <summary>把选中的程序移出白名单（= 删除那条允许规则）。</summary>
    private void OnWhitelistRemoveButtonClick(object? sender, EventArgs e)
    {
        var rule = GetConfirmedWhitelistRule();

        if (rule is null || string.IsNullOrEmpty(rule.ApplicationPath))
        {
            return;
        }

        var strictModeOn = _strictModeEnabled;

        var confirmed = ConfirmForm.Show(
            owner: DialogOwner,
            title: "移出白名单",
            question: $"确定要把「{rule.ApplicationNameText}」移出白名单吗？",
            details: new[]
            {
                new KeyValuePair<string, string>("程序名", rule.ApplicationNameText),
                new KeyValuePair<string, string>("完整路径", rule.ApplicationPath),
                new KeyValuePair<string, string>("将删除规则", rule.Name),
            },
            warnings: strictModeOn
                ? new[]
                {
                    "⚠ 严格模式正在生效：移出之后，这个程序会立刻上不了网（已经建立的连接要等它自己断开）。",
                    "只会删除这一条允许规则，不影响其它程序，也不影响黑名单。",
                }
                : new[]
                {
                    "严格模式当前没有开启，所以移出白名单暂时不会影响它联网。",
                    "只会删除这一条允许规则，不影响其它程序，也不影响黑名单。",
                },
            confirmText: "移出");

        if (!confirmed)
        {
            return;
        }

        try
        {
            var response = CallService(
                ServiceProtocol.Commands.DeleteRule,
                new ServiceRequest { RuleName = rule.Name },
                "移出白名单");

            if (response is null)
            {
                return;
            }

            LocalLog.Operation(LocalLog.Pick($"移出白名单：{rule.ApplicationPath}（规则 {rule.Name}）", $"Remove from allowlist: {rule.ApplicationPath} (rule {rule.Name})."));
            AfterRulesChanged();
        }
        catch (Exception ex)
        {
            ShowError("移出白名单失败", ex, "Failed to remove from the allowlist");
        }
    }

    /// <summary>清空白名单（删除全部允许规则）。严格模式开启时会让这些程序立刻断网，必须写清楚。</summary>
    private void OnWhitelistClearButtonClick(object? sender, EventArgs e)
    {
        var rules = _whitelistRules;

        if (rules.Count == 0)
        {
            AfterRulesChanged();
            UiMessageBox.Show(
                this,
                "当前白名单是空的，无需清理。",
                AppConstants.AppName,
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
            return;
        }

        var strictModeOn = _strictModeEnabled;

        var ruleList = string.Join(
            Environment.NewLine,
            rules.Select(rule => $"    {rule.ApplicationNameText}"));

        var confirmed = ConfirmForm.Show(
            owner: DialogOwner,
            title: "清空白名单",
            question: $"确定要移除全部 {rules.Count} 个白名单程序吗？",
            details: new[]
            {
                new KeyValuePair<string, string>("程序数", $"{rules.Count} 个"),
                new KeyValuePair<string, string>("影响", strictModeOn
                    ? "严格模式正在生效：这些程序会立刻上不了网"
                    : "严格模式没有开启：暂时不影响联网"),
            },
            warnings: new[]
            {
                "将要移出白名单的程序：",
                ruleList,
                "只会删除本工具创建的允许规则，不影响黑名单，也不影响其它软件或系统的规则。",
            },
            confirmText: "清空");

        if (!confirmed)
        {
            return;
        }

        try
        {
            var response = CallService(
                ServiceProtocol.Commands.ClearWhitelist,
                new ServiceRequest(),
                "清空白名单");

            if (response is null)
            {
                return;
            }

            LocalLog.Operation(LocalLog.Pick($"清空白名单：实际删除 {response.Affected} 条允许规则", $"Clear allowlist: {response.Affected} allow rules deleted."));
            AfterRulesChanged();
        }
        catch (Exception ex)
        {
            ShowError("清空白名单失败", ex, "Failed to clear the allowlist");
        }
    }

    // ==================================================================
    // 规则分组 / 导入导出（2.4）
    // ==================================================================

    private void OnRulesGroupButtonClick(object? sender, EventArgs e)
        => AssignGroupToRule(GetConfirmedRule());

    private void OnWhitelistGroupButtonClick(object? sender, EventArgs e)
        => AssignGroupToRule(GetConfirmedWhitelistRule());

    /// <summary>给一条规则设置分组（空字符串 = 未分组）。</summary>
    private void AssignGroupToRule(FirewallRuleItem? rule)
    {
        if (rule is null)
        {
            return;
        }

        var existingGroups = _appGuardRules
            .Select(item => item.Group)
            .Where(item => !string.IsNullOrWhiteSpace(item))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(item => item, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var group = RuleGroupPrompt.Ask(DialogOwner, existingGroups, rule.Group);

        if (group is null)
        {
            return;
        }

        var response = CallService(
            ServiceProtocol.Commands.SetGroup,
            new ServiceRequest { RuleName = rule.Name, Group = group },
            "修改分组");

        if (response is null)
        {
            return;
        }

        LocalLog.Operation(LocalLog.Pick($"规则分组：{rule.Name} → {(group.Length == 0 ? "未分组" : group)}", $"Rule group: {rule.Name} -> {(group.Length == 0 ? "(none)" : group)}."));

        RefreshRulesFromFirewall();
    }

    /// <summary>导出全部规则（黑名单 + 白名单 + 封禁 IP），含分组。</summary>
    private void OnExportBlocklistButtonClick(object? sender, EventArgs e)
        => ExportRules(FirewallAction.Block);

    private void OnExportWhitelistButtonClick(object? sender, EventArgs e)
        => ExportRules(FirewallAction.Allow);

    /// <summary>导出某一类规则（黑名单或白名单，含封禁 IP 与分组）。</summary>
    private void ExportRules(FirewallAction scope)
    {
        var pageName = scope == FirewallAction.Block ? "黑名单" : "白名单";
        var pageNameEn = scope == FirewallAction.Block ? "blocklist" : "whitelist";
        var fileTag = scope == FirewallAction.Block ? "blacklist" : "whitelist";
        var count = _appGuardRules.Count(rule => rule.Action == scope);

        if (count == 0)
        {
            UiMessageBox.Show(
                this,
                $"当前{pageName}没有规则可导出。",
                AppConstants.AppName,
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
            return;
        }

        using var dialog = new SaveFileDialog
        {
            Title = $"导出{pageName}",
            Filter = "WinAppGuard 规则 (*.json)|*.json|所有文件 (*.*)|*.*",
            FileName = $"winappguard-{fileTag}-{DateTime.Now:yyyyMMdd}.json",
            OverwritePrompt = true,
        };

        if (dialog.ShowDialog(this) != DialogResult.OK)
        {
            return;
        }

        try
        {
            var document = RuleExport.Build(_appGuardRules, scope);
            var json = RuleExport.Serialize(document);

            File.WriteAllText(dialog.FileName, json, new UTF8Encoding(false));
            LocalLog.Operation(LocalLog.Pick($"导出{pageName}：{document.Rules.Count} 条 → {dialog.FileName}", $"Export {pageNameEn}: {document.Rules.Count} rules -> {dialog.FileName}."));

            UiMessageBox.Show(
                this,
                $"已导出 {document.Rules.Count} 条{pageName}规则（含分组）。\n\n{dialog.FileName}\n\n" +
                "注意：文件里包含程序完整路径，发给别人等于公开你在用哪些软件。",
                AppConstants.AppName,
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
        }
        catch (Exception ex)
        {
            ShowError($"导出{pageName}失败", ex, $"Failed to export {pageNameEn}");
        }
    }

    private void OnImportBlocklistButtonClick(object? sender, EventArgs e)
        => ImportRules(FirewallAction.Block);

    private void OnImportWhitelistButtonClick(object? sender, EventArgs e)
        => ImportRules(FirewallAction.Allow);

    /// <summary>导入某一类规则（只能导入本页导出的文件）。</summary>
    private void ImportRules(FirewallAction scope)
    {
        var pageName = scope == FirewallAction.Block ? "黑名单" : "白名单";

        using var dialog = new OpenFileDialog
        {
            Title = $"导入{pageName}",
            Filter = "WinAppGuard 规则 (*.json)|*.json|所有文件 (*.*)|*.*",
            CheckFileExists = true,
            Multiselect = false,
        };

        if (dialog.ShowDialog(this) != DialogResult.OK)
        {
            return;
        }

        string json;

        try
        {
            json = File.ReadAllText(dialog.FileName, Encoding.UTF8);
        }
        catch (Exception ex)
        {
            ShowError("读取规则文件失败", ex, "Failed to read the rules file");
            return;
        }

        if (!RuleExport.TryParse(json, out var document, out var error) || document is null)
        {
            UiMessageBox.Show(
                this,
                $"不能导入这个文件：\n\n{error}",
                AppConstants.AppName,
                MessageBoxButtons.OK,
                MessageBoxIcon.Warning);
            return;
        }

        // 不能把黑名单文件导进白名单页（反之亦然）—— 否则会悄悄创建另一类规则。
        if (!RuleExport.TryMatchScope(document, scope, out var scopeError))
        {
            UiMessageBox.Show(
                this,
                $"不能在这个页面导入：\n\n{scopeError}",
                AppConstants.AppName,
                MessageBoxButtons.OK,
                MessageBoxIcon.Warning);
            return;
        }

        if (document.Rules.Count == 0)
        {
            UiMessageBox.Show(
                this,
                "文件里没有任何规则。",
                AppConstants.AppName,
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
            return;
        }

        var previewLines = document.Rules.Take(10).Select(DescribeImportEntry).ToList();
        var preview = string.Join(Environment.NewLine, previewLines);

        if (document.Rules.Count > previewLines.Count)
        {
            preview += Environment.NewLine + $"    …… 还有 {document.Rules.Count - previewLines.Count} 条";
        }

        var confirmed = ConfirmForm.Show(
            owner: DialogOwner,
            title: $"导入{pageName}",
            question: $"确定要把这 {document.Rules.Count} 条规则导入{pageName}吗？",
            details: new[]
            {
                new KeyValuePair<string, string>("内容", RuleExport.Summarize(document)),
                new KeyValuePair<string, string>("文件", Path.GetFileName(dialog.FileName)),
                new KeyValuePair<string, string>("导出时间", document.ExportedUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm")),
            },
            warnings: new[]
            {
                "将要导入的规则（最多显示 10 条）：",
                preview,
                "已存在的同名规则会自动跳过；系统关键进程等受保护程序也会被跳过。",
                "导入只会创建规则，**不会删除**你现有的任何规则。",
            },
            confirmText: "导入");

        if (!confirmed)
        {
            return;
        }

        ApplyImportedRules(scope, json);
    }

    private static string DescribeImportEntry(RuleExportEntry entry)
    {
        var parsed = string.IsNullOrEmpty(entry.Expiry)
            ? RuleExpiry.Never
            : RuleExpiry.Parse(entry.Expiry);

        if (Localizer.IsEnglish)
        {
            var actionEn = entry.Action == "block" ? "block" : "allow";
            var kindEn = entry.Kind == "ip" ? "IP" : "program";
            var groupEn = entry.Group.Length == 0 ? string.Empty : $" | group {entry.Group}";

            return $"[{kindEn}] {actionEn} {entry.Value} ({Localizer.T(parsed.Describe(DateTime.UtcNow))}){groupEn}";
        }

        var action = entry.Action == "block" ? "阻止" : "允许";
        var kind = entry.Kind == "ip" ? "IP" : "程序";
        var expiry = parsed.Describe(DateTime.UtcNow);
        var group = entry.Group.Length == 0 ? string.Empty : $" ｜ 分组 {entry.Group}";

        return $"[{kind}] {action} {entry.Value}（{expiry}）{group}";
    }

    /// <summary>
    /// 真正创建导入的规则：**交给服务端**整份校验并落盘（3.0-b）。
    /// 界面只负责预览与确认，不再自己创建规则 —— 受保护程序、路径校验都在服务里。
    /// </summary>
    private void ApplyImportedRules(FirewallAction scope, string json)
    {
        var response = CallService(
            ServiceProtocol.Commands.ImportRules,
            new ServiceRequest
            {
                Action = scope == FirewallAction.Block ? "block" : "allow",
                Json = json,
            },
            "导入规则");

        if (response is null)
        {
            return;
        }

        AfterRulesChanged();

        var lines = new List<string> { $"新建 {response.Affected} 条" };

        if (!string.IsNullOrWhiteSpace(response.Error))
        {
            lines.Add(response.Error);
        }

        LocalLog.Operation(LocalLog.Pick($"导入规则：{string.Join("，", lines)}", $"Import rules: created {response.Affected}, hasErrors={!string.IsNullOrWhiteSpace(response.Error)}."));

        UiMessageBox.Show(
            this,
            "导入完成：\n\n" + string.Join(Environment.NewLine, lines.Select(line => "· " + line)) +
            "\n\n已存在的同名规则会自动跳过；受保护程序也会跳过。",
            AppConstants.AppName,
            MessageBoxButtons.OK,
            string.IsNullOrWhiteSpace(response.Error)
                ? MessageBoxIcon.Information
                : MessageBoxIcon.Warning);
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
        // 服务不可用时也不能改规则（3.0-b 起唯一写入路径是服务）。
        var canBlock = _serviceAvailable && hasPath && !isBlocked && !isProtected;

        // 只有已经处于阻止状态，才有东西可以「允许」。
        var canAllow = _serviceAvailable && hasPath && isBlocked;

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
        // 服务不可用时白名单也是只读（写操作全部走服务）。
        _whitelistButton.Enabled = _serviceAvailable && hasPath;
        _whitelistButton.Text = isWhitelistedByUs ? "移出白名单" : "加入白名单";
        _menuWhitelistAdd.Enabled = _serviceAvailable && hasPath && !isWhitelistedByUs;
        _menuWhitelistRemove.Enabled = _serviceAvailable && isWhitelistedByUs;

        _selectionHintLabel.Text = BuildSelectionHint(item, hasPath, isBlocked);
    }

    /// <summary>根据当前选中的规则，决定规则页哪些操作可用。</summary>
    private void UpdateRulesActionState()
    {
        if (!_serviceAvailable)
        {
            _rulesDeleteButton.Enabled = false;
            _rulesGroupButton.Enabled = false;
            _rulesDeleteAllButton.Enabled = false;
            _rulesHintLabel.Text = Localizer.T("服务未运行：规则只读");
            return;
        }

        var rule = GetConfirmedRule();

        _rulesDeleteButton.Enabled = rule is not null;
        _rulesGroupButton.Enabled = rule is not null;

        // 按「表格里实际显示了几条」来判断，而不是按内存缓存 ——
        // 按钮状态应该和用户看到的东西一致。
        _rulesDeleteAllButton.Enabled = _rules.Count > 0;

        if (rule is null)
        {
            _rulesHintLabel.Text = _rules.Count == 0
                ? Localizer.T("黑名单是空的")
                : Localizer.T("点击一条规则来选择要操作的程序 / IP");
            return;
        }

        var what = string.IsNullOrEmpty(rule.IpAddress)
            ? rule.ApplicationNameText
            : $"IP {rule.IpAddress}";

        _rulesHintLabel.Text = Localizer.F("已选中 {0}", what);
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

            var scanTask = Task.Run(() => ConnectionScanner.Scan(options));

            // 3.5：流量快照和连接扫描并行取，避免小请求把首屏拖慢。
            var trafficTask = Task.Run(QueryTrafficSnapshot);

            var connections = await scanTask;
            var traffic = await trafficTask;

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

            ApplyTrafficSnapshot(connections, traffic.Traffic, traffic.Supported);

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

            // 3.5：界面读不到的提权/受保护进程路径，交给服务（SYSTEM）代查。
            _ = ResolveMissingProcessPathsAsync();
        }
        catch (Exception ex)
        {
            if (IsDisposed || Disposing)
            {
                return;
            }

            _summaryLabel.Text = Localizer.T("扫描失败");

            // 关掉自动刷新，否则会每隔 3 秒弹一次错误框，把界面顶死。
            _autoRefreshCheckBox.Checked = false;

            ShowError("扫描 TCP 连接失败", ex, "Failed to scan TCP connections");
        }
        finally
        {
            _isScanning = false;
            _refreshButton.Enabled = true;
        }
    }

    // ==================================================================
    // 3.5：每程序流量
    // ==================================================================

    /// <summary>
    /// 向服务要一份流量快照。
    /// 服务没运行 → 保持上次结论（界面显示破折号）；
    /// 旧服务返回“未知命令” → Supported=false，隐藏流量列，不显示一堆假的 0。
    /// </summary>
    private TrafficQueryResult QueryTrafficSnapshot()
    {
        try
        {
            var response = ServiceClient.TryRequest(
                new ServiceRequest { Command = ServiceProtocol.Commands.QueryTraffic },
                TimeSpan.FromSeconds(2),
                out _);

            if (response is null)
            {
                return new TrafficQueryResult(null, _trafficSupported);
            }

            return response is { Ok: true, Traffic: not null }
                ? new TrafficQueryResult(response.Traffic, true)
                : new TrafficQueryResult(null, false);
        }
        catch (Exception)
        {
            return new TrafficQueryResult(null, _trafficSupported);
        }
    }

    private readonly record struct TrafficQueryResult(List<TrafficDto>? Traffic, bool Supported);

    /// <summary>
    /// 把服务聚合好的流量按「路径优先、PID 兜底」贴到每一行。
    ///
    /// 为什么路径优先：服务按路径合并同一程序的多个实例；PID 会复用，
    /// 拿 PID 当主键会把上一个程序的流量算到新程序头上。
    /// 只有服务也拿不到路径时，才用 PID 兜底。
    /// </summary>
    private void ApplyTrafficSnapshot(
        IReadOnlyList<TcpConnectionItem> connections,
        List<TrafficDto>? traffic,
        bool supported)
    {
        if (!_trafficColumnVisibilityApplied || _trafficSupported != supported)
        {
            _trafficColumnVisibilityApplied = true;
            _trafficSupported = supported;
            SetTrafficColumnsVisible(supported);
        }

        _trafficByPath.Clear();
        _trafficByPid.Clear();

        if (traffic is not null)
        {
            foreach (var item in traffic)
            {
                if (item.IsPathKnown && !string.IsNullOrEmpty(item.Path))
                {
                    _trafficByPath[item.Path] = item;
                }
                else if (item.Pids is { Count: > 0 })
                {
                    foreach (var pid in item.Pids)
                    {
                        _trafficByPid[pid] = item;
                    }
                }
            }
        }

        foreach (var connection in connections)
        {
            ApplyTrafficTo(connection);
        }
    }

    /// <summary>给单行贴流量（路径优先，PID 兜底）。</summary>
    private void ApplyTrafficTo(TcpConnectionItem item)
    {
        if (!string.IsNullOrEmpty(item.ProcessPath)
            && _trafficByPath.TryGetValue(item.ProcessPath, out var byPath))
        {
            item.ApplyTraffic(byPath.BytesOut, byPath.BytesIn);
            return;
        }

        if (_trafficByPid.TryGetValue(item.Pid, out var byPid))
        {
            item.ApplyTraffic(byPid.BytesOut, byPid.BytesIn);
        }
    }

    /// <summary>旧服务不支持 query.traffic 时隐藏三列，而不是让用户看着一列破折号猜。</summary>
    private void SetTrafficColumnsVisible(bool visible)
    {
        foreach (var name in new[]
                 {
                     nameof(TcpConnectionItem.TrafficOutText),
                     nameof(TcpConnectionItem.TrafficInText),
                     nameof(TcpConnectionItem.TrafficTotalText),
                 })
        {
            if (_connectionGrid.Columns[name] is { } column)
            {
                column.Visible = visible;
            }
        }

        if (!visible
            && _sortColumn is ConnectionSortColumn.TrafficOut
                or ConnectionSortColumn.TrafficIn
                or ConnectionSortColumn.TrafficTotal)
        {
            _sortColumn = ConnectionSortColumn.None;
            _sortAscending = true;
            UpdateSortGlyphs();
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
            LocalLog.Error(LocalLog.Pick("检查数字签名失败", "Failed to check the digital signature."), ex);
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
            ? LocalLog.Pick(
                "已开启证书吊销检查：Windows 证书服务会联网查询 CA 服务器。",
                "Certificate revocation checking enabled: Windows Certificate Services will contact CA servers.")
            : LocalLog.Pick(
                "已关闭证书吊销检查：只读本地缓存，本程序完全不留网络流量。",
                "Certificate revocation checking disabled: local cache only; this app generates no network traffic."));

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
            ? LocalLog.Pick(
                $"已开启 IP 归属查询：会把远程 IP 发送到 {AppConstants.OwnershipLookupHost}:{AppConstants.OwnershipLookupPort} 查询归属。",
                $"IP ownership lookup enabled: remote IPs are sent to {AppConstants.OwnershipLookupHost}:{AppConstants.OwnershipLookupPort}.")
            : LocalLog.Pick(
                "已关闭 IP 归属查询：此后不再产生任何相关网络请求。",
                "IP ownership lookup disabled: no related network requests will be made."));

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

        UiMessageBox.Show(
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
            UiMessageBox.Show(this, reason, AppConstants.AppName, MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        var connectionCount = _connections.Count(c => PathsEqual(c.ProcessPath, item.ProcessPath));
        var ruleName = RuleNaming.BuildBlockRuleName(item.ProcessPath);

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
            var response = CallService(
                ServiceProtocol.Commands.AddProgramRule,
                new ServiceRequest
                {
                    Value = item.ProcessPath,
                    Action = "block",
                    Expiry = chosenExpiry.Encode(),
                    Scope = RuleScope.Any.Encode(),
                },
                "阻止联网");

            if (response is null)
            {
                return;
            }

            LocalLog.Operation(LocalLog.Pick(
                $"阻止联网：{item.ProcessPath}（时长：{chosenExpiry.DescribeSchedule()}）",
                $"Block network access: {item.ProcessPath} (duration: {DescribeScheduleEnglish(chosenExpiry)})."));

            AfterRulesChanged();
        }
        catch (Exception ex)
        {
            ShowError("阻止失败", ex, "Failed to block");
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
    /// <summary>
    /// 黑名单页「添加程序…」：按路径把一个程序加进黑名单（永久阻止）。
    ///
    /// 为什么要有：有些程序只在后台悄悄联网，连接页不一定抓得到；
    /// 而且白名单页有「添加程序…」，两边对称才不会让人觉得"为什么那边能加、这边不能"。
    /// </summary>
    private void OnRulesAddButtonClick(object? sender, EventArgs e)
    {
        using var dialog = new OpenFileDialog
        {
            Title = "选择要阻止联网的程序",
            Filter = "程序 (*.exe)|*.exe",
            CheckFileExists = true,
            Multiselect = false,
        };

        if (dialog.ShowDialog(this) != DialogResult.OK)
        {
            return;
        }

        var path = dialog.FileName;
        var name = Path.GetFileName(path);

        if (ProtectedProcesses.IsProtected(path, out var reason))
        {
            UiMessageBox.Show(
                this,
                $"不能阻止「{name}」：{reason}。",
                AppConstants.AppName,
                MessageBoxButtons.OK,
                MessageBoxIcon.Warning);
            return;
        }

        var scope = RuleScopeForm.Ask(DialogOwner, RuleScope.Any);

        if (scope is null)
        {
            return;
        }

        var confirmed = ConfirmForm.Show(
            owner: DialogOwner,
            title: "加入黑名单",
            question: $"确定要阻止「{name}」联网吗？",
            details: new[]
            {
                new KeyValuePair<string, string>("程序名", name),
                new KeyValuePair<string, string>("完整路径", path),
                new KeyValuePair<string, string>("生效范围", scope.Describe()),
                new KeyValuePair<string, string>("将创建规则",
                    RuleNaming.BuildBlockRuleName(path)),
            },
            warnings: new[]
            {
                scope.IsAny
                    ? "确认后该程序会立刻无法联网（已经建立的连接也会断开）。"
                    : Localizer.IsEnglish
                        ? $"Only \"{DescribeScopeEnglish(scope)}\" is blocked: connections on other ports or networks are unaffected."
                        : $"只拦「{scope.Describe()}」：其它端口 / 网络位置上的连接不受影响。",
                "这是永久规则，要恢复请回到这一页删除它。",
                "想限时阻止（30 分钟 / 2 小时 / 下次重启），请到「联网连接」页操作。",
            },
            confirmText: "阻止");

        if (!confirmed)
        {
            return;
        }

        try
        {
            var response = CallService(
                ServiceProtocol.Commands.AddProgramRule,
                new ServiceRequest
                {
                    Value = path,
                    Action = "block",
                    Expiry = RuleExpiry.Never.Encode(),
                    Scope = scope.Encode(),
                },
                "加入黑名单");

            if (response is null)
            {
                return;
            }

            LocalLog.Operation(LocalLog.Pick($"加入黑名单：{path}（范围 {scope.Describe()}）", $"Add to blocklist: {path} (scope {DescribeScopeEnglish(scope)})."));
            AfterRulesChanged();
        }
        catch (Exception ex)
        {
            ShowError("加入黑名单失败", ex, "Failed to add to the blocklist");
        }
    }

    /// <summary>
    /// 弹出确认框，删除某个程序的**阻止**规则（即「允许它联网」）。
    ///
    /// 2.1.2 起只删阻止规则：白名单（允许规则）在「严格模式下白名单」页单独管理，
    /// 点一次「解除阻止」不应该顺手把程序踢出白名单。
    /// </summary>
    /// <returns>确实执行了删除返回 true；用户取消或无事可做返回 false。</returns>
    private bool ConfirmAndAllowProgram(string programPath, string programName)
    {
        var rulesForProgram = _appGuardRules
            .Where(rule => rule.Action == FirewallAction.Block
                           && PathsEqual(rule.ApplicationPath, programPath))
            .ToList();

        if (rulesForProgram.Count == 0)
        {
            // 可能是规则被人在 wf.msc 里删掉了，缓存过期。同步一次再说。
            AfterRulesChanged();

            UiMessageBox.Show(
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
            title: "解除阻止（允许联网）",
            question: $"确定要解除对「{programName}」的阻止吗？",
            details: new[]
            {
                new KeyValuePair<string, string>("程序名", programName),
                new KeyValuePair<string, string>("完整路径", programPath),
                new KeyValuePair<string, string>("将删除规则", $"{rulesForProgram.Count} 条"),
                new KeyValuePair<string, string>("会新建允许规则吗", "不会（删除即恢复放行）"),
            },
            warnings: new[]
            {
                "只会删除下面这些由 WinAppGuard 创建的规则：",
                ruleList,
                "不会创建任何允许规则 —— 2.0 起默认就是放行，删掉阻止规则就等于恢复联网。",
                "其他程序、以及系统和其他软件设置的防火墙规则一律不受影响。",
                "删除后该程序可以立刻重新联网；如果它没有自己恢复，重启该程序即可。",
            },
            confirmText: "解除阻止");

        if (!confirmed)
        {
            return false;
        }

        try
        {
            var response = CallService(
                ServiceProtocol.Commands.DeleteRulesForProgram,
                new ServiceRequest { Value = programPath },
                "允许联网");

            if (response is null)
            {
                return false;
            }

            LocalLog.Operation(LocalLog.Pick($"允许联网：{programPath}（删除 {response.Affected} 条规则）", $"Allow network access: {programPath} ({response.Affected} rules deleted)."));
            AfterRulesChanged();
            return true;
        }
        catch (Exception ex)
        {
            ShowError("允许失败", ex, "Failed to allow");
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
        var ruleName = RuleNaming.BuildAllowRuleName(programPath);

        var warnings = new List<string>
        {
            $"会创建一条「允许出站」的防火墙规则：{ruleName}",
            "严格模式生效时，只有加了白名单的程序才能上网；没加的一律上不了网。",
            "放行不会影响其它程序，也永远不会把谁锁在外面。",
            "「规则」页里能看到这条规则，随时可以删掉（那就是移出白名单）。",
        };

        if (!_strictModeEnabled)
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
            var response = CallService(
                ServiceProtocol.Commands.AddProgramRule,
                new ServiceRequest
                {
                    Value = programPath,
                    Action = "allow",
                    Expiry = RuleExpiry.Never.Encode(),
                    Scope = RuleScope.Any.Encode(),
                },
                "加入白名单");

            if (response is null)
            {
                return;
            }

            LocalLog.Operation(LocalLog.Pick($"加入白名单：{programPath}", $"Add to allowlist: {programPath}."));
            AfterRulesChanged();
        }
        catch (Exception ex)
        {
            ShowError("加入白名单失败", ex, "Failed to add to the allowlist");
        }
    }

    /// <summary>
    /// 把程序移出白名单 —— 删掉**本工具为它建的那条**允许规则。
    ///
    /// 只会删以 AppGuard_Allow_ 开头、且属于这个程序的那一条：
    /// 别人的规则我们碰都不碰（<see cref="RuleEngine.DeleteRule"/> 只删本程序写进 WFP 的规则）。
    /// </summary>
    private void RemoveFromWhitelist(string programPath, string programName)
    {
        var ruleName = RuleNaming.BuildAllowRuleName(programPath);

        var warnings = new List<string>
        {
            $"会删掉这条「允许出站」规则：{ruleName}",
        };

        if (_strictModeEnabled)
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
            var response = CallService(
                ServiceProtocol.Commands.DeleteRule,
                new ServiceRequest { RuleName = ruleName },
                "移出白名单");

            if (response is null)
            {
                // 规则可能已经在别处被删掉：同步一次，让界面回到真实状态。
                AfterRulesChanged();
                return;
            }

            LocalLog.Operation(LocalLog.Pick($"移出白名单：{programPath}（规则 {ruleName}）", $"Remove from allowlist: {programPath} (rule {ruleName})."));
            AfterRulesChanged();
        }
        catch (Exception ex)
        {
            ShowError("移出白名单失败", ex, "Failed to remove from the allowlist");
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
                    _strictModeEnabled
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
            var response = CallService(
                ServiceProtocol.Commands.DeleteRule,
                new ServiceRequest { RuleName = rule.Name },
                "删除规则");

            if (response is null)
            {
                return;
            }

            LocalLog.Operation(LocalLog.Pick($"删除规则：{rule.Name}（程序 {rule.ApplicationPath}）", $"Delete rule: {rule.Name} (program {rule.ApplicationPath})."));
            AfterRulesChanged();
        }
        catch (Exception ex)
        {
            ShowError("删除规则失败", ex, "Failed to delete the rule");
        }
    }

    /// <summary>
    /// 托盘菜单：清空全部规则（黑名单 + 白名单一起删）。
    /// 这是不可撤销的批量操作，所以需要**连续确认两次**。
    /// </summary>
    private void OnRulesDeleteAllButtonClick(object? sender, EventArgs e)
    {
        // 黑名单页的「清空」只删**阻止**规则；白名单在另一页，各自管各自的。
        var rules = _rules;

        if (rules.Count == 0)
        {
            AfterRulesChanged();
            UiMessageBox.Show(
                this,
                "黑名单是空的，无需清理。",
                AppConstants.AppName,
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
            return;
        }

        var ruleList = string.Join(
            Environment.NewLine,
            rules.Select(r => $"    {r.Name}  →  {r.ApplicationPath}"));

        // 只删黑名单（阻止规则），**不动白名单**：白名单在单独一页，有自己的「清空」按钮。
        var deleteWarnings = new List<string>
        {
            "将要删除的阻止规则如下：",
            ruleList,
            "删除后这些程序会立刻恢复联网（封禁的 IP 也会立刻解封）。",
            "其他软件和系统自带的防火墙规则，以及白名单，都不受影响。",
        };

        // ---------------- 第一次确认：说明清楚要删什么 ----------------
        var firstConfirmed = ConfirmForm.Show(
            owner: DialogOwner,
            title: "清空黑名单",
            question: $"确定要清空黑名单吗？（共 {rules.Count} 条阻止规则）",
            details: new[]
            {
                new KeyValuePair<string, string>("规则条数", $"{rules.Count} 条"),
                new KeyValuePair<string, string>("影响", "这些程序 / IP 将立刻恢复联网 / 解封"),
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
            question: "这一步不可撤销，确定要清空黑名单吗？",
            details: new[]
            {
                new KeyValuePair<string, string>("规则条数", $"{rules.Count} 条"),
            },
            warnings: new[]
            {
                "清空后这些程序会立刻恢复联网（封禁的 IP 立刻解封）。",
                "如果你只是想放行某一个程序，删那一条就够了，不要用这个按钮。",
                "白名单在另一页，这一步不会动它。",
            },
            confirmText: "确认清空");

        if (!secondConfirmed)
        {
            return;
        }

        try
        {
            var response = CallService(
                ServiceProtocol.Commands.ClearBlocklist,
                new ServiceRequest(),
                "清空黑名单");

            if (response is null)
            {
                return;
            }

            LocalLog.Operation(LocalLog.Pick($"清空黑名单：实际删除 {response.Affected} 条阻止规则", $"Clear blocklist: {response.Affected} block rules deleted."));
            AfterRulesChanged();

            UiMessageBox.Show(
                this,
                $"已清空黑名单，删除 {response.Affected} 条阻止规则。\n\n" +
                "这些程序现在可以重新联网；白名单和其它软件的规则没有受到影响。",
                AppConstants.AppName,
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
        }
        catch (Exception ex)
        {
            ShowError("清空黑名单失败", ex, "Failed to clear the blocklist");
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
        nameof(TcpConnectionItem.TrafficOutText) => ConnectionSortColumn.TrafficOut,
        nameof(TcpConnectionItem.TrafficInText) => ConnectionSortColumn.TrafficIn,
        nameof(TcpConnectionItem.TrafficTotalText) => ConnectionSortColumn.TrafficTotal,
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
        ConnectionSortColumn.TrafficOut => nameof(TcpConnectionItem.TrafficOutText),
        ConnectionSortColumn.TrafficIn => nameof(TcpConnectionItem.TrafficInText),
        ConnectionSortColumn.TrafficTotal => nameof(TcpConnectionItem.TrafficTotalText),
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
                    _autostartStatusLabel.Text = Localizer.T("当前状态：已开启");
                    _autostartStatusLabel.ForeColor = Color.FromArgb(0, 120, 0);
                    break;

                case AutoStartState.Misconfigured:
                    _autostartStatusLabel.Text = Localizer.T("当前状态：已开启，但任务指向的不是当前程序");
                    _autostartStatusLabel.ForeColor = Color.FromArgb(191, 87, 0);
                    break;

                default:
                    _autostartStatusLabel.Text = Localizer.T("当前状态：未开启");
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
            LocalLog.Error(LocalLog.Pick("读取开机自启状态失败", "Failed to read the auto-start status."), ex);
            _autostartStatusLabel.Text = Localizer.T("当前状态：读取失败");
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
        if (Localizer.IsEnglish)
        {
            if (!status.Exists)
            {
                return "This task does not exist. Click Enable auto-start to create it.";
            }

            var level = string.Equals(status.RunLevel, "HighestAvailable", StringComparison.OrdinalIgnoreCase)
                ? "Highest privileges (no UAC prompt at logon)"
                : status.RunLevel;

            var english = new List<string>
            {
                $"Task name: {AppConstants.ScheduledTaskName}",
                $"Executable: {status.ExecutablePath}",
                $"Arguments: {status.Arguments}",
                $"Run level: {level}",
                $"Trigger: {status.Trigger}",
                $"Task state: {status.TaskState}",
            };

            if (status.State == AutoStartState.Misconfigured)
            {
                english.Add($"Current executable: {Environment.ProcessPath}");
                english.Add("The paths differ — the app was probably moved. Click Enable auto-start again to fix it.");
            }

            return string.Join(Environment.NewLine, english);
        }

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
            UiMessageBox.Show(
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
            if (AdminHelper.IsRunningAsAdmin())
            {
                AutoStartManager.Enable(exePath);
            }
            else if (!RunElevatedAutostart(enable: true, exePath))
            {
                throw new InvalidOperationException("已取消管理员授权，开机自启未开启。");
            }

            LocalLog.Operation(LocalLog.Pick($"开启开机自启：任务名 {AppConstants.ScheduledTaskName}，执行的程序 {exePath}", $"Enable auto-start: task {AppConstants.ScheduledTaskName}, command {exePath}."));
            RefreshAutoStartStatus();

            UiMessageBox.Show(
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

            ShowError("开启开机自启失败", ex, "Failed to enable auto-start");
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
            bool deleted;

            if (AdminHelper.IsRunningAsAdmin())
            {
                deleted = AutoStartManager.Disable();
            }
            else
            {
                if (!RunElevatedAutostart(enable: false, Environment.ProcessPath ?? Application.ExecutablePath))
                {
                    throw new InvalidOperationException("已取消管理员授权，开机自启任务未删除。");
                }

                deleted = true;
            }

            LocalLog.Operation(LocalLog.Pick($"关闭开机自启：删除任务 {AppConstants.ScheduledTaskName}，实际删除={(deleted ? "是" : "任务本来就不存在")}", $"Disable auto-start: task {AppConstants.ScheduledTaskName}, deleted={deleted}."));
            RefreshAutoStartStatus();

            UiMessageBox.Show(
                this,
                deleted ? "开机自启已关闭，任务已从任务计划程序里删除。" : "系统里本来就没有这个任务，无需删除。",
                AppConstants.AppName,
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
        }
        catch (Exception ex)
        {
            RefreshAutoStartStatus();

            ShowError("关闭开机自启失败", ex, "Failed to disable auto-start");
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
            LocalLog.Info(LocalLog.Pick("收到另一个实例的请求，把主窗口显示出来。", "Another instance asked to show the main window."));
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
        => ShowTrayBalloon(title, text, ToolTipIcon.Info);

    private void ShowTrayBalloon(string title, string text, ToolTipIcon icon)
    {
        _trayIcon.ShowBalloonTip(
            5000, Localizer.T(title), Localizer.T(text), icon);
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
                "如果想让它们恢复联网，请先回到主界面用「解除阻止（允许联网）」，或用托盘菜单的「清空全部规则」。",
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

        LocalLog.Info(LocalLog.Pick($"用户从托盘退出程序。退出时被阻止的程序数={blockedCount}，规则依然生效。", $"User exited from the tray. Blocked programs at exit={blockedCount}; rules remain active."));
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
    /// <summary>3.3：白名单页顶部说明（纯函数，便于自检两种语言）。</summary>
    internal static string BuildWhitelistNotice(bool strictModeOn)
    {
        if (Localizer.IsEnglish)
        {
            return "The whitelist only applies in strict mode: while strict mode is on, only the programs listed here "
                   + "(plus required system programs) can reach the network.\r\n"
                   + "When strict mode is off, these rules restrict nothing.\r\n"
                   + (strictModeOn
                       ? "Now: strict mode is ON — this whitelist is in effect."
                       : "Now: strict mode is OFF — this whitelist has no effect.");
        }

        return "白名单只在「严格模式」下起作用：严格模式开着时，只有这里列出的程序"
               + "（以及系统必需程序）能上网。\r\n"
               + "严格模式没开时，这些规则不会限制任何东西。\r\n"
               + (strictModeOn
                   ? "当前：严格模式已开启 —— 白名单正在生效。"
                   : "当前：严格模式未开启 —— 白名单暂不生效。");
    }
    /// <summary>3.3：日志用的英文范围描述（中文仍走 RuleScope.Describe）。</summary>
    private static string DescribeScopeEnglish(RuleScope scope)
        => scope.IsAny ? "any" : scope.Encode();

    /// <summary>3.3：日志用的英文到期描述（绝对时间，便于追溯）。</summary>
    private static string DescribeScheduleEnglish(RuleExpiry expiry)
        => expiry.Kind switch
        {
            RuleExpiryKind.AtTime when expiry.ExpiresAtUtc is { } at =>
                $"until {at.ToLocalTime():yyyy-MM-dd HH:mm}",
            RuleExpiryKind.OnNextBoot => "until next restart",
            _ => "permanent",
        };

    private void ShowError(string what, Exception ex, string? whatEnglish = null)
    {
        LocalLog.Error(LocalLog.Pick(what, whatEnglish ?? "Operation failed."), ex);

        UiMessageBox.Show(
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

    /// <summary>
    /// 展开/收起「任务计划程序原始 XML」。
    /// 默认收起：这块内容只有极少数场景要看，常驻会把设置页拉长 220px。
    /// </summary>
    private void OnToggleTaskXmlClick(object? sender, EventArgs e)
    {
        _taskXmlPanel.Visible = !_taskXmlPanel.Visible;

        _toggleTaskXmlButton.Text = _taskXmlPanel.Visible
            ? "收起任务计划原始定义"
            : "查看任务计划原始定义…";

        // 展开时顺手重新读一次，避免看到几小时前的旧内容。
        if (_taskXmlPanel.Visible)
        {
            RefreshAutoStartStatus();
        }
    }

    /// <summary>项目主页（开源标识点击后打开）。</summary>
    internal const string ProjectUrl = "https://github.com/lovercyh/winappguard";

    /// <summary>点开源标识：用默认浏览器打开项目主页。</summary>
    private void OnOpenSourceLinkClicked(object? sender, LinkLabelLinkClickedEventArgs e)
    {
        try
        {
            _openSourceLink.LinkVisited = true;

            System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo
            {
                FileName = ProjectUrl,
                UseShellExecute = true,
            });
        }
        catch (Exception ex)
        {
            // 打不开浏览器不是致命问题，但要让用户知道可以自己复制地址。
            UiMessageBox.Show(
                this,
                $"打不开浏览器。可以手动访问：\n{ProjectUrl}\n\n（{ex.Message}）",
                AppConstants.AppName,
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
        }
    }

    /// <summary>状态栏「服务：未运行」被点击：启动服务（需要管理员）。</summary>
    private void OnServiceStatusLabelClick(object? sender, EventArgs e)
    {
        if (_serviceAvailable)
        {
            return;
        }

        if (!ServiceIsInstalled())
        {
            UiMessageBox.Show(
                this,
                "防护服务还没有安装。\n\n请运行安装目录里的 WinAppGuardSetup.exe --install。",
                AppConstants.AppName,
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
            return;
        }

        if (FindSetupPath() is null)
        {
            UiMessageBox.Show(
                this,
                "找不到 WinAppGuardSetup.exe，无法启动服务。\n\n" +
                "请重新运行安装器（--repair）。",
                AppConstants.AppName,
                MessageBoxButtons.OK,
                MessageBoxIcon.Warning);
            return;
        }

        if (TryStartService(interactive: true))
        {
            ShowTrayBalloon(Localizer.T("正在启动防护服务…"), Localizer.T("启动成功后界面会自动恢复可编辑状态。"));
        }
    }

    /// <summary>
    /// 服务没在运行时尝试自动拉起一次。
    /// 只在界面**已经是管理员**时自动做 —— 否则会在启动时突然弹 UAC，
    /// 那属于"用户没要求的提权"。非管理员场景由用户点状态栏链接触发。
    /// </summary>
    private void MaybeAutoStartService()
    {
        if (_triedAutoStartService)
        {
            return;
        }

        _triedAutoStartService = true;

        if (!AdminHelper.IsRunningAsAdmin()
            || !ServiceIsInstalled()
            || FindSetupPath() is null)
        {
            return;
        }

        LocalLog.Info(LocalLog.Pick("服务未运行：界面以管理员运行，尝试自动启动。", "Service is not running: the UI has admin rights and will try to start it."));
        _ = Task.Run(() => TryStartService(interactive: false));
    }

    /// <summary>
    /// 以提权助手执行「开启/关闭开机自启」（普通权限界面用）。
    /// 助手是 WinAppGuardSvc.exe（同一份 exe，多一个模式）。
    /// </summary>
    private static bool RunElevatedAutostart(bool enable, string exePath)
    {
        var helper = Path.Combine(AppContext.BaseDirectory, "WinAppGuardSvc.exe");

        if (!File.Exists(helper))
        {
            return false;
        }

        try
        {
            var startInfo = new ProcessStartInfo(helper)
            {
                UseShellExecute = true,
                Verb = "runas",
                WindowStyle = ProcessWindowStyle.Hidden,
                Arguments = $"--elevated-autostart {(enable ? "enable" : "disable")} \"{exePath}\"",
            };

            using var process = Process.Start(startInfo);

            if (process is null)
            {
                return false;
            }

            if (!process.WaitForExit(60_000))
            {
                return false;
            }

            return process.ExitCode == 0;
        }
        catch (System.ComponentModel.Win32Exception ex) when (ex.NativeErrorCode == 1223)
        {
            // 用户取消 UAC。
            return false;
        }
        catch (Exception ex)
        {
            LocalLog.Warning(LocalLog.Pick($"提权修改开机自启失败：{ex.Message}", "Failed to change auto-start with elevation."));
            return false;
        }
    }

    /// <summary>用安装器的 --start-service 启动服务（顺带修正「延迟启动」）。</summary>
    private static bool TryStartService(bool interactive)
    {
        var setup = FindSetupPath();

        if (setup is null)
        {
            return false;
        }

        try
        {
            var startInfo = new ProcessStartInfo(setup, "--start-service")
            {
                UseShellExecute = interactive,
                CreateNoWindow = !interactive,
            };

            if (interactive)
            {
                if (!AdminHelper.IsRunningAsAdmin())
                {
                    startInfo.Verb = "runas";
                }
            }
            else
            {
                startInfo.RedirectStandardOutput = true;
                startInfo.RedirectStandardError = true;
            }

            using var process = Process.Start(startInfo);

            if (process is null)
            {
                return false;
            }

            if (interactive)
            {
                return true;
            }

            if (!process.WaitForExit(15000))
            {
                try
                {
                    process.Kill();
                }
                catch (Exception)
                {
                    // 杀不掉也不影响：下次探测会再看一次状态。
                }

                return false;
            }

            LocalLog.Info(LocalLog.Pick($"自动启动服务：退出码 {process.ExitCode}", $"Auto-start service: exit code {process.ExitCode}."));
            return process.ExitCode == 0;
        }
        catch (Exception ex)
        {
            // 用户在 UAC 里点"否"也走这里（Win32 1223）；不打扰，记日志即可。
            LocalLog.Warning(LocalLog.Pick($"启动服务失败：{ex.Message}", "Failed to start the service."));
            return false;
        }
    }

    private static bool ServiceIsInstalled()
    {
        try
        {
            using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(
                @"SYSTEM\CurrentControlSet\Services\" + ServiceProtocol.ServiceName);

            return key is not null;
        }
        catch (Exception)
        {
            return false;
        }
    }

    private static string? FindSetupPath()
    {
        var candidates = new[]
        {
            Path.Combine(AppContext.BaseDirectory, "WinAppGuardSetup.exe"),
            Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                "WinAppGuard",
                "WinAppGuardSetup.exe"),
        };

        return candidates.FirstOrDefault(File.Exists);
    }

    /// <summary>
    /// 异步探测防护服务状态，然后回到 UI 线程更新状态栏。
    /// 连不上是**正常状态**（离线模式），不弹窗、不报错。
    /// </summary>
    private void ProbeServiceStatus()
    {
        _ = Task.Run(() =>
        {
            var status = ServiceClient.TryGetStatus(TimeSpan.FromSeconds(1.5));

            try
            {
                if (IsDisposed || !IsHandleCreated)
                {
                    return;
                }

                BeginInvoke(new Action(() =>
                {
                    UpdateServiceStatusLabel(status);

                    // 服务从"不通"变成"通"：自动把规则页从只读恢复成可编辑，
                    // 不需要用户手动点刷新（服务延迟启动时很常见）。
                    if (status is not null && !_serviceAvailable && !IsDisposed)
                    {
                        RefreshRulesFromFirewall();
                    }
                    else if (status is null
                             && ProtectedModeClient.CurrentStatus.State
                                == ProtectedModeState.Ready)
                    {
                        // 服务没起来：如果界面已经是管理员、且服务已安装，顺手拉一次。
                        // （非管理员时不主动弹 UAC —— 用户点状态栏的"点击启动"即可。）
                        // 不是所有者/密钥不可用时不要尝试启动，那只会制造误导。
                        MaybeAutoStartService();
                    }
                }));
            }
            catch (Exception)
            {
                // 窗口正在关闭：丢弃这次结果。
            }
        });
    }

    /// <summary>更新服务状态标签（自检直接调用它验证两种状态）。</summary>
    internal void UpdateServiceStatusLabel(ServiceStatus? status)
    {
        if (status is null)
        {
            // 3.1：先说明“为什么连不上”——不是所有者 / 密钥不可用 / 未初始化，
            // 而不是一律显示“服务未运行”，让用户去点启动。
            var protectedMode = ProtectedModeClient.CurrentStatus;

            if (protectedMode.State != ProtectedModeState.Ready)
            {
                var (text, tooltip, reason, ruleReason) = protectedMode.State switch
                {
                    ProtectedModeState.NotOwner => (
                        "受保护模式：当前账户不是所有者（离线模式，界面只读）",
                        "只有安装 WinAppGuard 时的账户能使用服务。\n"
                        + "请用所有者账户登录；或由管理员运行 WinAppGuardSetup.exe --reset-owner。",
                        "受保护模式：当前账户不是所有者",
                        "当前账户不是所有者（规则只读）"),
                    ProtectedModeState.KeyUnavailable => (
                        "受保护模式：密钥不可用（离线模式，界面只读）",
                        "密钥文件缺失，或 DPAPI 解不开。\n"
                        + "请以所有者身份运行 WinAppGuardSetup.exe --rotate-key 重建密钥。",
                        "受保护模式：密钥不可用",
                        "密钥不可用（规则只读）"),
                    ProtectedModeState.ConfigBroken => (
                        "受保护模式：配置损坏（离线模式，界面只读）",
                        "受保护模式配置无法读取或校验失败。\n"
                        + "请以所有者身份运行 WinAppGuardSetup.exe --repair。",
                        "受保护模式：配置损坏",
                        "受保护模式配置损坏（规则只读）"),
                    _ => (
                        "服务：未运行（离线模式）—— 受保护模式未初始化",
                        "还没有受保护模式密钥。\n"
                        + "请运行 WinAppGuardSetup.exe --install/--repair。",
                        "受保护模式未初始化",
                        "受保护模式未初始化（规则只读）"),
                };

                _serviceStatusLabel.Text = Localizer.T(text);
                _serviceStatusLabel.ForeColor = Color.FromArgb(150, 90, 0);
                _serviceStatusLabel.IsLink = false;
                _serviceStatusLabel.ToolTipText = Localizer.T(tooltip);

                _serviceAvailable = false;
                _statusRulesLabel.Text = Localizer.T(ruleReason);
                MarkRulesReadOnly(reason);
                UpdateRulesActionState();
                UpdateWhitelistActionState();
                UpdateActionState();

                _strictModeEnabled = false;
                _strictModePermittedCount = 0;
                _dnsCollecting = false;
                NotifyLockdownEndedByService();
                RefreshStrictModeStatus();

                _auditCollecting = false;
                UpdateAuditControlsEnabled();
                return;
            }

            var installed = ServiceIsInstalled();

            _serviceStatusLabel.Text = Localizer.T(installed
                ? "服务：未运行（离线模式）—— 点击启动"
                : "服务：未运行（离线模式）");
            _serviceStatusLabel.ForeColor = Color.FromArgb(150, 90, 0);
            _serviceStatusLabel.IsLink = installed;
            _serviceStatusLabel.ToolTipText = Localizer.T(installed
                ? "防护服务没有运行：点击这里启动（需要管理员权限）。\n" +
                  "规则页面在服务恢复前只读；查看连接和导出仍然可用。"
                : "防护服务未安装：规则页面只读。\n" +
                  "请运行 WinAppGuardSetup.exe --install 安装服务。");

            // 服务停了要**立刻**反映到规则页，不能等用户去点刷新。
            _serviceAvailable = false;
            _statusRulesLabel.Text = Localizer.T("防护服务未运行（规则只读）");
            MarkRulesReadOnly("防护服务未运行");
            UpdateRulesActionState();
            UpdateWhitelistActionState();
            UpdateActionState();

            // 会话活在服务里：服务不在了，严格模式必然已经撤销。
            _strictModeEnabled = false;
            _strictModePermittedCount = 0;
            _dnsCollecting = false;
            NotifyLockdownEndedByService();
            RefreshStrictModeStatus();

            // 审计采集也随服务停止；已有记录仍可读。
            _auditCollecting = false;
            UpdateAuditControlsEnabled();
            return;
        }

        var lockdownWasActive = _lockdownActive;

        _strictModeEnabled = status.StrictModeActive;
        _strictModePermittedCount = status.StrictModePermittedCount;
        _dnsCollecting = status.DnsCollecting;
        _lockdownActive = status.StrictModeLockdownActive;
        _lockdownExpiresUtc = status.StrictModeLockdownExpiresUtc;
        RefreshStrictModeStatus();

        // 到点自动恢复：只提示一次。手动关闭会先把 _lockdownActive 清掉，不会误报。
        if (lockdownWasActive && !_lockdownActive)
        {
            ShowTrayBalloon("临时锁网已结束", "已到时间，网络自动恢复。");
        }

        // 审计设置 / 采集状态由服务给，界面只做显示与只读。
        ApplyAuditStatus(status);

        _serviceStatusLabel.Text =
            Localizer.F("服务：运行中 · {0} 条规则", status.BlockRuleCount + status.AllowRuleCount);
        _serviceStatusLabel.ForeColor = Color.FromArgb(0, 120, 0);
        _serviceStatusLabel.IsLink = false;
        _serviceStatusLabel.ToolTipText = Localizer.IsEnglish
            ? $"Service version {status.ServiceVersion}, protocol v{status.ProtocolVersion}.\n" +
              $"Sublayer {(status.SublayerPresent ? "present" : "missing")}; " +
              $"blocked {status.BlockRuleCount} / allowed {status.AllowRuleCount} / IP {status.IpRuleCount}." +
              (status.TamperRebuiltCount > 0
                  ? $"\nRebuilt {status.TamperRebuiltCount} externally deleted rules" +
                    (status.LastTamperUtc is { } lastEn ? $" (last {lastEn.ToLocalTime():MM-dd HH:mm})" : string.Empty)
                  : string.Empty)
            : $"服务版本 {status.ServiceVersion}，协议 v{status.ProtocolVersion}。\n" +
              $"子层{(status.SublayerPresent ? "存在" : "缺失")}；" +
              $"阻止 {status.BlockRuleCount} / 允许 {status.AllowRuleCount} / IP {status.IpRuleCount}。" +
              (status.TamperRebuiltCount > 0
                  ? $"\n已自动重建 {status.TamperRebuiltCount} 条被外部删除的规则" +
                    (status.LastTamperUtc is { } last ? $"（最近 {last.ToLocalTime():MM-dd HH:mm}）" : string.Empty)
                  : string.Empty);

        // 篡改提示：计数增加说明服务刚刚重建了规则（第一次同步不弹，避免启动即打扰）。
        if (_lastTamperRebuilt >= 0 && status.TamperRebuiltCount > _lastTamperRebuilt)
        {
            var rebuilt = status.TamperRebuiltCount - _lastTamperRebuilt;

            LocalLog.Warning(LocalLog.Pick($"检测到规则被外部删除：服务已自动重建 {rebuilt} 条。", $"Rules were deleted externally; the service rebuilt {rebuilt}."));
            ShowTrayBalloon(
                "规则被外部删除，已自动重建",
                $"检测到 {rebuilt} 条规则被人从系统里删掉，已按权威副本恢复。\n" +
                "如果这不是你做的，建议检查是谁在改动防火墙。",
                ToolTipIcon.Warning);
        }

        _lastTamperRebuilt = status.TamperRebuiltCount;

        // 临时阻断到期由服务定时解除；界面只负责提示 + 刷新列表。
        if (_lastExpiredPurged >= 0 && status.ExpiredPurgedCount > _lastExpiredPurged)
        {
            var programs = (status.LastPurgedPrograms ?? new List<string>())
                .Select(path => Path.GetFileName(path))
                .Where(name => !string.IsNullOrWhiteSpace(name))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            var text = programs.Count == 0
                ? "有临时阻断规则到期，已自动解除（详见服务日志）。"
                : programs.Count == 1
                    ? $"「{programs[0]}」的临时阻断已到期，已自动解除，它现在可以重新联网了。"
                    : $"{programs.Count} 个程序的临时阻断已到期，已自动解除：{string.Join("、", programs.Take(8))}";

            LocalLog.Operation(LocalLog.Pick($"临时阻断到期，服务已自动解除：{text}", $"Temporary block expired and was lifted automatically: {(programs.Count == 0 ? "unknown program" : string.Join(", ", programs.Take(8)))}."));
            ShowTrayBalloon(Localizer.T("临时阻断已自动解除"), text);
            RefreshRulesFromFirewall();
        }

        _lastExpiredPurged = status.ExpiredPurgedCount;
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
    //   3. 每个出口都留了"恢复默认放行"的路（严格模式会话由服务持有，服务停止即撤销）。
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
    private string BuildStrictModeDetailText(bool enabled)
    {
        if (Localizer.IsEnglish)
        {
            var english = new List<string>();

            if (enabled)
            {
                english.Add($"Now: only {_strictModePermittedCount} programs are allowed; new connections from everything else are blocked.");
                english.Add("This is a session-only restriction: turning strict mode off, or stopping/crashing the protection service, removes it immediately.");

                if (_lockdownActive && _lockdownExpiresUtc is { } lockdownExpires)
                {
                    english.Add($"Timed lockdown: {FormatLockdownRemaining(lockdownExpires - DateTime.UtcNow)}. It ends automatically; turning strict mode off or stopping the service also restores the network.");
                }
            }
            else
            {
                english.Add("When enabled: programs not on the whitelist cannot reach the network; only whitelisted programs are allowed.");
                english.Add("Whitelist = this tool's allow rules + this app + required system programs (DNS, time sync, Windows Update, etc.).");
                english.Add("Since 2.0 this is a true whitelist: allow rules created by Windows or other software no longer pass automatically.");
                english.Add("The restriction exists only for the current service session; stopping or crashing the service removes it automatically.");
                english.Add("It does not change any Windows Firewall setting.");
            }

            english.Add(string.Empty);
            english.Add($"WinAppGuard whitelist: {_whitelistedPaths.Count} programs" +
                        (SelfIsWhitelisted() ? " (including this app)" : " (this app is allowed automatically)"));
            english.Add($"Required system programs: {SystemAllowList.GetPaths().Count} (built-in list for DNS/update and other basics)");
            english.Add($"Allow rules for specific programs from Windows/other software: {_otherAllowPaths.Count} programs" +
                        " (not allowed automatically under strict mode — the biggest difference from 1.x)");
            english.Add($"There are also {_programlessAllowRuleCount} allow rules without a program (also inactive under strict mode; shown for reference)");

            return string.Join(Environment.NewLine, english);
        }

        var lines = new List<string>();

        if (enabled)
        {
            lines.Add($"现在：只放行 {_strictModePermittedCount} 个程序，其它程序的新连接会被拦掉。");
            lines.Add("这是「会话内」的临时限制：关闭严格模式、或防护服务停止/崩溃，限制立刻消失。");

            if (_lockdownActive && _lockdownExpiresUtc is { } lockdownExpires)
            {
                lines.Add($"临时锁网：{FormatLockdownRemaining(lockdownExpires - DateTime.UtcNow)}。到点自动恢复；关闭严格模式或服务停止也会立即恢复。");
            }
        }
        else
        {
            lines.Add("开启后：所有没加白名单的程序都上不了网（新连接会被拦掉），只放行白名单。");
            lines.Add("白名单 = 本工具的允许规则 + 本程序 + 系统必需程序（DNS、时间同步、Windows 更新等）。");
            lines.Add("2.0 是「真白名单」：Windows 自带和别的软件的允许规则不再自动放行。");
            lines.Add("限制只存在于本次服务运行期间（会话内）：服务停止或崩溃时会自动撤销，不需要还原。");
            lines.Add("它不会修改 Windows 防火墙的任何设置。");
        }

        lines.Add(string.Empty);
        lines.Add($"本工具白名单：{_whitelistedPaths.Count} 个程序" +
                  (SelfIsWhitelisted() ? "（含本工具自己）" : "（本程序会自动放行自己）"));
        lines.Add($"系统必需程序：{SystemAllowList.GetPaths().Count} 个（内置清单，保证 DNS / 更新等基础功能）");
        lines.Add($"系统/其它软件为具体程序建的允许规则：{_otherAllowPaths.Count} 个程序" +
                  "（严格模式下不再自动放行 —— 这是与 1.x 最大的区别）");
        lines.Add($"另有 {_programlessAllowRuleCount} 条「不限程序」的允许规则（严格模式下同样不生效，这里只作参考）");

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
            var enabled = _strictModeEnabled && _serviceAvailable;
            var lockdownRemaining = _lockdownActive && _lockdownExpiresUtc is { } expires
                ? expires - DateTime.UtcNow
                : TimeSpan.Zero;
            var lockdownActive = enabled && lockdownRemaining > TimeSpan.Zero;

            _strictModeStatusLabel.Text = !_serviceAvailable
                ? (Localizer.IsEnglish ? "Status: service is not running; strict mode unavailable" : "当前状态：服务未运行，严格模式不可用")
                : enabled
                    ? lockdownActive
                        ? (Localizer.IsEnglish
                            ? $"Status: timed lockdown active ({FormatLockdownRemaining(lockdownRemaining)}; {_strictModePermittedCount} programs allowed)"
                            : $"当前状态：临时锁网中（{FormatLockdownRemaining(lockdownRemaining)}，放行 {_strictModePermittedCount} 个程序）")
                        : (Localizer.IsEnglish
                            ? $"Status: strict mode active ({_strictModePermittedCount} programs allowed)"
                            : $"当前状态：严格模式生效中（放行 {_strictModePermittedCount} 个程序）")
                    : (Localizer.IsEnglish ? "Status: off; everything is allowed by default" : "当前状态：未开启，默认放行");

            _strictModeToggleButton.Text = enabled ? Localizer.T("关闭严格模式") : Localizer.T("开启严格模式…");

            // 会话归服务：服务不在就没有会话，按钮必须灰掉（不能假装还能开）。
            _strictModeToggleButton.Enabled = _serviceAvailable;

            // 临时锁网只允许在「严格模式未开启」时开始；已经开着时再点只会得到一句拒绝。
            _lockdown30Button.Enabled = _serviceAvailable && !enabled;
            _lockdown2hButton.Enabled = _serviceAvailable && !enabled;
            _trayLockdownItem.Enabled = _serviceAvailable && !enabled;

            _strictModeDetailLabel.Text = BuildStrictModeDetailText(enabled);
        }
        catch (Exception ex)
        {
            LocalLog.Error(LocalLog.Pick("刷新严格模式状态失败", "Failed to refresh the strict-mode status."), ex);
            _strictModeStatusLabel.Text = Localizer.T("当前状态：读取失败（详见日志）");
        }
    }

    /// <summary>
    /// 3.5：把临时锁网剩余时间写成人话。
    /// **纯函数**：自检直接断言中英文输出，避免出现「剩余 0 分钟」这种丢人的状态。
    /// </summary>
    internal static string FormatLockdownRemaining(TimeSpan remaining)
    {
        var totalMinutes = (int)Math.Ceiling(remaining.TotalMinutes);

        if (totalMinutes <= 0)
        {
            totalMinutes = 1;
        }

        var hours = totalMinutes / 60;
        var minutes = totalMinutes % 60;

        var text = hours > 0
            ? (minutes > 0
                ? $"剩余 {hours} 小时 {minutes} 分钟"
                : $"剩余 {hours} 小时")
            : $"剩余 {minutes} 分钟";

        return Localizer.T(text);
    }

    /// <summary>
    /// 服务停止/崩溃时动态会话必然消失。用户开的是「30 分钟锁网」，
    /// 结果 3 分钟就恢复了 —— 这件事必须主动说，不能等他自己发现。
    /// </summary>
    private void NotifyLockdownEndedByService()
    {
        if (!_lockdownActive)
        {
            return;
        }

        _lockdownActive = false;
        _lockdownExpiresUtc = null;

        ShowTrayBalloon("临时锁网已解除", "防护服务已停止或不可用，网络已经恢复。");
    }

    private void OnStrictModeToggleClick(object? sender, EventArgs e)
    {
        if (_strictModeEnabled)
        {
            DisableStrictMode();
        }
        else
        {
            EnableStrictModeWithConfirmation();
        }
    }

    private void OnLockdown30Click(object? sender, EventArgs e)
        => StartLockdown(TimeSpan.FromMinutes(30));

    private void OnLockdown2hClick(object? sender, EventArgs e)
        => StartLockdown(TimeSpan.FromHours(2));

    /// <summary>
    /// 3.5：临时锁网。复用严格模式的动态会话，只多一个到期时间。
    ///
    /// 只做**一次**确认：它有时限、可提前结束、服务停止也会恢复，
    /// 后果不像「永久阻止」那样重；但清单和自动恢复规则必须讲清楚。
    /// </summary>
    private void StartLockdown(TimeSpan duration)
    {
        if (!_serviceAvailable)
        {
            UiMessageBox.Show(
                this,
                Localizer.T("防护服务未运行，无法开始临时锁网。"),
                AppConstants.AppName,
                MessageBoxButtons.OK,
                MessageBoxIcon.Warning);
            return;
        }

        if (_strictModeEnabled)
        {
            UiMessageBox.Show(
                this,
                Localizer.T("严格模式已经开启。要提前结束，请点「关闭严格模式」。"),
                AppConstants.AppName,
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
            return;
        }

        var affected = BuildProgramsThatWillLoseAccess();
        var durationText = DescribeLockdownDuration(duration);

        var confirmed = ConfirmForm.Show(
            owner: DialogOwner,
            title: "临时锁网",
            question: Localizer.IsEnglish
                ? $"Lock the network for {durationText}? Programs not on the whitelist will be offline."
                : $"临时锁网 {durationText}？没有加入白名单的程序会断网。",
            details: new[]
            {
                new KeyValuePair<string, string>("将要做的", "临时开启严格模式（会话内）"),
                new KeyValuePair<string, string>("持续时间", durationText),
                new KeyValuePair<string, string>("到期后", "自动恢复联网，不需要手动操作"),
                new KeyValuePair<string, string>(
                    "会被影响",
                    affected.Count == 0
                        ? "（没有 —— 当前联网的程序都已经在白名单里）"
                        : $"{affected.Count} 个正在联网、但没加白名单的程序"),
            },
            warnings: new[]
            {
                "未加白名单的程序会立刻无法建立新的出站连接（已经连上的要等它自己断开）。",
                "可以随时点「关闭严格模式」提前结束。",
                "防护服务停止或崩溃时会自动恢复联网，不会留下永久断网。",
                "不会修改 Windows 防火墙的任何设置。",
            },
            confirmText: "开始锁网");

        if (!confirmed)
        {
            return;
        }

        try
        {
            var response = CallService(
                ServiceProtocol.Commands.StrictLockdown,
                new ServiceRequest { LockdownSeconds = (int)duration.TotalSeconds },
                "临时锁网");

            if (response is null)
            {
                RefreshStrictModeStatus();
                return;
            }

            _strictModeEnabled = response.Status?.StrictModeActive ?? true;
            _strictModePermittedCount = response.Status?.StrictModePermittedCount ?? 0;
            _lockdownActive = response.Status?.StrictModeLockdownActive ?? true;
            _lockdownExpiresUtc = response.Status?.StrictModeLockdownExpiresUtc;

            LocalLog.Operation(LocalLog.Pick(
                $"临时锁网已开启：{durationText}。",
                $"Timed lockdown enabled for {durationText} (ok={response.Ok})."));

            RefreshStrictModeStatus();

            ShowTrayBalloon(
                "临时锁网已开启",
                Localizer.IsEnglish
                    ? $"Programs without whitelist access are offline; the network comes back in {durationText}."
                    : $"未加白名单的程序已断网，{durationText}后自动恢复。");
        }
        catch (Exception ex)
        {
            ShowError("临时锁网失败", ex, "Failed to start the timed lockdown");
            RefreshStrictModeStatus();
        }
    }

    /// <summary>把锁网时长写成人话（只支持界面提供的两档，但保留通用格式）。</summary>
    private static string DescribeLockdownDuration(TimeSpan duration)
    {
        var hours = (int)duration.TotalHours;
        var minutes = (int)duration.TotalMinutes % 60;

        if (hours > 0 && minutes == 0)
        {
            return Localizer.IsEnglish ? $"{hours} hours" : $"{hours} 小时";
        }

        if (hours > 0)
        {
            return Localizer.IsEnglish
                ? $"{hours} hours {minutes} minutes"
                : $"{hours} 小时 {minutes} 分钟";
        }

        return Localizer.IsEnglish ? $"{minutes} minutes" : $"{minutes} 分钟";
    }

    /// <summary>关闭严格模式。这是"安全方向"的操作，所以只要一次确认。</summary>
    private void DisableStrictMode()
    {
        var wasLockdown = _lockdownActive;

        var confirmed = ConfirmForm.Show(
            owner: DialogOwner,
            title: "关闭严格模式",
            question: "确定要关闭严格模式吗？",
            details: new[]
            {
                new KeyValuePair<string, string>("将要做的", "结束严格模式会话，撤销全部拦截"),
                new KeyValuePair<string, string>("影响", "所有程序恢复联网（白名单规则本身保留）"),
            },
            warnings: new[]
            {
                "严格模式是会话级的：程序退出时也会自动撤销，这一步只是提前做而已。",
                "白名单（AppGuard_Allow_ 规则）不会被删，下次开启严格模式时直接生效。",
                "不会修改 Windows 防火墙的任何设置。",
            },
            confirmText: "关闭严格模式");

        if (!confirmed)
        {
            return;
        }

        try
        {
            var response = CallService(
                ServiceProtocol.Commands.StrictDisable,
                new ServiceRequest(),
                "关闭严格模式");

            if (response is null)
            {
                RefreshStrictModeStatus();
                return;
            }

            _strictModeEnabled = false;
            _strictModePermittedCount = 0;
            _lockdownActive = false;
            _lockdownExpiresUtc = null;

            LocalLog.Operation(LocalLog.Pick($"严格模式已关闭：{response.Message}", $"Strict mode disabled (ok={response.Ok})."));

            AfterRulesChanged();
            RefreshStrictModeStatus();

            ShowTrayBalloon(
                wasLockdown ? "临时锁网已结束" : "严格模式已关闭",
                wasLockdown ? "已提前结束，网络已经恢复。" : "限制已撤销，所有程序恢复联网。");
        }
        catch (Exception ex)
        {
            ShowError("关闭严格模式失败", ex, "Failed to disable strict mode");
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
        var systemCount = SystemAllowList.GetPaths().Count;

        var firstConfirmed = ConfirmForm.Show(
            owner: DialogOwner,
            title: "开启严格模式（第 1/2 步）",
            question: "开启后，没有加入白名单的程序将无法上网。确定继续吗？",
            details: new[]
            {
                new KeyValuePair<string, string>(
                    "将要做的", "建立一个会话内的拦截（不改 Windows 防火墙的任何设置）"),
                new KeyValuePair<string, string>(
                    "将会放行", $"本工具白名单 {_whitelistedPaths.Count} 个程序 + 本程序 + {systemCount} 个系统必需程序"),
                new KeyValuePair<string, string>(
                    "会被影响", $"{affected.Count} 个正在联网、但没加白名单的程序"),
            },
            warnings: new[]
            {
                "2.0 是「真白名单」：Windows 自带的允许规则、别的软件建的允许规则都不再生效。",
                $"为了不让 DNS / 时间同步 / Windows 更新被一起挡掉，内置放行了 {systemCount} 个系统必需程序（以 svchost 为主）。",
                "程序退出、崩溃或被强杀时会自动撤销 —— 不需要任何还原操作。",
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
            warnings.Add("注意：系统必需程序（DNS / 更新等）仍然会被放行，实际影响可能比这个清单小。");
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
            var response = CallService(
                ServiceProtocol.Commands.StrictEnable,
                new ServiceRequest(),
                "开启严格模式");

            if (response is null)
            {
                RefreshStrictModeStatus();
                return;
            }

            _strictModeEnabled = response.Status?.StrictModeActive ?? true;
            _strictModePermittedCount = response.Status?.StrictModePermittedCount ?? 0;

            LocalLog.Operation(LocalLog.Pick($"严格模式已开启：{response.Message}", $"Strict mode enabled (ok={response.Ok})."));

            // 严格模式不改规则，只建立了会话；状态文字要立刻更新。
            RefreshStrictModeStatus();

            ShowTrayBalloon(
                "严格模式已开启",
                $"只放行 {_strictModePermittedCount} 个程序，其它程序的新连接会被拦掉。" +
                "防护服务停止或崩溃时会自动撤销。");
        }
        catch (Exception ex)
        {
            ShowError("开启严格模式失败", ex, "Failed to enable strict mode");
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
        var systemPaths = new HashSet<string>(SystemAllowList.GetPaths(), StringComparer.OrdinalIgnoreCase);
        var selfPath = Environment.ProcessPath;

        foreach (var item in _scannedConnections)
        {
            // 2.0 是「真白名单」：别的软件/系统为它建的允许规则**不再**能救它，
            // 所以这里不能再按 _otherAllowPaths 排除 —— 否则会少报、把用户吓不到点上。
            if (string.IsNullOrEmpty(item.ProcessPath)
                || _whitelistedPaths.Contains(item.ProcessPath)
                || systemPaths.Contains(item.ProcessPath)
                || (selfPath is not null && PathsEqual(item.ProcessPath, selfPath)))
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
            UiMessageBox.Show(
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
