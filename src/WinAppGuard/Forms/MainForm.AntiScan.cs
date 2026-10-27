using System.Diagnostics;
using WinAppGuard.Contracts;
using WinAppGuard.Core;
using WinAppGuard.Core.Diagnostics.AntiScan;
using WinAppGuard.Localization;

namespace WinAppGuard.Forms;

/// <summary>
/// 4.0：「防护」页 —— 反端口扫描事件与临时入站封禁。
///
/// 只展示服务端已经采到的 TCP SYN 事件；界面不做抓包、不做规则判断。
/// Npcap 缺失时页面仍然可用，但会明确显示“反扫描不可用”。
/// </summary>
public sealed partial class MainForm
{
    private const int AntiScanRefreshIntervalMs = 3000;

    private TextBox _antiSearchBox = null!;
    private ComboBox _antiSeverityFilter = null!;
    private Button _antiRefreshButton = null!;
    private Button _antiReleaseButton = null!;
    private Button _antiReleaseAllButton = null!;
    private Button _antiClearButton = null!;
    private Button _antiSettingsButton = null!;
    private Label _antiStatusLabel = null!;
    private SplitContainer _antiSplit = null!;
    private DataGridViewBuffered _antiEventGrid = null!;
    private DataGridViewBuffered _antiBlockGrid = null!;
    private System.Windows.Forms.Timer? _antiTimer;

    private List<AntiScanEventDto> _antiEvents = new();
    private List<AntiScanBlockDto> _antiBlocks = new();
    private AntiScanSettingsDto? _antiSettings;
    private AntiScanStatusDto? _antiStatus;
    private bool _antiLoading;
    private bool _antiServiceAvailable = true;
    private string? _antiEventSignature;
    private string? _antiBlockSignature;
    private DateTime _npcapConnectingUntilUtc = DateTime.MinValue;
    private bool _npcapInstallerRunning;

    /// <summary>
    /// 状态栏的「Npcap」项：只反映采集是否真的在跑，不把"装了驱动"说成"已连接"。
    ///
    /// 未连接时整项可点：没安装 → 拉起随包官方安装程序；已安装但没采到 → 让服务立刻重连。
    /// </summary>
    private void UpdateNpcapStatusLabel(ServiceStatus? status) => ApplyNpcapStatus(
        status?.AntiScanEnabled ?? true,
        NpcapLocator.IsAvailable || status?.AntiScanNpcapAvailable == true,
        status?.AntiScanCollecting == true,
        status is not null);

    private void ApplyNpcapStatus(bool enabled, bool installed, bool collecting, bool serviceOnline)
    {
        var connecting = _npcapConnectingUntilUtc > DateTime.UtcNow || _npcapInstallerRunning;

        if (!enabled)
        {
            _npcapStatusLabel.Text = Localizer.T("Npcap：未连接（反扫描已关闭）");
            _npcapStatusLabel.ForeColor = SystemColors.GrayText;
            _npcapStatusLabel.IsLink = false;
            _npcapStatusLabel.ToolTipText = Localizer.T("反端口扫描已在设置里关闭，开启后才会连接 Npcap。");
            return;
        }

        if (collecting)
        {
            var version = NpcapLocator.GetVersion();
            _npcapStatusLabel.Text = version is null
                ? Localizer.T("Npcap：已连接")
                : Localizer.F("Npcap：已连接（{0}）", version);
            _npcapStatusLabel.ForeColor = Color.FromArgb(0, 120, 0);
            _npcapStatusLabel.IsLink = false;
            _npcapStatusLabel.ToolTipText = Localizer.T("反端口扫描正在通过 Npcap 采集入站 TCP SYN。");
            return;
        }

        if (!installed)
        {
            _npcapStatusLabel.Text = Localizer.T("Npcap：未连接（点击安装）");
            _npcapStatusLabel.ForeColor = Color.FromArgb(150, 90, 0);
            _npcapStatusLabel.IsLink = true;
            _npcapStatusLabel.ToolTipText = Localizer.T(
                "反端口扫描需要 Npcap。点击后用随包官方安装程序安装（会弹一次 UAC）。");
            return;
        }

        if (connecting)
        {
            _npcapStatusLabel.Text = Localizer.T("Npcap：连接中…");
            _npcapStatusLabel.ForeColor = SystemColors.GrayText;
            _npcapStatusLabel.IsLink = false;
            _npcapStatusLabel.ToolTipText = Localizer.T("已请求服务重新开始采集，稍候会自动更新。");
            return;
        }

        if (!serviceOnline)
        {
            _npcapStatusLabel.Text = Localizer.T("Npcap：未连接（服务离线）");
            _npcapStatusLabel.ForeColor = Color.FromArgb(150, 90, 0);
            _npcapStatusLabel.IsLink = false;
            _npcapStatusLabel.ToolTipText = Localizer.T("防护服务没有运行，无法连接 Npcap。请先启动服务。");
            return;
        }

        _npcapStatusLabel.Text = Localizer.T("Npcap：未连接（点击重试）");
        _npcapStatusLabel.ForeColor = Color.FromArgb(150, 90, 0);
        _npcapStatusLabel.IsLink = true;
        _npcapStatusLabel.ToolTipText = Localizer.T("Npcap 已安装，但采集没有运行：点击让服务重新连接。");
    }

    private void OnNpcapStatusLabelClick(object? sender, EventArgs e)
    {
        if (_npcapInstallerRunning)
        {
            return;
        }

        var installed = NpcapLocator.IsAvailable || _antiStatus?.NpcapAvailable == true;

        if (!installed)
        {
            _ = InstallNpcapFromBundleAsync();
            return;
        }

        RetryNpcapCapture();
    }

    /// <summary>已安装但没采到：重新下发当前设置，服务会立刻重试一次。</summary>
    private void RetryNpcapCapture()
    {
        if (!_serviceAvailable)
        {
            ShowTrayBalloon(
                Localizer.T("服务未运行"),
                Localizer.T("先启动防护服务，再连接 Npcap。"));
            return;
        }

        try
        {
            var snapshot = QueryAntiScanSnapshot();

            if (snapshot is null)
            {
                ShowTrayBalloon(
                    Localizer.T("服务未运行"),
                    Localizer.T("先启动防护服务，再连接 Npcap。"));
                return;
            }

            var settings = snapshot.Value.Settings ?? _antiSettings ?? new AntiScanSettingsDto();

            // 关闭状态点重试没有意义，顺手帮用户打开。
            settings.Enabled = true;

            var response = CallService(
                ServiceProtocol.Commands.ConfigureAntiScan,
                new ServiceRequest { AntiScanSettings = settings },
                Localizer.T("重新连接 Npcap"));

            _antiSettings = response?.AntiScanSettings ?? settings;
            _antiStatus = response?.AntiScanStatus ?? _antiStatus;
            _npcapConnectingUntilUtc = DateTime.UtcNow.AddSeconds(20);
            ApplyNpcapStatus(
                true,
                NpcapLocator.IsAvailable || _antiStatus?.NpcapAvailable == true,
                _antiStatus?.Collecting == true,
                _serviceAvailable);

            _ = RefreshAntiScanAsync();
        }
        catch (Exception ex)
        {
            ShowError(
                Localizer.T("重新连接 Npcap 失败"),
                ex,
                "Failed to reconnect Npcap");
        }
    }

    /// <summary>未安装：调用随包官方安装程序（和安装 WinAppGuard 时同一份文件、同一组锁定参数）。</summary>
    private async Task InstallNpcapFromBundleAsync()
    {
        var directory = Path.GetDirectoryName(Environment.ProcessPath) ?? AppContext.BaseDirectory;
        var installer = Path.Combine(directory, NpcapInstaller.FileName);

        if (!File.Exists(installer))
        {
            ShowNpcapError(
                Localizer.T("找不到 Npcap 安装包"),
                Localizer.F(
                    "安装目录里没有 {0}。请用发布包里的 WinAppGuardSetup.exe 重新运行 --repair，或手动安装 Npcap。",
                    NpcapInstaller.FileName));
            return;
        }

        _npcapInstallerRunning = true;
        ApplyNpcapStatus(
            true,
            NpcapLocator.IsAvailable || _antiStatus?.NpcapAvailable == true,
            _antiStatus?.Collecting == true,
            _serviceAvailable);

        int? exitCode;
        string? error;

        try
        {
            (exitCode, error) = await Task.Run(() =>
            {
                if (!NpcapInstaller.Verify(installer, out var reason))
                {
                    return ((int?)null, (string?)reason);
                }

                return (NpcapInstaller.RunElevated(installer, out var runError), runError);
            });
        }
        finally
        {
            _npcapInstallerRunning = false;
        }

        if (error is not null)
        {
            ShowNpcapError(Localizer.T("Npcap 安装失败"), error);
            ProbeServiceStatus();
            return;
        }

        if (exitCode is null)
        {
            // 用户在 UAC 里点了取消，或安装器自己取消了：不当成错误。
            ShowTrayBalloon(
                Localizer.T("已取消 Npcap 安装"),
                Localizer.T("反端口扫描暂时不可用，其它功能不受影响。"));
            ProbeServiceStatus();
            return;
        }

        switch (exitCode.Value)
        {
            case 0:
                ShowTrayBalloon(
                    Localizer.T("Npcap 安装完成"),
                    Localizer.T("反扫描会在几秒内自动连接。"));
                break;
            case 3010:
                ShowTrayBalloon(
                    Localizer.T("Npcap 已安装，需要重启"),
                    Localizer.T("重启后反端口扫描才会生效。"));
                break;
            case 1:
                ShowTrayBalloon(
                    Localizer.T("已取消 Npcap 安装"),
                    Localizer.T("反端口扫描暂时不可用，其它功能不受影响。"));
                break;
            default:
                ShowTrayBalloon(
                    Localizer.T("Npcap 安装未完成"),
                    Localizer.F("安装器退出码 {0}；反端口扫描暂时不可用。", exitCode.Value));
                break;
        }

        if (exitCode.Value is 0 or 3010)
        {
            _npcapConnectingUntilUtc = DateTime.UtcNow.AddSeconds(30);
            RetryNpcapCapture();
        }

        ProbeServiceStatus();
    }

    /// <summary>纯文字错误提示（没有异常对象时用；仍然写本地日志）。</summary>
    private void ShowNpcapError(string title, string message)
    {
        LocalLog.Error(
            LocalLog.Pick(title, "Npcap operation failed."),
            new InvalidOperationException(message));

        UiMessageBox.Show(
            this,
            $"{title}：\n\n{message}",
            AppConstants.AppName,
            MessageBoxButtons.OK,
            MessageBoxIcon.Error);
    }

    private void InitializeAntiScanPage()
    {
        var top = new Panel
        {
            Dock = DockStyle.Top,
            Height = 108,
            Padding = new Padding(0, 4, 0, 0),
        };

        var notice = new Label
        {
            Location = new Point(0, 0),
            Width = 1000,
            Height = 20,
            ForeColor = Color.FromArgb(191, 87, 0),
            Text = Localizer.T("反端口扫描只检测入站 TCP SYN，不读载荷、不阻断已有连接；自动封禁默认关闭。"),
            AutoEllipsis = true,
        };

        _antiSearchBox = new TextBox
        {
            Location = new Point(0, 26),
            Width = 180,
            PlaceholderText = Localizer.T("搜索：来源 IP / 处置"),
        };
        _antiSearchBox.TextChanged += (_, _) => RebuildAntiScanView();

        _antiSeverityFilter = new ComboBox
        {
            Location = new Point(188, 25),
            Width = 92,
            DropDownStyle = ComboBoxStyle.DropDownList,
        };
        _antiSeverityFilter.Items.AddRange(new object[]
        {
            Localizer.T("全部级别"),
            Localizer.T("高"),
            Localizer.T("中"),
        });
        _antiSeverityFilter.SelectedIndex = 0;
        _antiSeverityFilter.SelectedIndexChanged += (_, _) => RebuildAntiScanView();

        // 按钮用 FlowLayoutPanel + AutoSize：150% DPI 下字体变大时按钮跟着变宽，
        // 不会出现文字被截断（写死像素宽度在 13.5pt 字体下必然截断）。
        var actions = new FlowLayoutPanel
        {
            Location = new Point(288, 22),
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            WrapContents = false,
            FlowDirection = FlowDirection.LeftToRight,
        };

        _antiRefreshButton = new Button
        {
            Text = Localizer.T("刷新"),
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            MinimumSize = new Size(68, 27),
            Margin = new Padding(0, 0, 8, 0),
        };
        _antiRefreshButton.Click += (_, _) => _ = RefreshAntiScanAsync();

        _antiReleaseButton = new Button
        {
            Text = Localizer.T("解除选中"),
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            MinimumSize = new Size(88, 27),
            Margin = new Padding(0, 0, 8, 0),
        };
        _antiReleaseButton.Click += OnAntiScanReleaseClick;

        _antiReleaseAllButton = new Button
        {
            Text = Localizer.T("解除全部"),
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            MinimumSize = new Size(88, 27),
            Margin = new Padding(0, 0, 8, 0),
        };
        _antiReleaseAllButton.Click += OnAntiScanReleaseAllClick;

        _antiClearButton = new Button
        {
            Text = Localizer.T("清空…"),
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            MinimumSize = new Size(76, 27),
            Margin = new Padding(0, 0, 8, 0),
        };
        _antiClearButton.Click += OnAntiScanClearClick;

        _antiSettingsButton = new Button
        {
            Text = Localizer.T("设置…"),
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            MinimumSize = new Size(76, 27),
        };
        _antiSettingsButton.Click += OnAntiScanSettingsClick;

        actions.Controls.AddRange(new Control[]
        {
            _antiRefreshButton,
            _antiReleaseButton,
            _antiReleaseAllButton,
            _antiClearButton,
            _antiSettingsButton,
        });

        _antiStatusLabel = new Label
        {
            Location = new Point(0, 56),
            Width = 1000,
            Height = 22,
            ForeColor = SystemColors.GrayText,
            AutoEllipsis = true,
        };

        var hint = new Label
        {
            Location = new Point(0, 80),
            Width = 1000,
            Height = 22,
            ForeColor = SystemColors.GrayText,
            Text = Localizer.T("Npcap 只用于抓取 TCP SYN；封禁使用 WFP 入站 accept 层，只拦新连接。"),
            AutoEllipsis = true,
        };

        top.Resize += (_, _) =>
        {
            var width = Math.Max(200, top.ClientSize.Width - 8);
            notice.Width = width;
            _antiStatusLabel.Width = width;
            hint.Width = width;
        };

        top.Controls.AddRange(new Control[]
        {
            notice,
            _antiSearchBox,
            _antiSeverityFilter,
            actions,
            _antiStatusLabel,
            hint,
        });

        _antiSplit = new SplitContainer
        {
            Dock = DockStyle.Fill,
            Orientation = Orientation.Horizontal,
            SplitterWidth = 6,
        };

        _antiEventGrid = CreateAntiScanGrid(
            "还没有扫描事件。\r\n反扫描没有发现符合阈值的入站 TCP 端口扫描。");
        AddAntiScanColumn(_antiEventGrid, "时间", nameof(AntiScanEventRow.TimeText), 110);
        AddAntiScanColumn(_antiEventGrid, "来源 IP", nameof(AntiScanEventRow.SourceAddress), 150);
        AddAntiScanColumn(_antiEventGrid, "端口数", nameof(AntiScanEventRow.DistinctPorts), 60);
        AddAntiScanColumn(_antiEventGrid, "主机数", nameof(AntiScanEventRow.DistinctHosts), 60);
        AddAntiScanColumn(_antiEventGrid, "SYN", nameof(AntiScanEventRow.SynCount), 55);
        AddAntiScanColumn(_antiEventGrid, "窗口", nameof(AntiScanEventRow.WindowText), 55);
        AddAntiScanColumn(_antiEventGrid, "级别", nameof(AntiScanEventRow.SeverityText), 55);
        AddAntiScanColumn(_antiEventGrid, "处置", nameof(AntiScanEventRow.ActionText), 70);
        AddAntiScanColumn(_antiEventGrid, "封禁至", nameof(AntiScanEventRow.BlockedUntilText), 120, fill: true);

        _antiBlockGrid = CreateAntiScanGrid(
            "没有临时封禁。\r\n自动封禁关闭，或扫描来源尚未达到高危规则。");
        AddAntiScanColumn(_antiBlockGrid, "来源 IP", nameof(AntiScanBlockRow.Address), 160);
        AddAntiScanColumn(_antiBlockGrid, "封禁至", nameof(AntiScanBlockRow.UntilText), 140);
        AddAntiScanColumn(_antiBlockGrid, "原因", nameof(AntiScanBlockRow.Reason), 200, fill: true);
        AddAntiScanColumn(_antiBlockGrid, "事件", nameof(AntiScanBlockRow.EventText), 90);

        _antiBlockGrid.SelectionChanged += (_, _) => UpdateAntiScanButtons();
        _antiEventGrid.SelectionChanged += (_, _) => UpdateAntiScanButtons();

        _antiSplit.Panel1.Controls.Add(_antiEventGrid);
        _antiSplit.Panel2.Controls.Add(_antiBlockGrid);

        _tabAntiScan.Controls.Add(_antiSplit);
        _tabAntiScan.Controls.Add(top);

        _tabControl.SelectedIndexChanged += (_, _) =>
        {
            if (_tabControl.SelectedTab == _tabAntiScan)
            {
                _ = RefreshAntiScanAsync();
            }
        };

        _antiTimer = new System.Windows.Forms.Timer { Interval = AntiScanRefreshIntervalMs };
        _antiTimer.Tick += (_, _) =>
        {
            if (_tabControl.SelectedTab == _tabAntiScan)
            {
                _ = RefreshAntiScanAsync();
            }
        };
        _antiTimer.Start();

        _antiSplit.Resize += (_, _) =>
        {
            if (_antiSplit.Height > 160)
            {
                _antiSplit.SplitterDistance = Math.Max(100, (int)(_antiSplit.Height * 0.58));
            }
        };

        UpdateAntiScanButtons();
        UpdateAntiScanSummary();
    }

    private static DataGridViewBuffered CreateAntiScanGrid(string emptyText) => new()
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
        EmptyText = emptyText,
    };

    private static void AddAntiScanColumn(
        DataGridView grid, string header, string property, int width, bool fill = false)
    {
        var column = new DataGridViewTextBoxColumn
        {
            HeaderText = header,
            DataPropertyName = property,
            Name = property,
            ReadOnly = true,
            SortMode = DataGridViewColumnSortMode.NotSortable,
        };

        if (fill)
        {
            column.AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill;
            column.MinimumWidth = width;
        }
        else
        {
            column.Width = width;
        }

        grid.Columns.Add(column);
    }

    private async Task RefreshAntiScanAsync()
    {
        if (SuppressBackgroundServices || _antiLoading || IsDisposed || Disposing)
        {
            return;
        }

        _antiLoading = true;
        UpdateAntiScanButtons();

        try
        {
            var result = await Task.Run(QueryAntiScanSnapshot);

            if (IsDisposed || Disposing)
            {
                return;
            }

            if (result is not null)
            {
                _antiServiceAvailable = true;
                _antiEvents = result.Value.Events;
                _antiBlocks = result.Value.Blocks;
                _antiSettings = result.Value.Settings;
                _antiStatus = result.Value.Status;
                RebuildAntiScanView();
            }
            else
            {
                _antiServiceAvailable = false;
                UpdateAntiScanSummary();
            }
        }
        catch (Exception ex)
        {
            _antiServiceAvailable = false;
            LocalLog.Error(LocalLog.Pick("读取反扫描状态失败", "Failed to read anti-scan status."), ex);
            UpdateAntiScanSummary();
        }
        finally
        {
            _antiLoading = false;

            if (!IsDisposed && !Disposing)
            {
                UpdateAntiScanButtons();
            }
        }
    }

    private static AntiScanSnapshot? QueryAntiScanSnapshot()
    {
        try
        {
            var response = ServiceClient.TryRequest(
                new ServiceRequest { Command = ServiceProtocol.Commands.QueryAntiScan },
                TimeSpan.FromSeconds(2),
                out _);

            return response is { Ok: true }
                ? new AntiScanSnapshot(
                    response.AntiScanEvents ?? new List<AntiScanEventDto>(),
                    response.AntiScanBlocks ?? new List<AntiScanBlockDto>(),
                    response.AntiScanSettings,
                    response.AntiScanStatus)
                : null;
        }
        catch (Exception)
        {
            return null;
        }
    }

    private readonly record struct AntiScanSnapshot(
        List<AntiScanEventDto> Events,
        List<AntiScanBlockDto> Blocks,
        AntiScanSettingsDto? Settings,
        AntiScanStatusDto? Status);

    private void RebuildAntiScanView()
    {
        var keyword = _antiSearchBox.Text.Trim();

        var events = _antiEvents
            .Where(item => AntiScanEventMatches(item, keyword))
            .Select(item => new AntiScanEventRow(item))
            .ToList();

        var eventSignature = string.Join(
            "|",
            events.Take(100).Select(row => $"{row.Id}/{row.Action}/{row.BlockedUntilUtc?.Ticks}"));

        if (!string.Equals(eventSignature, _antiEventSignature, StringComparison.Ordinal))
        {
            _antiEventSignature = eventSignature;
            _antiEventGrid.DataSource = events;
        }

        var blocks = _antiBlocks
            .Where(item => keyword.Length == 0
                           || item.Address.Contains(keyword, StringComparison.OrdinalIgnoreCase)
                           || item.Reason.Contains(keyword, StringComparison.OrdinalIgnoreCase))
            .Select(item => new AntiScanBlockRow(item))
            .ToList();

        var blockSignature = string.Join(
            "|",
            blocks.Take(100).Select(row => $"{row.Address}/{row.BlockedUntilUtc.Ticks}"));

        if (!string.Equals(blockSignature, _antiBlockSignature, StringComparison.Ordinal))
        {
            _antiBlockSignature = blockSignature;
            _antiBlockGrid.DataSource = blocks;
        }

        UpdateAntiScanSummary();
        UpdateAntiScanButtons();
    }

    private bool AntiScanEventMatches(AntiScanEventDto item, string keyword)
    {
        if (_antiSeverityFilter.SelectedIndex == 1
            && item.Severity != AntiScanSeverityHigh)
        {
            return false;
        }

        if (_antiSeverityFilter.SelectedIndex == 2
            && item.Severity != AntiScanSeverityMedium)
        {
            return false;
        }

        return keyword.Length == 0
               || item.SourceAddress.Contains(keyword, StringComparison.OrdinalIgnoreCase)
               || item.Action.Contains(keyword, StringComparison.OrdinalIgnoreCase);
    }

    private void UpdateAntiScanSummary()
    {
        var status = _antiStatus;

        string text;

        if (status is null)
        {
            text = _antiServiceAvailable
                ? Localizer.T("反扫描状态未知（旧版服务或尚未启动）。")
                : Localizer.T("服务不可用，显示上次数据。");
        }
        else
        {
            var npcap = status.NpcapAvailable
                ? Localizer.F("Npcap {0}", status.NpcapVersion ?? "?")
                : Localizer.T("Npcap 未安装");

            var collecting = status.Collecting
                ? Localizer.T("采集中")
                : Localizer.T("采集未运行");

            text = Localizer.F(
                "反扫描：{0} · {1} · {2} · 敏感度 {3} · 自动封禁 {4} · 事件 {5} · 临时封禁 {6}",
                status.Enabled ? Localizer.T("已开启") : Localizer.T("已停用"),
                npcap,
                collecting,
                Localizer.T(status.Sensitivity == "conservative" ? "保守" : "标准"),
                status.AutoBlock ? Localizer.T("开") : Localizer.T("关"),
                status.EventCount,
                status.BlockedCount);

            if (!status.NpcapAvailable)
            {
                text += " · " + Localizer.T("安装 Npcap 后才会采集");
            }

            if (!string.IsNullOrEmpty(status.LastError))
            {
                text += " · " + status.LastError;
            }
        }

        if (!_antiServiceAvailable)
        {
            text = Localizer.T("服务不可用，显示上次数据") + " · " + text;
        }

        _antiStatusLabel.Text = text;
    }

    private void UpdateAntiScanButtons()
    {
        var enabled = !_antiLoading && _antiServiceAvailable;
        var blockSelected = _antiBlockGrid?.CurrentRow?.DataBoundItem is AntiScanBlockRow;

        _antiRefreshButton.Enabled = !_antiLoading;
        _antiSettingsButton.Enabled = enabled;
        _antiReleaseButton.Enabled = enabled && blockSelected;
        _antiReleaseAllButton.Enabled = enabled && _antiBlocks.Count > 0;
        _antiClearButton.Enabled = enabled && (_antiEvents.Count > 0 || _antiBlocks.Count > 0);
    }

    private void OnAntiScanSettingsClick(object? sender, EventArgs e)
    {
        var updated = AntiScanSettingsForm.Ask(
            DialogOwner,
            _antiSettings ?? new AntiScanSettingsDto(),
            _antiStatus?.NpcapAvailable == true,
            _antiStatus?.NpcapVersion);

        if (updated is null)
        {
            return;
        }

        try
        {
            var response = CallService(
                ServiceProtocol.Commands.ConfigureAntiScan,
                new ServiceRequest { AntiScanSettings = updated },
                Localizer.T("修改反扫描设置"));

            if (response is null)
            {
                return;
            }

            _antiSettings = response.AntiScanSettings ?? updated;
            _antiStatus = response.AntiScanStatus ?? _antiStatus;
            ResetAntiScanSignatures();
            _ = RefreshAntiScanAsync();

            ShowTrayBalloon(
                Localizer.T(updated.Enabled ? "反扫描已开启" : "反扫描已关闭"),
                updated.Enabled
                    ? Localizer.T("只检测入站端口扫描；自动封禁") +
                      Localizer.T(updated.AutoBlock ? "已开启。" : "仍关闭。")
                    : Localizer.T("不再读取 Npcap 事件，已有临时封禁已解除。"));
        }
        catch (Exception ex)
        {
            ShowError(
                Localizer.T("修改反扫描设置失败"),
                ex,
                "Failed to update anti-scan settings");
        }
    }

    private void OnAntiScanReleaseClick(object? sender, EventArgs e)
    {
        if (_antiBlockGrid.CurrentRow?.DataBoundItem is not AntiScanBlockRow row)
        {
            return;
        }

        try
        {
            var response = CallService(
                ServiceProtocol.Commands.ReleaseAntiScanBlock,
                new ServiceRequest { AntiScanAddress = row.Address },
                Localizer.T("解除临时封禁"));

            if (response is null)
            {
                return;
            }

            _antiBlocks = response.AntiScanBlocks ?? _antiBlocks;
            _antiStatus = response.AntiScanStatus ?? _antiStatus;
            ResetAntiScanSignatures();
            RebuildAntiScanView();

            ShowTrayBalloon(
                Localizer.T("已解除临时封禁"),
                Localizer.F("{0} 的新入站连接已恢复。", row.Address));
        }
        catch (Exception ex)
        {
            ShowError(
                Localizer.T("解除临时封禁失败"),
                ex,
                "Failed to release an anti-scan block");
        }
    }

    private void OnAntiScanReleaseAllClick(object? sender, EventArgs e)
    {
        if (_antiBlocks.Count == 0)
        {
            return;
        }

        var confirmed = ConfirmForm.Show(
            owner: DialogOwner,
            title: "解除全部临时封禁",
            question: "确定要解除全部反扫描临时封禁吗？",
            details: new[]
            {
                new KeyValuePair<string, string>("将要做的", "删除反扫描创建的全部入站封禁"),
                new KeyValuePair<string, string>("不会影响", "程序阻止规则、白名单和严格模式"),
            },
            warnings: new[]
            {
                "来源 IP 可以立刻重新建立新连接。",
                "已有连接本来就不会被临时封禁切断。",
            },
            confirmText: "解除全部");

        if (confirmed)
        {
            ReleaseAllAntiScanBlocks();
        }
    }

    private void ReleaseAllAntiScanBlocks()
    {
        try
        {
            var response = CallService(
                ServiceProtocol.Commands.ReleaseAntiScanBlock,
                new ServiceRequest { AntiScanReleaseAll = true },
                Localizer.T("解除全部临时封禁"));

            if (response is null)
            {
                return;
            }

            _antiBlocks = response.AntiScanBlocks ?? new List<AntiScanBlockDto>();
            _antiStatus = response.AntiScanStatus ?? _antiStatus;
            ResetAntiScanSignatures();
            RebuildAntiScanView();

            ShowTrayBalloon(
                Localizer.T("临时封禁已全部解除"),
                Localizer.F("共解除 {0} 条。", response.Affected));
        }
        catch (Exception ex)
        {
            ShowError(
                Localizer.T("解除全部临时封禁失败"),
                ex,
                "Failed to release anti-scan blocks");
        }
    }

    private void OnAntiScanClearClick(object? sender, EventArgs e)
    {
        var confirmed = ConfirmForm.Show(
            owner: DialogOwner,
            title: "清空反扫描记录",
            question: "确定要清空反扫描事件并解除全部临时封禁吗？",
            details: new[]
            {
                new KeyValuePair<string, string>("将要做的", "清空本次运行的扫描事件，并解除全部临时封禁"),
                new KeyValuePair<string, string>("不会影响", "程序阻止规则、白名单、严格模式和 IDS 告警"),
            },
            warnings: new[]
            {
                "被解除的来源 IP 可以重新建立入站连接。",
                "当前扫描事件只保存在内存中，清空后无法恢复。",
            },
            confirmText: "清空并解除");

        if (!confirmed)
        {
            return;
        }

        try
        {
            var response = CallService(
                ServiceProtocol.Commands.ClearAntiScan,
                new ServiceRequest(),
                Localizer.T("清空反扫描记录"));

            if (response is null)
            {
                return;
            }

            _antiEvents = new List<AntiScanEventDto>();
            _antiBlocks = new List<AntiScanBlockDto>();
            _antiStatus = response.AntiScanStatus ?? _antiStatus;
            ResetAntiScanSignatures();
            RebuildAntiScanView();

            ShowTrayBalloon(
                Localizer.T("反扫描记录已清空"),
                Localizer.T("临时封禁已解除；规则和 IDS 告警没有变化。"));
        }
        catch (Exception ex)
        {
            ShowError(
                Localizer.T("清空反扫描记录失败"),
                ex,
                "Failed to clear anti-scan records");
        }
    }

    private void ResetAntiScanSignatures()
    {
        _antiEventSignature = null;
        _antiBlockSignature = null;
    }

    private const string AntiScanSeverityHigh = "high";
    private const string AntiScanSeverityMedium = "medium";

    private sealed class AntiScanEventRow
    {
        public AntiScanEventRow(AntiScanEventDto item)
        {
            Id = item.Id;
            SourceAddress = item.SourceAddress;
            DistinctPorts = item.DistinctPorts;
            DistinctHosts = item.DistinctHosts;
            SynCount = item.SynCount;
            WindowSeconds = item.WindowSeconds;
            TimeUtc = item.TimeUtc;
            Severity = item.Severity;
            Action = item.Action;
            BlockedUntilUtc = item.BlockedUntilUtc;
        }

        public string Id { get; }

        public string SourceAddress { get; }

        public int DistinctPorts { get; }

        public int DistinctHosts { get; }

        public int SynCount { get; }

        public int WindowSeconds { get; }

        public DateTime TimeUtc { get; }

        public string Severity { get; }

        public string Action { get; }

        public DateTime? BlockedUntilUtc { get; }

        public string TimeText => TimeUtc.ToLocalTime().ToString("MM-dd HH:mm:ss");

        public string WindowText => $"{WindowSeconds}s";

        public string SeverityText => Localizer.T(Severity == AntiScanSeverityHigh ? "高" : "中");

        public string ActionText => Localizer.T(Action == "blocked" ? "已临时封禁" : "仅告警");

        public string BlockedUntilText => BlockedUntilUtc is { } until
            ? until.ToLocalTime().ToString("MM-dd HH:mm:ss")
            : "—";
    }

    private sealed class AntiScanBlockRow
    {
        public AntiScanBlockRow(AntiScanBlockDto item)
        {
            Address = item.Address;
            BlockedUntilUtc = item.BlockedUntilUtc;
            Reason = item.Reason;
            EventId = item.EventId;
        }

        public string Address { get; }

        public DateTime BlockedUntilUtc { get; }

        public string Reason { get; }

        public string? EventId { get; }

        public string UntilText => BlockedUntilUtc.ToLocalTime().ToString("MM-dd HH:mm:ss");

        public string EventText => string.IsNullOrEmpty(EventId) ? "—" : EventId[..Math.Min(8, EventId.Length)];
    }
}
