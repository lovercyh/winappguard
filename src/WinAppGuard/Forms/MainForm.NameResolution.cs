using WinAppGuard.Contracts;
using WinAppGuard.Core;
using WinAppGuard.Localization;

namespace WinAppGuard.Forms;

/// <summary>
/// 4.5：「防护 → 局域网 → 名称解析」页。
///
/// 展示 LLMNR / NBNS / mDNS 的来源与告警；可对单个来源做 10 分钟窄阻断
/// （只拦它的 UDP 5355/137/5353，不整机封禁）。
/// </summary>
public sealed partial class MainForm
{
    private const int NameRefreshIntervalMs = 3000;

    private Label _nameStatusLabel = null!;
    private Button _nameRefreshButton = null!;
    private Button _nameClearButton = null!;
    private Button _nameBlockButton = null!;
    private CheckBox _nameAutoRefreshCheckBox = null!;
    private DataGridViewBuffered _nameSourceGrid = null!;
    private DataGridViewBuffered _nameEventGrid = null!;

    private List<NameSourceDto> _nameSources = new();
    private List<LanEventDto> _nameEvents = new();
    private NameResolutionStatusDto? _nameStatus;
    private bool _nameLoading;
    private bool _nameServiceAvailable = true;
    private BaselineTable<NameSourceRow>? _nameSourceTable;
    private EventTable<LanEventRow>? _nameEventTable;

    private void InitializeNameResolutionPage()
    {
        var top = new Panel
        {
            Dock = DockStyle.Top,
            Height = 96,
            Padding = new Padding(0, 4, 0, 0),
        };

        _nameRefreshButton = new Button
        {
            Text = Localizer.T("刷新"),
            AutoSize = true,
            MinimumSize = new Size(68, 27),
        };
        _nameRefreshButton.Click += (_, _) => _ = RefreshNameAsync();

        _nameClearButton = new Button
        {
            Text = Localizer.T("清空…"),
            AutoSize = true,
            MinimumSize = new Size(76, 27),
        };
        _nameClearButton.Click += OnNameClearClick;

        _nameBlockButton = new Button
        {
            Text = Localizer.T("临时阻断此来源（10 分钟）"),
            AutoSize = true,
            MinimumSize = new Size(150, 27),
        };
        _nameBlockButton.Click += OnNameBlockClick;

        var actions = new FlowLayoutPanel
        {
            Location = new Point(0, 2),
            AutoSize = true,
            AutoSizeMode = AutoSizeMode.GrowAndShrink,
            WrapContents = false,
            FlowDirection = FlowDirection.LeftToRight,
        };
        actions.Controls.AddRange(new Control[]
        {
            _nameRefreshButton, _nameClearButton, _nameBlockButton,
        });

        _nameAutoRefreshCheckBox = new CheckBox
        {
            Location = new Point(600, 42),
            AutoSize = true,
            Text = Localizer.T("每 3 秒自动刷新"),
            Checked = true,
        };
        _nameAutoRefreshCheckBox.CheckedChanged += (_, _) =>
        {
            // 5.9：调度器读取复选框状态；这里只负责勾选后立刻刷新一次。
            if (_nameAutoRefreshCheckBox.Checked)
            {
                _ = RefreshNameAsync();
            }
        };

        _nameStatusLabel = new Label
        {
            Location = new Point(0, 68),
            Width = 1000,
            Height = 22,
            ForeColor = SystemColors.GrayText,
            AutoEllipsis = true,
        };

        top.Resize += (_, _) =>
        {
            var width = Math.Max(200, top.ClientSize.Width - 8);
            _nameStatusLabel.Width = width;
            _nameAutoRefreshCheckBox.Left = Math.Max(600, width - 170);
        };

        top.Controls.AddRange(new Control[]
        {
            actions, _nameAutoRefreshCheckBox, _nameStatusLabel,
        });

        _nameSourceGrid = CreateLanGrid(
            Localizer.T("还没有名称解析来源。\r\nLLMNR / NBNS / mDNS 的应答来源会显示在这里。"));
        AddLanColumn(_nameSourceGrid, Localizer.T("地址"), nameof(NameSourceRow.Address), 180);
        AddLanColumn(_nameSourceGrid, Localizer.T("MAC"), nameof(NameSourceRow.Mac), 140);
        AddLanColumn(_nameSourceGrid, Localizer.T("协议"), nameof(NameSourceRow.Protocols), 100);
        AddLanColumn(_nameSourceGrid, Localizer.T("最近应答"), nameof(NameSourceRow.AnswerSummary), 300, fill: true);
        AddLanColumn(_nameSourceGrid, Localizer.T("响应数"), nameof(NameSourceRow.ResponseCount), 65);
        AddLanColumn(_nameSourceGrid, Localizer.T("阻断"), nameof(NameSourceRow.BlockText), 100);

        _nameEventGrid = CreateLanGrid(
            Localizer.T("还没有名称解析告警。\r\nLLMNR / NBNS / mDNS 投毒与 WPAD 检测结果会出现在这里。"));
        AddLanColumn(_nameEventGrid, Localizer.T("时间"), nameof(LanEventRow.TimeText), 110);
        AddLanColumn(_nameEventGrid, Localizer.T("类型"), nameof(LanEventRow.KindText), 170);
        AddLanColumn(_nameEventGrid, Localizer.T("级别"), nameof(LanEventRow.SeverityText), 55);
        AddLanColumn(_nameEventGrid, Localizer.T("详情"), nameof(LanEventRow.Detail), 320, fill: true);

        var split = new SplitContainer
        {
            Dock = DockStyle.Fill,
            Orientation = Orientation.Horizontal,
            SplitterWidth = 6,
        };
        split.Panel1.Controls.Add(_nameSourceGrid);
        split.Panel2.Controls.Add(_nameEventGrid);

        split.Resize += (_, _) =>
        {
            if (split.Height > 220)
            {
                split.SplitterDistance = Math.Max(120, (int)(split.Height * 0.45));
            }
        };

        _nameSourceGrid.SelectionChanged += (_, _) => UpdateNameButtons();

        _lanNamePage.Controls.Add(split);
        _lanNamePage.Controls.Add(top);

        UpdateNameButtons();
        UpdateNameSummary();
    }

    private async Task RefreshNameAsync()
    {
        if (SuppressBackgroundServices || _nameLoading || IsDisposed || Disposing)
        {
            return;
        }

        _nameLoading = true;
        UpdateNameButtons();

        try
        {
            var result = await Task.Run(QueryNameSnapshot);

            if (IsDisposed || Disposing)
            {
                return;
            }

            if (result is not null)
            {
                _nameServiceAvailable = true;
                _nameStatus = result.Value.Status;
                _nameSources = result.Value.Sources;
                _nameEvents = result.Value.Events;
                RebuildNameView();
            }
            else
            {
                _nameServiceAvailable = false;
                UpdateNameSummary();
            }
        }
        catch (Exception ex)
        {
            _nameServiceAvailable = false;
            LocalLog.Error(
                LocalLog.Pick("读取名称解析安全状态失败", "Failed to read name resolution security."),
                ex);
            UpdateNameSummary();
        }
        finally
        {
            _nameLoading = false;

            if (!IsDisposed && !Disposing)
            {
                UpdateNameButtons();
            }
        }
    }

    private static NameSnapshotResult? QueryNameSnapshot()
    {
        try
        {
            var view = Gateway.TryQuery(
                new ServiceRequest { Command = ServiceProtocol.Commands.QueryNameResolution },
                TimeSpan.FromSeconds(3),
                out _);

            return view is null
                ? null
                : new NameSnapshotResult(
                    view.NameResolutionStatus,
                    view.NameSources ?? new List<NameSourceDto>(),
                    view.NameResolutionEvents ?? new List<LanEventDto>());
        }
        catch (Exception)
        {
            return null;
        }
    }

    private readonly record struct NameSnapshotResult(
        NameResolutionStatusDto? Status,
        List<NameSourceDto> Sources,
        List<LanEventDto> Events);

    private void RebuildNameView()
    {
        var sourceRows = _nameSources.Select(item => new NameSourceRow(item)).ToList();

        _nameSourceTable ??= new BaselineTable<NameSourceRow>(
            _nameSourceGrid,
            row => $"{row.Address}/{row.Mac}/{row.Protocols}/{row.ResponseCount}/{row.Blocked}/{row.BlockExpiresUtc?.Ticks}",
            row => row.Address);

        _nameSourceTable.Bind(sourceRows);

        var eventRows = _nameEvents.Select(item => new LanEventRow(item)).ToList();

        _nameEventTable ??= new EventTable<LanEventRow>(
            _nameEventGrid,
            row => $"{row.Id}/{row.Kind}/{row.TimeUtc.Ticks}",
            row => row.Id);

        _nameEventTable.Bind(eventRows);

        UpdateNameSummary();
        UpdateNameButtons();
    }

    private void UpdateNameSummary()
    {
        var status = _nameStatus;
        var parts = new List<string> { Localizer.T("名称解析") };

        if (!_nameServiceAvailable)
        {
            parts.Add(Localizer.T("服务不可用，显示上次数据"));
        }

        if (status is null)
        {
            parts.Add(Localizer.T("状态未知"));
        }
        else
        {
            parts.Add(status.Collecting ? Localizer.T("采集中") : Localizer.T("采集未运行"));
            parts.Add(Localizer.F("来源 {0}", status.SourceCount));
            parts.Add(Localizer.F("事件 {0}", status.EventCount));

            if (status.BlockedCount > 0)
            {
                parts.Add(Localizer.F("已阻断 {0}", status.BlockedCount));
            }

            if (!string.IsNullOrWhiteSpace(status.LastError))
            {
                parts.Add(status.LastError!);
            }
        }

        _nameStatusLabel.Text = string.Join(" · ", parts);
    }

    private void UpdateNameButtons()
    {
        var available = _nameServiceAvailable && !_nameLoading;
        var source = _nameSourceGrid?.CurrentRow?.DataBoundItem as NameSourceRow;

        _nameRefreshButton.Enabled = !_nameLoading;
        _nameClearButton.Enabled = available && _nameEvents.Count > 0;
        _nameBlockButton.Enabled = available && source is not null;
        _nameBlockButton.Text = source?.Blocked == true
            ? Localizer.T("解除阻断")
            : Localizer.T("临时阻断此来源（10 分钟）");
        _nameAutoRefreshCheckBox.Enabled = available;
    }

    private async void OnNameClearClick(object? sender, EventArgs e)
    {
        var confirmed = ConfirmForm.Show(
            owner: DialogOwner,
            title: Localizer.T("清空名称解析事件"),
            question: Localizer.T("确定要清空全部名称解析事件吗？"),
            details: new[]
            {
                new KeyValuePair<string, string>(
                    Localizer.T("将要做的"),
                    Localizer.T("删除已落盘的 name_* 事件")),
                new KeyValuePair<string, string>(
                    Localizer.T("不会影响"),
                    Localizer.T("ARP/DHCP、DNS、IPv6 事件和其它防护功能")),
            },
            warnings: new[]
            {
                Localizer.T("清空后历史事件无法恢复。"),
                Localizer.T("不会修改任何系统设置。"),
            },
            confirmText: Localizer.T("清空"));

        if (!confirmed)
        {
            return;
        }

        try
        {
            var response = await CallServiceAsync(
                ServiceProtocol.Commands.ClearNameResolution,
                new ServiceRequest(),
                Localizer.T("清空名称解析事件"));

            if (response is null)
            {
                return;
            }

            _nameSourceTable?.Invalidate();
            _nameEventTable?.Invalidate();
            _nameEvents = new List<LanEventDto>();
            _nameStatus = response.NameResolutionStatus ?? _nameStatus;
            _nameSources = response.NameSources ?? _nameSources;
            RebuildNameView();
            ShowTrayBalloon(
                Localizer.T("名称解析事件已清空"),
                Localizer.T("只删除了 name_* 事件。"));
        }
        catch (Exception ex)
        {
            ShowError(Localizer.T("清空名称解析事件失败"), ex, "Failed to clear name resolution events");
        }
    }

    private async void OnNameBlockClick(object? sender, EventArgs e)
    {
        if (_nameSourceGrid.CurrentRow?.DataBoundItem is not NameSourceRow row)
        {
            return;
        }

        var enabling = !row.Blocked;

        if (enabling)
        {
            var confirmed = ConfirmForm.Show(
                owner: DialogOwner,
                title: Localizer.T("临时阻断此名称解析来源"),
                question: Localizer.F("确定要临时阻断「{0}」的名称解析应答吗？", row.Address),
                details: new[]
                {
                    new KeyValuePair<string, string>(
                        Localizer.T("将要做的"),
                        Localizer.T("只阻断该来源的 LLMNR / NBNS / mDNS 应答（UDP 5355/137/5353），最长 10 分钟")),
                    new KeyValuePair<string, string>(
                        Localizer.T("不会影响"),
                        Localizer.T("该来源的其它流量、正常 DNS 和其它防护功能")),
                },
                warnings: new[]
                {
                    Localizer.T("10 分钟后自动解除；服务重启也会解除。"),
                    Localizer.T("阻断期间该来源无法应答本机的名称解析请求。"),
                },
                confirmText: Localizer.T("阻断 10 分钟"));

            if (!confirmed)
            {
                return;
            }
        }

        try
        {
            var response = await CallServiceAsync(
                ServiceProtocol.Commands.BlockNameSource,
                new ServiceRequest
                {
                    NameBlockAddress = row.Address,
                    NameBlockMinutes = 10,
                    NameBlockEnabled = enabling,
                },
                Localizer.T(enabling ? "临时阻断此名称解析来源" : "解除名称解析阻断"));

            if (response is null)
            {
                return;
            }

            _nameSourceTable?.Invalidate();
            _nameEventTable?.Invalidate();
            _nameSources = response.NameSources ?? _nameSources;
            _nameEvents = response.NameResolutionEvents ?? _nameEvents;
            _nameStatus = response.NameResolutionStatus ?? _nameStatus;
            RebuildNameView();
            ShowTrayBalloon(
                Localizer.T(enabling ? "已临时阻断名称解析来源" : "已解除名称解析阻断"),
                enabling
                    ? Localizer.F("{0}\n10 分钟后自动解除。", row.Address)
                    : row.Address);
        }
        catch (Exception ex)
        {
            ShowError(Localizer.T("修改名称解析阻断失败"), ex, "Failed to change name resolution block");
        }
    }

    private sealed class NameSourceRow
    {
        public NameSourceRow(NameSourceDto item)
        {
            Address = item.Address;
            Mac = string.IsNullOrWhiteSpace(item.Mac) ? "—" : item.Mac;
            Protocols = item.Protocols;
            AnswerSummary = string.IsNullOrWhiteSpace(item.AnswerSummary) ? "—" : item.AnswerSummary;
            ResponseCount = item.ResponseCount;
            Blocked = item.Blocked;
            BlockExpiresUtc = item.BlockExpiresUtc;
        }

        public string Address { get; }

        public string Mac { get; }

        public string Protocols { get; }

        public string AnswerSummary { get; }

        public int ResponseCount { get; }

        public bool Blocked { get; }

        public DateTime? BlockExpiresUtc { get; }

        public string BlockText => !Blocked || BlockExpiresUtc is null
            ? "—"
            : Localizer.F(
                "剩余 {0} 分钟",
                Math.Max(1, (int)Math.Ceiling((BlockExpiresUtc.Value - DateTime.UtcNow).TotalMinutes)));
    }
}
