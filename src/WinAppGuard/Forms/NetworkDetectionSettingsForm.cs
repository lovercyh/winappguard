using WinAppGuard.Contracts;
using WinAppGuard.Core.Diagnostics.NetworkDetection;
using WinAppGuard.Localization;

namespace WinAppGuard.Forms;

/// <summary>5.1：反网络攻击设置，包含规则分类开关。</summary>
internal sealed class NetworkDetectionSettingsForm : Form
{
    private readonly CheckBox _enabled;
    private readonly ComboBox _profile;
    private readonly ComboBox _capture;
    private readonly Button _captureRefresh;
    private readonly Label _captureNote;
    private readonly CheckBox _notify;
    private readonly NumericUpDown _retention;
    private readonly CheckedListBox _categories;
    private readonly Button _selectAll;
    private readonly Button _selectNone;

    private NetworkDetectionSettingsForm(NetworkDetectionSettingsDto current)
    {
        Text = Localizer.T("反网络攻击设置");
        Font = new Font("Microsoft YaHei UI", 9F);
        FormBorderStyle = FormBorderStyle.FixedDialog;
        StartPosition = FormStartPosition.CenterParent;
        MaximizeBox = false;
        MinimizeBox = false;
        ShowInTaskbar = false;
        AutoScroll = true;
        ClientSize = new Size(520, 660);

        var layout = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            Padding = new Padding(16),
            RowCount = 13,
        };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        for (var i = 0; i < 13; i++)
        {
            layout.RowStyles.Add(i == 7
                ? new RowStyle(SizeType.Absolute, 170)
                : new RowStyle(SizeType.AutoSize));
        }

        _enabled = new CheckBox
        {
            AutoSize = true,
            Checked = current.Enabled,
            Text = Localizer.T("启用反网络攻击检测（Suricata + ET Open）"),
        };
        layout.Controls.Add(_enabled, 0, 0);

        layout.Controls.Add(new Label
        {
            AutoSize = true,
            Margin = new Padding(0, 12, 0, 4),
            Text = Localizer.T("规则档位："),
        }, 0, 1);

        _profile = new ComboBox
        {
            DropDownStyle = ComboBoxStyle.DropDownList,
            Width = 320,
        };
        _profile.Items.Add(Localizer.T("标准（推荐，客户端高价值规则）"));
        _profile.Items.Add(Localizer.T("全量（ET Open 全部规则，资源占用更高）"));
        _profile.SelectedIndex = string.Equals(
            current.RuleProfile, "full", StringComparison.OrdinalIgnoreCase) ? 1 : 0;
        layout.Controls.Add(_profile, 0, 2);

        layout.Controls.Add(new Label
        {
            AutoSize = true,
            Margin = new Padding(0, 12, 0, 4),
            Text = Localizer.T("监听网卡："),
        }, 0, 3);

        var capturePanel = new FlowLayoutPanel
        {
            AutoSize = true,
            FlowDirection = FlowDirection.LeftToRight,
            WrapContents = false,
            Margin = new Padding(0),
        };

        _capture = new ComboBox
        {
            DropDownStyle = ComboBoxStyle.DropDownList,
            Width = 360,
        };

        _captureRefresh = new Button
        {
            Text = Localizer.T("刷新"),
            Width = 72,
            Margin = new Padding(6, 0, 0, 0),
        };
        _captureRefresh.Click += (_, _) => LoadCaptureDevices(SelectedCaptureDeviceId());

        capturePanel.Controls.Add(_capture);
        capturePanel.Controls.Add(_captureRefresh);
        layout.Controls.Add(capturePanel, 0, 4);

        _captureNote = new Label
        {
            AutoSize = true,
            ForeColor = SystemColors.GrayText,
            MaximumSize = new Size(470, 0),
            Margin = new Padding(0, 4, 0, 0),
            Text = Localizer.T("修改监听网卡会重启 Suricata 检测；保存设置需要一次 UAC。"),
        };
        layout.Controls.Add(_captureNote, 0, 5);

        layout.Controls.Add(new Label
        {
            AutoSize = true,
            Margin = new Padding(0, 12, 0, 4),
            Text = Localizer.T("规则分类（只作用于标准档）："),
        }, 0, 6);

        _categories = new CheckedListBox
        {
            Dock = DockStyle.Fill,
            CheckOnClick = true,
            IntegralHeight = false,
            BorderStyle = BorderStyle.FixedSingle,
        };

        var enabledCategories = current.EnabledRuleCategories is { Count: > 0 }
            ? current.EnabledRuleCategories
            : NetworkRuleCategories.DefaultEnabled.ToList();

        foreach (var id in NetworkRuleCategories.All)
        {
            var option = new CategoryOption(
                id,
                Localizer.T(NetworkRuleCategories.DisplayName(id)));

            _categories.Items.Add(option, enabledCategories.Contains(
                id, StringComparer.OrdinalIgnoreCase));
        }

        layout.Controls.Add(_categories, 0, 7);

        var categoryButtons = new FlowLayoutPanel
        {
            AutoSize = true,
            FlowDirection = FlowDirection.LeftToRight,
            Margin = new Padding(0, 6, 0, 0),
        };
        _selectAll = new Button { Text = Localizer.T("全选"), Width = 78 };
        _selectNone = new Button { Text = Localizer.T("全不选"), Width = 78 };
        _selectAll.Click += (_, _) => SetAllCategories(true);
        _selectNone.Click += (_, _) => SetAllCategories(false);
        categoryButtons.Controls.Add(_selectAll);
        categoryButtons.Controls.Add(_selectNone);
        layout.Controls.Add(categoryButtons, 0, 8);

        _notify = new CheckBox
        {
            AutoSize = true,
            Checked = current.Notify,
            Margin = new Padding(0, 12, 0, 0),
            Text = Localizer.T("新的高危告警显示托盘通知"),
        };
        layout.Controls.Add(_notify, 0, 9);

        var retentionPanel = new FlowLayoutPanel
        {
            AutoSize = true,
            Margin = new Padding(0, 12, 0, 0),
        };
        retentionPanel.Controls.Add(new Label
        {
            AutoSize = true,
            Text = Localizer.T("告警保留天数："),
            Margin = new Padding(0, 6, 6, 0),
        });

        _retention = new NumericUpDown
        {
            Minimum = 1,
            Maximum = 365,
            Value = Math.Clamp(current.RetentionDays, 1, 365),
            Width = 80,
        };
        retentionPanel.Controls.Add(_retention);
        layout.Controls.Add(retentionPanel, 0, 10);

        layout.Controls.Add(new Label
        {
            AutoSize = true,
            ForeColor = Color.FromArgb(150, 90, 0),
            MaximumSize = new Size(440, 0),
            Margin = new Padding(0, 12, 0, 0),
            Text = Localizer.T(
                "被动检测只告警，不自动拦截。命中后由你手动选择是否用 WFP 临时阻断；HTTPS 正文不可见。全量档忽略分类开关。"),
        }, 0, 11);

        var buttons = new FlowLayoutPanel
        {
            FlowDirection = FlowDirection.RightToLeft,
            Dock = DockStyle.Fill,
            AutoSize = true,
            Margin = new Padding(0, 16, 0, 0),
        };
        var cancel = new Button { Text = Localizer.T("取消"), DialogResult = DialogResult.Cancel, Width = 88 };
        var ok = new Button { Text = Localizer.T("保存"), DialogResult = DialogResult.OK, Width = 88 };
        buttons.Controls.Add(cancel);
        buttons.Controls.Add(ok);
        layout.Controls.Add(buttons, 0, 12);

        _profile.SelectedIndexChanged += (_, _) => UpdateCategoryState();
        UpdateCategoryState();
        LoadCaptureDevices(current.CaptureDeviceId);

        Controls.Add(layout);
        AcceptButton = ok;
        CancelButton = cancel;
    }

    private void SetAllCategories(bool value)
    {
        for (var i = 0; i < _categories.Items.Count; i++)
        {
            _categories.SetItemChecked(i, value);
        }
    }

    private void UpdateCategoryState()
    {
        var enabled = _profile.SelectedIndex != 1;
        _categories.Enabled = enabled;
        _selectAll.Enabled = enabled;
        _selectNone.Enabled = enabled;
    }

    private List<string> SelectedCategories()
        => _categories.CheckedItems
            .Cast<CategoryOption>()
            .Select(option => option.Id)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

    private string SelectedCaptureDeviceId()
        => (_capture.SelectedItem as AdapterOption)?.Id ?? string.Empty;

    private void LoadCaptureDevices(string? selectedId)
    {
        var adapters = NetworkCaptureDevices.Enumerate().ToList();

        _capture.BeginUpdate();
        _capture.Items.Clear();
        _capture.Items.Add(new AdapterOption(string.Empty, Localizer.T("自动（推荐）")));

        foreach (var adapter in adapters
                     .Where(item => !item.IsLoopback
                                    && item.Type != System.Net.NetworkInformation.NetworkInterfaceType.Loopback)
                     .OrderByDescending(item => item.IsUp)
                     .ThenBy(item => item.DisplayName, StringComparer.CurrentCultureIgnoreCase))
        {
            var status = adapter.IsUp ? string.Empty : Localizer.T("（未连接）");
            var virtualAdapter = adapter.Description.Contains(
                    "Virtual", StringComparison.OrdinalIgnoreCase)
                || adapter.Description.Contains("VMware", StringComparison.OrdinalIgnoreCase)
                || adapter.Description.Contains("Hyper-V", StringComparison.OrdinalIgnoreCase)
                    ? Localizer.T("（虚拟网卡）")
                    : string.Empty;
            var tunnel = adapter.IsTunnel
                ? Localizer.T("（VPN / 隧道，可能抓不到）")
                : string.Empty;

            _capture.Items.Add(new AdapterOption(
                adapter.Id,
                $"{adapter.DisplayName} — {adapter.Description}{status}{virtualAdapter}{tunnel}"));
        }

        var selected = _capture.Items
            .Cast<AdapterOption>()
            .FirstOrDefault(option =>
                !string.IsNullOrEmpty(selectedId)
                && string.Equals(option.Id, selectedId, StringComparison.OrdinalIgnoreCase));

        if (selected is null && !string.IsNullOrWhiteSpace(selectedId))
        {
            selected = new AdapterOption(
                selectedId.Trim(),
                Localizer.T("原选择（当前不可用）"));
            _capture.Items.Add(selected);
            _captureNote.Text = Localizer.T(
                "原选择不可用，已回退到自动；重新选择后会保存新网卡。");
        }
        else
        {
            _captureNote.Text = Localizer.T(
                "修改监听网卡会重启 Suricata 检测；保存设置需要一次 UAC。");
        }

        _capture.SelectedItem = selected ?? _capture.Items[0];
        _capture.EndUpdate();
    }

    internal static NetworkDetectionSettingsDto? Ask(
        IWin32Window? owner,
        NetworkDetectionSettingsDto current)
    {
        using var form = new NetworkDetectionSettingsForm(current);

        if (form.ShowDialog(owner) != DialogResult.OK)
        {
            return null;
        }

        var profile = form._profile.SelectedIndex == 1 ? "full" : "standard";
        var categories = form.SelectedCategories();

        if (profile == "standard" && categories.Count == 0)
        {
            UiMessageBox.Show(
                owner,
                Localizer.T("至少需要启用一个规则分类。"),
                Localizer.T("规则分类"),
                MessageBoxButtons.OK,
                MessageBoxIcon.Warning);
            return null;
        }

        return new NetworkDetectionSettingsDto
        {
            Enabled = form._enabled.Checked,
            RuleProfile = profile,
            Notify = form._notify.Checked,
            RetentionDays = (int)form._retention.Value,
            EnabledRuleCategories = categories,
            CaptureDeviceId = form.SelectedCaptureDeviceId(),
        };
    }

    private sealed class CategoryOption
    {
        internal CategoryOption(string id, string name)
        {
            Id = id;
            Name = name;
        }

        internal string Id { get; }

        internal string Name { get; }

        public override string ToString() => Name;
    }

    private sealed class AdapterOption
    {
        internal AdapterOption(string id, string name)
        {
            Id = id;
            Name = name;
        }

        internal string Id { get; }

        internal string Name { get; }

        public override string ToString() => Name;
    }
}
