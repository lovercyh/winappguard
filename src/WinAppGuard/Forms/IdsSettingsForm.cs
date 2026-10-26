using WinAppGuard.Contracts;
using WinAppGuard.Localization;

namespace WinAppGuard.Forms;

/// <summary>
/// 3.7：IDS 设置对话框。
///
/// 只收集用户选择，真正的写操作由主窗体走提权 IPC（write.ids.configure）。
/// 设置是机器级的，服务持久化；界面不直接写文件。
/// 抑制列表也在这里管理：取消选中项后随设置一起提交，只弹一次 UAC。
/// </summary>
internal sealed class IdsSettingsForm : Form
{
    private readonly CheckBox _enabled;
    private readonly ComboBox _sensitivity;
    private readonly ComboBox _retention;
    private readonly CheckBox _beaconing;
    private readonly CheckBox _scan;
    private readonly CheckBox _lateral;
    private readonly CheckBox _dns;
    private readonly ListBox _suppressionList;
    private readonly Button _removeSuppression;
    private readonly int[] _retentionDays;
    private readonly List<IdsSuppressionDto> _suppressions;
    private readonly HashSet<string> _originalSuppressionIds;

    private IdsSettingsForm(IdsSettingsDto current, IReadOnlyList<IdsSuppressionDto> suppressions)
    {
        Text = Localizer.T("IDS 设置");
        FormBorderStyle = FormBorderStyle.FixedDialog;
        StartPosition = FormStartPosition.CenterParent;
        MaximizeBox = false;
        MinimizeBox = false;
        ShowInTaskbar = false;
        ClientSize = new Size(500, 566);
        Font = new Font("Microsoft YaHei UI", 9F);

        _suppressions = suppressions.ToList();
        _originalSuppressionIds = _suppressions
            .Select(item => item.Id)
            .ToHashSet(StringComparer.Ordinal);

        var layout = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            Padding = new Padding(16),
            RowCount = 14,
        };

        for (var i = 0; i < 14; i++)
        {
            layout.RowStyles.Add(i == 11
                ? new RowStyle(SizeType.Absolute, 104)
                : new RowStyle(SizeType.AutoSize));
        }

        _enabled = new CheckBox
        {
            Text = Localizer.T("启用 IDS（只检测、不阻断）"),
            Checked = current.Enabled,
            AutoSize = true,
        };

        var sensitivityLabel = new Label
        {
            Text = Localizer.T("敏感度："),
            AutoSize = true,
            Margin = new Padding(3, 10, 3, 3),
        };

        _sensitivity = new ComboBox
        {
            DropDownStyle = ComboBoxStyle.DropDownList,
            Width = 360,
        };
        _sensitivity.Items.Add(Localizer.T("标准（POC 已实测：正常使用 10 分钟 0 告警）"));
        _sensitivity.Items.Add(Localizer.T("保守（阈值约为标准的 2 倍）"));
        _sensitivity.SelectedIndex = current.Sensitivity == "conservative" ? 1 : 0;

        var retentionLabel = new Label
        {
            Text = Localizer.T("告警保留："),
            AutoSize = true,
            Margin = new Padding(3, 10, 3, 3),
        };

        _retention = new ComboBox
        {
            DropDownStyle = ComboBoxStyle.DropDownList,
            Width = 160,
        };

        _retentionDays = new[] { 1, 3, 7, 30, 90, 180, 365 }
            .Concat(new[] { current.RetentionDays })
            .Distinct()
            .OrderBy(days => days)
            .ToArray();

        foreach (var days in _retentionDays)
        {
            _retention.Items.Add(Localizer.F("{0} 天", days));
        }

        _retention.SelectedIndex = Array.IndexOf(_retentionDays, current.RetentionDays);

        if (_retention.SelectedIndex < 0)
        {
            _retention.SelectedIndex = 0;
        }

        var rulesLabel = new Label
        {
            Text = Localizer.T("规则："),
            AutoSize = true,
            ForeColor = SystemColors.GrayText,
            Margin = new Padding(3, 12, 3, 3),
        };

        _beaconing = new CheckBox
        {
            Text = Localizer.T("周期性外联（beaconing）"),
            Checked = current.BeaconingRule,
            AutoSize = true,
        };

        _scan = new CheckBox
        {
            Text = Localizer.T("端口 / 主机扫描"),
            Checked = current.ScanRule,
            AutoSize = true,
        };

        _lateral = new CheckBox
        {
            Text = Localizer.T("内网横向（445 / 3389 / 5985 / 135 / 139）"),
            Checked = current.LateralRule,
            AutoSize = true,
        };

        _dns = new CheckBox
        {
            Text = Localizer.T("DNS 异常（同一父域大量子域 / NXDOMAIN）"),
            Checked = current.DnsRule,
            AutoSize = true,
        };

        var suppressionHeader = new FlowLayoutPanel
        {
            FlowDirection = FlowDirection.LeftToRight,
            AutoSize = true,
            WrapContents = false,
            Margin = new Padding(0, 12, 0, 0),
        };

        var suppressionLabel = new Label
        {
            Text = Localizer.T("现有抑制（只影响相同规则 / 程序 / 目标）："),
            AutoSize = true,
            ForeColor = SystemColors.GrayText,
            Margin = new Padding(3, 6, 12, 3),
        };

        _removeSuppression = new Button
        {
            Text = Localizer.T("取消选中抑制"),
            AutoSize = true,
            MinimumSize = new Size(112, 28),
        };
        _removeSuppression.Click += (_, _) => RemoveSelectedSuppression();

        suppressionHeader.Controls.Add(suppressionLabel);
        suppressionHeader.Controls.Add(_removeSuppression);

        _suppressionList = new ListBox
        {
            Dock = DockStyle.Fill,
            IntegralHeight = false,
            HorizontalScrollbar = true,
        };
        _suppressionList.SelectedIndexChanged += (_, _) => UpdateSuppressionButtons();

        var hint = new Label
        {
            Text = Localizer.T(
                "所有规则只产生告警，不会自动阻断连接。\n" +
                "IDS 关闭后不再产生新告警，已有告警保留到保留期结束。"),
            AutoSize = true,
            ForeColor = SystemColors.GrayText,
            Dock = DockStyle.Fill,
            Margin = new Padding(3, 10, 3, 3),
        };

        var buttons = new FlowLayoutPanel
        {
            FlowDirection = FlowDirection.RightToLeft,
            Dock = DockStyle.Fill,
            AutoSize = true,
        };

        var ok = new Button
        {
            Text = Localizer.T("确定"),
            DialogResult = DialogResult.OK,
            AutoSize = true,
            MinimumSize = new Size(88, 30),
        };

        var cancel = new Button
        {
            Text = Localizer.T("取消"),
            DialogResult = DialogResult.Cancel,
            AutoSize = true,
            MinimumSize = new Size(88, 30),
        };

        buttons.Controls.Add(ok);
        buttons.Controls.Add(cancel);

        layout.Controls.Add(_enabled, 0, 0);
        layout.Controls.Add(sensitivityLabel, 0, 1);
        layout.Controls.Add(_sensitivity, 0, 2);
        layout.Controls.Add(retentionLabel, 0, 3);
        layout.Controls.Add(_retention, 0, 4);
        layout.Controls.Add(rulesLabel, 0, 5);
        layout.Controls.Add(_beaconing, 0, 6);
        layout.Controls.Add(_scan, 0, 7);
        layout.Controls.Add(_lateral, 0, 8);
        layout.Controls.Add(_dns, 0, 9);
        layout.Controls.Add(suppressionHeader, 0, 10);
        layout.Controls.Add(_suppressionList, 0, 11);
        layout.Controls.Add(hint, 0, 12);
        layout.Controls.Add(buttons, 0, 13);

        Controls.Add(layout);
        AcceptButton = ok;
        CancelButton = cancel;

        RebuildSuppressionList();
    }

    private void RebuildSuppressionList()
    {
        var selectedId = (_suppressionList.SelectedItem as SuppressionItem)?.Value.Id;

        _suppressionList.BeginUpdate();
        _suppressionList.Items.Clear();

        foreach (var suppression in _suppressions)
        {
            _suppressionList.Items.Add(new SuppressionItem(suppression));
        }

        _suppressionList.EndUpdate();

        if (selectedId is not null)
        {
            for (var i = 0; i < _suppressionList.Items.Count; i++)
            {
                if (_suppressionList.Items[i] is SuppressionItem item
                    && string.Equals(item.Value.Id, selectedId, StringComparison.Ordinal))
                {
                    _suppressionList.SelectedIndex = i;
                    break;
                }
            }
        }

        UpdateSuppressionButtons();
    }

    private void RemoveSelectedSuppression()
    {
        if (_suppressionList.SelectedItem is not SuppressionItem item)
        {
            return;
        }

        _suppressions.RemoveAll(candidate =>
            string.Equals(candidate.Id, item.Value.Id, StringComparison.Ordinal));

        RebuildSuppressionList();
    }

    private void UpdateSuppressionButtons()
        => _removeSuppression.Enabled = _suppressionList.SelectedItem is SuppressionItem;

    /// <summary>取消返回 null；确定返回设置和要取消的抑制 id。</summary>
    internal static Result? Ask(
        IWin32Window? owner,
        IdsSettingsDto current,
        IReadOnlyList<IdsSuppressionDto> suppressions)
    {
        using var form = new IdsSettingsForm(current, suppressions);

        if (form.ShowDialog(owner) != DialogResult.OK)
        {
            return null;
        }

        var remaining = form._suppressions
            .Select(item => item.Id)
            .ToHashSet(StringComparer.Ordinal);

        return new Result(
            new IdsSettingsDto
            {
                Enabled = form._enabled.Checked,
                Sensitivity = form._sensitivity.SelectedIndex == 1 ? "conservative" : "standard",
                RetentionDays = form._retentionDays[Math.Max(0, form._retention.SelectedIndex)],
                BeaconingRule = form._beaconing.Checked,
                ScanRule = form._scan.Checked,
                LateralRule = form._lateral.Checked,
                DnsRule = form._dns.Checked,
            },
            form._originalSuppressionIds
                .Where(id => !remaining.Contains(id))
                .ToList());
    }

    internal readonly record struct Result(IdsSettingsDto Settings, List<string> RemovedSuppressionIds);

    private sealed class SuppressionItem
    {
        public SuppressionItem(IdsSuppressionDto value)
        {
            Value = value;
        }

        public IdsSuppressionDto Value { get; }

        public override string ToString()
        {
            var rule = Value.RuleId switch
            {
                "beaconing" => Localizer.T("周期性外联"),
                "scan" => Localizer.T("端口 / 主机扫描"),
                "lateral" => Localizer.T("内网横向"),
                "dns" => Localizer.T("DNS 异常"),
                "*" => Localizer.T("全部规则"),
                _ => Value.RuleId,
            };

            var process = string.IsNullOrEmpty(Value.ProcessPath)
                ? (string.IsNullOrEmpty(Value.ProcessName)
                    ? Localizer.T("全部程序")
                    : Value.ProcessName)
                : Path.GetFileName(Value.ProcessPath);

            var target = string.IsNullOrEmpty(Value.Target)
                ? Localizer.T("全部目标")
                : Value.Target;

            var until = Value.UntilUtc is { } untilUtc
                ? Localizer.F("到期 {0}", untilUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm"))
                : Localizer.T("永久");

            return $"{rule} · {process} · {target} · {until}";
        }
    }
}
