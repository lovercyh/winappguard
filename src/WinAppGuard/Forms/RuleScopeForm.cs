using System.Globalization;
using WinAppGuard.Models;

namespace WinAppGuard.Forms;

/// <summary>
/// 「作用范围」对话框：协议 / 远端端口 / 网络位置。
///
/// 为什么单独一个对话框而不塞进"添加程序"里：
///   大多数人只想"把这个程序拦掉"（范围=任意），多一点选项就会劝退；
///   需要精细化的人则希望一次看清三项设置。
/// </summary>
internal sealed class RuleScopeForm : Form
{
    private readonly ComboBox _protocol;
    private readonly TextBox _ports;
    private readonly ComboBox _profile;
    private readonly Label _error;

    private RuleScopeForm(RuleScope current)
    {
        Text = "作用范围";
        FormBorderStyle = FormBorderStyle.FixedDialog;
        StartPosition = FormStartPosition.CenterParent;
        MaximizeBox = false;
        MinimizeBox = false;
        ShowInTaskbar = false;
        ClientSize = new Size(470, 250);
        Font = new Font("Microsoft YaHei UI", 9F);

        var layout = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 2,
            Padding = new Padding(16),
            RowCount = 5,
        };
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 110));
        layout.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));

        var protocolLabel = new Label { Text = "协议：", AutoSize = true, Anchor = AnchorStyles.Left };
        _protocol = new ComboBox
        {
            DropDownStyle = ComboBoxStyle.DropDownList,
            Dock = DockStyle.Top,
        };
        _protocol.Items.AddRange(new object[] { "任意协议", "TCP", "UDP" });
        _protocol.SelectedIndex = current.Protocol switch
        {
            RuleProtocol.Tcp => 1,
            RuleProtocol.Udp => 2,
            _ => 0,
        };

        var portLabel = new Label { Text = "远端端口：", AutoSize = true, Anchor = AnchorStyles.Left };
        _ports = new TextBox
        {
            Dock = DockStyle.Top,
            PlaceholderText = "留空 = 不限；单个 443，或范围 8000-8100",
        };
        _ports.Text = !current.HasPort
            ? string.Empty
            : current.IsSinglePort
                ? current.PortFrom.ToString(CultureInfo.InvariantCulture)
                : $"{current.PortFrom}-{current.PortTo}";

        var profileLabel = new Label { Text = "网络位置：", AutoSize = true, Anchor = AnchorStyles.Left };
        _profile = new ComboBox
        {
            DropDownStyle = ComboBoxStyle.DropDownList,
            Dock = DockStyle.Top,
        };
        _profile.Items.AddRange(new object[] { "任意网络", "公用网络", "专用网络", "域网络" });
        _profile.SelectedIndex = current.Profile switch
        {
            NetworkProfile.Public => 1,
            NetworkProfile.Private => 2,
            NetworkProfile.Domain => 3,
            _ => 0,
        };

        var hint = new Label
        {
            Text = "说明：\n· 端口是**远端端口**（目标是 443 就填 443）；\n" +
                   "· 指定端口时必须选 TCP 或 UDP（协议「任意」时无法按端口匹配）；\n" +
                   "· 网络位置就是 Windows 的「公用 / 专用 / 域」网络。",
            AutoSize = true,
            ForeColor = SystemColors.GrayText,
            Dock = DockStyle.Fill,
        };

        _error = new Label
        {
            Text = string.Empty,
            AutoSize = true,
            ForeColor = Color.FromArgb(180, 30, 30),
            Dock = DockStyle.Fill,
        };

        var buttons = new FlowLayoutPanel
        {
            FlowDirection = FlowDirection.RightToLeft,
            Dock = DockStyle.Fill,
            AutoSize = true,
        };

        var okButton = new Button
        {
            Text = "确定",
            AutoSize = true,
            MinimumSize = new Size(88, 30),
        };
        okButton.Click += OnOkClick;

        var cancelButton = new Button
        {
            Text = "取消",
            DialogResult = DialogResult.Cancel,
            AutoSize = true,
            MinimumSize = new Size(88, 30),
        };

        var resetButton = new Button
        {
            Text = "全部不限",
            AutoSize = true,
            MinimumSize = new Size(96, 30),
        };
        resetButton.Click += (_, _) =>
        {
            _protocol.SelectedIndex = 0;
            _ports.Clear();
            _profile.SelectedIndex = 0;
        };

        buttons.Controls.Add(okButton);
        buttons.Controls.Add(cancelButton);
        buttons.Controls.Add(resetButton);

        layout.Controls.Add(protocolLabel, 0, 0);
        layout.Controls.Add(_protocol, 1, 0);
        layout.Controls.Add(portLabel, 0, 1);
        layout.Controls.Add(_ports, 1, 1);
        layout.Controls.Add(profileLabel, 0, 2);
        layout.Controls.Add(_profile, 1, 2);
        layout.Controls.Add(hint, 0, 3);
        layout.SetColumnSpan(hint, 2);
        layout.Controls.Add(_error, 0, 4);
        layout.SetColumnSpan(_error, 2);

        Controls.Add(layout);
        Controls.Add(buttons);
        buttons.Dock = DockStyle.Bottom;

        AcceptButton = okButton;
        CancelButton = cancelButton;
        Result = null;
    }

    /// <summary>确定时返回用户选的范围；取消返回 null。</summary>
    internal RuleScope? Result { get; private set; }

    private void OnOkClick(object? sender, EventArgs e)
    {
        var protocol = _protocol.SelectedIndex switch
        {
            1 => RuleProtocol.Tcp,
            2 => RuleProtocol.Udp,
            _ => RuleProtocol.Any,
        };

        var profile = _profile.SelectedIndex switch
        {
            1 => NetworkProfile.Public,
            2 => NetworkProfile.Private,
            3 => NetworkProfile.Domain,
            _ => NetworkProfile.Any,
        };

        if (!TryParsePorts(_ports.Text, out var from, out var to, out var portError))
        {
            _error.Text = portError;
            return;
        }

        var scope = new RuleScope(protocol, from, to, profile);
        var validation = scope.Validate();

        if (validation is not null)
        {
            _error.Text = validation;
            return;
        }

        Result = scope;
        DialogResult = DialogResult.OK;
        Close();
    }

    /// <summary>解析「443」或「8000-8100」；空字符串 = 不限。</summary>
    internal static bool TryParsePorts(string? text, out int from, out int to, out string error)
    {
        from = 0;
        to = 0;
        error = string.Empty;

        var value = (text ?? string.Empty).Trim();

        if (value.Length == 0)
        {
            return true;
        }

        var parts = value.Split('-', StringSplitOptions.TrimEntries);

        if (parts.Length == 1)
        {
            if (!int.TryParse(parts[0], NumberStyles.Integer, CultureInfo.InvariantCulture, out from)
                || from is < 1 or > 65535)
            {
                error = "端口要填 1–65535 之间的数字，或者留空。";
                return false;
            }

            to = from;
            return true;
        }

        if (parts.Length == 2)
        {
            if (!int.TryParse(parts[0], NumberStyles.Integer, CultureInfo.InvariantCulture, out from)
                || !int.TryParse(parts[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out to)
                || from is < 1 or > 65535
                || to is < 1 or > 65535)
            {
                error = "端口范围的格式是「起始-结束」，两个数都要在 1–65535 之间。";
                return false;
            }

            if (from > to)
            {
                error = "端口范围的起始值不能大于结束值。";
                return false;
            }

            return true;
        }

        error = "端口格式不对：填一个端口（443），或一个范围（8000-8100）。";
        return false;
    }

    /// <summary>显示对话框；取消返回 null。</summary>
    internal static RuleScope? Ask(IWin32Window? owner, RuleScope current)
    {
        using var form = new RuleScopeForm(current);
        return form.ShowDialog(owner) == DialogResult.OK ? form.Result : null;
    }
}
