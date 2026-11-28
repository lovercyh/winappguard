using WinAppGuard.Contracts;
using WinAppGuard.Localization;

namespace WinAppGuard.Forms;

/// <summary>6.0：局域网设备信任清单（按 ARP/DHCP 事件里的 MAC 聚合）。</summary>
public sealed partial class MainForm
{
    private TabPage _tabLanDevices = null!;
    private DataGridView _lanDeviceGrid = null!;
    private Button _lanDeviceTrustButton = null!;

    private void InitializeLanDevicePage()
    {
        _tabLanDevices = new TabPage
        {
            Name = "_tabLanDevices",
            Text = Localizer.T("局域网设备"),
            Padding = new Padding(9),
            UseVisualStyleBackColor = true,
        };

        var top = new FlowLayoutPanel
        {
            Dock = DockStyle.Top,
            Height = 38,
            FlowDirection = FlowDirection.LeftToRight,
        };

        _lanDeviceTrustButton = new Button
        {
            Text = Localizer.T("信任选中设备"),
            AutoSize = true,
        };
        _lanDeviceTrustButton.Click += OnLanDeviceTrustClick;
        top.Controls.Add(_lanDeviceTrustButton);

        _lanDeviceGrid = new DataGridView
        {
            Dock = DockStyle.Fill,
            ReadOnly = true,
            AllowUserToAddRows = false,
            AllowUserToDeleteRows = false,
            AutoGenerateColumns = false,
            RowHeadersVisible = false,
            SelectionMode = DataGridViewSelectionMode.FullRowSelect,
            BackgroundColor = Color.White,
        };

        AddLanDeviceColumn("MAC", nameof(LanDeviceRow.Mac), 160);
        AddLanDeviceColumn(Localizer.T("最近 IP"), nameof(LanDeviceRow.Ip), 160);
        AddLanDeviceColumn(Localizer.T("事件数"), nameof(LanDeviceRow.Count), 70);
        AddLanDeviceColumn(Localizer.T("最近出现"), nameof(LanDeviceRow.LastSeen), 150);

        _tabLanDevices.Controls.Add(_lanDeviceGrid);
        _tabLanDevices.Controls.Add(top);
        _protectionTabs.Controls.Add(_tabLanDevices);
    }

    private void AddLanDeviceColumn(string header, string property, int width)
    {
        _lanDeviceGrid.Columns.Add(new DataGridViewTextBoxColumn
        {
            HeaderText = header,
            DataPropertyName = property,
            Width = width,
        });
    }

    private void RebuildLanDevicesView()
    {
        if (_lanDeviceGrid is null || _lanDeviceGrid.IsDisposed)
        {
            return;
        }

        var devices = _lanEvents
            .Where(item => !string.IsNullOrWhiteSpace(item.SourceMac))
            .GroupBy(item => item.SourceMac!, StringComparer.OrdinalIgnoreCase)
            .Select(group =>
            {
                var latest = group.OrderByDescending(item => item.TimeUtc).First();
                return new LanDeviceRow(
                    group.Key,
                    latest.TargetIp ?? string.Empty,
                    group.Count().ToString(),
                    latest.TimeUtc.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss"));
            })
            .OrderByDescending(item => item.LastSeen)
            .ToList();

        _lanDeviceGrid.DataSource = devices;
        _lanDeviceTrustButton.Enabled = devices.Count > 0;
    }

    private void OnLanDeviceTrustClick(object? sender, EventArgs e)
    {
        if (_lanDeviceGrid.CurrentRow?.DataBoundItem is not LanDeviceRow row)
        {
            return;
        }

        TrustLan("device", row.Mac, Localizer.T("信任局域网设备"));
    }

    private sealed record LanDeviceRow(string Mac, string Ip, string Count, string LastSeen);
}
