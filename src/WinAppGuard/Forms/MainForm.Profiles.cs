using WinAppGuard.Contracts;
using WinAppGuard.Localization;

namespace WinAppGuard.Forms;

/// <summary>6.0：程序画像页（只读，数据来自服务状态快照）。</summary>
public sealed partial class MainForm
{
    private TabPage _tabProgramProfiles = null!;
    private DataGridView _profileGrid = null!;
    private Label _profileSummary = null!;

    private void InitializeProgramProfilePage()
    {
        _tabProgramProfiles = new TabPage
        {
            Name = "_tabProgramProfiles",
            Text = Localizer.T("程序画像"),
            Padding = new Padding(9),
            UseVisualStyleBackColor = true,
        };

        _profileSummary = new Label
        {
            Dock = DockStyle.Top,
            Height = 44,
            Text = Localizer.T("画像：等待服务状态…"),
        };

        _profileGrid = new DataGridView
        {
            Dock = DockStyle.Fill,
            ReadOnly = true,
            AllowUserToAddRows = false,
            AllowUserToDeleteRows = false,
            AllowUserToResizeRows = false,
            AutoGenerateColumns = false,
            RowHeadersVisible = false,
            SelectionMode = DataGridViewSelectionMode.FullRowSelect,
            BackgroundColor = Color.White,
        };

        _profileGrid.Columns.Add(new DataGridViewTextBoxColumn
        {
            DataPropertyName = nameof(ProgramProfileRow.Path),
            HeaderText = Localizer.T("程序路径"),
            AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill,
        });
        _profileGrid.Columns.Add(new DataGridViewTextBoxColumn
        {
            DataPropertyName = nameof(ProgramProfileRow.Alerts),
            HeaderText = Localizer.T("告警数"),
            Width = 70,
        });
        _profileGrid.Columns.Add(new DataGridViewTextBoxColumn
        {
            DataPropertyName = nameof(ProgramProfileRow.Rate),
            HeaderText = Localizer.T("告警/小时"),
            Width = 90,
        });
        _profileGrid.Columns.Add(new DataGridViewTextBoxColumn
        {
            DataPropertyName = nameof(ProgramProfileRow.ColdStart),
            HeaderText = Localizer.T("冷启动"),
            Width = 70,
        });
        _profileGrid.Columns.Add(new DataGridViewTextBoxColumn
        {
            DataPropertyName = nameof(ProgramProfileRow.Service),
            HeaderText = Localizer.T("服务实例"),
            Width = 120,
        });
        _profileGrid.Columns.Add(new DataGridViewTextBoxColumn
        {
            DataPropertyName = nameof(ProgramProfileRow.Lolbin),
            HeaderText = Localizer.T("LOLBin"),
            Width = 180,
        });

        _tabProgramProfiles.Controls.Add(_profileGrid);
        _tabProgramProfiles.Controls.Add(_profileSummary);
        _tabControl.Controls.Add(_tabProgramProfiles);
    }

    private void UpdateProgramProfilePage(ServiceStatus? status)
    {
        if (_profileGrid is null || _profileGrid.IsDisposed)
        {
            return;
        }

        var profiles = status?.ProgramProfiles;

        if (profiles is null || profiles.Count == 0)
        {
            _profileSummary.Text = Localizer.T("画像：暂无数据（新告警会开始积累）");
            _profileGrid.DataSource = Array.Empty<ProgramProfileRow>();
            return;
        }

        _profileSummary.Text = Localizer.IsEnglish
            ? $"{profiles.Count} program profile(s); cold-start profiles do not raise new detections."
            : $"共 {profiles.Count} 个程序画像；冷启动画像只积累，不触发新检测。";

        _profileGrid.DataSource = profiles
            .Select(profile => new ProgramProfileRow(
                profile.Path,
                profile.AlertCount.ToString(),
                profile.EwmaAlertsPerHour.ToString("N2"),
                profile.ColdStart ? Localizer.T("是") : Localizer.T("否"),
                profile.ServiceInstance ?? string.Empty,
                profile.LolbinRule ?? string.Empty))
            .ToList();
    }

    private sealed record ProgramProfileRow(
        string Path, string Alerts, string Rate, string ColdStart, string Service, string Lolbin);
}
