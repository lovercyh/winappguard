using WinAppGuard.Core;
using WinAppGuard.Localization;
using WinAppGuard.Models;

namespace WinAppGuard.Forms;

/// <summary>
/// 5.13：文件夹批量添加黑名单 / 白名单。
///
/// 只扫描当前文件夹里的 .exe，生成预览；真正写入仍走服务端的批量导入路径。
/// 不跟随 junction/symlink，不访问网络路径，最多 2000 条。
/// </summary>
internal sealed class FolderRuleBatchForm : Form
{
    private readonly FirewallAction _action;
    private readonly HashSet<string> _existingRuleNames;
    private readonly TextBox _folderBox = new();
    private readonly CheckBox _recursiveCheck = new();
    private readonly ComboBox _expiryCombo = new();
    private readonly TextBox _groupBox = new();
    private readonly CheckBox _riskCheck = new();
    private readonly Button _browseButton = new();
    private readonly Button _scanButton = new();
    private readonly Button _addButton = new();
    private readonly Button _cancelButton = new();
    private readonly Button _selectAllButton = new();
    private readonly Button _selectNoneButton = new();
    private readonly ListView _list = new();
    private readonly Label _statusLabel = new();
    private readonly Label _warningLabel = new();
    private CancellationTokenSource? _scanCancellation;
    private bool _populating;

    internal FolderRuleBatchForm(
        FirewallAction action,
        IEnumerable<string> existingRuleNames)
    {
        _action = action;
        _existingRuleNames = new HashSet<string>(
            existingRuleNames, StringComparer.OrdinalIgnoreCase);

        BuildUi();
        UpdateAddButton();
    }

    internal List<string> SelectedPaths { get; } = new();

    internal string ExpiryEncoded { get; private set; } = string.Empty;

    internal string Group { get; private set; } = string.Empty;

    private bool IsAllow => _action == FirewallAction.Allow;

    private void BuildUi()
    {
        Text = IsAllow
            ? T("添加文件夹到白名单", "Add folder to whitelist")
            : T("添加文件夹到黑名单", "Add folder to blocklist");

        ClientSize = new Size(880, 660);
        FormBorderStyle = FormBorderStyle.FixedDialog;
        StartPosition = FormStartPosition.CenterParent;
        MinimizeBox = false;
        MaximizeBox = false;
        ShowIcon = false;
        ShowInTaskbar = false;

        var y = 12;

        _warningLabel.Location = new Point(12, y);
        _warningLabel.Size = new Size(856, 58);
        _warningLabel.ForeColor = Color.FromArgb(180, 60, 0);
        _warningLabel.Text = IsAllow
            ? T(
                "⚠ 把整个文件夹加入白名单，会让其中所有 exe 都能联网。\r\n" +
                "不要把 Downloads、Desktop、Temp 等可写目录加入白名单。\r\n" +
                "本次只添加扫描到的 exe；以后新增的 exe 不会自动加入。",
                "⚠ Adding a folder to the whitelist lets every .exe inside reach the network.\r\n" +
                "Do not add writable folders such as Downloads, Desktop or Temp.\r\n" +
                "Only the .exe files scanned now are added; future files are not automatic.")
            : string.Empty;
        _warningLabel.Visible = IsAllow;
        Controls.Add(_warningLabel);

        if (IsAllow)
        {
            y += _warningLabel.Height + 8;
        }

        var folderLabel = new Label
        {
            Text = T("文件夹：", "Folder:"),
            Location = new Point(12, y + 4),
            AutoSize = true,
        };
        Controls.Add(folderLabel);

        _folderBox.Location = new Point(80, y);
        _folderBox.Size = new Size(660, 26);
        _folderBox.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
        Controls.Add(_folderBox);

        _browseButton.Location = new Point(752, y - 2);
        _browseButton.Size = new Size(116, 30);
        _browseButton.Text = T("浏览…", "Browse…");
        _browseButton.Click += OnBrowseClick;
        Controls.Add(_browseButton);

        y += 40;

        _recursiveCheck.Location = new Point(12, y);
        _recursiveCheck.Size = new Size(180, 24);
        _recursiveCheck.Text = T("包含子文件夹", "Include subfolders");
        _recursiveCheck.Checked = true;
        Controls.Add(_recursiveCheck);

        var expiryLabel = new Label
        {
            Text = T("到期：", "Expiry:"),
            Location = new Point(206, y + 4),
            AutoSize = true,
        };
        Controls.Add(expiryLabel);

        _expiryCombo.DropDownStyle = ComboBoxStyle.DropDownList;
        _expiryCombo.Location = new Point(256, y);
        _expiryCombo.Size = new Size(150, 24);
        _expiryCombo.Items.AddRange(new object[]
        {
            T("永久", "Never"),
            T("1 小时", "1 hour"),
            T("8 小时", "8 hours"),
            T("24 小时", "24 hours"),
            T("下次重启", "Until reboot"),
        });
        _expiryCombo.SelectedIndex = 0;
        Controls.Add(_expiryCombo);

        var groupLabel = new Label
        {
            Text = T("分组：", "Group:"),
            Location = new Point(422, y + 4),
            AutoSize = true,
        };
        Controls.Add(groupLabel);

        _groupBox.Location = new Point(472, y);
        _groupBox.Size = new Size(396, 26);
        _groupBox.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
        Controls.Add(_groupBox);

        y += 38;

        _scanButton.Location = new Point(12, y);
        _scanButton.Size = new Size(120, 30);
        _scanButton.Text = T("扫描文件夹", "Scan folder");
        _scanButton.Click += OnScanClick;
        Controls.Add(_scanButton);

        _statusLabel.Location = new Point(144, y + 5);
        _statusLabel.Size = new Size(720, 22);
        _statusLabel.ForeColor = SystemColors.GrayText;
        _statusLabel.Text = T("选择文件夹后点“扫描文件夹”。", "Choose a folder, then click Scan.");
        Controls.Add(_statusLabel);

        y += 38;

        _list.Location = new Point(12, y);
        _list.Size = new Size(856, 660 - y - 58);
        _list.Anchor = AnchorStyles.Top | AnchorStyles.Bottom | AnchorStyles.Left | AnchorStyles.Right;
        _list.View = View.Details;
        _list.CheckBoxes = true;
        _list.FullRowSelect = true;
        _list.GridLines = true;
        _list.HideSelection = false;
        _list.Columns.Add(T("程序路径", "Executable"), 620);
        _list.Columns.Add(T("状态", "Status"), 210);
        _list.ItemChecked += (_, _) =>
        {
            if (!_populating)
            {
                UpdateAddButton();
            }
        };
        Controls.Add(_list);

        var bottom = ClientSize.Height - 46;

        _selectAllButton.Location = new Point(12, bottom);
        _selectAllButton.Size = new Size(110, 30);
        _selectAllButton.Text = T("全选可添加", "Select all");
        _selectAllButton.Click += (_, _) => SetAllSelectable(true);
        Controls.Add(_selectAllButton);

        _selectNoneButton.Location = new Point(128, bottom);
        _selectNoneButton.Size = new Size(110, 30);
        _selectNoneButton.Text = T("全不选", "Select none");
        _selectNoneButton.Click += (_, _) => SetAllSelectable(false);
        Controls.Add(_selectNoneButton);

        _riskCheck.Location = new Point(250, bottom + 3);
        _riskCheck.Size = new Size(360, 24);
        _riskCheck.Text = T("我理解风险，仍要添加", "I understand the risk");
        _riskCheck.Visible = IsAllow;
        _riskCheck.CheckedChanged += (_, _) => UpdateAddButton();
        Controls.Add(_riskCheck);

        _addButton.Location = new Point(642, bottom);
        _addButton.Size = new Size(110, 30);
        _addButton.Text = T("添加选中", "Add selected");
        _addButton.Click += OnAddClick;
        Controls.Add(_addButton);

        _cancelButton.Location = new Point(758, bottom);
        _cancelButton.Size = new Size(110, 30);
        _cancelButton.Text = T("取消", "Cancel");
        _cancelButton.DialogResult = DialogResult.Cancel;
        Controls.Add(_cancelButton);

        AcceptButton = _addButton;
        CancelButton = _cancelButton;

        FormClosed += (_, _) =>
        {
            _scanCancellation?.Cancel();
            _scanCancellation?.Dispose();
            _scanCancellation = null;
        };
    }

    private void OnBrowseClick(object? sender, EventArgs e)
    {
        using var dialog = new FolderBrowserDialog
        {
            Description = T("选择包含 exe 的文件夹", "Choose a folder containing .exe files"),
            ShowNewFolderButton = false,
        };

        if (dialog.ShowDialog(this) != DialogResult.OK)
        {
            return;
        }

        _folderBox.Text = dialog.SelectedPath;

        if (string.IsNullOrWhiteSpace(_groupBox.Text))
        {
            _groupBox.Text = BuildDefaultGroup(dialog.SelectedPath);
        }
    }

    private async void OnScanClick(object? sender, EventArgs e)
    {
        var folder = _folderBox.Text.Trim();

        if (folder.Length == 0)
        {
            UiMessageBox.Show(
                this,
                T("请先选择文件夹。", "Choose a folder first."),
                AppConstants.AppName,
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
            return;
        }

        if (string.IsNullOrWhiteSpace(_groupBox.Text))
        {
            _groupBox.Text = BuildDefaultGroup(folder);
        }

        _scanCancellation?.Cancel();
        _scanCancellation?.Dispose();
        _scanCancellation = new CancellationTokenSource();

        _scanButton.Enabled = false;
        _addButton.Enabled = false;
        _list.Items.Clear();
        _statusLabel.Text = T("正在扫描…", "Scanning…");
        UseWaitCursor = true;

        try
        {
            var recursive = _recursiveCheck.Checked;
            var token = _scanCancellation.Token;
            var result = await Task.Run(
                () => FolderRuleScanner.Scan(folder, recursive, FolderRuleScanner.DefaultMaxFiles, token),
                token);

            PopulateList(result, folder);
        }
        catch (OperationCanceledException)
        {
            _statusLabel.Text = T("扫描已取消。", "Scan cancelled.");
        }
        catch (Exception ex)
        {
            _statusLabel.Text = T($"扫描失败：{ex.Message}", $"Scan failed: {ex.Message}");
        }
        finally
        {
            UseWaitCursor = false;
            _scanButton.Enabled = true;
            UpdateAddButton();
        }
    }

    private void PopulateList(FolderScanResult result, string folder)
    {
        _populating = true;

        try
        {
        foreach (var path in result.Files)
        {
            var ruleName = IsAllow
                ? RuleNaming.BuildAllowRuleName(path)
                : RuleNaming.BuildBlockRuleName(path);

            var isProtected = ProtectedProcesses.IsProtected(path, out var protectReason);
            var exists = _existingRuleNames.Contains(ruleName);

            var status = isProtected
                ? T($"受保护，跳过：{protectReason}", $"Protected, skipped: {protectReason}")
                : exists
                    ? T("已存在，跳过", "Already exists, skipped")
                    : T("可添加", "Ready");

            var item = new ListViewItem(path)
            {
                Tag = new Candidate(path, !isProtected && !exists),
            };
            item.SubItems.Add(status);
            item.Checked = !isProtected && !exists;

            if (isProtected || exists)
            {
                item.ForeColor = SystemColors.GrayText;
            }

            _list.Items.Add(item);
        }

        var message = T(
            $"找到 {result.Files.Count} 个 exe；只添加当前扫描到的文件",
            $"{result.Files.Count} .exe file(s) found; only the files scanned now are added");

        if (result.Truncated)
        {
            message += T(
                $"（达到上限 {FolderRuleScanner.DefaultMaxFiles}，只显示前 {result.Files.Count} 个）",
                $" (limit {FolderRuleScanner.DefaultMaxFiles} reached; showing the first {result.Files.Count})");
        }

        if (result.Errors.Count > 0)
        {
            message += T(
                $"；{result.Errors.Count} 个扫描警告，详见日志",
                $"; {result.Errors.Count} scan warning(s), see the log");
        }

        _statusLabel.Text = message;

        if (result.Files.Count == 0)
        {
            UiMessageBox.Show(
                this,
                T(
                    "这个文件夹里没有找到 .exe。\r\n\r\n" +
                    "注意：.bat / .cmd / .ps1 / .msi / .lnk 不是独立的进程映像，不能按文件路径拦截。",
                    "No .exe was found in this folder.\r\n\r\n" +
                    "Note: .bat / .cmd / .ps1 / .msi / .lnk are not independent process images and cannot be blocked by file path."),
                AppConstants.AppName,
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
        }
        }
        finally
        {
            _populating = false;
            UpdateAddButton();
        }
    }

    private void SetAllSelectable(bool selected)
    {
        _populating = true;

        try
        {
            foreach (ListViewItem item in _list.Items)
            {
                if (item.Tag is Candidate candidate && candidate.Selectable)
                {
                    item.Checked = selected;
                }
            }
        }
        finally
        {
            _populating = false;
            UpdateAddButton();
        }
    }

    private void UpdateAddButton()
    {
        var any = _list.CheckedItems
            .Cast<ListViewItem>()
            .Any(item => item.Tag is Candidate candidate && candidate.Selectable);

        _addButton.Enabled = any && (!IsAllow || _riskCheck.Checked);
    }

    private void OnAddClick(object? sender, EventArgs e)
    {
        SelectedPaths.Clear();

        foreach (ListViewItem item in _list.CheckedItems)
        {
            if (item.Tag is Candidate candidate && candidate.Selectable)
            {
                SelectedPaths.Add(candidate.Path);
            }
        }

        if (SelectedPaths.Count == 0)
        {
            return;
        }

        if (IsAllow && !_riskCheck.Checked)
        {
            return;
        }

        ExpiryEncoded = BuildExpiry().Encode();
        Group = _groupBox.Text.Trim();

        if (Group.Length == 0)
        {
            Group = BuildDefaultGroup(_folderBox.Text.Trim());
        }

        if (Group.Length > 40)
        {
            Group = Group[..40];
        }

        DialogResult = DialogResult.OK;
        Close();
    }

    private RuleExpiry BuildExpiry()
        => _expiryCombo.SelectedIndex switch
        {
            1 => RuleExpiry.At(DateTime.UtcNow.AddHours(1)),
            2 => RuleExpiry.At(DateTime.UtcNow.AddHours(8)),
            3 => RuleExpiry.At(DateTime.UtcNow.AddHours(24)),
            4 => RuleExpiry.OnNextBoot(SystemUptime.BootTimeUtc),
            _ => RuleExpiry.Never,
        };

    private string BuildDefaultGroup(string folder)
    {
        var name = string.Empty;

        if (!string.IsNullOrWhiteSpace(folder))
        {
            try
            {
                name = new DirectoryInfo(folder).Name;
            }
            catch (Exception)
            {
                name = folder;
            }
        }

        if (string.IsNullOrWhiteSpace(name))
        {
            name = T("未命名", "unnamed");
        }

        var prefix = IsAllow ? T("文件夹白名单：", "Folder allow: ") : T("文件夹黑名单：", "Folder block: ");
        var group = prefix + name;

        return group.Length > 40 ? group[..40] : group;
    }

    private static string T(string chinese, string english)
        => Localizer.IsEnglish ? english : chinese;

    private sealed record Candidate(string Path, bool Selectable);
}
