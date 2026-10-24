namespace WinAppGuard.Localization;

/// <summary>
/// MessageBox 的本地化包装。3.2 起 GUI 内的提示统一走这里，
/// 英文资源缺失时回退中文，不会出现空白框。
/// </summary>
internal static class UiMessageBox
{
    internal static DialogResult Show(
        string text, string caption,
        MessageBoxButtons buttons = MessageBoxButtons.OK,
        MessageBoxIcon icon = MessageBoxIcon.Information)
        => MessageBox.Show(
            Localizer.T(text), Localizer.T(caption), buttons, icon);

    internal static DialogResult Show(
        IWin32Window? owner, string text, string caption,
        MessageBoxButtons buttons = MessageBoxButtons.OK,
        MessageBoxIcon icon = MessageBoxIcon.Information)
        => MessageBox.Show(
            owner, Localizer.T(text), Localizer.T(caption), buttons, icon);
}
