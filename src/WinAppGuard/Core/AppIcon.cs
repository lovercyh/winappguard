namespace WinAppGuard.Core;

/// <summary>
/// 应用程序图标。
///
/// 图标以**嵌入资源**的方式随程序一起打包，这样单文件发布也不会丢，
/// 运行期也不需要依赖任何外部文件。
///
/// exe 自身的图标由 csproj 里的 &lt;ApplicationIcon&gt; 指定 ——
/// 两处用的是同一个 app.ico 文件，避免出现「托盘一个样、exe 另一个样」。
/// </summary>
public static class AppIcon
{
    /// <summary>嵌入资源的逻辑名称，必须与 csproj 里的 LogicalName 一致。</summary>
    private const string ResourceName = "WinAppGuard.AppIcon.ico";

    /// <summary>
    /// 按指定尺寸加载图标。
    ///
    /// 系统托盘的实际尺寸是 <see cref="SystemInformation.SmallIconSize"/>（高 DPI 下可能是 20x20 或 24x24），
    /// ico 文件里各尺寸都是单独画好的，直接按目标尺寸取比让系统缩放清晰得多。
    /// </summary>
    public static Icon Load(Size size)
    {
        using var stream = typeof(AppIcon).Assembly.GetManifestResourceStream(ResourceName);

        if (stream is null)
        {
            // 资源万一丢了也要能用 —— 退回系统默认图标，总好过程序起不来。
            return SystemIcons.Application;
        }

        return new Icon(stream, size);
    }
}
