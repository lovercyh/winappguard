using System.Text;
using System.Text.Json;

namespace WinAppGuard.Core;

/// <summary>
/// 「界面状态」：窗口大小 / 位置，以及两个表格的列宽。
///
/// 为什么单独一个文件（`ui-state.json`），而不是塞进 `settings.json`：
/// `settings.json` 的约定是**只存布尔值**（README、安全说明、自检都按这条写死），
/// 而窗口尺寸/列宽是数值型的历史数据，混进去会直接破坏那条约定。
///
/// 隐私：里面只有窗口尺寸、屏幕坐标、列宽和界面语言 ——
/// **没有任何程序名、路径、IP 或时间戳**。
///
/// 健壮性：文件缺失、读不出、字段非法、坐标跑到屏幕外 —— 一律回落到「不恢复」，
/// 绝不能让一个记错的窗口位置把界面卡在屏幕外面打不开。
/// </summary>
internal sealed class UiState
{
    /// <summary>窗口客户区宽度；0 表示没有记录过。</summary>
    public int Width { get; set; }

    /// <summary>窗口客户区高度；0 表示没有记录过。</summary>
    public int Height { get; set; }

    /// <summary>窗口左上角 X；int.MinValue 表示没有记录过。</summary>
    public int X { get; set; } = int.MinValue;

    /// <summary>窗口左上角 Y；int.MinValue 表示没有记录过。</summary>
    public int Y { get; set; } = int.MinValue;

    /// <summary>上次退出时是否最大化。</summary>
    public bool Maximized { get; set; }

    /// <summary>
    /// 界面语言：auto / zh / en。只影响 UI，不影响服务或规则。
    /// auto = 系统 UI 是中文就中文，其它语言一律英文。
    /// </summary>
    public string Language { get; set; } = "auto";

    /// <summary>列宽：键是「表格名.列名」，值是像素宽。</summary>
    public Dictionary<string, int> ColumnWidths { get; set; } =
        new(StringComparer.OrdinalIgnoreCase);

    /// <summary>默认路径（界面上不展示这个文件，它只是本机状态）。</summary>
    public static string FilePath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        AppConstants.AppDataFolderName,
        "ui-state.json");

    /// <summary>读取。任何异常都回落到空状态（= 用默认布局）。</summary>
    public static UiState Load(string? path = null)
    {
        try
        {
            var file = path ?? FilePath;
            if (!File.Exists(file))
            {
                return new UiState();
            }

            var json = File.ReadAllText(file, Encoding.UTF8);
            var state = JsonSerializer.Deserialize<UiState>(json) ?? new UiState();

            state.ColumnWidths ??= new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);

            if (state.Language is not ("auto" or "zh" or "en"))
            {
                state.Language = "auto";
            }

            return state;
        }
        catch (Exception)
        {
            return new UiState();
        }
    }

    /// <summary>保存（先写临时文件再改名；失败就算了，不能因此影响程序运行）。</summary>
    public void Save(string? path = null)
    {
        try
        {
            var file = path ?? FilePath;

            var directory = Path.GetDirectoryName(file);
            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }

            var json = JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true });
            var temporary = file + ".tmp";

            File.WriteAllText(temporary, json, new UTF8Encoding(false));
            File.Move(temporary, file, overwrite: true);
        }
        catch (Exception)
        {
            // 存不下就算了：界面状态丢失最多是窗口位置回到默认，不能影响功能。
        }
    }

    /// <summary>
    /// 这个窗口位置是不是落在某块屏幕的可见区域里。
    /// 用来防止「上次在副屏关闭、这次副屏拔了」导致窗口跑到看不见的地方。
    /// </summary>
    public bool HasUsableBounds()
    {
        if (Width <= 0 || Height <= 0 || X == int.MinValue || Y == int.MinValue)
        {
            return false;
        }

        var bounds = new Rectangle(X, Y, Width, Height);

        foreach (var screen in Screen.AllScreens)
        {
            // 至少要有 120×120 的标题栏区域落在屏幕里，否则拖不回来。
            var visible = Rectangle.Intersect(
                bounds,
                new Rectangle(screen.WorkingArea.X, screen.WorkingArea.Y, screen.WorkingArea.Width, 120));

            if (visible.Width >= 120 && visible.Height >= 60)
            {
                return true;
            }
        }

        return false;
    }
}
