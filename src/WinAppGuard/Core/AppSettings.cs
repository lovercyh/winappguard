using System.Text;
using System.Text.Json;

namespace WinAppGuard.Core;

/// <summary>
/// 程序设置。保存在 %LOCALAPPDATA%\WinAppGuard\settings.json。
///
/// 为什么必须有它：
///   IP 归属查询默认**开启**。如果设置不落盘，用户把它关掉、重启程序后又会被打开 ——
///   他对隐私做出的选择被静默回滚。这不是取舍问题，是缺陷。
///
/// 隐私约定：
///   **这个文件里只存开关布尔值，绝不存任何 IP、进程名、路径或时间戳。**
///   它是设置，不是历史记录。自检工具会用 JSON 解析断言这一点。
///
/// 健壮性：
///   1. 文件缺失、读不出、JSON 非法 —— 一律回落到默认值，绝不因此报错；
///   2. 写入采用「先写临时文件再改名」，避免写入过程被打断留下半个文件，
///      那会导致下次启动读不出来、用户的「关闭」选择又悄悄丢掉。
///
/// 可测试性：
///   Load/Save 都可以传入路径。产品用默认路径；自检工具传临时文件，
///   这样验证「关闭能持久生效」时不会碰到用户真正的设置文件。
/// </summary>
public sealed class AppSettings
{
    /// <summary>
    /// IP 归属查询是否开启。
    /// 默认**开启**（产品负责人明确选择：与证书吊销检查一致的取舍）。
    /// </summary>
    public bool IpOwnershipEnabled { get; set; } = true;

    /// <summary>
    /// 是否已经向用户显示过「IP 归属查询会联网」的一次性告知。
    /// 只负责「不再重复弹」；回落到默认值 false 只会多弹一次，不会漏提示。
    /// </summary>
    public bool IpOwnershipNoticeShown { get; set; }

    /// <summary>设置文件的默认路径。界面上会显示它，让用户知道文件在哪、能不能删。</summary>
    public static string SettingsFilePath => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        AppConstants.AppDataFolderName,
        AppConstants.SettingsFileName);

    /// <summary>
    /// 读取设置。不传路径时用默认路径。
    /// 任何异常都回落到默认值 —— 一个设置文件绝不能让程序起不来。
    /// </summary>
    public static AppSettings Load(string? path = null)
    {
        try
        {
            var file = path ?? SettingsFilePath;
            if (!File.Exists(file))
            {
                return new AppSettings();
            }

            var json = File.ReadAllText(file, Encoding.UTF8);
            return JsonSerializer.Deserialize<AppSettings>(json) ?? new AppSettings();
        }
        catch (Exception)
        {
            return new AppSettings();
        }
    }

    /// <summary>
    /// 保存设置。不传路径时用默认路径。
    /// 同样地，任何异常都吞掉，不让设置文件影响程序运行。
    /// </summary>
    public void Save(string? path = null)
    {
        try
        {
            var file = path ?? SettingsFilePath;

            var directory = Path.GetDirectoryName(file);
            if (!string.IsNullOrEmpty(directory))
            {
                Directory.CreateDirectory(directory);
            }

            var json = JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true });

            // 先写临时文件再原子改名：中途崩溃也不会留下半个文件。
            var temporary = file + ".tmp";
            File.WriteAllText(temporary, json, Encoding.UTF8);
            File.Move(temporary, file, overwrite: true);
        }
        catch (Exception)
        {
            // 存不下就算了，不能因为设置文件影响程序运行。
        }
    }
}
