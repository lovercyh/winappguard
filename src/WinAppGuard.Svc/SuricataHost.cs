using System.Diagnostics;
using System.Text;
using WinAppGuard.Contracts;
using WinAppGuard.Core.Diagnostics.AntiScan;
using WinAppGuard.Core.Diagnostics.NetworkDetection;

namespace WinAppGuard.Service;

/// <summary>
/// 5.0：Suricata 子进程宿主。
///
/// 只做三件事：
///   1. 找到官方 Suricata；
///   2. 生成最小可用配置并启动/停止子进程；
///   3. 暴露版本、规则数、最后错误，供界面显示。
///
/// 不修改 Suricata 二进制，不注册独立服务，不碰防火墙规则。
/// </summary>
internal static class SuricataHost
{
    private static readonly object Gate = new();

    private static Process? _process;
    private static System.Threading.Timer? _monitor;
    private static bool _enabled;
    private static bool _stopping;
    private static DateTime _nextRestartUtc = DateTime.MinValue;
    private static int _restartDelaySeconds = 5;
    private static string? _executable;
    private static string? _installDirectory;
    private static string? _configPath;
    private static string? _rulesFile;
    private static string? _lastError;
    private static string? _version;
    private static string _profile = "standard";
    private static IReadOnlyList<string> _enabledCategories = NetworkRuleCategories.DefaultEnabled;
    private static string _captureDeviceId = string.Empty;
    private static string? _captureDeviceName;
    private static bool _captureFallback;
    private static string? _captureNote;
    private static int _ruleCount;
    private static string _validatedSignature = string.Empty;
    private static string? _activeBackupPath;
    private static int _generation;
    private static int _preparing;
    private static int _startRequested;
    private static string? _captureDevicePath;
    private static Process? _validationProcess;

    internal static bool IsRunning
    {
        get
        {
            lock (Gate)
            {
                return _process is { HasExited: false };
            }
        }
    }

    internal static string? LastError
    {
        get { lock (Gate) { return _lastError; } }
    }

    internal static string? Version
    {
        get { lock (Gate) { return _version; } }
    }

    internal static int RuleCount
    {
        get { lock (Gate) { return _ruleCount; } }
    }

    /// <summary>6.0：正在拼接规则或执行 -T 校验。</summary>
    internal static bool Preparing => Volatile.Read(ref _preparing) == 1;

    internal static string? CaptureDeviceName
    {
        get { lock (Gate) { return _captureDeviceName; } }
    }

    internal static bool CaptureFallback
    {
        get { lock (Gate) { return _captureFallback; } }
    }

    internal static string? CaptureNote
    {
        get { lock (Gate) { return _captureNote; } }
    }

    internal static void Start(
        bool enabled,
        string ruleProfile,
        IReadOnlyList<string>? enabledCategories = null,
        string? captureDeviceId = null)
    {
        lock (Gate)
        {
            _enabled = enabled;
            _stopping = false;
            _profile = string.Equals(ruleProfile, "full", StringComparison.OrdinalIgnoreCase)
                ? "full"
                : string.Equals(ruleProfile, "curated", StringComparison.OrdinalIgnoreCase)
                    ? "curated"
                    : "standard";
            _enabledCategories = _profile == "curated"
                ? NetworkRuleCategories.Curated
                : NormalizeCategories(enabledCategories);
            _captureDeviceId = captureDeviceId?.Trim() ?? string.Empty;
            _generation++;

            if (!enabled)
            {
                StopProcessLocked();
                _monitor?.Dispose();
                _monitor = null;
                return;
            }

            if (_monitor is null)
            {
                _monitor = new System.Threading.Timer(
                    _ => MonitorTick(),
                    null,
                    TimeSpan.FromSeconds(1),
                    TimeSpan.FromSeconds(10));
            }
        }

        QueueStart(ruleProfile);
    }

    internal static void Stop()
    {
        lock (Gate)
        {
            _enabled = false;
            _stopping = true;
            _generation++;
            _monitor?.Dispose();
            _monitor = null;
            KillValidationProcess();
            StopProcessLocked();
        }
    }

    /// <summary>配置档切换后调用：重启子进程，让 Suricata 重新加载规则。</summary>
    internal static void Reload(
        string ruleProfile,
        IReadOnlyList<string>? enabledCategories = null,
        string? captureDeviceId = null)
    {
        lock (Gate)
        {
            _profile = string.Equals(ruleProfile, "full", StringComparison.OrdinalIgnoreCase)
                ? "full"
                : string.Equals(ruleProfile, "curated", StringComparison.OrdinalIgnoreCase)
                    ? "curated"
                    : "standard";
            _enabledCategories = _profile == "curated"
                ? NetworkRuleCategories.Curated
                : NormalizeCategories(enabledCategories);
            _captureDeviceId = captureDeviceId?.Trim() ?? string.Empty;
            _generation++;
            KillValidationProcess();
            StopProcessLocked();
            _nextRestartUtc = DateTime.MinValue;
        }

        if (_enabled)
        {
            QueueStart(ruleProfile);
        }
    }

    internal static int ThreatFoxThreshold(string profile) => profile switch
    {
        "full" => 0,
        "standard" => 90,
        _ => 100,
    };

    private static int RuleConfidence(string line)
    {
        const string marker = "confidence_level ";
        var index = line.IndexOf(marker, StringComparison.OrdinalIgnoreCase);

        if (index < 0)
        {
            return 0;
        }

        index += marker.Length;
        var end = index;

        while (end < line.Length && char.IsAsciiDigit(line[end]))
        {
            end++;
        }

        return int.TryParse(line.AsSpan(index, end - index), out var value) ? value : 0;
    }

    private static IReadOnlyList<string> NormalizeCategories(
        IReadOnlyList<string>? categories)
    {
        var selected = (categories ?? Array.Empty<string>())
            .Where(NetworkRuleCategories.IsKnown)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        return selected.Count > 0
            ? selected
            : NetworkRuleCategories.DefaultEnabled;
    }

    private static void MonitorTick()
    {
        string profile;

        lock (Gate)
        {
            if (!_enabled || _stopping)
            {
                return;
            }

            if (_process is { HasExited: false })
            {
                return;
            }

            if (DateTime.UtcNow < _nextRestartUtc)
            {
                return;
            }

            profile = _profile;
            _lastError = _process is null
                ? _lastError
                : $"Suricata 已退出（代码 {SafeExitCode(_process)}）。";
        }

        EnsureRunning(profile);
    }

    private static void EnsureRunning(string ruleProfile)
    {
        if (Interlocked.CompareExchange(ref _preparing, 1, 0) != 0)
        {
            Interlocked.Exchange(ref _startRequested, 1);
            return;
        }

        try
        {
            int generation;

            lock (Gate)
            {
                if (!_enabled || _stopping || _process is { HasExited: false })
                {
                    return;
                }

                generation = _generation;
            }

            // 6.0：拼接 13 万条规则并执行 Suricata -T 可能耗时数分钟。
            // 这段必须放在锁外，否则保存设置和状态查询会一起超时。
            if (!PrepareRules(ruleProfile))
            {
                lock (Gate)
                {
                    Interlocked.Exchange(ref _startRequested, 0);

                    if (_enabled && !_stopping)
                    {
                        ScheduleRestartLocked();
                    }
                }

                return;
            }

            lock (Gate)
            {
                if (generation != _generation || !_enabled || _stopping
                    || _process is { HasExited: false })
                {
                    _nextRestartUtc = DateTime.MinValue;

                    if (generation != _generation && _enabled && !_stopping)
                    {
                        // 准备期间用户又切了档位：立即用新档位重来，不等监控定时器。
                        Interlocked.Exchange(ref _startRequested, 1);
                    }

                    return;
                }

                StartProcessLocked(ruleProfile);
            }
        }
        catch (Exception ex)
        {
            lock (Gate)
            {
                _lastError = $"启动 Suricata 失败：{ex.Message}";
                ScheduleRestartLocked();
            }

            ServiceLog.Warning("WAG-ND-002", "Failed to start Suricata.", ex);
        }
        finally
        {
            Interlocked.Exchange(ref _preparing, 0);

            if (Interlocked.Exchange(ref _startRequested, 0) == 1)
            {
                string profile;

                lock (Gate)
                {
                    profile = _profile;
                }

                QueueStart(profile);
            }
        }
    }

    /// <summary>
    /// 6.0：在锁外完成规则拼接、-T 校验和网卡解析。
    /// 返回 false 表示本轮失败，由调用方安排重试。
    /// </summary>
    private static bool PrepareRules(string ruleProfile)
    {
        if (!EnsurePrepared(ruleProfile))
        {
            return false;
        }

        if (!ValidateConfig())
        {
            RestoreActiveRulesBackup();
            return false;
        }

        CommitActiveRulesBackup();

        var resolution = NetworkCaptureDevices.Resolve(
            _captureDeviceId,
            NetworkCaptureDevices.Enumerate());

        _captureDeviceName = resolution.AdapterName;
        _captureFallback = resolution.Fallback;
        _captureNote = resolution.Reason;

        if (resolution.DevicePath is null)
        {
            _lastError = resolution.Reason
                ?? "找不到可用的网卡；请检查 Npcap 和网络连接。";
            return false;
        }

        _captureDevicePath = resolution.DevicePath;
        return true;
    }

    /// <summary>6.0：进程启动只占很短的时间，放在锁内完成。</summary>
    private static void StartProcessLocked(string ruleProfile)
    {
        var device = _captureDevicePath;

        if (string.IsNullOrEmpty(device))
        {
            _lastError = "找不到可用的网卡；请检查 Npcap 和网络连接。";
            ScheduleRestartLocked();
            return;
        }

        var classification = Path.Combine(_installDirectory!, "classification.config");
        var reference = Path.Combine(_installDirectory!, "reference.config");

        var arguments =
            $"-c \"{_configPath}\" " +
            $"-i \"{device}\" " +
            $"-l \"{ServicePaths.SuricataDirectory}\" " +
            $"-S \"{_rulesFile}\" " +
            $"--set \"classification-file={classification}\" " +
            $"--set \"reference-config-file={reference}\"";

        var info = new ProcessStartInfo
        {
            FileName = _executable!,
            Arguments = arguments,
            WorkingDirectory = _installDirectory!,
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
        };

        ApplyNpcapPath(info);

        var process = new Process { StartInfo = info, EnableRaisingEvents = true };
        process.OutputDataReceived += (_, e) => AppendLog(e.Data);
        process.ErrorDataReceived += (_, e) => AppendLog(e.Data);

        if (!process.Start())
        {
            _lastError = "无法启动 Suricata 进程。";
            process.Dispose();
            ScheduleRestartLocked();
            return;
        }

        process.BeginOutputReadLine();
        process.BeginErrorReadLine();

        _process = process;
        _restartDelaySeconds = 5;
        _nextRestartUtc = DateTime.MinValue;
        _lastError = null;

        ServiceLog.Info(
            "WAG-ND-001",
            $"Suricata started (pid={process.Id}, profile={ruleProfile}, rules={_ruleCount}, device={device}).");
    }

    private static void QueueStart(string ruleProfile)
    {
        _ = Task.Run(() =>
        {
            try
            {
                EnsureRunning(ruleProfile);
            }
            catch (Exception ex)
            {
                ServiceLog.Warning("WAG-ND-002", "Failed to queue Suricata start.", ex);
            }
        });
    }

    /// <summary>
    /// 启动前先用 Suricata 自己的 -T 校验配置和规则。
    /// 规则/配置没变时复用上次结果，避免每次重启都扫描 1 万多条规则。
    /// </summary>
    private static bool ValidateConfig()
    {
        try
        {
            var configTime = File.GetLastWriteTimeUtc(_configPath!).Ticks;
            var rulesTime = File.GetLastWriteTimeUtc(_rulesFile!).Ticks;
            var signature = $"{_configPath}|{configTime}|{_rulesFile}|{rulesTime}|{_profile}";

            if (string.Equals(signature, _validatedSignature, StringComparison.Ordinal))
            {
                return true;
            }

            var classification = Path.Combine(_installDirectory!, "classification.config");
            var reference = Path.Combine(_installDirectory!, "reference.config");

            var info = new ProcessStartInfo
            {
                FileName = _executable!,
                Arguments =
                    $"-T -c \"{_configPath}\" -S \"{_rulesFile}\" " +
                    $"-l \"{ServicePaths.SuricataDirectory}\" " +
                    $"--set \"classification-file={classification}\" " +
                    $"--set \"reference-config-file={reference}\"",
                WorkingDirectory = _installDirectory!,
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
            };

            ApplyNpcapPath(info);

            var process = Process.Start(info);

            if (process is null)
            {
                _lastError = "无法执行 Suricata 配置校验。";
                return false;
            }

            _validationProcess = process;

            try
            {
                var output = process.StandardOutput.ReadToEnd()
                    + process.StandardError.ReadToEnd();

                var timeout = _ruleCount switch
                {
                    > 100_000 => 600_000,
                    > 60_000 => 180_000,
                    _ => 60_000,
                };

                if (!process.WaitForExit(timeout))
                {
                    try
                    {
                        process.Kill(entireProcessTree: true);
                    }
                    catch (Exception)
                    {
                        // 进程可能已经退出。
                    }

                    _lastError = "Suricata 配置校验超时。";
                    return false;
                }

                if (process.ExitCode != 0)
                {
                    var lastLine = output
                        .Split('\n', StringSplitOptions.RemoveEmptyEntries)
                        .LastOrDefault()?
                        .Trim();

                    _lastError = "Suricata 配置校验失败"
                        + (string.IsNullOrEmpty(lastLine) ? "。" : $"：{lastLine}");
                    return false;
                }

                _validatedSignature = signature;
                return true;
            }
            finally
            {
                _validationProcess = null;
                process.Dispose();
            }
        }
        catch (Exception ex)
        {
            _lastError = $"Suricata 配置校验失败：{ex.Message}";
            return false;
        }
    }

    /// <summary>
    /// 5.1：把用户勾选的分类规则拼成 active.rules。
    /// 先写临时文件再原子替换，Suricata 校验失败时不会破坏旧文件。
    /// </summary>
    private static bool BuildActiveRules(string ruleProfile, out string rulesFile)
    {
        rulesFile = ServicePaths.SuricataActiveRulesFile;
        var temporary = rulesFile + ".tmp";

        var categories = _enabledCategories
            .Where(NetworkRuleCategories.IsKnown)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        var full = string.Equals(ruleProfile, "full", StringComparison.OrdinalIgnoreCase);

        if (!full && categories.Count == 0)
        {
            _lastError = "至少需要启用一个规则分类。";
            return false;
        }

        try
        {
            using (var writer = new StreamWriter(
                       temporary,
                       append: false,
                       new UTF8Encoding(false)))
            {
                writer.WriteLine("# WinAppGuard 6.0 active rule set");
                writer.WriteLine(full
                    ? "# profile: full (ET Open all rules)"
                    : $"# categories: {string.Join(",", categories)}");
                writer.WriteLine($"# generated: {DateTime.UtcNow:O}");

                if (full)
                {
                    var allRules = ServicePaths.SuricataFullRulesFile;

                    if (!File.Exists(allRules))
                    {
                        _lastError =
                            $"缺少全量规则文件：{allRules}；请重新安装或更新 ET Open。";
                        return false;
                    }

                    foreach (var line in File.ReadLines(allRules, Encoding.UTF8))
                    {
                        var trimmed = line.TrimStart();

                        if (trimmed.Length == 0 || trimmed.StartsWith('#'))
                        {
                            continue;
                        }

                        writer.WriteLine(line);
                    }
                }
                else
                {
                    foreach (var category in categories)
                    {
                        var path = Path.Combine(
                            ServicePaths.SuricataStandardRulesDirectory,
                            NetworkRuleCategories.FileName(category));

                        if (!File.Exists(path))
                        {
                            _lastError =
                                $"缺少规则分类文件：{path}；请重新安装或更新 ET Open。";
                            return false;
                        }

                        foreach (var line in File.ReadLines(path, Encoding.UTF8))
                        {
                            var trimmed = line.TrimStart();

                            if (trimmed.Length == 0 || trimmed.StartsWith('#'))
                            {
                                continue;
                            }

                            writer.WriteLine(line);
                        }
                    }
                }

                AppendThreatFoxRules(writer, ThreatFoxThreshold(ruleProfile));
            }

            var backup = rulesFile + ".bak";
            _activeBackupPath = backup;

            if (File.Exists(rulesFile))
            {
                File.Copy(rulesFile, backup, overwrite: true);
            }
            else if (File.Exists(backup))
            {
                File.Delete(backup);
            }

            File.Move(temporary, rulesFile, overwrite: true);
            return true;
        }
        catch (Exception ex)
        {
            _lastError = $"生成生效规则失败：{ex.Message}";
            return false;
        }
        finally
        {
            try
            {
                if (File.Exists(temporary))
                {
                    File.Delete(temporary);
                }
            }
            catch (Exception)
            {
                // 临时文件清理失败不影响检测。
            }
        }
    }

    private static IEnumerable<string> EnumerateThreatFoxRules(string path, int minConfidence)
    {
        foreach (var line in File.ReadLines(path, Encoding.UTF8))
        {
            if (!line.StartsWith("alert ", StringComparison.Ordinal))
            {
                continue;
            }

            if (RuleConfidence(line) < minConfidence)
            {
                continue;
            }

            yield return line;
        }
    }

    internal static int CountThreatFoxRules(string path, int minConfidence)
        => EnumerateThreatFoxRules(path, minConfidence).Count();

    private static void AppendThreatFoxRules(StreamWriter writer, int minConfidence)
    {
        var path = ServicePaths.ThreatFoxRulesFile;

        if (!File.Exists(path))
        {
            writer.WriteLine("# ThreatFox rules not installed; IOC matching still runs in-process.");
            return;
        }

        writer.WriteLine($"# ThreatFox rules (confidence >= {minConfidence})");

        var appended = 0;

        foreach (var line in EnumerateThreatFoxRules(path, minConfidence))
        {
            writer.WriteLine(line);
            appended++;
        }

        if (appended == 0)
        {
            writer.WriteLine("# No ThreatFox rules matched the confidence threshold.");
        }
    }

    private static void CommitActiveRulesBackup()
    {
        if (_activeBackupPath is null)
        {
            return;
        }

        try
        {
            if (File.Exists(_activeBackupPath))
            {
                File.Delete(_activeBackupPath);
            }
        }
        catch (Exception)
        {
            // 备份删除失败不影响运行。
        }

        _activeBackupPath = null;
    }

    private static void RestoreActiveRulesBackup()
    {
        if (_activeBackupPath is null)
        {
            return;
        }

        try
        {
            if (File.Exists(_activeBackupPath))
            {
                File.Copy(
                    _activeBackupPath,
                    ServicePaths.SuricataActiveRulesFile,
                    overwrite: true);
                File.Delete(_activeBackupPath);
            }
        }
        catch (Exception)
        {
            // 恢复失败时保留备份；下次启动会重新生成。
        }

        _activeBackupPath = null;
    }

    private static bool EnsurePrepared(string ruleProfile)
    {
        if (_executable is null || !File.Exists(_executable))
        {
            var found = FindExecutable();

            if (found is null)
            {
                _lastError = "未找到 suricata.exe；请安装 Suricata 或重新安装 WinAppGuard。";
                return false;
            }

            _executable = found.Value.Executable;
            _installDirectory = found.Value.Directory;
            _version = found.Value.Version;
        }

        Directory.CreateDirectory(ServicePaths.SuricataDirectory);
        Directory.CreateDirectory(ServicePaths.SuricataRulesDirectory);

        string rulesFile;

        if (!BuildActiveRules(ruleProfile, out rulesFile))
        {
            return false;
        }

        if (!File.Exists(rulesFile))
        {
            _lastError = "没有可加载的规则文件；请重新安装或更新 ET Open。";
            return false;
        }

        _configPath = Path.Combine(_installDirectory!, "suricata.yaml");

        if (!File.Exists(_configPath))
        {
            _lastError = $"找不到 Suricata 配置：{_configPath}；请重新安装 Suricata。";
            return false;
        }

        _rulesFile = rulesFile;
        _ruleCount = CountRules(rulesFile);

        return true;
    }

    /// <summary>
    /// 5.0：部分 Npcap 安装把 wpcap.dll 放在 System32\Npcap 而不是 System32。
    /// 给子进程补 PATH，避免 Suricata 因找不到 wpcap.dll 退出。
    /// 安装器仍会优先启用 WinPcap 兼容模式，这里是兜底。
    /// </summary>
    private static void ApplyNpcapPath(ProcessStartInfo info)
    {
        var npcapDirectory = Path.Combine(Environment.SystemDirectory, "Npcap");

        if (!Directory.Exists(npcapDirectory))
        {
            return;
        }

        var current = info.Environment.TryGetValue("PATH", out var path)
            ? path
            : Environment.GetEnvironmentVariable("PATH") ?? string.Empty;

        info.Environment["PATH"] = npcapDirectory + ";" + current;
    }

    private static (string Executable, string Directory, string? Version)? FindExecutable()
    {
        var candidates = new[]
        {
            Path.Combine(AppContext.BaseDirectory, "suricata", "suricata.exe"),
            Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
                "Suricata", "suricata.exe"),
            Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
                "Suricata", "suricata.exe"),
        };

        foreach (var candidate in candidates)
        {
            if (File.Exists(candidate))
            {
                var directory = Path.GetDirectoryName(candidate) ?? AppContext.BaseDirectory;
                return (candidate, directory, ReadVersion(candidate));
            }
        }

        var path = Environment.GetEnvironmentVariable("PATH") ?? string.Empty;

        foreach (var part in path.Split(Path.PathSeparator))
        {
            try
            {
                var candidate = Path.Combine(part.Trim(), "suricata.exe");

                if (File.Exists(candidate))
                {
                    var directory = Path.GetDirectoryName(candidate) ?? part;
                    return (candidate, directory, ReadVersion(candidate));
                }
            }
            catch (Exception)
            {
                // PATH 里的坏路径跳过。
            }
        }

        return null;
    }

    private static string? ReadVersion(string executable)
    {
        try
        {
            return FileVersionInfo.GetVersionInfo(executable).ProductVersion;
        }
        catch (Exception)
        {
            return null;
        }
    }

    private static int CountRules(string path)
    {
        try
        {
            var count = 0;

            foreach (var line in File.ReadLines(path, Encoding.UTF8))
            {
                var trimmed = line.TrimStart();

                if (trimmed.Length == 0 || trimmed.StartsWith('#'))
                {
                    continue;
                }

                count++;
            }

            return count;
        }
        catch (Exception)
        {
            return 0;
        }
    }

    private static void ScheduleRestartLocked()
    {
        _nextRestartUtc = DateTime.UtcNow.AddSeconds(_restartDelaySeconds);
        _restartDelaySeconds = Math.Min(_restartDelaySeconds * 2, 60);
    }

    private static void KillValidationProcess()
    {
        var process = _validationProcess;

        if (process is null)
        {
            return;
        }

        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
            }
        }
        catch (Exception)
        {
            // 校验进程可能已经退出。
        }
    }

    private static void StopProcessLocked()
    {
        var process = _process;
        _process = null;

        if (process is null)
        {
            return;
        }

        try
        {
            if (!process.HasExited)
            {
                process.Kill(entireProcessTree: true);
                process.WaitForExit(1000);
            }
        }
        catch (Exception)
        {
            // 进程可能已经退出。
        }
        finally
        {
            process.Dispose();
        }
    }

    private static int SafeExitCode(Process process)
    {
        try
        {
            return process.ExitCode;
        }
        catch (Exception)
        {
            return -1;
        }
    }

    private static void AppendLog(string? line)
    {
        if (string.IsNullOrWhiteSpace(line))
        {
            return;
        }

        try
        {
            File.AppendAllText(
                ServicePaths.SuricataLogFile,
                $"{DateTime.Now:O} {line}{Environment.NewLine}",
                new UTF8Encoding(false));
        }
        catch (Exception)
        {
            // 日志写失败不影响检测进程。
        }
    }
}
