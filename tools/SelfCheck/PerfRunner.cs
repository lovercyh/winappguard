using System.Diagnostics;
using System.Text.Json;
using WinAppGuard.Contracts;
using WinAppGuard.Contracts.Protocol;

namespace WinAppGuard.SelfCheck;

/// <summary>
/// 5.12：性能基线场景。只读，不修改规则。
///
/// 用法：
///   WinAppGuard.SelfCheck.exe --perf
///   WinAppGuard.SelfCheck.exe --perf --perf-iterations 500 --perf-out perf.json
///   WinAppGuard.SelfCheck.exe --perf --perf-threads 10 --perf-requests 100
///
/// 需要服务正在运行，并且当前账户能加载所有者签名密钥。
/// </summary>
internal static class PerfRunner
{
    internal static void Run(string[] args)
    {
        var iterations = GetInt(args, "--perf-iterations", 200);
        var threads = GetInt(args, "--perf-threads", 10);
        var requestsPerThread = GetInt(args, "--perf-requests", 100);
        var idleSeconds = GetInt(args, "--perf-idle-seconds", 10);
        var outputPath = GetValue(args, "--perf-out");

        var status = ServiceClient.TryGetStatus(TimeSpan.FromSeconds(3), out var statusError);

        if (status is null)
        {
            Console.Error.WriteLine($"服务不可用：{statusError ?? "没有返回状态"}");
            Environment.ExitCode = 1;
            return;
        }

        Console.WriteLine("== WinAppGuard 5.12 性能基线 ==");
        Console.WriteLine($"服务版本={status.ServiceVersion} 协议={status.ProtocolVersion} 规则={status.BlockRuleCount + status.AllowRuleCount}");
        Console.WriteLine($"迭代={iterations} 并发={threads}×{requestsPerThread}");
        Console.WriteLine();

        var results = new List<ScenarioResult>
        {
            RunPayload<StatusView>(
                "S1 status",
                iterations,
                () => ServiceClient.TryRequestAs<StatusView>(
                    new ServiceRequest { Command = ServiceProtocol.Commands.Status },
                    TimeSpan.FromSeconds(3))),

            RunPayload<RulesView>(
                "S2 rules.list",
                iterations,
                () => ServiceClient.TryRequestAs<RulesView>(
                    new ServiceRequest { Command = ServiceProtocol.Commands.ListRules },
                    TimeSpan.FromSeconds(5))),

            RunPayload<TrafficView>(
                "S3 query.traffic",
                iterations,
                () => ServiceClient.TryRequestAs<TrafficView>(
                    new ServiceRequest { Command = ServiceProtocol.Commands.QueryTraffic },
                    TimeSpan.FromSeconds(3))),

            RunPayload<QueryView>(
                "S4 query.ids",
                iterations,
                () => ServiceClient.TryRequestAs<QueryView>(
                    new ServiceRequest { Command = ServiceProtocol.Commands.QueryIdsAlerts },
                    TimeSpan.FromSeconds(3))),
        };

        results.Add(RunConcurrent(threads, requestsPerThread));
        RunIdle(idleSeconds);

        Console.WriteLine();
        Console.WriteLine("== 汇总 ==");

        foreach (var result in results)
        {
            Console.WriteLine(result.ToText());
        }

        if (results.Any(result => result.Errors > 0))
        {
            Environment.ExitCode = 1;
        }

        if (!string.IsNullOrWhiteSpace(outputPath))
        {
            var json = JsonSerializer.Serialize(
                new
                {
                    generatedAtUtc = DateTime.UtcNow,
                    serviceVersion = status.ServiceVersion,
                    protocol = status.ProtocolVersion,
                    iterations,
                    results,
                },
                new JsonSerializerOptions { WriteIndented = true });

            File.WriteAllText(outputPath, json);
            Console.WriteLine();
            Console.WriteLine($"已写入：{outputPath}");
        }
    }

    private static ScenarioResult RunPayload<T>(
        string name,
        int iterations,
        Func<T?> call)
        where T : ResponsePayload
    {
        // 预热：避免把第一次连接/握手算进统计。
        for (var i = 0; i < 3; i++)
        {
            _ = call();
        }

        var times = new List<double>(iterations);
        var bytes = new List<int>(iterations);
        var errors = 0;
        var stopwatch = new Stopwatch();

        for (var i = 0; i < iterations; i++)
        {
            stopwatch.Restart();
            var payload = call();
            stopwatch.Stop();

            if (payload is null || !payload.Ok)
            {
                errors++;
                continue;
            }

            times.Add(stopwatch.Elapsed.TotalMilliseconds);
            bytes.Add(JsonSerializer.SerializeToUtf8Bytes(
                payload, payload.GetType(), ServiceProtocol.JsonOptions).Length);
        }

        return ScenarioResult.Create(name, times, bytes, errors);
    }

    private static ScenarioResult RunConcurrent(int threads, int requestsPerThread)
    {
        var errors = 0;
        var stopwatch = Stopwatch.StartNew();

        var workers = Enumerable.Range(0, Math.Max(1, threads))
            .Select(_ => new Thread(() =>
            {
                for (var i = 0; i < requestsPerThread; i++)
                {
                    var payload = ServiceClient.TryRequestAs<StatusView>(
                        new ServiceRequest { Command = ServiceProtocol.Commands.Status },
                        TimeSpan.FromSeconds(5));

                    if (payload is null || !payload.Ok)
                    {
                        Interlocked.Increment(ref errors);
                    }
                }
            }))
            .ToList();

        foreach (var worker in workers)
        {
            worker.IsBackground = true;
            worker.Start();
        }

        foreach (var worker in workers)
        {
            worker.Join();
        }

        stopwatch.Stop();

        var total = Math.Max(1, threads) * Math.Max(1, requestsPerThread);
        var throughput = total / Math.Max(0.001, stopwatch.Elapsed.TotalSeconds);

        return new ScenarioResult(
            $"S5 并发 {threads}×{requestsPerThread}",
            total,
            errors,
            0,
            0,
            0,
            0,
            throughput);
    }

    private static void RunIdle(int seconds)
    {
        if (seconds <= 0)
        {
            return;
        }

        var process = Process.GetProcessesByName("WinAppGuardSvc").FirstOrDefault();

        if (process is null)
        {
            Console.WriteLine("S8 空载：未找到 WinAppGuardSvc 进程");
            return;
        }

        try
        {
            process.Refresh();
            var cpuStart = process.TotalProcessorTime;
            Thread.Sleep(TimeSpan.FromSeconds(seconds));
            process.Refresh();

            var cpu = (process.TotalProcessorTime - cpuStart).TotalMilliseconds;
            var workingSet = process.WorkingSet64 / 1024.0 / 1024.0;

            Console.WriteLine(
                $"S8 空载 {seconds}s: cpu={cpu:0.0}ms, workingSet={workingSet:0.0}MB");
        }
        finally
        {
            process.Dispose();
        }
    }

    private static int GetInt(string[] args, string name, int fallback)
    {
        var value = GetValue(args, name);
        return int.TryParse(value, out var parsed) && parsed > 0 ? parsed : fallback;
    }

    private static string? GetValue(string[] args, string name)
    {
        var index = Array.FindIndex(
            args, arg => arg.Equals(name, StringComparison.OrdinalIgnoreCase));

        return index >= 0 && index + 1 < args.Length
            ? args[index + 1]
            : null;
    }

    private sealed class ScenarioResult
    {
        public ScenarioResult(
            string name,
            int requests,
            int errors,
            double p50,
            double p95,
            double p99,
            long extra,
            double throughput)
        {
            Name = name;
            Requests = requests;
            Errors = errors;
            P50 = p50;
            P95 = p95;
            P99 = p99;
            Extra = extra;
            Throughput = throughput;
        }

        public string Name { get; }

        public int Requests { get; }

        public int Errors { get; }

        public double P50 { get; }

        public double P95 { get; }

        public double P99 { get; }

        public long Extra { get; }

        public double Throughput { get; }

        public static ScenarioResult Create(
            string name,
            List<double> times,
            List<int> bytes,
            int errors)
        {
            if (times.Count == 0)
            {
                return new ScenarioResult(name, 0, errors, 0, 0, 0, 0, 0);
            }

            var sorted = times.OrderBy(value => value).ToList();
            var bytesAverage = bytes.Count == 0 ? 0 : (long)bytes.Average();

            return new ScenarioResult(
                name,
                sorted.Count,
                errors,
                Percentile(sorted, 50),
                Percentile(sorted, 95),
                Percentile(sorted, 99),
                bytesAverage,
                0);
        }

        private static double Percentile(List<double> sorted, double percentile)
        {
            if (sorted.Count == 0)
            {
                return 0;
            }

            var index = (int)Math.Ceiling(percentile / 100.0 * sorted.Count) - 1;
            return sorted[Math.Clamp(index, 0, sorted.Count - 1)];
        }

        public string ToText()
            => Throughput > 0
                ? $"{Name}: requests={Requests}, errors={Errors}, throughput={Throughput:0.0}/s"
                : $"{Name}: requests={Requests}, errors={Errors}, p50={P50:0.00}ms, p95={P95:0.00}ms, p99={P99:0.00}ms, bytes≈{Extra}";
    }
}
