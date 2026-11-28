using WinAppGuard.Core.Diagnostics.Ids;
using WinAppGuard.Core.Diagnostics.Ioc;

namespace WinAppGuard.Architecture.Tests;

/// <summary>
/// 6.0：ThreatFox IOC 解析与匹配。
///
/// 静态库有共享状态，整个测试放在一个 Fact 里顺序执行，避免并行互相清空索引。
/// </summary>
public sealed class ThreatFoxIocStoreTests
{
    [Fact]
    public void LoadsBundledSnapshot()
    {
        var path = FindRepoFile(Path.Combine("threatfox", "full.csv"));

        if (path is null)
        {
            return;
        }

        var stopwatch = System.Diagnostics.Stopwatch.StartNew();

        try
        {
            Assert.True(ThreatFoxIocStore.Load(path, 75));
            stopwatch.Stop();

            var snapshot = ThreatFoxIocStore.Snapshot();

            Assert.True(snapshot.IpCount > 10_000, $"ip={snapshot.IpCount}");
            Assert.True(snapshot.DomainCount > 10_000, $"domain={snapshot.DomainCount}");
            Assert.True(snapshot.HashCount > 50_000, $"hash={snapshot.HashCount}");
            Assert.NotNull(snapshot.SourceUtc);
            Assert.True(
                stopwatch.Elapsed < TimeSpan.FromSeconds(30),
                $"load took {stopwatch.Elapsed}");
        }
        finally
        {
            ThreatFoxIocStore.Unload();
        }
    }

    [Fact]
    public void ParsesAndMatchesOnlyAtOrAboveConfidence()
    {
        var path = Path.Combine(Path.GetTempPath(), $"wag-ioc-{Guid.NewGuid():N}.csv");

        try
        {
            File.WriteAllText(path, string.Join('\n', new[]
            {
                "# ThreatFox IOCs: additions - CSV format (full dump)",
                "# Last updated: 2026-11-28 13:05:07 UTC",
                "#",
                "\"first_seen_utc\",\"ioc_id\",\"ioc_value\",\"ioc_type\",\"threat_type\",\"fk_malware\",\"malware_alias\",\"malware_printable\",\"last_seen_utc\",\"confidence_level\",\"is_compromised\",\"reference\",\"tags\",\"anonymous\",\"reporter\"",
                "\"2026-11-28 13:05:07\", \"1001\", \"203.0.113.10:8443\", \"ip:port\", \"botnet_cc\", \"win.cobalt_strike\", \"None\", \"Cobalt Strike\", \"\", \"100\", \"True\", \"None\", \"cobaltstrike\", \"1\", \"anonymous\"",
                "\"2026-11-28 13:05:06\", \"1002\", \"evil.example.com\", \"domain\", \"botnet_cc\", \"win.asyncrat\", \"None\", \"AsyncRAT\", \"\", \"90\", \"True\", \"None\", \"asyncrat\", \"1\", \"anonymous\"",
                "\"2026-11-28 13:05:05\", \"1003\", \"http://cdn.evil.example.com/payload\", \"url\", \"payload_delivery\", \"win.vidar\", \"None\", \"Vidar\", \"\", \"85\", \"True\", \"None\", \"vidar\", \"1\", \"anonymous\"",
                "\"2026-11-28 13:05:04\", \"1004\", \"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\", \"sha256_hash\", \"payload\", \"win.remcos\", \"None\", \"Remcos\", \"\", \"100\", \"True\", \"None\", \"remcos\", \"1\", \"anonymous\"",
                "\"2026-11-28 13:05:03\", \"1005\", \"198.51.100.7:80\", \"ip:port\", \"botnet_cc\", \"win.mirai\", \"None\", \"Mirai\", \"\", \"50\", \"True\", \"None\", \"mirai\", \"1\", \"anonymous\"",
                "\"2026-11-28 13:05:02\", \"1006\", \"update.microsoft.com\", \"domain\", \"botnet_cc\", \"win.fake\", \"None\", \"Fake\", \"\", \"100\", \"True\", \"None\", \"fake\", \"1\", \"anonymous\"",
                string.Empty,
            }));

            Assert.True(ThreatFoxIocStore.Load(path, 75));

            var snapshot = ThreatFoxIocStore.Snapshot();
            Assert.True(snapshot.Loaded);
            Assert.Equal(75, snapshot.MinConfidence);
            Assert.Equal(new DateTime(2026, 11, 28, 13, 5, 7, DateTimeKind.Utc), snapshot.SourceUtc);
            Assert.Equal(1, snapshot.IpCount);      // 203.0.113.10 only; 198.51.100.7 is 50%
            Assert.Equal(2, snapshot.DomainCount);  // evil.example.com + cdn.evil.example.com (url)
            Assert.Equal(1, snapshot.HashCount);    // allowlisted domain dropped

            var now = DateTime.UtcNow;

            ThreatFoxIocStore.ObserveFlow(new NetworkFlowObservation(
                now, 4242, "TCP", "203.0.113.10", 8443, true, true, 0));
            ThreatFoxIocStore.ObserveFlow(new NetworkFlowObservation(
                now, 4242, "TCP", "198.51.100.7", 80, true, true, 0));
            ThreatFoxIocStore.ObserveDns(new NetworkDnsObservation(
                now, 4242, "EVIL.example.com.", "NOERROR"));
            ThreatFoxIocStore.ObserveDns(new NetworkDnsObservation(
                now, 4242, "sub.evil.example.com", "NOERROR"));
            ThreatFoxIocStore.ObserveDns(new NetworkDnsObservation(
                now, 4242, "update.microsoft.com", "NOERROR"));

            var hits = ThreatFoxIocStore.Drain();

            Assert.Equal(3, hits.Count);
            Assert.Contains(hits, hit => hit.Kind == "ip"
                                        && hit.Target == "203.0.113.10:8443"
                                        && hit.Malware == "Cobalt Strike"
                                        && hit.Confidence == 100
                                        && hit.Reference.EndsWith("/ioc/1001/", StringComparison.Ordinal));
            Assert.Contains(hits, hit => hit.Kind == "domain"
                                        && hit.Target == "evil.example.com"
                                        && hit.Malware == "AsyncRAT");
            Assert.Contains(hits, hit => hit.Kind == "domain"
                                        && hit.Target == "sub.evil.example.com"
                                        && hit.Malware == "AsyncRAT");
            Assert.DoesNotContain(hits, hit => hit.Target.Contains("198.51.100.7"));
            Assert.DoesNotContain(hits, hit => hit.Target.Contains("microsoft.com"));

            Assert.True(ThreatFoxIocStore.ContainsHash(
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"));
            Assert.False(ThreatFoxIocStore.ContainsHash(
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"));

            // 同一 PID + 目标有冷却，重复观测不会重复上报。
            ThreatFoxIocStore.ObserveFlow(new NetworkFlowObservation(
                now, 4242, "TCP", "203.0.113.10", 8443, true, true, 0));
            Assert.Empty(ThreatFoxIocStore.Drain());
        }
        finally
        {
            ThreatFoxIocStore.Unload();
            File.Delete(path);
        }
    }

    private static string? FindRepoFile(string relativePath)
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);

        for (var i = 0; i < 8 && directory is not null; i++)
        {
            var candidate = Path.Combine(directory.FullName, relativePath);

            if (File.Exists(candidate))
            {
                return candidate;
            }

            directory = directory.Parent;
        }

        return null;
    }
}
