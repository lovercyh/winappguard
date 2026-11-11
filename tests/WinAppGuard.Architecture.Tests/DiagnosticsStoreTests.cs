using System.Text.Json;
using WinAppGuard.Core;
using WinAppGuard.Core.Diagnostics.AntiScan;
using WinAppGuard.Core.Diagnostics.Lan;
using WinAppGuard.Core.Diagnostics.NetworkDetection;
using WinAppGuard.Models;

namespace WinAppGuard.Architecture.Tests;

public sealed class DiagnosticsStoreTests
{
    [Fact]
    public void FirstSeenLegacyArrayIsReadableAndRewritten()
    {
        var directory = TempDirectory();
        var path = Path.Combine(directory, "first-seen-programs.json");

        try
        {
            Directory.CreateDirectory(directory);
            File.WriteAllText(
                path,
                JsonSerializer.Serialize(new List<FirstSeenProgramRecord>
                {
                    new()
                    {
                        Path = @"C:\Apps\a.exe",
                        ProcessName = "a.exe",
                        FirstSeenUtc = DateTime.UtcNow.AddHours(-1),
                    },
                }));

            var store = new FirstSeenProgramStore(path);

            Assert.Equal(1, store.Count);
            Assert.NotNull(store.Find(@"C:\Apps\a.exe"));

            var json = File.ReadAllText(path);
            Assert.Contains("\"schema\": 1", json, StringComparison.Ordinal);
            Assert.Contains("\"records\"", json, StringComparison.Ordinal);

            var reloaded = new FirstSeenProgramStore(path);
            Assert.NotNull(reloaded.Find(@"C:\Apps\a.exe"));
        }
        finally
        {
            Cleanup(directory);
        }
    }

    [Fact]
    public void AntiScanLegacyStateIsReadableAndNormalized()
    {
        var path = StatePath("antiscan-state.json");

        try
        {
            File.WriteAllText(
                path,
                """
                {
                  "Settings": { "Sensitivity": "weird", "BlockMinutes": 999 },
                  "Blocks": [
                    { "Address": " 192.0.2.10 ", "Reason": null },
                    { "Address": "not-an-ip" }
                  ]
                }
                """);

            var state = AntiScanStateFile.Load(path, out var error, out var migrated);

            Assert.Null(error);
            Assert.True(migrated);
            Assert.Equal("standard", state.Settings.Sensitivity);
            Assert.Equal(60, state.Settings.BlockMinutes);
            Assert.True(state.Settings.DetectUdp);
            Assert.True(state.Settings.DetectIcmp);
            Assert.Equal("192.0.2.10", Assert.Single(state.Blocks).Address);
        }
        finally
        {
            Cleanup(Path.GetDirectoryName(path)!);
        }
    }

    [Fact]
    public void NetworkDetectionLegacyStateIsReadableAndNormalized()
    {
        var path = StatePath("network-state.json");

        try
        {
            File.WriteAllText(
                path,
                """
                {
                  "Settings": {
                    "Enabled": false,
                    "RuleProfile": "weird",
                    "RetentionDays": 999,
                    "CaptureDeviceId": "  device-1  "
                  },
                  "AlertStatuses": { "a": "ack" }
                }
                """);

            var state = NetworkDetectionStateFile.Load(path, out var error, out var migrated);

            Assert.Null(error);
            Assert.True(migrated);
            Assert.False(state.Settings.Enabled);
            Assert.Equal("standard", state.Settings.RuleProfile);
            Assert.Equal(365, state.Settings.RetentionDays);
            Assert.Equal("device-1", state.Settings.CaptureDeviceId);
            Assert.Equal("ack", state.AlertStatuses["a"]);
            Assert.NotEmpty(state.Settings.EnabledRuleCategories);
        }
        finally
        {
            Cleanup(Path.GetDirectoryName(path)!);
        }
    }

    [Fact]
    public void LanLegacyStateIsReadableAndDeduped()
    {
        var path = StatePath("lan-state.json");

        try
        {
            File.WriteAllText(
                path,
                """
                {
                  "settings": { "retentionDays": 15 },
                  "gateways": [
                    { "adapter": "eth0", "ip": "192.168.1.1", "mac": "aa-bb" },
                    { "adapter": "eth0", "ip": "192.168.1.1", "mac": "aa-bb" }
                  ],
                  "trustedDnsServers": [ "8.8.8.8", "8.8.8.8" ]
                }
                """);

            var state = LanStateStore.Load(path, out var error, out var migrated);

            Assert.Null(error);
            Assert.True(migrated);
            Assert.Equal(15, state.Settings.RetentionDays);
            Assert.Single(state.Gateways);
            Assert.Single(state.TrustedDnsServers);
        }
        finally
        {
            Cleanup(Path.GetDirectoryName(path)!);
        }
    }

    [Fact]
    public void LanEventStoreReadsLegacyDailyFileAndFiltersKinds()
    {
        var directory = TempDirectory();
        var now = DateTime.UtcNow;

        try
        {
            Directory.CreateDirectory(directory);
            File.WriteAllLines(
                Path.Combine(directory, $"events-{now.ToLocalTime():yyyyMMdd}.jsonl"),
                new[]
                {
                    JsonSerializer.Serialize(new LanEvent
                    {
                        Id = "dns",
                        TimeUtc = now.AddMinutes(-2),
                        Kind = LanEventKinds.DnsResponseUnexpectedServer,
                    }),
                    JsonSerializer.Serialize(new LanEvent
                    {
                        Id = "arp",
                        TimeUtc = now.AddMinutes(-1),
                        Kind = LanEventKinds.ArpGatewayMacChanged,
                    }),
                });

            var store = new LanEventStore(directory);
            store.Append(new LanEvent
            {
                Id = "dhcp",
                TimeUtc = now,
                Kind = LanEventKinds.DhcpUnexpectedServer,
            });

            var all = store.ReadRecent(10);

            Assert.Equal(new[] { "dhcp", "arp", "dns" }, all.Select(item => item.Id));
            Assert.Equal(
                new[] { "dns" },
                store.ReadRecent(10, "dns_").Select(item => item.Id));

            Assert.Equal(1, store.ClearKinds("arp_"));
            Assert.Equal(new[] { "dhcp", "dns" }, store.ReadRecent(10).Select(item => item.Id));
        }
        finally
        {
            Cleanup(directory);
        }
    }

    private static string StatePath(string fileName)
    {
        var directory = TempDirectory();
        Directory.CreateDirectory(directory);
        return Path.Combine(directory, fileName);
    }

    private static string TempDirectory()
        => Path.Combine(Path.GetTempPath(), $"wag-diagnostics-{Guid.NewGuid():N}");

    private static void Cleanup(string directory)
    {
        if (Directory.Exists(directory))
        {
            Directory.Delete(directory, recursive: true);
        }
    }
}
