using System.Text.Json;
using WinAppGuard.Core.Diagnostics.Ids;

namespace WinAppGuard.Architecture.Tests;

public sealed class IdsStoreTests
{
    [Fact]
    public void LegacyStateIsReadableAndNormalized()
    {
        var path = StatePath();

        try
        {
            File.WriteAllText(
                path,
                """
                {
                  "Settings": { "Enabled": false, "Sensitivity": "weird", "RetentionDays": 999 },
                  "Suppressions": [ null, { "Id": "", "RuleId": "" } ],
                  "AlertStatuses": { "a": "ack" }
                }
                """);

            var state = IdsStateFile.Load(path, out var error, out var migrated);

            Assert.Null(error);
            Assert.True(migrated);
            Assert.False(state.Settings.Enabled);
            Assert.Equal("standard", state.Settings.Sensitivity);
            Assert.Equal(365, state.Settings.RetentionDays);
            Assert.Single(state.Suppressions);
            Assert.False(string.IsNullOrEmpty(state.Suppressions[0].Id));
            Assert.Equal("*", state.Suppressions[0].RuleId);
            Assert.Equal("ack", state.AlertStatuses["a"]);
        }
        finally
        {
            Cleanup(path);
        }
    }

    [Fact]
    public void SaveWritesSchemaEnvelopeAndRoundTrips()
    {
        var path = StatePath();

        try
        {
            var original = new IdsState
            {
                Settings = new IdsSettings
                {
                    Enabled = false,
                    Sensitivity = "conservative",
                    RetentionDays = 14,
                },
                Suppressions = new List<IdsSuppression>
                {
                    new() { Id = "s1", RuleId = "ids.scan" },
                },
                AlertStatuses = new Dictionary<string, string> { ["a1"] = "ack" },
            };

            IdsStateFile.Save(path, original);

            var json = File.ReadAllText(path);
            Assert.Contains("\"schema\": 1", json, StringComparison.Ordinal);
            Assert.Contains("\"data\"", json, StringComparison.Ordinal);

            var loaded = IdsStateFile.Load(path, out var error, out var migrated);

            Assert.Null(error);
            Assert.False(migrated);
            Assert.False(loaded.Settings.Enabled);
            Assert.Equal("conservative", loaded.Settings.Sensitivity);
            Assert.Equal(14, loaded.Settings.RetentionDays);
            Assert.Equal("s1", Assert.Single(loaded.Suppressions).Id);
            Assert.Equal("ack", loaded.AlertStatuses["a1"]);
        }
        finally
        {
            Cleanup(path);
        }
    }

    [Fact]
    public void CorruptStateIsBackedUpAndDefaultsAreUsed()
    {
        var path = StatePath();

        try
        {
            File.WriteAllText(path, "this is not json");

            var state = IdsStateFile.Load(path, out var error);

            Assert.False(string.IsNullOrWhiteSpace(error));
            Assert.True(state.Settings.Enabled);
            Assert.False(File.Exists(path));
            Assert.NotEmpty(Directory.GetFiles(
                Path.GetDirectoryName(path)!,
                Path.GetFileName(path) + ".corrupt-*"));
        }
        finally
        {
            Cleanup(path);
        }
    }

    [Fact]
    public void LegacyAlertFileIsReadAndDeduped()
    {
        var directory = AlertDirectory();
        var now = DateTime.UtcNow;

        try
        {
            Directory.CreateDirectory(directory);
            var legacy = Path.Combine(directory, "alerts.jsonl");

            File.WriteAllLines(
                legacy,
                new[]
                {
                    JsonSerializer.Serialize(new IdsAlert
                    {
                        Id = "old",
                        TimeUtc = now.AddDays(-10),
                    }),
                    JsonSerializer.Serialize(new IdsAlert
                    {
                        Id = "fresh",
                        TimeUtc = now.AddHours(-1),
                    }),
                    JsonSerializer.Serialize(new IdsAlert
                    {
                        Id = "fresh",
                        TimeUtc = now.AddHours(-1),
                    }),
                });

            var store = new IdsAlertStore(directory, retentionDays: 7);
            store.Append(new IdsAlert { Id = "new", TimeUtc = now });

            var alerts = store.LoadRecent(7, 100);

            Assert.Equal(
                new[] { "new", "fresh" },
                alerts.Select(alert => alert.Id).OrderByDescending(id => id == "new"));
            Assert.DoesNotContain(alerts, alert => alert.Id == "old");
        }
        finally
        {
            CleanupDirectory(directory);
        }
    }

    [Fact]
    public void LegacyAlertFileIsPrunedByTime()
    {
        var directory = AlertDirectory();
        var now = DateTime.UtcNow;

        try
        {
            Directory.CreateDirectory(directory);
            var legacy = Path.Combine(directory, "alerts.jsonl");

            File.WriteAllLines(
                legacy,
                new[]
                {
                    JsonSerializer.Serialize(new IdsAlert
                    {
                        Id = "old",
                        TimeUtc = now.AddDays(-30),
                    }),
                    JsonSerializer.Serialize(new IdsAlert
                    {
                        Id = "fresh",
                        TimeUtc = now.AddHours(-1),
                    }),
                });

            var store = new IdsAlertStore(directory, retentionDays: 7);
            var removed = store.Prune(7);

            Assert.Equal(1, removed);
            var lines = File.ReadAllLines(legacy);
            Assert.Single(lines);
            Assert.Contains("fresh", lines[0], StringComparison.Ordinal);
        }
        finally
        {
            CleanupDirectory(directory);
        }
    }

    [Fact]
    public void ClearRemovesLegacyAndSegmentedAlertFiles()
    {
        var directory = AlertDirectory();

        try
        {
            Directory.CreateDirectory(directory);
            File.WriteAllText(Path.Combine(directory, "alerts.jsonl"), string.Empty);

            var store = new IdsAlertStore(directory, retentionDays: 7);
            store.Append(new IdsAlert { Id = "a", TimeUtc = DateTime.UtcNow });
            store.Clear();

            Assert.Empty(Directory.GetFiles(directory, "alerts*.jsonl"));
        }
        finally
        {
            CleanupDirectory(directory);
        }
    }

    private static string StatePath()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"wag-ids-state-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        return Path.Combine(directory, "ids-state.json");
    }

    private static string AlertDirectory()
        => Path.Combine(Path.GetTempPath(), $"wag-ids-alerts-{Guid.NewGuid():N}");

    private static void Cleanup(string path)
    {
        var directory = Path.GetDirectoryName(path);

        if (directory is not null && Directory.Exists(directory))
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    private static void CleanupDirectory(string directory)
    {
        if (Directory.Exists(directory))
        {
            Directory.Delete(directory, recursive: true);
        }
    }
}
