using System.Text.Json;
using WinAppGuard.Core.Features;
using WinAppGuard.Core.Storage;

namespace WinAppGuard.Architecture.Tests;

public sealed class JsonlEventLogTests
{
    [Fact]
    public void AppendAndReadRecent()
    {
        var directory = TempDirectory();
        var log = new JsonlEventLog<TestEvent>(directory, "test", retentionDays: 7, maxBytesPerFile: 1024 * 1024);
        var now = new DateTime(2026, 11, 11, 12, 0, 0, DateTimeKind.Utc);

        try
        {
            log.Append(new TestEvent { Name = "a" }, now);
            log.Append(new TestEvent { Name = "b" }, now.AddSeconds(1));

            var values = log.ReadRecent(10, now.AddSeconds(2));

            Assert.Equal(new[] { "a", "b" }, values.Select(item => item.Name));
        }
        finally
        {
            Cleanup(directory);
        }
    }

    [Fact]
    public void BadLineIsSkipped()
    {
        var directory = TempDirectory();
        var log = new JsonlEventLog<TestEvent>(directory, "test", retentionDays: 7, maxBytesPerFile: 1024 * 1024);
        var now = new DateTime(2026, 11, 11, 12, 0, 0, DateTimeKind.Utc);

        try
        {
            log.Append(new TestEvent { Name = "good" }, now);
            File.AppendAllText(
                Path.Combine(directory, "test-20261111-00.jsonl"),
                "not json\n");

            var values = log.ReadRecent(10, now);

            Assert.Single(values);
            Assert.Equal("good", values[0].Name);
        }
        finally
        {
            Cleanup(directory);
        }
    }

    [Fact]
    public void RotatesWhenFileIsFull()
    {
        var directory = TempDirectory();
        var log = new JsonlEventLog<TestEvent>(directory, "test", retentionDays: 7, maxBytesPerFile: 80);
        var now = new DateTime(2026, 11, 11, 12, 0, 0, DateTimeKind.Utc);

        try
        {
            for (var i = 0; i < 5; i++)
            {
                log.Append(new TestEvent { Name = $"event-{i}" }, now.AddSeconds(i));
            }

            Assert.True(
                Directory.GetFiles(directory, "test-*.jsonl").Length > 1,
                "事件文件超过大小上限后应轮转。");
        }
        finally
        {
            Cleanup(directory);
        }
    }

    [Fact]
    public void PruneDeletesExpiredFiles()
    {
        var directory = TempDirectory();
        var log = new JsonlEventLog<TestEvent>(directory, "test", retentionDays: 7, maxBytesPerFile: 1024 * 1024);
        var now = new DateTime(2026, 11, 11, 12, 0, 0, DateTimeKind.Utc);

        try
        {
            Directory.CreateDirectory(directory);
            var oldFile = Path.Combine(directory, "test-20261101-00.jsonl");
            File.WriteAllText(oldFile, string.Empty);

            var deleted = log.Prune(now);

            Assert.Equal(1, deleted);
            Assert.False(File.Exists(oldFile));
        }
        finally
        {
            Cleanup(directory);
        }
    }

    [Fact]
    public void LegacySingleFileIsReadable()
    {
        var directory = TempDirectory();
        var now = new DateTime(2026, 11, 11, 12, 0, 0, DateTimeKind.Utc);
        var log = new JsonlEventLog<TestEvent>(
            directory, "test", retentionDays: 7, maxBytesPerFile: 1024 * 1024,
            timestampSelector: item => item.TimeUtc);

        try
        {
            Directory.CreateDirectory(directory);
            File.WriteAllText(
                Path.Combine(directory, "test.jsonl"),
                JsonSerializer.Serialize(new TestEvent { Name = "legacy", TimeUtc = now }) + "\n");

            var values = log.ReadAll();

            Assert.Single(values);
            Assert.Equal("legacy", values[0].Name);
        }
        finally
        {
            Cleanup(directory);
        }
    }

    [Fact]
    public void LegacySingleFileIsPrunedByTimestamp()
    {
        var directory = TempDirectory();
        var now = new DateTime(2026, 11, 11, 12, 0, 0, DateTimeKind.Utc);
        var log = new JsonlEventLog<TestEvent>(
            directory, "test", retentionDays: 7, maxBytesPerFile: 1024 * 1024,
            timestampSelector: item => item.TimeUtc);
        var legacy = Path.Combine(directory, "test.jsonl");

        try
        {
            Directory.CreateDirectory(directory);
            File.WriteAllLines(
                legacy,
                new[]
                {
                    JsonSerializer.Serialize(new TestEvent
                    {
                        Name = "old",
                        TimeUtc = now.AddDays(-30),
                    }),
                    JsonSerializer.Serialize(new TestEvent
                    {
                        Name = "fresh",
                        TimeUtc = now.AddHours(-1),
                    }),
                });

            _ = log.Prune(now, retentionDays: 7);

            var lines = File.ReadAllLines(legacy);

            Assert.Single(lines);
            Assert.Contains("fresh", lines[0], StringComparison.Ordinal);
        }
        finally
        {
            Cleanup(directory);
        }
    }

    [Fact]
    public void ClearRemovesLegacyAndSegmentedFiles()
    {
        var directory = TempDirectory();
        var log = new JsonlEventLog<TestEvent>(
            directory, "test", retentionDays: 7, maxBytesPerFile: 1024 * 1024);

        try
        {
            Directory.CreateDirectory(directory);
            File.WriteAllText(Path.Combine(directory, "test.jsonl"), string.Empty);
            log.Append(new TestEvent { Name = "a" });

            log.Clear();

            Assert.Empty(Directory.GetFiles(directory, "test*.jsonl"));
        }
        finally
        {
            Cleanup(directory);
        }
    }

    private static string TempDirectory()
        => Path.Combine(Path.GetTempPath(), $"wag-events-{Guid.NewGuid():N}");

    private static void Cleanup(string directory)
    {
        if (Directory.Exists(directory))
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    public sealed class TestEvent : FeatureEvent
    {
        public string Name { get; set; } = string.Empty;
    }
}
