using System.Text.Json;
using WinAppGuard.Core.Storage;

namespace WinAppGuard.Architecture.Tests;

public sealed class JsonStateFileTests
{
    [Fact]
    public void SaveAndLoadRoundTrip()
    {
        var path = TempPath();
        var file = new JsonStateFile<TestState>(path, schemaVersion: 2);

        try
        {
            file.Save(new TestState { Value = 42, Text = "hello" });
            var loaded = file.Load(out var error);

            Assert.Null(error);
            Assert.NotNull(loaded);
            Assert.Equal(42, loaded!.Value);
            Assert.Equal("hello", loaded.Text);

            var json = File.ReadAllText(path);
            Assert.Contains("\"schema\": 2", json, StringComparison.Ordinal);
            Assert.Contains("\"data\"", json, StringComparison.Ordinal);
        }
        finally
        {
            Cleanup(path);
        }
    }

    [Fact]
    public void MissingFileReturnsNullWithoutError()
    {
        var file = new JsonStateFile<TestState>(TempPath(), schemaVersion: 1);
        var loaded = file.Load(out var error);

        Assert.Null(loaded);
        Assert.Null(error);
    }

    [Fact]
    public void LegacyRawJsonIsReadable()
    {
        var path = TempPath();
        var file = new JsonStateFile<TestState>(path, schemaVersion: 1);

        try
        {
            File.WriteAllText(path, "{\"value\":7,\"text\":\"legacy\"}");
            var loaded = file.Load(out var error);

            Assert.Null(error);
            Assert.NotNull(loaded);
            Assert.Equal(7, loaded!.Value);
            Assert.Equal("legacy", loaded.Text);
        }
        finally
        {
            Cleanup(path);
        }
    }

    [Fact]
    public void SchemaMismatchUsesMigration()
    {
        var path = TempPath();
        var file = new JsonStateFile<TestState>(path, schemaVersion: 2)
        {
            Migrate = root => new TestState
            {
                Value = root.GetProperty("oldValue").GetInt32(),
            },
        };

        try
        {
            File.WriteAllText(
                path,
                "{\"schema\":1,\"savedAtUtc\":\"2026-01-01T00:00:00Z\",\"data\":{\"oldValue\":9}}");

            var loaded = file.Load(out var error);

            Assert.Null(error);
            Assert.Equal(9, loaded!.Value);
        }
        finally
        {
            Cleanup(path);
        }
    }

    [Fact]
    public void CorruptFileIsBackedUp()
    {
        var path = TempPath();
        var file = new JsonStateFile<TestState>(path, schemaVersion: 1);

        try
        {
            File.WriteAllText(path, "this is not json");
            var loaded = file.Load(out var error);

            Assert.Null(loaded);
            Assert.False(string.IsNullOrWhiteSpace(error));
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

    private static string TempPath()
    {
        var directory = Path.Combine(Path.GetTempPath(), $"wag-state-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        return Path.Combine(directory, "state.json");
    }

    private static void Cleanup(string path)
    {
        var directory = Path.GetDirectoryName(path);

        if (directory is not null && Directory.Exists(directory))
        {
            Directory.Delete(directory, recursive: true);
        }
    }

    public sealed class TestState
    {
        public int Value { get; set; }

        public string Text { get; set; } = string.Empty;
    }
}
