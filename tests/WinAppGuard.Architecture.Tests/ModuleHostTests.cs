using WinAppGuard.Service;

namespace WinAppGuard.Architecture.Tests;

public sealed class ModuleHostTests
{
    [Fact]
    public void StartsInOrderAndStopsInReverse()
    {
        var events = new List<string>();
        using var host = new ModuleHost(new[]
        {
            Module("b", 20, events),
            Module("a", 10, events),
            Module("c", 30, events),
        });

        host.StartAll();
        host.StopAll();

        Assert.Equal(
            new[] { "start:a", "start:b", "start:c", "stop:c", "stop:b", "stop:a" },
            events);
    }

    [Fact]
    public void OneModuleFailureDoesNotBlockTheRest()
    {
        var events = new List<string>();
        var broken = new TestModule(
            "broken",
            order: 10,
            events: events,
            start: () => throw new InvalidOperationException("boom"),
            stop: () => { });

        using var host = new ModuleHost(new[]
        {
            broken,
            Module("after", 20, events),
        });

        host.StartAll();

        var health = host.Snapshot();

        Assert.Equal(ModuleState.Failed, health.Single(item => item.Name == "broken").State);
        Assert.Equal(ModuleState.Running, health.Single(item => item.Name == "after").State);
        Assert.Contains("start:after", events);
    }

    [Fact]
    public void OnlyRestartableModulesAreRestarted()
    {
        var events = new List<string>();
        var attempts = 0;
        var flaky = new TestModule(
            "flaky",
            order: 10,
            events: events,
            start: () =>
            {
                attempts++;

                if (attempts == 1)
                {
                    throw new InvalidOperationException("first attempt fails");
                }
            },
            stop: () => { },
            restartable: true);

        var fixedFailure = new TestModule(
            "fixed",
            order: 20,
            events: events,
            start: () => throw new InvalidOperationException("always fails"),
            stop: () => { },
            restartable: false);

        using var host = new ModuleHost(new[] { flaky, fixedFailure });

        host.StartAll();

        var restarted = host.RestartFailedModules(DateTime.UtcNow.AddMinutes(1));

        Assert.Equal(1, restarted);

        var health = host.Snapshot();

        Assert.Equal(ModuleState.Running, health.Single(item => item.Name == "flaky").State);
        Assert.Equal(ModuleState.Failed, health.Single(item => item.Name == "fixed").State);
        Assert.Equal(1, health.Single(item => item.Name == "flaky").RestartCount);
    }

    [Fact]
    public void RestartIsBounded()
    {
        var events = new List<string>();
        var failing = new TestModule(
            "failing",
            order: 10,
            events: events,
            start: () => throw new InvalidOperationException("always fails"),
            stop: () => { },
            restartable: true);

        using var host = new ModuleHost(new[] { failing });

        host.StartAll();

        var now = DateTime.UtcNow;

        Assert.Equal(1, host.RestartFailedModules(now.AddMinutes(1)));
        Assert.Equal(1, host.RestartFailedModules(now.AddMinutes(2)));
        Assert.Equal(1, host.RestartFailedModules(now.AddMinutes(3)));
        Assert.Equal(0, host.RestartFailedModules(now.AddMinutes(4)));

        Assert.Equal(3, host.Snapshot()[0].RestartCount);
    }

    [Fact]
    public void DuplicateModuleNameIsRejected()
    {
        var events = new List<string>();

        Assert.Throws<InvalidOperationException>(() =>
            new ModuleHost(new[]
            {
                Module("same", 10, events),
                Module("same", 20, events),
            }));
    }

    [Fact]
    public void ServiceCatalogDefinesTwelveModules()
    {
        var modules = ServiceModules.Create(new ControlServer());

        Assert.Equal(12, modules.Count);
        Assert.Equal(12, modules.Select(module => module.Name).Distinct(StringComparer.Ordinal).Count());
        Assert.Equal(12, modules.Select(module => module.Order).Distinct().Count());
    }

    private static TestModule Module(string name, int order, List<string> events)
        => new(
            name,
            order,
            events,
            start: () => events.Add($"start:{name}"),
            stop: () => events.Add($"stop:{name}"));

    private sealed class TestModule : IServiceModule
    {
        private readonly Action _start;
        private readonly Action _stop;

        internal TestModule(
            string name,
            int order,
            List<string> events,
            Action start,
            Action stop,
            bool restartable = false)
        {
            Name = name;
            Order = order;
            _start = start;
            _stop = stop;
            Restartable = restartable;
        }

        public string Name { get; }

        public int Order { get; }

        public bool Restartable { get; }

        public void Start() => _start();

        public void Stop() => _stop();

        public string? GetDetail() => null;
    }
}
