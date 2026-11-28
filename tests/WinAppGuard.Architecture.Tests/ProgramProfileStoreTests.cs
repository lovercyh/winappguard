using WinAppGuard.Core.Features.ProgramProfile;

namespace WinAppGuard.Architecture.Tests;

/// <summary>6.0：程序画像只保存进程×网络元数据。</summary>
public sealed class ProgramProfileStoreTests
{
    [Fact]
    public void ObserveStoresBoundedMetadataAndReloads()
    {
        var path = Path.Combine(
            Path.GetTempPath(), "wag-profile-" + Guid.NewGuid().ToString("N"), "profiles.json");

        try
        {
            using (var store = new ProgramProfileStore(path))
            {
                store.Observe(
                    @"C:\Tools\a.exe",
                    "203.0.113.9",
                    443,
                    "malware",
                    "svc-a",
                    "LOLBIN-TEST");

                store.Observe(
                    @"C:\Tools\a.exe",
                    "203.0.113.10",
                    8443,
                    "malware",
                    null,
                    null);

                Assert.Equal(1, store.Count);

                var summary = Assert.Single(store.Snapshot());
                Assert.Equal(2, summary.AlertCount);
                Assert.Contains("203.0.113.9", summary.RemoteAddresses);
                Assert.Contains(8443, summary.RemotePorts);
                Assert.Equal("svc-a", summary.LastServiceInstance);
            }

            using var reloaded = new ProgramProfileStore(path);
            Assert.Equal(1, reloaded.Count);
            Assert.Equal(@"C:\Tools\a.exe", reloaded.Snapshot()[0].Path);
        }
        finally
        {
            try
            {
                var directory = Path.GetDirectoryName(path);
                if (directory is not null && Directory.Exists(directory))
                {
                    Directory.Delete(directory, recursive: true);
                }
            }
            catch (Exception)
            {
                // 清理失败不影响测试结论。
            }
        }
    }
}
