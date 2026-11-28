using WinAppGuard.Models;

namespace WinAppGuard.Architecture.Tests;

/// <summary>
/// 5.16：时钟回拨不能被当成“重启”，否则会提前解除临时规则。
/// </summary>
public sealed class RuleExpiryTests
{
    [Fact]
    public void ClockRollbackDoesNotExpireNextBootRule()
    {
        var boot = new DateTime(2026, 1, 1, 10, 0, 0, DateTimeKind.Utc);
        var expiry = RuleExpiry.OnNextBoot(boot);

        Assert.False(expiry.IsExpired(
            DateTime.UtcNow,
            boot.AddMinutes(-10)));
    }

    [Fact]
    public void ForwardBootTimeBeyondToleranceExpires()
    {
        var boot = new DateTime(2026, 1, 1, 10, 0, 0, DateTimeKind.Utc);
        var expiry = RuleExpiry.OnNextBoot(boot);

        Assert.True(expiry.IsExpired(
            DateTime.UtcNow,
            boot.AddMinutes(10)));
    }
}
