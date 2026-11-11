using WinAppGuard.Contracts;

namespace WinAppGuard.Architecture.Tests;

public sealed class ResultTests
{
    [Fact]
    public void SuccessCarriesValue()
    {
        var result = Result<int>.Success(42);

        Assert.True(result.Ok);
        Assert.Equal(42, result.Value);
        Assert.Equal(ErrorCode.None, result.Error);
    }

    [Fact]
    public void FailureCarriesCode()
    {
        var result = Result<int>.Fail(ErrorCode.Unavailable);

        Assert.False(result.Ok);
        Assert.True(result.IsFailure);
        Assert.Equal(ErrorCode.Unavailable, result.Error);
    }
}
