namespace WinAppGuard.Contracts;

/// <summary>5.9：不抛异常的返回值。只用于新架构路径，旧接口保持原样。</summary>
public readonly record struct Result<T>(bool Ok, T? Value, ErrorCode Error)
{
    public static Result<T> Success(T value) => new(true, value, ErrorCode.None);

    public static Result<T> Fail(ErrorCode error) => new(false, default, error);

    public bool IsFailure => !Ok;
}
