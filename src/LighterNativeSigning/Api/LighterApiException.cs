namespace LighterNativeSigning.Api;

public sealed class LighterApiException : Exception
{
    public LighterApiException(string message)
        : base(message)
    {
    }

    public LighterApiException(string message, Exception innerException)
        : base(message, innerException)
    {
    }
}

