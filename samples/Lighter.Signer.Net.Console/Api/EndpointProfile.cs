namespace Lighter.Signer.Sample.Api;

public sealed record EndpointProfile(string Name, Uri BaseUri, uint ChainId)
{
    public static EndpointProfile Mainnet { get; } = new(
        "mainnet",
        new Uri("https://mainnet.zklighter.elliot.ai/", UriKind.Absolute),
        304);

    public static EndpointProfile Testnet { get; } = new(
        "testnet",
        new Uri("https://testnet.zklighter.elliot.ai/", UriKind.Absolute),
        300);
}

