using LighterNativeSigning.Api;
using LighterNativeSigning.App;
using LighterNativeSigning.Configuration;
using LighterNativeSigning.Signing;

var credentialPath = GetCredentialPath(args);
using var cancellationSource = new CancellationTokenSource();
Console.CancelKeyPress += (_, eventArgs) =>
{
    eventArgs.Cancel = true;
    cancellationSource.Cancel();
};

try
{
    var credentials = await ApiCredentialReader.ReadAsync(credentialPath, cancellationSource.Token);
    var endpoint = await EndpointResolver.ResolveAsync(credentials, cancellationSource.Token);
    Console.WriteLine($"Using Lighter {endpoint.Name} REST endpoint.");

    var signer = new LighterSigner(
        credentials.PrivateKey,
        credentials.AccountIndex,
        credentials.KeyIndex,
        endpoint.ChainId);
    await using var apiClient = new LighterApiClient(endpoint);
    var workflow = new TradingWorkflow(apiClient, credentials, signer, Console.Out);
    await workflow.RunAsync(cancellationSource.Token);
    return 0;
}
catch (OperationCanceledException)
{
    Console.Error.WriteLine("Operation canceled.");
    return 2;
}
catch (Exception exception)
{
    Console.Error.WriteLine($"FAILED: {exception.Message}");
    return 1;
}

static string GetCredentialPath(string[] arguments)
{
    if (arguments.Length == 0)
    {
        return Path.Combine(Directory.GetCurrentDirectory(), "APIKEY");
    }

    if (arguments.Length == 2 && string.Equals(arguments[0], "--credentials", StringComparison.Ordinal))
    {
        return Path.GetFullPath(arguments[1]);
    }

    throw new ArgumentException("Usage: LighterNativeSigning [--credentials <path>]");
}
