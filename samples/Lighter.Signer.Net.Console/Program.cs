using Lighter.Signer.Sample.Api;
using Lighter.Signer.Sample.Workflow;
using Lighter.Signer.Sample.Configuration;
using Lighter.Signer;

string credentialPath = GetCredentialPath(args);
using CancellationTokenSource cancellationSource = new();
Console.CancelKeyPress += (_, eventArgs) =>
{
    eventArgs.Cancel = true;
    cancellationSource.Cancel();
};

try
{
    ApiCredentials credentials = await ApiCredentialReader.ReadAsync(credentialPath, cancellationSource.Token);
    EndpointProfile endpoint = await EndpointResolver.ResolveAsync(credentials, cancellationSource.Token);
    Console.WriteLine($"Using Lighter {endpoint.Name} REST endpoint.");

    LighterSigner signer = new(credentials.PrivateKey, credentials.AccountIndex, credentials.KeyIndex, endpoint.ChainId);
    await using LighterApiClient apiClient = new(endpoint);
    TradingWorkflow workflow = new(apiClient, credentials, signer, Console.Out);
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
        return Path.Combine(Directory.GetCurrentDirectory(), "APIKEY");

    if (arguments.Length == 2 && string.Equals(arguments[0], "--credentials", StringComparison.Ordinal))
        return Path.GetFullPath(arguments[1]);

    throw new ArgumentException("Usage: Lighter.Signer.Net.Console [--credentials <path>]");
}
