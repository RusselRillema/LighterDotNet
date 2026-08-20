using Lighter.Signer.Sample.Configuration;
using Lighter.Signer.Cryptography;

namespace Lighter.Signer.Sample.Api;

public static class EndpointResolver
{
    public static async Task<EndpointProfile> ResolveAsync(
        ApiCredentials credentials,
        CancellationToken cancellationToken)
    {
        string computedPublicKey = NormalizeKey(new SchnorrSigner(credentials.PrivateKey).PublicKey);
        if (!string.Equals(computedPublicKey, NormalizeKey(credentials.PublicKey), StringComparison.Ordinal))
            throw new InvalidDataException("The configured public and private API keys do not match.");

        string? configuredUrl = Environment.GetEnvironmentVariable("LIGHTER_BASE_URL");
        if (!string.IsNullOrWhiteSpace(configuredUrl))
        {
            EndpointProfile profile = CreateConfiguredProfile(configuredUrl);
            EndpointCheckResult result = await CheckServerAsync(profile, credentials, computedPublicKey, cancellationToken);
            if (result == EndpointCheckResult.Matched)
                return profile;

            throw new LighterApiException($"The configured API key did not match LIGHTER_BASE_URL ({Describe(result)}).");
        }

        List<string> checks = new();
        foreach (EndpointProfile profile in new[] { EndpointProfile.Mainnet, EndpointProfile.Testnet })
        {
            EndpointCheckResult result = await CheckServerAsync(profile, credentials, computedPublicKey, cancellationToken);
            if (result == EndpointCheckResult.Matched)
                return profile;

            checks.Add($"{profile.Name}: {Describe(result)}");
        }

        throw new LighterApiException($"The API key did not match the official endpoints ({string.Join("; ", checks)}).");
    }

    private static EndpointProfile CreateConfiguredProfile(string configuredUrl)
    {
        if (!Uri.TryCreate(configuredUrl.TrimEnd('/') + '/', UriKind.Absolute, out Uri? baseUri))
            throw new InvalidDataException("LIGHTER_BASE_URL is not a valid absolute URL.");

        if (Uri.Compare(baseUri, EndpointProfile.Mainnet.BaseUri, UriComponents.HostAndPort, UriFormat.Unescaped, StringComparison.OrdinalIgnoreCase) == 0)
            return EndpointProfile.Mainnet;

        if (Uri.Compare(baseUri, EndpointProfile.Testnet.BaseUri, UriComponents.HostAndPort, UriFormat.Unescaped, StringComparison.OrdinalIgnoreCase) == 0)
            return EndpointProfile.Testnet;

        if (!uint.TryParse(Environment.GetEnvironmentVariable("LIGHTER_CHAIN_ID"), out uint chainId))
            throw new InvalidDataException("LIGHTER_CHAIN_ID is required for a custom LIGHTER_BASE_URL.");

        return new EndpointProfile("custom", baseUri, chainId);
    }

    private static async Task<EndpointCheckResult> CheckServerAsync(
        EndpointProfile profile,
        ApiCredentials credentials,
        string computedPublicKey,
        CancellationToken cancellationToken)
    {
        try
        {
            await using LighterApiClient client = new(profile);
            string? serverPublicKey = await client.GetApiPublicKeyAsync(credentials.AccountIndex, credentials.KeyIndex, cancellationToken);
            if (serverPublicKey is null)
                return EndpointCheckResult.KeyNotFound;

            return string.Equals(NormalizeKey(serverPublicKey), computedPublicKey, StringComparison.Ordinal)
                ? EndpointCheckResult.Matched
                : EndpointCheckResult.PublicKeyDifferent;
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (TaskCanceledException)
        {
            return EndpointCheckResult.TimedOut;
        }
        catch (HttpRequestException)
        {
            return EndpointCheckResult.Unreachable;
        }
        catch (LighterApiException)
        {
            return EndpointCheckResult.InvalidResponse;
        }
    }

    private static string Describe(EndpointCheckResult result) => result switch
    {
        EndpointCheckResult.KeyNotFound => "account/key index not found",
        EndpointCheckResult.PublicKeyDifferent => "stored public key differs",
        EndpointCheckResult.TimedOut => "request timed out",
        EndpointCheckResult.Unreachable => "endpoint unreachable",
        EndpointCheckResult.InvalidResponse => "endpoint rejected or returned an invalid response",
        _ => "unknown result",
    };

    private static string NormalizeKey(Fp5 publicKey) => Convert.ToHexString(publicKey.ToLittleEndianBytes()).ToLowerInvariant();

    private static string NormalizeKey(string publicKey) =>
        (publicKey.StartsWith("0x", StringComparison.OrdinalIgnoreCase) ? publicKey[2..] : publicKey)
        .ToLowerInvariant();

    private enum EndpointCheckResult
    {
        Matched,
        KeyNotFound,
        PublicKeyDifferent,
        TimedOut,
        Unreachable,
        InvalidResponse,
    }
}
