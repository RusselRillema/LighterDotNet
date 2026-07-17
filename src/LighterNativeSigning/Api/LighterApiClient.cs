using System.Net.Http.Headers;
using System.Text.Json;
using LighterNativeSigning.Signing.Transactions;

namespace LighterNativeSigning.Api;

public sealed class LighterApiClient : ILighterApiClient, IAsyncDisposable
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
    };

    private readonly HttpClient _httpClient;
    private readonly bool _ownsClient;

    public LighterApiClient(EndpointProfile endpoint, HttpClient? httpClient = null)
    {
        _httpClient = httpClient ?? new HttpClient();
        _ownsClient = httpClient is null;
        _httpClient.BaseAddress = endpoint.BaseUri;
        _httpClient.Timeout = TimeSpan.FromSeconds(30);
    }

    public async Task<Account> GetAccountAsync(long accountIndex, CancellationToken cancellationToken)
    {
        var response = await GetAsync<AccountResponse>(
            $"api/v1/account?by=index&value={accountIndex}",
            authToken: null,
            cancellationToken);
        if (response.Accounts.Count != 1)
        {
            throw new LighterApiException("The exchange did not return exactly one account.");
        }

        return response.Accounts[0];
    }

    public async Task<string?> GetApiPublicKeyAsync(
        long accountIndex,
        byte apiKeyIndex,
        CancellationToken cancellationToken)
    {
        var response = await GetAsync<ApiKeysResponse>(
            $"api/v1/apikeys?account_index={accountIndex}&api_key_index={apiKeyIndex}",
            authToken: null,
            cancellationToken);
        return response.ApiKeys.SingleOrDefault(key => key.ApiKeyIndex == apiKeyIndex)?.PublicKey;
    }

    public async Task<long> GetNextNonceAsync(long accountIndex, byte apiKeyIndex, CancellationToken cancellationToken)
    {
        var response = await GetAsync<NonceResponse>(
            $"api/v1/nextNonce?account_index={accountIndex}&api_key_index={apiKeyIndex}",
            authToken: null,
            cancellationToken);
        return response.Nonce;
    }

    public async Task<MarketDetails> GetMarketAsync(string symbol, CancellationToken cancellationToken)
    {
        var response = await GetAsync<MarketsResponse>(
            "api/v1/orderBookDetails?filter=perp",
            authToken: null,
            cancellationToken);
        return response.PerpetualMarkets.SingleOrDefault(market =>
                   string.Equals(market.Symbol, symbol, StringComparison.OrdinalIgnoreCase) &&
                   string.Equals(market.Status, "active", StringComparison.OrdinalIgnoreCase))
               ?? throw new LighterApiException($"The active {symbol} perpetual market was not found.");
    }

    public Task<OrdersResponse> GetOpenOrdersAsync(
        long accountIndex,
        string authToken,
        CancellationToken cancellationToken) =>
        GetAsync<OrdersResponse>(
            $"api/v1/accountActiveOrders?account_index={accountIndex}",
            authToken,
            cancellationToken);

    public async Task<SendTransactionResponse> SendTransactionAsync(
        SignedTransaction transaction,
        CancellationToken cancellationToken)
    {
        using var form = new FormUrlEncodedContent(
        [
            new KeyValuePair<string, string>("tx_type", transaction.TransactionType.ToString(System.Globalization.CultureInfo.InvariantCulture)),
            new KeyValuePair<string, string>("tx_info", transaction.TransactionInfo),
        ]);
        using var request = new HttpRequestMessage(HttpMethod.Post, "api/v1/sendTx")
        {
            Content = form,
        };
        return await SendAsync<SendTransactionResponse>(request, cancellationToken);
    }

    public ValueTask DisposeAsync()
    {
        if (_ownsClient)
        {
            _httpClient.Dispose();
        }

        return ValueTask.CompletedTask;
    }

    private async Task<T> GetAsync<T>(string relativeUri, string? authToken, CancellationToken cancellationToken)
        where T : ApiResponse
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, relativeUri);
        if (authToken is not null)
        {
            request.Headers.TryAddWithoutValidation("authorization", authToken);
        }

        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        return await SendAsync<T>(request, cancellationToken);
    }

    private async Task<T> SendAsync<T>(HttpRequestMessage request, CancellationToken cancellationToken)
        where T : ApiResponse
    {
        using var response = await _httpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, cancellationToken);
        T? result;
        try
        {
            await using var stream = await response.Content.ReadAsStreamAsync(cancellationToken);
            result = await JsonSerializer.DeserializeAsync<T>(stream, JsonOptions, cancellationToken);
        }
        catch (JsonException exception)
        {
            if (!response.IsSuccessStatusCode)
            {
                throw new LighterApiException(
                    $"Exchange request failed with HTTP status {(int)response.StatusCode}.",
                    exception);
            }

            throw new LighterApiException("The exchange returned invalid JSON.", exception);
        }

        if (!response.IsSuccessStatusCode)
        {
            var detail = string.IsNullOrWhiteSpace(result?.Message)
                ? string.Empty
                : $": {result.Message.Trim()}";
            throw new LighterApiException(
                $"Exchange request failed with HTTP status {(int)response.StatusCode}{detail}");
        }

        if (result is null)
        {
            throw new LighterApiException("The exchange returned an empty response.");
        }

        if (result.Code != 200)
        {
            throw new LighterApiException($"Exchange rejected the request: {result.Message ?? "unknown error"}");
        }

        return result;
    }
}
