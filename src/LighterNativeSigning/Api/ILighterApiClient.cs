using LighterNativeSigning.Signing.Transactions;

namespace LighterNativeSigning.Api;

public interface ILighterApiClient
{
    Task<Account> GetAccountAsync(long accountIndex, CancellationToken cancellationToken);

    Task<string?> GetApiPublicKeyAsync(long accountIndex, byte apiKeyIndex, CancellationToken cancellationToken);

    Task<long> GetNextNonceAsync(long accountIndex, byte apiKeyIndex, CancellationToken cancellationToken);

    Task<MarketDetails> GetMarketAsync(string symbol, CancellationToken cancellationToken);

    Task<OrdersResponse> GetOpenOrdersAsync(long accountIndex, string authToken, CancellationToken cancellationToken);

    Task<SendTransactionResponse> SendTransactionAsync(SignedTransaction transaction, CancellationToken cancellationToken);
}

