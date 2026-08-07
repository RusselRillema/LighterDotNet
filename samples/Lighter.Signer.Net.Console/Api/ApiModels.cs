using System.Text.Json.Serialization;

namespace Lighter.Signer.Sample.Api;

public class ApiResponse
{
    [JsonPropertyName("code")]
    public int Code { get; init; }

    [JsonPropertyName("message")]
    public string? Message { get; init; }
}

public sealed class AccountResponse : ApiResponse
{
    [JsonPropertyName("accounts")]
    public List<Account> Accounts { get; init; } = [];
}

public sealed class Account
{
    [JsonPropertyName("assets")]
    public List<AccountAsset> Assets { get; init; } = [];

    [JsonPropertyName("positions")]
    public List<AccountPosition> Positions { get; init; } = [];
}

public sealed class AccountAsset
{
    [JsonPropertyName("asset_id")]
    public int AssetId { get; init; }
}

public sealed class AccountPosition
{
    [JsonPropertyName("market_id")]
    public int MarketId { get; init; }
}

public sealed class ApiKeysResponse : ApiResponse
{
    [JsonPropertyName("api_keys")]
    public List<ApiKey> ApiKeys { get; init; } = [];
}

public sealed class ApiKey
{
    [JsonPropertyName("api_key_index")]
    public byte ApiKeyIndex { get; init; }

    [JsonPropertyName("public_key")]
    public string PublicKey { get; init; } = string.Empty;
}

public sealed class NonceResponse : ApiResponse
{
    [JsonPropertyName("nonce")]
    public long Nonce { get; init; }
}

public sealed class MarketsResponse : ApiResponse
{
    [JsonPropertyName("order_book_details")]
    public List<MarketDetails> PerpetualMarkets { get; init; } = [];
}

public sealed class MarketDetails
{
    [JsonPropertyName("symbol")]
    public string Symbol { get; init; } = string.Empty;

    [JsonPropertyName("market_id")]
    public short MarketId { get; init; }

    [JsonPropertyName("status")]
    public string Status { get; init; } = string.Empty;

    [JsonPropertyName("min_base_amount")]
    public string MinimumBaseAmount { get; init; } = string.Empty;

    [JsonPropertyName("supported_size_decimals")]
    public int SupportedSizeDecimals { get; init; }

    [JsonPropertyName("supported_price_decimals")]
    public int SupportedPriceDecimals { get; init; }
}

public sealed class OrdersResponse : ApiResponse
{
    [JsonPropertyName("orders")]
    public List<OpenOrder> Orders { get; init; } = [];
}

public sealed class OpenOrder
{
    [JsonPropertyName("order_index")]
    public long OrderIndex { get; init; }

    [JsonPropertyName("client_order_index")]
    public long ClientOrderIndex { get; init; }

    [JsonPropertyName("order_id")]
    public string OrderId { get; init; } = string.Empty;

    [JsonPropertyName("market_index")]
    public short MarketIndex { get; init; }
}

public sealed class SendTransactionResponse : ApiResponse
{
    [JsonPropertyName("tx_hash")]
    public string TransactionHash { get; init; } = string.Empty;

    [JsonPropertyName("predicted_execution_time_ms")]
    public long PredictedExecutionTimeMilliseconds { get; init; }
}

