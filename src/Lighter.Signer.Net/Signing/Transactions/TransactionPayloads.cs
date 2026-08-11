using System.Text.Json.Serialization;

namespace Lighter.Signer.Transactions;

internal sealed class CreateOrderPayload
{
    public required long AccountIndex { get; init; }
    public required byte ApiKeyIndex { get; init; }
    public required short MarketIndex { get; init; }
    public required long ClientOrderIndex { get; init; }
    public required long BaseAmount { get; init; }
    public required uint Price { get; init; }
    public required byte IsAsk { get; init; }
    public required byte Type { get; init; }
    public required byte TimeInForce { get; init; }
    public required byte ReduceOnly { get; init; }
    public required uint TriggerPrice { get; init; }
    public required long OrderExpiry { get; init; }
    public required long ExpiredAt { get; init; }
    public required long Nonce { get; init; }
    public required byte[] Sig { get; init; }

    [JsonPropertyName("L2TxAttributes")]
    public required SortedDictionary<byte, long>? Attributes { get; init; }
}

internal sealed class CancelOrderPayload
{
    public required long AccountIndex { get; init; }
    public required byte ApiKeyIndex { get; init; }
    public required short MarketIndex { get; init; }
    public required long Index { get; init; }
    public required long ExpiredAt { get; init; }
    public required long Nonce { get; init; }
    public required byte[] Sig { get; init; }

    [JsonPropertyName("L2TxAttributes")]
    public required SortedDictionary<byte, long>? Attributes { get; init; }
}

internal sealed class ModifyOrderPayload
{
    public required long AccountIndex { get; init; }
    public required byte ApiKeyIndex { get; init; }
    public required short MarketIndex { get; init; }
    public required long Index { get; init; }
    public required long BaseAmount { get; init; }
    public required uint Price { get; init; }
    public required uint TriggerPrice { get; init; }
    public required long ExpiredAt { get; init; }
    public required long Nonce { get; init; }
    public required byte[] Sig { get; init; }

    [JsonPropertyName("L2TxAttributes")]
    public required SortedDictionary<byte, long>? Attributes { get; init; }
}

internal sealed class UpdateLeveragePayload
{
    public required long AccountIndex { get; init; }
    public required byte ApiKeyIndex { get; init; }
    public required short MarketIndex { get; init; }
    public required ushort InitialMarginFraction { get; init; }
    public required byte MarginMode { get; init; }
    public required long ExpiredAt { get; init; }
    public required long Nonce { get; init; }
    public required byte[] Sig { get; init; }

    [JsonPropertyName("L2TxAttributes")]
    public required SortedDictionary<byte, long>? Attributes { get; init; }
}

internal sealed class ApproveIntegratorPayload
{
    public required long AccountIndex { get; init; }
    public required byte ApiKeyIndex { get; init; }
    public required long IntegratorAccountIndex { get; init; }
    public required uint MaxPerpsTakerFee { get; init; }
    public required uint MaxPerpsMakerFee { get; init; }
    public required uint MaxSpotTakerFee { get; init; }
    public required uint MaxSpotMakerFee { get; init; }
    public required long ApprovalExpiry { get; init; }
    public required long ExpiredAt { get; init; }
    public required long Nonce { get; init; }
    public required byte[] Sig { get; init; }

    [JsonPropertyName("L1Sig")]
    public string L1Signature => string.Empty;

    [JsonPropertyName("L2TxAttributes")]
    public required SortedDictionary<byte, long>? Attributes { get; init; }
}

internal sealed class TransferPayload
{
    public required long FromAccountIndex { get; init; }
    public required byte ApiKeyIndex { get; init; }
    public required long ToAccountIndex { get; init; }
    public required short AssetIndex { get; init; }
    public required byte FromRouteType { get; init; }
    public required byte ToRouteType { get; init; }
    public required long Amount { get; init; }

    [JsonPropertyName("USDCFee")]
    public required long UsdcFee { get; init; }

    public required int[] Memo { get; init; }
    public required long ExpiredAt { get; init; }
    public required long Nonce { get; init; }
    public required byte[] Sig { get; init; }

    [JsonPropertyName("L1Sig")]
    public string L1Signature => string.Empty;

    [JsonPropertyName("L2TxAttributes")]
    public required SortedDictionary<byte, long>? Attributes { get; init; }
}
