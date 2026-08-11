namespace Lighter.Signer.Transactions;

public sealed record ModifyOrderRequest(
    short MarketIndex,
    long Index,
    long BaseAmount,
    uint Price,
    uint TriggerPrice);
