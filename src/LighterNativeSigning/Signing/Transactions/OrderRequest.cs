namespace LighterNativeSigning.Signing.Transactions;

public sealed record OrderRequest(
    short MarketIndex,
    long ClientOrderIndex,
    long BaseAmount,
    uint Price,
    bool IsAsk,
    byte Type,
    byte TimeInForce,
    bool ReduceOnly,
    uint TriggerPrice,
    long OrderExpiry);

