namespace Lighter.Signer.Transactions;

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
    long OrderExpiry)
{
    // A constructor overload taking the enums would be ambiguous with the primary constructor
    // whenever both Type and TimeInForce are the literal 0, so the convenience lives in a factory.
    public static OrderRequest Create(
        short marketIndex,
        long clientOrderIndex,
        long baseAmount,
        uint price,
        bool isAsk,
        OrderType type,
        OrderTimeInForce timeInForce,
        bool reduceOnly,
        uint triggerPrice,
        long orderExpiry)
        => new(
            marketIndex,
            clientOrderIndex,
            baseAmount,
            price,
            isAsk,
            (byte)type,
            (byte)timeInForce,
            reduceOnly,
            triggerPrice,
            orderExpiry);
}
