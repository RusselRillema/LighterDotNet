namespace Lighter.Signer.Transactions;

/// <summary>Create-order parameters, hashed and serialized exactly as the Go signer's OrderInfo.</summary>
/// <param name="MarketIndex">0-254 for perpetual markets or 2048-4094 for spot markets.</param>
/// <param name="ClientOrderIndex">Caller-chosen identifier up to 2^48 - 1; 0 lets the exchange assign one.</param>
/// <param name="BaseAmount">Scaled base amount; may be 0 only for reduce-only orders.</param>
/// <param name="Price">Scaled price; must be at least 1.</param>
/// <param name="IsAsk">True to sell, false to buy.</param>
/// <param name="Type">An <see cref="OrderType"/> byte value.</param>
/// <param name="TimeInForce">An <see cref="OrderTimeInForce"/> byte value.</param>
/// <param name="ReduceOnly">Only reduces an existing position; perpetual markets only.</param>
/// <param name="TriggerPrice">Required for stop-loss and take-profit orders; 0 otherwise.</param>
/// <param name="OrderExpiry">Unix milliseconds; 0 = none (market/IOC), -1 selects the 28-day default.</param>
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
