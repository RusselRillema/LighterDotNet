namespace Lighter.Signer.Transactions;

/// <summary>
/// Modify-order parameters. <see cref="ExchangeOrderIndex"/> also accepts a client order
/// index, mirroring the Go signer.
/// </summary>
/// <param name="MarketIndex">0-254 for perpetual markets or 2048-4094 for spot markets.</param>
/// <param name="ExchangeOrderIndex">The order to modify; 1 to 2^60 - 1.</param>
/// <param name="BaseAmount">New scaled base amount; 0 keeps the current amount.</param>
/// <param name="Price">New scaled price; must be at least 1.</param>
/// <param name="TriggerPrice">New trigger price; 0 for none.</param>
public sealed record ModifyOrderRequest(
    short MarketIndex,
    long ExchangeOrderIndex,
    long BaseAmount,
    uint Price,
    uint TriggerPrice);
