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
/// <param name="OrderVersion">
/// Client-chosen version guard up to 2^48 - 1, mirroring the Python SDK's order_version: the exchange
/// applies the modify only when this exceeds the order's stored version and then stores it, so stale or
/// retried modifies cannot overwrite a newer one. A millisecond timestamp is the usual choice;
/// 0 (<see cref="ExchangeConstants.NilOrderVersion"/>) leaves the order unversioned.
/// </param>
public sealed record ModifyOrderRequest(short MarketIndex, long ExchangeOrderIndex, long BaseAmount, uint Price, uint TriggerPrice, long OrderVersion = ExchangeConstants.NilOrderVersion);
