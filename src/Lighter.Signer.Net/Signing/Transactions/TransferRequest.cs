namespace Lighter.Signer.Transactions;

/// <summary>Sub-account transfer parameters.</summary>
/// <param name="ToAccountIndex">Destination account index; must be positive.</param>
/// <param name="AssetIndex">The asset to transfer; non-negative.</param>
/// <param name="FromRouteType">0 = perps, 1 = spot.</param>
/// <param name="ToRouteType">0 = perps, 1 = spot.</param>
/// <param name="Amount">Scaled amount; must be positive.</param>
/// <param name="UsdcFee">Scaled USDC fee; non-negative.</param>
/// <param name="Memo">
/// Exactly 32 bytes, given as 32 raw characters or as 64 hex characters (optionally
/// 0x-prefixed). Shorter memos must be padded by the caller; the signer does not pad.
/// </param>
public sealed record TransferRequest(
    long ToAccountIndex,
    short AssetIndex,
    byte FromRouteType,
    byte ToRouteType,
    long Amount,
    long UsdcFee,
    string Memo);
