namespace LighterNativeSigning.Signing.Transactions;

public sealed record TransferRequest(
    long ToAccountIndex,
    short AssetIndex,
    byte FromRouteType,
    byte ToRouteType,
    long Amount,
    long UsdcFee,
    byte[] Memo);
