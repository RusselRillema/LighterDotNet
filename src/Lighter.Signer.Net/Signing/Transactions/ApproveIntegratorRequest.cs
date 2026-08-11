namespace Lighter.Signer.Transactions;

public sealed record ApproveIntegratorRequest(
    long IntegratorAccountIndex,
    uint MaxPerpsTakerFee,
    uint MaxPerpsMakerFee,
    uint MaxSpotTakerFee,
    uint MaxSpotMakerFee,
    long ApprovalExpiry);
