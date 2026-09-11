namespace Lighter.Signer.Transactions;

/// <summary>Integrator approval parameters. Fees are in millionths, capped at 1,000,000.</summary>
/// <param name="IntegratorAccountIndex">The integrator account to approve; -1 to 2^48 - 2.</param>
/// <param name="MaxPerpsTakerFee">Maximum perpetual-market taker fee in millionths.</param>
/// <param name="MaxPerpsMakerFee">Maximum perpetual-market maker fee in millionths.</param>
/// <param name="MaxSpotTakerFee">Maximum spot-market taker fee in millionths.</param>
/// <param name="MaxSpotMakerFee">Maximum spot-market maker fee in millionths.</param>
/// <param name="ApprovalExpiry">Unix milliseconds; 0 revokes the approval and requires all fees to be zero.</param>
public sealed record ApproveIntegratorRequest(long IntegratorAccountIndex, uint MaxPerpsTakerFee, uint MaxPerpsMakerFee, uint MaxSpotTakerFee, uint MaxSpotMakerFee, long ApprovalExpiry);
