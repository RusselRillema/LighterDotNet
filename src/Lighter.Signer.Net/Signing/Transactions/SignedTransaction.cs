namespace Lighter.Signer.Transactions;

/// <summary>A signed Lighter transaction ready for submission.</summary>
/// <param name="TransactionType">The Lighter transaction type identifier (the sendTx tx_type value).</param>
/// <param name="TransactionInfo">The serialized signed payload (the sendTx tx_info value).</param>
/// <param name="TransactionHash">Lowercase hex of the signed transaction hash.</param>
/// <param name="L1SignatureBody">
/// For approve-integrator transactions, the human-readable message an account's L1 (Ethereum)
/// key signs to produce the payload's L1Sig; <see langword="null"/> for other transaction types.
/// </param>
public sealed record SignedTransaction(byte TransactionType, string TransactionInfo, string TransactionHash, string? L1SignatureBody = null);
