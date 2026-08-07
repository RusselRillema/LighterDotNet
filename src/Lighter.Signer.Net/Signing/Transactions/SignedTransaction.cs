namespace Lighter.Signer.Transactions;

public sealed record SignedTransaction(byte TransactionType, string TransactionInfo, string TransactionHash);

