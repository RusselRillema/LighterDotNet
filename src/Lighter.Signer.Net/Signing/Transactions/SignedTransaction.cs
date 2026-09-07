using System.Text;
using System.Text.Json;

namespace Lighter.Signer.Transactions;

/// <summary>A signed Lighter transaction ready for submission.</summary>
/// <param name="TransactionType">The Lighter transaction type identifier (the sendTx tx_type value).</param>
/// <param name="TransactionInfo">The serialized signed payload (the sendTx tx_info value).</param>
/// <param name="TransactionHash">Lowercase hex of the signed transaction hash.</param>
/// <param name="L1SignatureBody">
/// For approve-integrator transactions, the human-readable message an account's L1 (Ethereum)
/// key signs to produce the payload's L1Sig; <see langword="null"/> for other transaction types.
/// Attach that signature with <see cref="WithL1Signature"/>.
/// </param>
public sealed record SignedTransaction(byte TransactionType, string TransactionInfo, string TransactionHash, string? L1SignatureBody = null)
{
    /// <summary>
    /// Returns a copy whose payload carries <paramref name="l1Signature"/> as L1Sig. Mirrors the official
    /// Python SDK, which signs <see cref="L1SignatureBody"/> as an EIP-191 personal message with the
    /// account's Ethereum key and patches the result into the signed payload. The transaction hash does
    /// not cover L1Sig, so the L2 signature stays valid.
    /// </summary>
    /// <param name="l1Signature">The 65-byte EIP-191 signature (r, s, v) as 0x-prefixed hex.</param>
    public SignedTransaction WithL1Signature(string l1Signature)
    {
        ArgumentNullException.ThrowIfNull(l1Signature);
        if (l1Signature.Length != 132 || !l1Signature.StartsWith("0x", StringComparison.Ordinal))
            throw new ArgumentException("The L1 signature must be 65 bytes as 0x-prefixed hex (132 characters).", nameof(l1Signature));

        try
        {
            Convert.FromHexString(l1Signature.AsSpan(2));
        }
        catch (FormatException exception)
        {
            throw new ArgumentException("The L1 signature hex encoding is invalid.", nameof(l1Signature), exception);
        }

        // Only the L1Sig value is spliced, so every other byte of the signed payload is untouched.
        byte[] payload = Encoding.UTF8.GetBytes(TransactionInfo);
        Utf8JsonReader reader = new(payload);
        while (reader.Read())
        {
            if (reader.CurrentDepth != 1 || reader.TokenType != JsonTokenType.PropertyName || !reader.ValueTextEquals("L1Sig"))
                continue;

            if (!reader.Read() || reader.TokenType != JsonTokenType.String)
                throw new InvalidOperationException("The payload's L1Sig is not a string.");

            int valueStart = (int)reader.TokenStartIndex;
            int valueEnd = (int)reader.BytesConsumed;
            byte[] patched = [.. payload.AsSpan(0, valueStart), .. Encoding.UTF8.GetBytes("\"" + l1Signature + "\""), .. payload.AsSpan(valueEnd)];
            return this with { TransactionInfo = Encoding.UTF8.GetString(patched) };
        }

        throw new InvalidOperationException("This transaction type does not carry an L1 signature.");
    }
}
