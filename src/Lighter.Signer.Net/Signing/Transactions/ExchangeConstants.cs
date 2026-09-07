namespace Lighter.Signer.Transactions;

/// <summary>
/// Exchange-protocol bounds enforced by the signer's validation, mirroring the constants in the
/// Go signer's types/txtypes/constants.go. Useful for pre-validating inputs client-side.
/// </summary>
public static class ExchangeConstants
{
    /// <summary>Lowest perpetual market index. Mirrors Go's MinPerpsMarketIndex.</summary>
    public const short MinPerpetualMarketIndex = 0;

    /// <summary>Highest perpetual market index. Mirrors Go's MaxPerpsMarketIndex.</summary>
    public const short MaxPerpetualMarketIndex = 254;

    /// <summary>The nil market sentinel; never a real market. Mirrors Go's NilMarketIndex.</summary>
    public const short NilMarketIndex = 255;

    /// <summary>Lowest spot market index. Mirrors Go's MinSpotMarketIndex.</summary>
    public const short MinSpotMarketIndex = 2048;

    /// <summary>Highest spot market index. Mirrors Go's MaxSpotMarketIndex.</summary>
    public const short MaxSpotMarketIndex = 4094;

    /// <summary>
    /// Lowest account index the Go signer accepts wherever an account is referenced: transfer
    /// destinations and integrator account indices may be -1 as well as 0, the treasury account
    /// (Go's TreasuryAccountIndex). No account exists at -1 (the account API reports it as not
    /// found), so -1 only passes signer validation; the signer's own account must be positive.
    /// Mirrors Go's MinAccountIndex.
    /// </summary>
    public const long MinAccountIndex = -1;

    /// <summary>Highest account index (2^48 - 2). Mirrors Go's MaxAccountIndex.</summary>
    public const long MaxAccountIndex = 281_474_976_710_654;

    /// <summary>Highest api-key slot. Mirrors Go's MaxApiKeyIndex.</summary>
    public const byte MaxApiKeyIndex = 254;

    /// <summary>The nil api-key sentinel, which cannot sign. Mirrors Go's NilApiKeyIndex.</summary>
    public const byte NilApiKeyIndex = 255;

    /// <summary>Client order index 0 lets the exchange assign one. Mirrors Go's NilClientOrderIndex.</summary>
    public const long NilClientOrderIndex = 0;

    /// <summary>Lowest caller-chosen client order index. Mirrors Go's MinClientOrderIndex.</summary>
    public const long MinClientOrderIndex = 1;

    /// <summary>Highest client order index (2^48 - 1). Mirrors Go's MaxClientOrderIndex.</summary>
    public const long MaxClientOrderIndex = (1L << 48) - 1;

    /// <summary>Lowest exchange-assigned order index. Mirrors Go's MinOrderIndex.</summary>
    public const long MinOrderIndex = MaxClientOrderIndex + 1;

    /// <summary>Highest exchange-assigned order index (2^60 - 1). Mirrors Go's MaxOrderIndex.</summary>
    public const long MaxOrderIndex = (1L << 60) - 1;

    /// <summary>Lowest transferable asset index; 0 is the nil sentinel. Mirrors Go's MinAssetIndex.</summary>
    public const short MinAssetIndex = 1;

    /// <summary>Highest transferable asset index (2^6 - 2). Mirrors Go's MaxAssetIndex.</summary>
    public const short MaxAssetIndex = 62;

    /// <summary>Highest transfer amount and fee (2^60 - 1). Mirrors Go's MaxTransferAmount.</summary>
    public const long MaxTransferAmount = (1L << 60) - 1;

    /// <summary>Lowest non-nil order base amount. Mirrors Go's MinOrderBaseAmount.</summary>
    public const long MinOrderBaseAmount = 1;

    /// <summary>Highest order base amount (2^48 - 1). Mirrors Go's MaxOrderBaseAmount.</summary>
    public const long MaxOrderBaseAmount = (1L << 48) - 1;

    /// <summary>Lowest order price. Mirrors Go's MinOrderPrice.</summary>
    public const uint MinOrderPrice = 1;

    /// <summary>The fee denominator: fees are expressed in millionths and capped at this value. Mirrors Go's FeeTick.</summary>
    public const long FeeTick = 1_000_000;

    /// <summary>The margin-fraction denominator; leverage = 10000 / initialMarginFraction. Mirrors Go's MarginFractionTick.</summary>
    public const ushort MarginFractionTick = 10_000;

    /// <summary>Highest accepted timestamp in Unix milliseconds (2^48 - 1). Mirrors Go's MaxTimestamp.</summary>
    public const long MaxTimestampMilliseconds = (1L << 48) - 1;

    /// <summary>Most L2 transaction attributes a single transaction supports. Mirrors Go's NbAttributesPerTx.</summary>
    public const int MaxAttributesPerTransaction = 4;
}
