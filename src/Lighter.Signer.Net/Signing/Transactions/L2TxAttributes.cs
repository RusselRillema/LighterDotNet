namespace Lighter.Signer.Transactions;

/// <summary>
/// Optional L2 transaction attributes. A field left <see langword="null"/> is omitted from the
/// transaction; at most four fields may be set on a single transaction.
/// </summary>
public sealed record L2TxAttributes
{
    /// <summary>Account receiving the integrator fees; required when either fee is non-zero.</summary>
    public long? IntegratorAccountIndex { get; init; }

    /// <summary>Integrator taker fee in millionths; requires <see cref="IntegratorAccountIndex"/> when non-zero.</summary>
    public uint? IntegratorTakerFee { get; init; }

    /// <summary>Integrator maker fee in millionths; requires <see cref="IntegratorAccountIndex"/> when non-zero.</summary>
    public uint? IntegratorMakerFee { get; init; }

    /// <summary>The only accepted value is 1; leave <see langword="null"/> to keep nonce checking.</summary>
    public byte? SkipNonce { get; init; }

    /// <summary>A <see cref="SelfTradeBehavior"/> value; cannot be combined with integrator fees.</summary>
    public byte? SelfTradeBehaviorMode { get; init; }

    /// <summary>A <see cref="SelfTradeEquality"/> value; cannot be combined with integrator fees.</summary>
    public byte? SelfTradeEqualityMode { get; init; }

    /// <summary>Modify-order version (the Python SDK's order_version), 0 to 2^48 - 1; the exchange applies a modify only when it exceeds the order's stored version. 0 skips the check.</summary>
    public long? OrderVersion { get; init; }
}
