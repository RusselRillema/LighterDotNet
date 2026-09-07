using Lighter.Signer.Cryptography;

namespace Lighter.Signer.Transactions;

internal static class L2TxAttributeEncoder
{
    internal const byte IntegratorAccountIndexType = 1;
    internal const byte IntegratorTakerFeeType = 2;
    internal const byte IntegratorMakerFeeType = 3;
    internal const byte SkipNonceType = 4;

    // Attribute type 5 is not exposed as it is not implemented

    internal const byte SelfTradeBehaviorModeType = 6;
    internal const byte SelfTradeEqualityModeType = 7;
    internal const byte OrderVersionType = 8;

    internal static SortedDictionary<byte, long>? ToValidatedMap(L2TxAttributes? attributes, long orderVersion = ExchangeConstants.NilOrderVersion)
    {
        SortedDictionary<byte, long> map = new();
        if (attributes is not null)
        {
            if (attributes.IntegratorAccountIndex.HasValue)
                map[IntegratorAccountIndexType] = attributes.IntegratorAccountIndex.Value;
            if (attributes.IntegratorTakerFee.HasValue)
                map[IntegratorTakerFeeType] = attributes.IntegratorTakerFee.Value;
            if (attributes.IntegratorMakerFee.HasValue)
                map[IntegratorMakerFeeType] = attributes.IntegratorMakerFee.Value;
            if (attributes.SkipNonce.HasValue)
                map[SkipNonceType] = attributes.SkipNonce.Value;
            if (attributes.SelfTradeBehaviorMode.HasValue)
                map[SelfTradeBehaviorModeType] = attributes.SelfTradeBehaviorMode.Value;
            if (attributes.SelfTradeEqualityMode.HasValue)
                map[SelfTradeEqualityModeType] = attributes.SelfTradeEqualityMode.Value;
        }

        // Matching the Go shared library, the nil order version is omitted rather than encoded as 0.
        if (orderVersion != ExchangeConstants.NilOrderVersion)
            map[OrderVersionType] = orderVersion;

        if (map.Count == 0)
            return null;

        if (map.Count > ExchangeConstants.MaxAttributesPerTransaction)
            throw new ArgumentException("A transaction supports at most four L2 transaction attributes, counting a modify-order version.", nameof(attributes));

        foreach ((byte attributeType, long value) in map)
        {
            (long minValue, long maxValue) = attributeType switch
            {
                IntegratorAccountIndexType => (0L, ExchangeConstants.MaxAccountIndex),
                IntegratorTakerFeeType or IntegratorMakerFeeType => (0L, ExchangeConstants.FeeTick),
                SkipNonceType => (1L, 1L),
                SelfTradeBehaviorModeType => (0L, (long)SelfTradeBehavior.Reduce),
                SelfTradeEqualityModeType => (0L, (long)SelfTradeEquality.MasterAccountIndex),
                OrderVersionType => (0L, ExchangeConstants.MaxTimestampMilliseconds),
                _ => throw new ArgumentException("The attribute type is unknown.", nameof(attributes)),
            };
            if (value < minValue || value > maxValue)
                throw new ArgumentOutOfRangeException(
                    nameof(attributes),
                    string.Create(System.Globalization.CultureInfo.InvariantCulture, $"The L2 transaction attribute {attributeType} value {value} is out of range."));
        }

        bool hasIntegratorFees = HasRealValue(map, IntegratorTakerFeeType) || HasRealValue(map, IntegratorMakerFeeType);
        if (hasIntegratorFees && !HasRealValue(map, IntegratorAccountIndexType))
            throw new ArgumentException("Integrator fees require an integrator account index.", nameof(attributes));

        bool hasSelfTradeSpecification = HasRealValue(map, SelfTradeBehaviorModeType) || HasRealValue(map, SelfTradeEqualityModeType);
        if (hasSelfTradeSpecification && hasIntegratorFees)
            throw new ArgumentException("Self-trade attributes cannot be combined with integrator fees.", nameof(attributes));

        if (map.GetValueOrDefault(SelfTradeBehaviorModeType) == (byte)SelfTradeBehavior.Reduce &&
            map.GetValueOrDefault(SelfTradeEqualityModeType) == (byte)SelfTradeEquality.MasterAccountIndex)
            throw new ArgumentException("The reduce self-trade behavior cannot be combined with master-account-index equality.", nameof(attributes));

        return map;
    }

    internal static Fp5 AggregateTransactionHash(Fp5 transactionHash, SortedDictionary<byte, long>? attributes)
    {
        if (attributes is null)
            return transactionHash;

        Goldilocks[] elements = new Goldilocks[2 * ExchangeConstants.MaxAttributesPerTransaction];
        int slot = 0;
        foreach ((byte attributeType, long value) in attributes)
        {
            if (value == 0)
                continue;

            elements[2 * slot] = new Goldilocks(attributeType);
            elements[(2 * slot) + 1] = Goldilocks.FromSigned(value);
            slot++;
        }

        if (slot == 0)
            return transactionHash;

        Fp5 attributesHash = Poseidon2.HashToFp5(elements);
        return Poseidon2.HashToFp5(
        [
            transactionHash[0],
            transactionHash[1],
            transactionHash[2],
            transactionHash[3],
            transactionHash[4],
            attributesHash[0],
            attributesHash[1],
            attributesHash[2],
            attributesHash[3],
            attributesHash[4],
        ]);
    }

    private static bool HasRealValue(SortedDictionary<byte, long> map, byte attributeType) => map.GetValueOrDefault(attributeType) != 0;
}
