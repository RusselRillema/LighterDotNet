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

    internal static SortedDictionary<byte, long>? ToValidatedMap(L2TxAttributes? attributes)
    {
        if (attributes is null)
        {
            return null;
        }

        var map = new SortedDictionary<byte, long>();
        if (attributes.IntegratorAccountIndex is { } integratorAccountIndex)
        {
            map[IntegratorAccountIndexType] = integratorAccountIndex;
        }

        if (attributes.IntegratorTakerFee is { } integratorTakerFee)
        {
            map[IntegratorTakerFeeType] = integratorTakerFee;
        }

        if (attributes.IntegratorMakerFee is { } integratorMakerFee)
        {
            map[IntegratorMakerFeeType] = integratorMakerFee;
        }

        if (attributes.SkipNonce is { } skipNonce)
        {
            map[SkipNonceType] = skipNonce;
        }

        if (attributes.SelfTradeBehaviorMode is { } selfTradeBehaviorMode)
        {
            map[SelfTradeBehaviorModeType] = selfTradeBehaviorMode;
        }

        if (attributes.SelfTradeEqualityMode is { } selfTradeEqualityMode)
        {
            map[SelfTradeEqualityModeType] = selfTradeEqualityMode;
        }

        if (map.Count == 0)
        {
            return null;
        }

        if (map.Count > ExchangeConstants.MaxAttributesPerTransaction)
        {
            throw new ArgumentException(
                "A transaction supports at most four L2 transaction attributes.",
                nameof(attributes));
        }

        foreach (var (attributeType, value) in map)
        {
            var (minValue, maxValue) = attributeType switch
            {
                IntegratorAccountIndexType => (0L, ExchangeConstants.MaxAccountIndex),
                IntegratorTakerFeeType or IntegratorMakerFeeType => (0L, ExchangeConstants.FeeTick),
                SkipNonceType => (1L, 1L),
                SelfTradeBehaviorModeType => (0L, 3L),
                SelfTradeEqualityModeType => (0L, 1L),
                _ => throw new ArgumentException("The attribute type is unknown.", nameof(attributes)),
            };
            if (value < minValue || value > maxValue)
            {
                throw new ArgumentOutOfRangeException(
                    nameof(attributes),
                    $"The L2 transaction attribute {attributeType} value {value} is out of range.");
            }
        }

        // Every exposed attribute has a nil value of zero, so "set to a real value" means non-zero.
        var hasIntegratorFees = HasRealValue(map, IntegratorTakerFeeType) || HasRealValue(map, IntegratorMakerFeeType);
        if (hasIntegratorFees && !HasRealValue(map, IntegratorAccountIndexType))
        {
            throw new ArgumentException(
                "Integrator fees require an integrator account index.",
                nameof(attributes));
        }

        var hasSelfTradeSpecification = HasRealValue(map, SelfTradeBehaviorModeType) || HasRealValue(map, SelfTradeEqualityModeType);
        if (hasSelfTradeSpecification && hasIntegratorFees)
        {
            throw new ArgumentException(
                "Self-trade attributes cannot be combined with integrator fees.",
                nameof(attributes));
        }

        if (map.GetValueOrDefault(SelfTradeBehaviorModeType) == (byte)SelfTradeBehavior.Reduce &&
            map.GetValueOrDefault(SelfTradeEqualityModeType) == (byte)SelfTradeEquality.MasterAccountIndex)
        {
            throw new ArgumentException(
                "The reduce self-trade behavior cannot be combined with master-account-index equality.",
                nameof(attributes));
        }

        return map;
    }

    internal static Fp5 AggregateTransactionHash(Fp5 transactionHash, SortedDictionary<byte, long>? attributes)
    {
        if (attributes is null)
        {
            return transactionHash;
        }

        // Real-valued attributes fill (type, value) pairs in ascending type order; the remaining
        // slots stay (0, 0). Nil-valued entries participate in JSON but never in the hash.
        var elements = new Goldilocks[2 * ExchangeConstants.MaxAttributesPerTransaction];
        var slot = 0;
        foreach (var (attributeType, value) in attributes)
        {
            if (value == 0)
            {
                continue;
            }

            elements[2 * slot] = new Goldilocks(attributeType);
            elements[(2 * slot) + 1] = Goldilocks.FromSigned(value);
            slot++;
        }

        if (slot == 0)
        {
            return transactionHash;
        }

        var attributesHash = Poseidon2.HashToFp5(elements);
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

    private static bool HasRealValue(SortedDictionary<byte, long> map, byte attributeType) =>
        map.GetValueOrDefault(attributeType) != 0;
}
