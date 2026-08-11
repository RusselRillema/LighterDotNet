using System.Buffers.Binary;
using System.Text;
using System.Text.Json;
using Lighter.Signer.Cryptography;
using Lighter.Signer.Transactions;

namespace Lighter.Signer;

public sealed class LighterSigner
{
    public const byte TransferTransactionType = 12;
    public const byte CreateOrderTransactionType = 14;
    public const byte CancelOrderTransactionType = 15;
    public const byte ModifyOrderTransactionType = 17;
    public const byte UpdateLeverageTransactionType = 20;
    public const byte ApproveIntegratorTransactionType = 45;

    /// <summary>Passing this as <see cref="OrderRequest.OrderExpiry"/> selects a 28-day expiry.</summary>
    public const long Default28DayOrderExpiry = -1;

    public static readonly TimeSpan DefaultTransactionExpiry = TimeSpan.FromMinutes(10) - TimeSpan.FromSeconds(1);

    private const long MaxTimestampMilliseconds = (1L << 48) - 1;
    private const long MaxClientOrderIndex = (1L << 48) - 1;
    private const long MaxOrderBaseAmount = (1L << 48) - 1;
    private const long MaxOrderIndex = (1L << 60) - 1;
    private const long MinAccountIndex = -1;
    private const long MaxAccountIndex = 281_474_976_710_654;
    private const long MaxIntegratorFee = 1_000_000;
    private const ushort MarginFractionTick = 10_000;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = null,
        WriteIndented = false,
    };

    private readonly long _accountIndex;
    private readonly byte _apiKeyIndex;
    private readonly uint _chainId;
    private readonly SchnorrSigner _signer;
    private readonly TimeProvider _timeProvider;
    private TimeSpan _transactionExpiry = DefaultTransactionExpiry;

    public LighterSigner(
        string privateKeyHex,
        long accountIndex,
        byte apiKeyIndex,
        uint chainId,
        TimeProvider? timeProvider = null)
    {
        if (accountIndex <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(accountIndex), "Account index must be positive.");
        }

        // 255 is the nil api-key sentinel, which the exchange refuses to sign for.
        if (apiKeyIndex == 255)
        {
            throw new ArgumentOutOfRangeException(nameof(apiKeyIndex), "API key index must be at most 254.");
        }

        _signer = new SchnorrSigner(privateKeyHex);
        _accountIndex = accountIndex;
        _apiKeyIndex = apiKeyIndex;
        _chainId = chainId;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public string PublicKeyHex => Convert.ToHexString(_signer.PublicKey.ToLittleEndianBytes()).ToLowerInvariant();

    /// <summary>How far in the future signed transactions expire. Defaults to ten minutes less a second.</summary>
    public TimeSpan TransactionExpiry
    {
        get => _transactionExpiry;
        set
        {
            if (value <= TimeSpan.Zero)
            {
                throw new ArgumentOutOfRangeException(nameof(value), "The transaction expiry must be positive.");
            }

            _transactionExpiry = value;
        }
    }

    public string CreateAuthToken(DateTimeOffset deadline)
    {
        var message = string.Create(
            System.Globalization.CultureInfo.InvariantCulture,
            $"{deadline.ToUnixTimeSeconds()}:{_accountIndex}:{_apiKeyIndex}");
        var messageBytes = Encoding.ASCII.GetBytes(message);
        var elements = new Goldilocks[(messageBytes.Length + 7) / 8];
        Span<byte> chunk = stackalloc byte[8];
        for (var index = 0; index < elements.Length; index++)
        {
            chunk.Clear();
            var source = messageBytes.AsSpan(index * 8, Math.Min(8, messageBytes.Length - (index * 8)));
            source.CopyTo(chunk);
            var value = BinaryPrimitives.ReadUInt64LittleEndian(chunk);
            if (value >= Goldilocks.Modulus)
            {
                throw new InvalidOperationException("The auth message cannot be represented canonically.");
            }

            elements[index] = new Goldilocks(value);
        }

        var messageHash = Poseidon2.HashToFp5(elements);
        var signature = _signer.Sign(messageHash).ToBytes();
        return string.Create(
            System.Globalization.CultureInfo.InvariantCulture,
            $"{message}:{Convert.ToHexString(signature).ToLowerInvariant()}");
    }

    public SignedTransaction SignCreateOrder(OrderRequest order, long nonce, L2TxAttributes? attributes = null)
    {
        ArgumentNullException.ThrowIfNull(order);
        if (order.OrderExpiry == Default28DayOrderExpiry)
        {
            order = order with { OrderExpiry = _timeProvider.GetUtcNow().AddDays(28).ToUnixTimeMilliseconds() };
        }

        ValidateCreateOrder(order, nonce);
        var attributeMap = L2TxAttributeCodec.ToValidatedMap(attributes);
        var expiredAt = GetTransactionExpiryMilliseconds();
        var hash = L2TxAttributeCodec.AggregateTransactionHash(
            Poseidon2.HashToFp5(
            [
                new Goldilocks(_chainId),
                new Goldilocks(CreateOrderTransactionType),
                Goldilocks.FromSigned(nonce),
                Goldilocks.FromSigned(expiredAt),
                Goldilocks.FromSigned(_accountIndex),
                new Goldilocks(_apiKeyIndex),
                Goldilocks.FromSigned(order.MarketIndex),
                Goldilocks.FromSigned(order.ClientOrderIndex),
                Goldilocks.FromSigned(order.BaseAmount),
                new Goldilocks(order.Price),
                new Goldilocks(order.IsAsk ? 1UL : 0UL),
                new Goldilocks(order.Type),
                new Goldilocks(order.TimeInForce),
                new Goldilocks(order.ReduceOnly ? 1UL : 0UL),
                new Goldilocks(order.TriggerPrice),
                Goldilocks.FromSigned(order.OrderExpiry),
            ]),
            attributeMap);
        var signature = _signer.Sign(hash).ToBytes();
        var payload = new CreateOrderPayload
        {
            AccountIndex = _accountIndex,
            ApiKeyIndex = _apiKeyIndex,
            MarketIndex = order.MarketIndex,
            ClientOrderIndex = order.ClientOrderIndex,
            BaseAmount = order.BaseAmount,
            Price = order.Price,
            IsAsk = order.IsAsk ? (byte)1 : (byte)0,
            Type = order.Type,
            TimeInForce = order.TimeInForce,
            ReduceOnly = order.ReduceOnly ? (byte)1 : (byte)0,
            TriggerPrice = order.TriggerPrice,
            OrderExpiry = order.OrderExpiry,
            ExpiredAt = expiredAt,
            Nonce = nonce,
            Sig = signature,
            Attributes = attributeMap,
        };
        return new SignedTransaction(
            CreateOrderTransactionType,
            JsonSerializer.Serialize(payload, JsonOptions),
            Convert.ToHexString(hash.ToLittleEndianBytes()).ToLowerInvariant());
    }

    public SignedTransaction SignCancelOrder(short marketIndex, long exchangeOrderIndex, long nonce, L2TxAttributes? attributes = null)
    {
        if (!IsPerpetualMarket(marketIndex) && !IsSpotMarket(marketIndex))
        {
            throw new ArgumentOutOfRangeException(nameof(marketIndex), "Market index is invalid.");
        }

        if (exchangeOrderIndex is < 1 or > MaxOrderIndex)
        {
            throw new ArgumentOutOfRangeException(nameof(exchangeOrderIndex), "Order index is invalid.");
        }

        if (nonce < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(nonce));
        }

        var attributeMap = L2TxAttributeCodec.ToValidatedMap(attributes);
        var expiredAt = GetTransactionExpiryMilliseconds();
        var hash = L2TxAttributeCodec.AggregateTransactionHash(
            Poseidon2.HashToFp5(
            [
                new Goldilocks(_chainId),
                new Goldilocks(CancelOrderTransactionType),
                Goldilocks.FromSigned(nonce),
                Goldilocks.FromSigned(expiredAt),
                Goldilocks.FromSigned(_accountIndex),
                new Goldilocks(_apiKeyIndex),
                Goldilocks.FromSigned(marketIndex),
                Goldilocks.FromSigned(exchangeOrderIndex),
            ]),
            attributeMap);
        var payload = new CancelOrderPayload
        {
            AccountIndex = _accountIndex,
            ApiKeyIndex = _apiKeyIndex,
            MarketIndex = marketIndex,
            Index = exchangeOrderIndex,
            ExpiredAt = expiredAt,
            Nonce = nonce,
            Sig = _signer.Sign(hash).ToBytes(),
            Attributes = attributeMap,
        };
        return new SignedTransaction(
            CancelOrderTransactionType,
            JsonSerializer.Serialize(payload, JsonOptions),
            Convert.ToHexString(hash.ToLittleEndianBytes()).ToLowerInvariant());
    }

    public SignedTransaction SignModifyOrder(ModifyOrderRequest modify, long nonce, L2TxAttributes? attributes = null)
    {
        ArgumentNullException.ThrowIfNull(modify);
        ValidateModifyOrder(modify, nonce);
        var attributeMap = L2TxAttributeCodec.ToValidatedMap(attributes);
        var expiredAt = GetTransactionExpiryMilliseconds();
        var hash = L2TxAttributeCodec.AggregateTransactionHash(
            Poseidon2.HashToFp5(
            [
                new Goldilocks(_chainId),
                new Goldilocks(ModifyOrderTransactionType),
                Goldilocks.FromSigned(nonce),
                Goldilocks.FromSigned(expiredAt),
                Goldilocks.FromSigned(_accountIndex),
                new Goldilocks(_apiKeyIndex),
                Goldilocks.FromSigned(modify.MarketIndex),
                Goldilocks.FromSigned(modify.Index),
                Goldilocks.FromSigned(modify.BaseAmount),
                new Goldilocks(modify.Price),
                new Goldilocks(modify.TriggerPrice),
            ]),
            attributeMap);
        var payload = new ModifyOrderPayload
        {
            AccountIndex = _accountIndex,
            ApiKeyIndex = _apiKeyIndex,
            MarketIndex = modify.MarketIndex,
            Index = modify.Index,
            BaseAmount = modify.BaseAmount,
            Price = modify.Price,
            TriggerPrice = modify.TriggerPrice,
            ExpiredAt = expiredAt,
            Nonce = nonce,
            Sig = _signer.Sign(hash).ToBytes(),
            Attributes = attributeMap,
        };
        return new SignedTransaction(
            ModifyOrderTransactionType,
            JsonSerializer.Serialize(payload, JsonOptions),
            Convert.ToHexString(hash.ToLittleEndianBytes()).ToLowerInvariant());
    }

    public SignedTransaction SignUpdateLeverage(
        short marketIndex,
        ushort initialMarginFraction,
        byte marginMode,
        long nonce,
        L2TxAttributes? attributes = null)
    {
        ValidateUpdateLeverage(marketIndex, initialMarginFraction, marginMode, nonce);
        var attributeMap = L2TxAttributeCodec.ToValidatedMap(attributes);
        var expiredAt = GetTransactionExpiryMilliseconds();
        var hash = L2TxAttributeCodec.AggregateTransactionHash(
            Poseidon2.HashToFp5(
            [
                new Goldilocks(_chainId),
                new Goldilocks(UpdateLeverageTransactionType),
                Goldilocks.FromSigned(nonce),
                Goldilocks.FromSigned(expiredAt),
                Goldilocks.FromSigned(_accountIndex),
                new Goldilocks(_apiKeyIndex),
                Goldilocks.FromSigned(marketIndex),
                new Goldilocks(initialMarginFraction),
                new Goldilocks(marginMode),
            ]),
            attributeMap);
        var payload = new UpdateLeveragePayload
        {
            AccountIndex = _accountIndex,
            ApiKeyIndex = _apiKeyIndex,
            MarketIndex = marketIndex,
            InitialMarginFraction = initialMarginFraction,
            MarginMode = marginMode,
            ExpiredAt = expiredAt,
            Nonce = nonce,
            Sig = _signer.Sign(hash).ToBytes(),
            Attributes = attributeMap,
        };
        return new SignedTransaction(
            UpdateLeverageTransactionType,
            JsonSerializer.Serialize(payload, JsonOptions),
            Convert.ToHexString(hash.ToLittleEndianBytes()).ToLowerInvariant());
    }

    public SignedTransaction SignApproveIntegrator(ApproveIntegratorRequest approval, long nonce, L2TxAttributes? attributes = null)
    {
        ArgumentNullException.ThrowIfNull(approval);
        ValidateApproveIntegrator(approval, nonce);
        var attributeMap = L2TxAttributeCodec.ToValidatedMap(attributes);
        var expiredAt = GetTransactionExpiryMilliseconds();
        var hash = L2TxAttributeCodec.AggregateTransactionHash(
            Poseidon2.HashToFp5(
            [
                new Goldilocks(_chainId),
                new Goldilocks(ApproveIntegratorTransactionType),
                Goldilocks.FromSigned(nonce),
                Goldilocks.FromSigned(expiredAt),
                Goldilocks.FromSigned(_accountIndex),
                new Goldilocks(_apiKeyIndex),
                Goldilocks.FromSigned(approval.IntegratorAccountIndex),
                new Goldilocks(approval.MaxPerpsTakerFee),
                new Goldilocks(approval.MaxPerpsMakerFee),
                new Goldilocks(approval.MaxSpotTakerFee),
                new Goldilocks(approval.MaxSpotMakerFee),
                Goldilocks.FromSigned(approval.ApprovalExpiry),
            ]),
            attributeMap);
        var payload = new ApproveIntegratorPayload
        {
            AccountIndex = _accountIndex,
            ApiKeyIndex = _apiKeyIndex,
            IntegratorAccountIndex = approval.IntegratorAccountIndex,
            MaxPerpsTakerFee = approval.MaxPerpsTakerFee,
            MaxPerpsMakerFee = approval.MaxPerpsMakerFee,
            MaxSpotTakerFee = approval.MaxSpotTakerFee,
            MaxSpotMakerFee = approval.MaxSpotMakerFee,
            ApprovalExpiry = approval.ApprovalExpiry,
            ExpiredAt = expiredAt,
            Nonce = nonce,
            Sig = _signer.Sign(hash).ToBytes(),
            Attributes = attributeMap,
        };
        return new SignedTransaction(
            ApproveIntegratorTransactionType,
            JsonSerializer.Serialize(payload, JsonOptions),
            Convert.ToHexString(hash.ToLittleEndianBytes()).ToLowerInvariant());
    }

    public SignedTransaction SignTransfer(TransferRequest transfer, long nonce, L2TxAttributes? attributes = null)
    {
        ArgumentNullException.ThrowIfNull(transfer);
        ValidateTransfer(transfer, nonce);

        var attributeMap = L2TxAttributeCodec.ToValidatedMap(attributes);
        var expiredAt = GetTransactionExpiryMilliseconds();
        var amount = (ulong)transfer.Amount;
        var fee = (ulong)transfer.UsdcFee;
        var hash = L2TxAttributeCodec.AggregateTransactionHash(
            Poseidon2.HashToFp5(
            [
                new Goldilocks(_chainId),
                new Goldilocks(TransferTransactionType),
                Goldilocks.FromSigned(nonce),
                Goldilocks.FromSigned(expiredAt),
                Goldilocks.FromSigned(_accountIndex),
                new Goldilocks(_apiKeyIndex),
                Goldilocks.FromSigned(transfer.ToAccountIndex),
                Goldilocks.FromSigned(transfer.AssetIndex),
                new Goldilocks(transfer.FromRouteType),
                new Goldilocks(transfer.ToRouteType),
                new Goldilocks(amount & uint.MaxValue),
                new Goldilocks(amount >> 32),
                new Goldilocks(fee & uint.MaxValue),
                new Goldilocks(fee >> 32),
            ]),
            attributeMap);
        var payload = new TransferPayload
        {
            FromAccountIndex = _accountIndex,
            ApiKeyIndex = _apiKeyIndex,
            ToAccountIndex = transfer.ToAccountIndex,
            AssetIndex = transfer.AssetIndex,
            FromRouteType = transfer.FromRouteType,
            ToRouteType = transfer.ToRouteType,
            Amount = transfer.Amount,
            UsdcFee = transfer.UsdcFee,
            Memo = transfer.Memo.Select(value => (int)value).ToArray(),
            ExpiredAt = expiredAt,
            Nonce = nonce,
            Sig = _signer.Sign(hash).ToBytes(),
            Attributes = attributeMap,
        };
        return new SignedTransaction(
            TransferTransactionType,
            JsonSerializer.Serialize(payload, JsonOptions),
            Convert.ToHexString(hash.ToLittleEndianBytes()).ToLowerInvariant());
    }

    private long GetTransactionExpiryMilliseconds()
    {
        var expiredAt = _timeProvider.GetUtcNow().Add(_transactionExpiry).ToUnixTimeMilliseconds();
        if (expiredAt is < 0 or > MaxTimestampMilliseconds)
        {
            throw new InvalidOperationException("The computed transaction expiry timestamp is out of range.");
        }

        return expiredAt;
    }

    private static bool IsPerpetualMarket(short marketIndex) => marketIndex is >= 0 and <= 254;

    private static bool IsSpotMarket(short marketIndex) => marketIndex is >= 2048 and <= 4094;

    private static void ValidateCreateOrder(OrderRequest order, long nonce)
    {
        var isPerpetualMarket = IsPerpetualMarket(order.MarketIndex);
        var isSpotMarket = IsSpotMarket(order.MarketIndex);
        if (!isPerpetualMarket && !isSpotMarket)
        {
            throw new ArgumentOutOfRangeException(nameof(order), "Market index is invalid.");
        }

        // Zero is the nil client order index and lets the exchange assign one.
        if (order.ClientOrderIndex is < 0 or > MaxClientOrderIndex)
        {
            throw new ArgumentOutOfRangeException(nameof(order), "Client order index is invalid.");
        }

        if (!order.ReduceOnly && order.BaseAmount == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(order), "Base amount is required for orders that are not reduce-only.");
        }

        if (order.BaseAmount is < 0 or > MaxOrderBaseAmount)
        {
            throw new ArgumentOutOfRangeException(nameof(order), "Base amount is invalid.");
        }

        // The upper price and trigger-price bounds (2^32 - 1) are implicit in the uint fields.
        if (order.Price == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(order), "Price is invalid.");
        }

        if (order.TimeInForce > (byte)OrderTimeInForce.PostOnly)
        {
            throw new ArgumentException("The time in force is invalid.", nameof(order));
        }

        if (order.ReduceOnly && isSpotMarket)
        {
            throw new ArgumentException("Reduce-only orders are not supported on spot markets.", nameof(order));
        }

        // Zero is the nil order expiry; a -1 request was already replaced with the 28-day default.
        if (order.OrderExpiry < 0)
        {
            throw new ArgumentException("The order expiry is invalid.", nameof(order));
        }

        switch (order.Type)
        {
            case (byte)OrderType.Limit:
                if (order.TriggerPrice != 0)
                {
                    throw new ArgumentException("Limit orders cannot specify a trigger price.", nameof(order));
                }

                if (order.TimeInForce == (byte)OrderTimeInForce.ImmediateOrCancel
                    ? order.OrderExpiry != 0
                    : order.OrderExpiry == 0)
                {
                    throw new ArgumentException("The limit order expiry is inconsistent with its time in force.", nameof(order));
                }

                break;

            case (byte)OrderType.Market:
                if (order.TimeInForce != (byte)OrderTimeInForce.ImmediateOrCancel)
                {
                    throw new ArgumentException("Market orders must be immediate-or-cancel.", nameof(order));
                }

                if (order.OrderExpiry != 0)
                {
                    throw new ArgumentException("Market orders cannot specify an order expiry.", nameof(order));
                }

                if (order.TriggerPrice != 0)
                {
                    throw new ArgumentException("Market orders cannot specify a trigger price.", nameof(order));
                }

                break;

            case (byte)OrderType.StopLoss:
            case (byte)OrderType.TakeProfit:
                if (!isPerpetualMarket)
                {
                    throw new ArgumentException("Trigger orders are only supported on perpetual markets.", nameof(order));
                }

                if (order.TimeInForce != (byte)OrderTimeInForce.ImmediateOrCancel)
                {
                    throw new ArgumentException("Stop-loss and take-profit orders must be immediate-or-cancel.", nameof(order));
                }

                if (order.TriggerPrice == 0)
                {
                    throw new ArgumentException("Trigger orders require a trigger price.", nameof(order));
                }

                if (order.OrderExpiry == 0)
                {
                    throw new ArgumentException("Trigger orders require an order expiry.", nameof(order));
                }

                break;

            case (byte)OrderType.StopLossLimit:
            case (byte)OrderType.TakeProfitLimit:
                if (!isPerpetualMarket)
                {
                    throw new ArgumentException("Trigger orders are only supported on perpetual markets.", nameof(order));
                }

                if (order.TriggerPrice == 0)
                {
                    throw new ArgumentException("Trigger orders require a trigger price.", nameof(order));
                }

                if (order.OrderExpiry == 0)
                {
                    throw new ArgumentException("Trigger orders require an order expiry.", nameof(order));
                }

                break;

            case (byte)OrderType.Twap:
                if (order.TimeInForce != (byte)OrderTimeInForce.GoodTillTime)
                {
                    throw new ArgumentException("TWAP orders must be good-till-time.", nameof(order));
                }

                if (order.TriggerPrice != 0)
                {
                    throw new ArgumentException("TWAP orders cannot specify a trigger price.", nameof(order));
                }

                if (order.OrderExpiry == 0)
                {
                    throw new ArgumentException("TWAP orders require an order expiry.", nameof(order));
                }

                break;

            default:
                throw new ArgumentException("The order type is invalid.", nameof(order));
        }

        if (nonce < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(nonce), "The nonce must be non-negative.");
        }
    }

    private static void ValidateModifyOrder(ModifyOrderRequest modify, long nonce)
    {
        if (!IsPerpetualMarket(modify.MarketIndex) && !IsSpotMarket(modify.MarketIndex))
        {
            throw new ArgumentOutOfRangeException(nameof(modify), "Market index is invalid.");
        }

        if (modify.Index is < 1 or > MaxOrderIndex)
        {
            throw new ArgumentOutOfRangeException(nameof(modify), "Order index is invalid.");
        }

        // Zero keeps the current base amount.
        if (modify.BaseAmount is < 0 or > MaxOrderBaseAmount)
        {
            throw new ArgumentOutOfRangeException(nameof(modify), "Base amount is invalid.");
        }

        // The upper price and trigger-price bounds (2^32 - 1) are implicit in the uint fields.
        if (modify.Price == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(modify), "Price is invalid.");
        }

        if (nonce < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(nonce), "The nonce must be non-negative.");
        }
    }

    private static void ValidateUpdateLeverage(short marketIndex, ushort initialMarginFraction, byte marginMode, long nonce)
    {
        if (marketIndex == 255)
        {
            throw new ArgumentOutOfRangeException(nameof(marketIndex), "Market index is invalid.");
        }

        if (marginMode > (byte)Transactions.MarginMode.Isolated)
        {
            throw new ArgumentOutOfRangeException(nameof(marginMode), "Margin mode must be cross (0) or isolated (1).");
        }

        if (initialMarginFraction is 0 or > MarginFractionTick)
        {
            throw new ArgumentOutOfRangeException(
                nameof(initialMarginFraction),
                "The initial margin fraction must be between 1 and 10000.");
        }

        if (nonce < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(nonce), "The nonce must be non-negative.");
        }
    }

    private static void ValidateApproveIntegrator(ApproveIntegratorRequest approval, long nonce)
    {
        if (approval.IntegratorAccountIndex is < MinAccountIndex or > MaxAccountIndex)
        {
            throw new ArgumentOutOfRangeException(nameof(approval), "Integrator account index is invalid.");
        }

        if (approval.MaxPerpsTakerFee > MaxIntegratorFee ||
            approval.MaxPerpsMakerFee > MaxIntegratorFee ||
            approval.MaxSpotTakerFee > MaxIntegratorFee ||
            approval.MaxSpotMakerFee > MaxIntegratorFee)
        {
            throw new ArgumentOutOfRangeException(nameof(approval), "Integrator fees cannot exceed the fee tick.");
        }

        // A zero approval expiry revokes the approval, which only makes sense with zero fees.
        if (approval.ApprovalExpiry == 0 &&
            (approval.MaxPerpsTakerFee != 0 || approval.MaxPerpsMakerFee != 0 ||
             approval.MaxSpotTakerFee != 0 || approval.MaxSpotMakerFee != 0))
        {
            throw new ArgumentException("A revocation (zero approval expiry) requires all fees to be zero.", nameof(approval));
        }

        if (approval.ApprovalExpiry is < 0 or > MaxTimestampMilliseconds)
        {
            throw new ArgumentOutOfRangeException(nameof(approval), "The approval expiry is invalid.");
        }

        if (nonce < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(nonce), "The nonce must be non-negative.");
        }
    }

    private static void ValidateTransfer(TransferRequest transfer, long nonce)
    {
        if (transfer.ToAccountIndex <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(transfer), "Destination account index must be positive.");
        }

        if (transfer.AssetIndex < 0 || transfer.FromRouteType > 1 || transfer.ToRouteType > 1)
        {
            throw new ArgumentException("The transfer asset or route type is invalid.", nameof(transfer));
        }

        if (transfer.Amount <= 0 || transfer.UsdcFee < 0 || nonce < 0)
        {
            throw new ArgumentException("The transfer amount, fee, or nonce is invalid.", nameof(transfer));
        }

        if (transfer.Memo is null || transfer.Memo.Length != 32)
        {
            throw new ArgumentException("The transfer memo must contain exactly 32 bytes.", nameof(transfer));
        }
    }
}
