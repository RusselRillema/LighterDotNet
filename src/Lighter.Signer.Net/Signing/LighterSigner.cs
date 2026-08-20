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

    /// <summary>Creates a signer bound to one account and api key.</summary>
    /// <param name="privateKeyHex">The 40-byte api-key private key as 80 hexadecimal characters.</param>
    /// <param name="accountIndex">The Lighter account index; must be positive.</param>
    /// <param name="apiKeyIndex">The api-key slot, 0-254.</param>
    /// <param name="chainId">304 for mainnet, 300 for testnet.</param>
    /// <param name="timeProvider">Clock override for testing; defaults to the system clock.</param>
    public LighterSigner(
        string privateKeyHex,
        long accountIndex,
        byte apiKeyIndex,
        uint chainId,
        TimeProvider? timeProvider = null)
    {
        if (accountIndex <= 0 || accountIndex > ExchangeConstants.MaxAccountIndex)
            throw new ArgumentOutOfRangeException(nameof(accountIndex), "Account index must be between 1 and 2^48 - 2.");

        // 255 is the nil api-key sentinel, which the exchange refuses to sign for.
        if (apiKeyIndex > ExchangeConstants.MaxApiKeyIndex)
            throw new ArgumentOutOfRangeException(nameof(apiKeyIndex), "API key index must be at most 254.");

        _signer = new SchnorrSigner(privateKeyHex);
        _accountIndex = accountIndex;
        _apiKeyIndex = apiKeyIndex;
        _chainId = chainId;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public string PublicKeyHex => Convert.ToHexString(_signer.PublicKey.ToLittleEndianBytes()).ToLowerInvariant();

    /// <summary>
    /// How far in the future signed transactions expire. Defaults to ten minutes less a second.
    /// Set before sharing the signer across threads; mutation is not synchronized with signing.
    /// </summary>
    public TimeSpan TransactionExpiry
    {
        get => _transactionExpiry;
        set
        {
            if (value <= TimeSpan.Zero || value.TotalMilliseconds > ExchangeConstants.MaxTimestampMilliseconds)
                throw new ArgumentOutOfRangeException(nameof(value), "The transaction expiry must be positive and at most 2^48 - 1 milliseconds.");

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
                throw new InvalidOperationException("The auth message cannot be represented canonically.");

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
            order = order with { OrderExpiry = _timeProvider.GetUtcNow().AddDays(28).ToUnixTimeMilliseconds() };

        ValidateCreateOrder(order, nonce);
        SortedDictionary<byte, long>? attributeMap = L2TxAttributeEncoder.ToValidatedMap(attributes);
        long expiredAt = GetTransactionExpiryMilliseconds();
        Fp5 hash = ComputeTransactionHash(
            CreateOrderTransactionType,
            nonce,
            expiredAt,
            attributeMap,
            [
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
            ]);
        CreateOrderPayload payload = new CreateOrderPayload
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
            Sig = _signer.Sign(hash).ToBytes(),
            Attributes = attributeMap,
        };
        return ToSignedTransaction(CreateOrderTransactionType, payload, hash);
    }

    public SignedTransaction SignCancelOrder(short marketIndex, long exchangeOrderIndex, long nonce, L2TxAttributes? attributes = null)
    {
        ValidateCancelOrder(marketIndex, exchangeOrderIndex, nonce);
        var attributeMap = L2TxAttributeEncoder.ToValidatedMap(attributes);
        var expiredAt = GetTransactionExpiryMilliseconds();
        var hash = ComputeTransactionHash(
            CancelOrderTransactionType,
            nonce,
            expiredAt,
            attributeMap,
            [
                Goldilocks.FromSigned(marketIndex),
                Goldilocks.FromSigned(exchangeOrderIndex),
            ]);
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
        return ToSignedTransaction(CancelOrderTransactionType, payload, hash);
    }

    public SignedTransaction SignModifyOrder(ModifyOrderRequest modify, long nonce, L2TxAttributes? attributes = null)
    {
        ArgumentNullException.ThrowIfNull(modify);
        ValidateModifyOrder(modify, nonce);
        var attributeMap = L2TxAttributeEncoder.ToValidatedMap(attributes);
        var expiredAt = GetTransactionExpiryMilliseconds();
        var hash = ComputeTransactionHash(
            ModifyOrderTransactionType,
            nonce,
            expiredAt,
            attributeMap,
            [
                Goldilocks.FromSigned(modify.MarketIndex),
                Goldilocks.FromSigned(modify.ExchangeOrderIndex),
                Goldilocks.FromSigned(modify.BaseAmount),
                new Goldilocks(modify.Price),
                new Goldilocks(modify.TriggerPrice),
            ]);
        var payload = new ModifyOrderPayload
        {
            AccountIndex = _accountIndex,
            ApiKeyIndex = _apiKeyIndex,
            MarketIndex = modify.MarketIndex,
            Index = modify.ExchangeOrderIndex,
            BaseAmount = modify.BaseAmount,
            Price = modify.Price,
            TriggerPrice = modify.TriggerPrice,
            ExpiredAt = expiredAt,
            Nonce = nonce,
            Sig = _signer.Sign(hash).ToBytes(),
            Attributes = attributeMap,
        };
        return ToSignedTransaction(ModifyOrderTransactionType, payload, hash);
    }

    public SignedTransaction SignUpdateLeverage(
        short marketIndex,
        ushort initialMarginFraction,
        byte marginMode,
        long nonce,
        L2TxAttributes? attributes = null)
    {
        ValidateUpdateLeverage(marketIndex, initialMarginFraction, marginMode, nonce);
        var attributeMap = L2TxAttributeEncoder.ToValidatedMap(attributes);
        var expiredAt = GetTransactionExpiryMilliseconds();
        var hash = ComputeTransactionHash(
            UpdateLeverageTransactionType,
            nonce,
            expiredAt,
            attributeMap,
            [
                Goldilocks.FromSigned(marketIndex),
                new Goldilocks(initialMarginFraction),
                new Goldilocks(marginMode),
            ]);
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
        return ToSignedTransaction(UpdateLeverageTransactionType, payload, hash);
    }

    public SignedTransaction SignApproveIntegrator(ApproveIntegratorRequest approval, long nonce, L2TxAttributes? attributes = null)
    {
        ArgumentNullException.ThrowIfNull(approval);
        ValidateApproveIntegrator(approval, nonce);
        var attributeMap = L2TxAttributeEncoder.ToValidatedMap(attributes);
        var expiredAt = GetTransactionExpiryMilliseconds();
        var hash = ComputeTransactionHash(
            ApproveIntegratorTransactionType,
            nonce,
            expiredAt,
            attributeMap,
            [
                Goldilocks.FromSigned(approval.IntegratorAccountIndex),
                new Goldilocks(approval.MaxPerpsTakerFee),
                new Goldilocks(approval.MaxPerpsMakerFee),
                new Goldilocks(approval.MaxSpotTakerFee),
                new Goldilocks(approval.MaxSpotMakerFee),
                Goldilocks.FromSigned(approval.ApprovalExpiry),
            ]);
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
        return ToSignedTransaction(
            ApproveIntegratorTransactionType,
            payload,
            hash,
            BuildApproveIntegratorL1SignatureBody(approval, nonce));
    }

    public SignedTransaction SignTransfer(TransferRequest transfer, long nonce, L2TxAttributes? attributes = null)
    {
        ArgumentNullException.ThrowIfNull(transfer);
        ValidateTransfer(transfer, nonce);
        var memo = DecodeTransferMemo(transfer.Memo);

        var attributeMap = L2TxAttributeEncoder.ToValidatedMap(attributes);
        var expiredAt = GetTransactionExpiryMilliseconds();
        var amount = (ulong)transfer.Amount;
        var fee = (ulong)transfer.UsdcFee;
        var hash = ComputeTransactionHash(
            TransferTransactionType,
            nonce,
            expiredAt,
            attributeMap,
            [
                Goldilocks.FromSigned(transfer.ToAccountIndex),
                Goldilocks.FromSigned(transfer.AssetIndex),
                new Goldilocks(transfer.FromRouteType),
                new Goldilocks(transfer.ToRouteType),
                new Goldilocks(amount & uint.MaxValue),
                new Goldilocks(amount >> 32),
                new Goldilocks(fee & uint.MaxValue),
                new Goldilocks(fee >> 32),
            ]);
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
            Memo = memo.Select(value => (int)value).ToArray(),
            ExpiredAt = expiredAt,
            Nonce = nonce,
            Sig = _signer.Sign(hash).ToBytes(),
            Attributes = attributeMap,
        };
        return ToSignedTransaction(TransferTransactionType, payload, hash);
    }

    private long GetTransactionExpiryMilliseconds()
    {
        var now = _timeProvider.GetUtcNow();
        if (_transactionExpiry > DateTimeOffset.MaxValue - now)
        {
            throw new InvalidOperationException("The transaction expiry extends beyond the representable time range.");
        }

        var expiredAt = now.Add(_transactionExpiry).ToUnixTimeMilliseconds();

        // DateTimeOffset.MaxValue (year 9999) is below the 2^48 - 1 ms protocol cap, so only a
        // pre-epoch clock can produce an out-of-range timestamp here.
        if (expiredAt < 0)
        {
            throw new InvalidOperationException("The computed transaction expiry timestamp is out of range.");
        }

        return expiredAt;
    }

    /// <summary>
    /// Hashes the six-element framing shared by every transaction type, the transaction-specific
    /// elements, and finally the aggregated attribute hash, mirroring the Go signer.
    /// </summary>
    private Fp5 ComputeTransactionHash(
        byte transactionType,
        long nonce,
        long expiredAt,
        SortedDictionary<byte, long>? attributeMap,
        ReadOnlySpan<Goldilocks> transactionElements)
    {
        var elements = new Goldilocks[6 + transactionElements.Length];
        elements[0] = new Goldilocks(_chainId);
        elements[1] = new Goldilocks(transactionType);
        elements[2] = Goldilocks.FromSigned(nonce);
        elements[3] = Goldilocks.FromSigned(expiredAt);
        elements[4] = Goldilocks.FromSigned(_accountIndex);
        elements[5] = new Goldilocks(_apiKeyIndex);
        transactionElements.CopyTo(elements.AsSpan(6));
        return L2TxAttributeEncoder.AggregateTransactionHash(Poseidon2.HashToFp5(elements), attributeMap);
    }

    private static SignedTransaction ToSignedTransaction<TPayload>(
        byte transactionType,
        TPayload payload,
        Fp5 hash,
        string? l1SignatureBody = null) =>
        new(
            transactionType,
            JsonSerializer.Serialize(payload, JsonOptions),
            Convert.ToHexString(hash.ToLittleEndianBytes()).ToLowerInvariant(),
            l1SignatureBody);

    /// <summary>
    /// The memo travels as exactly 32 bytes; matching the Go signer, the string form must be
    /// 32 raw characters or 32 hex-encoded bytes (64 characters, optionally 0x-prefixed).
    /// </summary>
    private static byte[] DecodeTransferMemo(string memo)
    {
        var value = memo;
        if (value.Length == 66)
        {
            if (!value.StartsWith("0x", StringComparison.Ordinal))
            {
                throw new ArgumentException(
                    "A 66-character memo must be 0x-prefixed hex.",
                    nameof(memo));
            }

            value = value[2..];
        }

        if (value.Length == 64)
        {
            try
            {
                return Convert.FromHexString(value);
            }
            catch (FormatException exception)
            {
                throw new ArgumentException("The memo hex encoding is invalid.", nameof(memo), exception);
            }
        }

        var bytes = Encoding.UTF8.GetBytes(value);
        if (bytes.Length != 32)
        {
            throw new ArgumentException(
                "The memo must be exactly 32 bytes, or 32 bytes hex-encoded (64 characters, optionally 0x-prefixed).",
                nameof(memo));
        }

        return bytes;
    }

    // Mirrors the Go signer's GetL1SignatureBody template: every value rendered as
    // "0x" + 16 zero-padded lowercase hex characters, negatives via two's complement.
    private string BuildApproveIntegratorL1SignatureBody(ApproveIntegratorRequest approval, long nonce) =>
        "Approve Integrator\n\n" +
        $"nonce: {ToHex16(unchecked((ulong)nonce))}\n" +
        $"account index: {ToHex16(unchecked((ulong)_accountIndex))}\n" +
        $"api key index: {ToHex16(_apiKeyIndex)}\n" +
        $"integrator account index: {ToHex16(unchecked((ulong)approval.IntegratorAccountIndex))}\n" +
        $"max perps taker fee: {ToHex16(approval.MaxPerpsTakerFee)}\n" +
        $"max perps maker fee: {ToHex16(approval.MaxPerpsMakerFee)}\n" +
        $"max spot taker fee: {ToHex16(approval.MaxSpotTakerFee)}\n" +
        $"max spot maker fee: {ToHex16(approval.MaxSpotMakerFee)}\n" +
        $"approval expiry: {ToHex16(unchecked((ulong)approval.ApprovalExpiry))}\n" +
        $"chainId: {ToHex16(_chainId)}\n" +
        "Only sign this message for a trusted client!";

    private static string ToHex16(ulong value) => string.Create(
        System.Globalization.CultureInfo.InvariantCulture,
        $"0x{value:x16}");

    private static bool IsPerpetualMarket(short marketIndex) =>
        marketIndex is >= ExchangeConstants.MinPerpetualMarketIndex and <= ExchangeConstants.MaxPerpetualMarketIndex;

    private static bool IsSpotMarket(short marketIndex) =>
        marketIndex is >= ExchangeConstants.MinSpotMarketIndex and <= ExchangeConstants.MaxSpotMarketIndex;

    private static void ValidateMarketIndex(short marketIndex, string paramName)
    {
        if (!IsPerpetualMarket(marketIndex) && !IsSpotMarket(marketIndex))
        {
            throw new ArgumentOutOfRangeException(paramName, "Market index must be 0-254 (perpetual) or 2048-4094 (spot).");
        }
    }

    private static void ValidateExchangeOrderIndex(long exchangeOrderIndex, string paramName)
    {
        // Accepts client order indices too, so the lower bound is MinClientOrderIndex.
        if (exchangeOrderIndex is < ExchangeConstants.MinClientOrderIndex or > ExchangeConstants.MaxOrderIndex)
        {
            throw new ArgumentOutOfRangeException(paramName, "Order index must be between 1 and 2^60 - 1.");
        }
    }

    private static void ValidateNonce(long nonce)
    {
        if (nonce < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(nonce), "The nonce must be non-negative.");
        }
    }

    private static void ValidateCreateOrder(OrderRequest order, long nonce)
    {
        ValidateMarketIndex(order.MarketIndex, nameof(order));
        var isPerpetualMarket = IsPerpetualMarket(order.MarketIndex);
        var isSpotMarket = IsSpotMarket(order.MarketIndex);

        // Zero is the nil client order index and lets the exchange assign one.
        if (order.ClientOrderIndex is < ExchangeConstants.NilClientOrderIndex or > ExchangeConstants.MaxClientOrderIndex)
        {
            throw new ArgumentOutOfRangeException(nameof(order), "Client order index must be 0 (exchange-assigned) or at most 2^48 - 1.");
        }

        if (!order.ReduceOnly && order.BaseAmount == 0)
        {
            throw new ArgumentOutOfRangeException(nameof(order), "Base amount is required for orders that are not reduce-only.");
        }

        if (order.BaseAmount is < 0 or > ExchangeConstants.MaxOrderBaseAmount)
        {
            throw new ArgumentOutOfRangeException(nameof(order), "Base amount must be non-negative and at most 2^48 - 1.");
        }

        // The upper price and trigger-price bounds (2^32 - 1) are implicit in the uint fields.
        if (order.Price < ExchangeConstants.MinOrderPrice)
        {
            throw new ArgumentOutOfRangeException(nameof(order), "Price must be at least 1.");
        }

        if (order.TimeInForce > (byte)OrderTimeInForce.PostOnly)
        {
            throw new ArgumentOutOfRangeException(nameof(order), "Time in force must be 0 (IOC), 1 (GTT), or 2 (post-only).");
        }

        if (order.ReduceOnly && isSpotMarket)
        {
            throw new ArgumentException("Reduce-only orders are not supported on spot markets.", nameof(order));
        }

        // Zero is the nil order expiry; a -1 request was already replaced with the 28-day default.
        if (order.OrderExpiry < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(order), "Order expiry must be 0 (none) or a positive timestamp.");
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
                throw new ArgumentException("Order type must be 0-6.", nameof(order));
        }

        ValidateNonce(nonce);
    }

    private static void ValidateCancelOrder(short marketIndex, long exchangeOrderIndex, long nonce)
    {
        ValidateMarketIndex(marketIndex, nameof(marketIndex));
        ValidateExchangeOrderIndex(exchangeOrderIndex, nameof(exchangeOrderIndex));
        ValidateNonce(nonce);
    }

    private static void ValidateModifyOrder(ModifyOrderRequest modify, long nonce)
    {
        ValidateMarketIndex(modify.MarketIndex, nameof(modify));
        ValidateExchangeOrderIndex(modify.ExchangeOrderIndex, nameof(modify));

        // Zero keeps the current base amount.
        if (modify.BaseAmount is < 0 or > ExchangeConstants.MaxOrderBaseAmount)
        {
            throw new ArgumentOutOfRangeException(nameof(modify), "Base amount must be non-negative and at most 2^48 - 1.");
        }

        // The upper price and trigger-price bounds (2^32 - 1) are implicit in the uint fields.
        if (modify.Price < ExchangeConstants.MinOrderPrice)
        {
            throw new ArgumentOutOfRangeException(nameof(modify), "Price must be at least 1.");
        }

        ValidateNonce(nonce);
    }

    private static void ValidateUpdateLeverage(short marketIndex, ushort initialMarginFraction, byte marginMode, long nonce)
    {
        // Matching Go, update-leverage only rejects the nil market sentinel (255); any other
        // index, including negative ones, is signable (pinned by a known-answer vector).
        if (marketIndex == ExchangeConstants.NilMarketIndex)
        {
            throw new ArgumentOutOfRangeException(nameof(marketIndex), "Market index 255 is the nil sentinel and cannot be used.");
        }

        if (marginMode > (byte)MarginMode.Isolated)
        {
            throw new ArgumentOutOfRangeException(nameof(marginMode), "Margin mode must be cross (0) or isolated (1).");
        }

        if (initialMarginFraction is 0 or > ExchangeConstants.MarginFractionTick)
        {
            throw new ArgumentOutOfRangeException(
                nameof(initialMarginFraction),
                "The initial margin fraction must be between 1 and 10000.");
        }

        ValidateNonce(nonce);
    }

    private static void ValidateApproveIntegrator(ApproveIntegratorRequest approval, long nonce)
    {
        if (approval.IntegratorAccountIndex is < ExchangeConstants.MinAccountIndex or > ExchangeConstants.MaxAccountIndex)
        {
            throw new ArgumentOutOfRangeException(nameof(approval), "Integrator account index must be between -1 and 2^48 - 2.");
        }

        if (approval.MaxPerpsTakerFee > ExchangeConstants.FeeTick ||
            approval.MaxPerpsMakerFee > ExchangeConstants.FeeTick ||
            approval.MaxSpotTakerFee > ExchangeConstants.FeeTick ||
            approval.MaxSpotMakerFee > ExchangeConstants.FeeTick)
        {
            throw new ArgumentOutOfRangeException(nameof(approval), "Integrator fees cannot exceed the fee tick (1,000,000).");
        }

        // A zero approval expiry revokes the approval, which only makes sense with zero fees.
        if (approval.ApprovalExpiry == 0 &&
            (approval.MaxPerpsTakerFee != 0 || approval.MaxPerpsMakerFee != 0 ||
             approval.MaxSpotTakerFee != 0 || approval.MaxSpotMakerFee != 0))
        {
            throw new ArgumentException("A revocation (zero approval expiry) requires all fees to be zero.", nameof(approval));
        }

        if (approval.ApprovalExpiry is < 0 or > ExchangeConstants.MaxTimestampMilliseconds)
        {
            throw new ArgumentOutOfRangeException(nameof(approval), "Approval expiry must be between 0 and 2^48 - 1.");
        }

        ValidateNonce(nonce);
    }

    private static void ValidateTransfer(TransferRequest transfer, long nonce)
    {
        // Matching Go, -1 and 0 (the treasury account) are valid transfer destinations.
        if (transfer.ToAccountIndex is < ExchangeConstants.MinAccountIndex or > ExchangeConstants.MaxAccountIndex)
        {
            throw new ArgumentOutOfRangeException(nameof(transfer), "Destination account index must be between -1 and 2^48 - 2.");
        }

        if (transfer.AssetIndex is < ExchangeConstants.MinAssetIndex or > ExchangeConstants.MaxAssetIndex)
        {
            throw new ArgumentOutOfRangeException(nameof(transfer), "Asset index must be between 1 and 62.");
        }

        if (transfer.FromRouteType > 1 || transfer.ToRouteType > 1)
        {
            throw new ArgumentOutOfRangeException(nameof(transfer), "Route types must be 0 (perps) or 1 (spot).");
        }

        if (transfer.Amount is <= 0 or > ExchangeConstants.MaxTransferAmount)
        {
            throw new ArgumentOutOfRangeException(nameof(transfer), "The transfer amount must be between 1 and 2^60 - 1.");
        }

        if (transfer.UsdcFee is < 0 or > ExchangeConstants.MaxTransferAmount)
        {
            throw new ArgumentOutOfRangeException(nameof(transfer), "The transfer fee must be between 0 and 2^60 - 1.");
        }

        if (transfer.Memo is null)
        {
            throw new ArgumentException("The transfer memo is required.", nameof(transfer));
        }

        ValidateNonce(nonce);
    }
}
