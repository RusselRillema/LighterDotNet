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

        _signer = new SchnorrSigner(privateKeyHex);
        _accountIndex = accountIndex;
        _apiKeyIndex = apiKeyIndex;
        _chainId = chainId;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public string PublicKeyHex => Convert.ToHexString(_signer.PublicKey.ToLittleEndianBytes()).ToLowerInvariant();

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

    public SignedTransaction SignCreateOrder(OrderRequest order, long nonce)
    {
        ValidateOrder(order, nonce);
        var expiredAt = GetTransactionExpiryMilliseconds();
        var hash = Poseidon2.HashToFp5(
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
        ]);
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
        };
        return new SignedTransaction(
            CreateOrderTransactionType,
            JsonSerializer.Serialize(payload, JsonOptions),
            Convert.ToHexString(hash.ToLittleEndianBytes()).ToLowerInvariant());
    }

    public SignedTransaction SignCancelOrder(short marketIndex, long exchangeOrderIndex, long nonce)
    {
        if (marketIndex is < 0 or > 254)
        {
            throw new ArgumentOutOfRangeException(nameof(marketIndex));
        }

        if (exchangeOrderIndex <= 0)
        {
            throw new ArgumentOutOfRangeException(nameof(exchangeOrderIndex));
        }

        if (nonce < 0)
        {
            throw new ArgumentOutOfRangeException(nameof(nonce));
        }

        var expiredAt = GetTransactionExpiryMilliseconds();
        var hash = Poseidon2.HashToFp5(
        [
            new Goldilocks(_chainId),
            new Goldilocks(CancelOrderTransactionType),
            Goldilocks.FromSigned(nonce),
            Goldilocks.FromSigned(expiredAt),
            Goldilocks.FromSigned(_accountIndex),
            new Goldilocks(_apiKeyIndex),
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
        };
        return new SignedTransaction(
            CancelOrderTransactionType,
            JsonSerializer.Serialize(payload, JsonOptions),
            Convert.ToHexString(hash.ToLittleEndianBytes()).ToLowerInvariant());
    }

    public SignedTransaction SignTransfer(TransferRequest transfer, long nonce)
    {
        ArgumentNullException.ThrowIfNull(transfer);
        ValidateTransfer(transfer, nonce);

        var expiredAt = GetTransactionExpiryMilliseconds();
        var amount = (ulong)transfer.Amount;
        var fee = (ulong)transfer.UsdcFee;
        var hash = Poseidon2.HashToFp5(
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
            Memo = transfer.Memo.Select(value => (int)value).ToArray(),
            ExpiredAt = expiredAt,
            Nonce = nonce,
            Sig = _signer.Sign(hash).ToBytes(),
        };
        return new SignedTransaction(
            TransferTransactionType,
            JsonSerializer.Serialize(payload, JsonOptions),
            Convert.ToHexString(hash.ToLittleEndianBytes()).ToLowerInvariant());
    }

    private long GetTransactionExpiryMilliseconds() =>
        _timeProvider.GetUtcNow().AddMinutes(10).AddSeconds(-1).ToUnixTimeMilliseconds();

    private static void ValidateOrder(OrderRequest order, long nonce)
    {
        if (order.MarketIndex is < 0 or > 254)
        {
            throw new ArgumentOutOfRangeException(nameof(order), "Perpetual market index is invalid.");
        }

        if (order.ClientOrderIndex <= 0 || order.ClientOrderIndex >= 1L << 48)
        {
            throw new ArgumentOutOfRangeException(nameof(order), "Client order index is invalid.");
        }

        if (order.BaseAmount <= 0 || order.BaseAmount >= 1L << 48)
        {
            throw new ArgumentOutOfRangeException(nameof(order), "Base amount is invalid.");
        }

        if (order.Price == 0 || order.Type != 0 || order.TimeInForce is not (1 or 2) || order.TriggerPrice != 0)
        {
            throw new ArgumentException("The requested limit order parameters are invalid.", nameof(order));
        }

        if (order.OrderExpiry <= 0 || nonce < 0)
        {
            throw new ArgumentException("Order expiry and nonce must be positive.", nameof(order));
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
