using Lighter.Signer.Sample.Api;
using Lighter.Signer.Sample.Configuration;
using Lighter.Signer.Transactions;
using System.Globalization;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace Lighter.Signer.Sample.Workflow;

public sealed class TradingWorkflow
{
    private const decimal RequestedXrpQuantity = 20m;
    private const decimal RequestedPrice = 1m;
    private const int MaximumPollAttempts = 30;

    private readonly ILighterApiClient _apiClient;
    private readonly ApiCredentials _credentials;
    private readonly LighterSigner _signer;
    private readonly TextWriter _output;
    private readonly TimeProvider _timeProvider;
    private readonly Func<TimeSpan, CancellationToken, Task> _delay;

    public TradingWorkflow(ILighterApiClient apiClient, ApiCredentials credentials, LighterSigner signer, TextWriter output, TimeProvider? timeProvider = null, Func<TimeSpan, CancellationToken, Task>? delay = null)
    {
        _apiClient = apiClient;
        _credentials = credentials;
        _signer = signer;
        _output = output;
        _timeProvider = timeProvider ?? TimeProvider.System;
        _delay = delay ?? ((duration, cancellationToken) => Task.Delay(duration, cancellationToken));
    }

    public async Task RunAsync(CancellationToken cancellationToken)
    {
        Account account = await _apiClient.GetAccountAsync(_credentials.AccountIndex, cancellationToken);
        await _output.WriteLineAsync($"1. Balances count: {account.Assets.Count}");
        await _output.WriteLineAsync($"   Positions count: {account.Positions.Count}");

        MarketDetails market = await _apiClient.GetMarketAsync("XRP", cancellationToken);
        if (decimal.TryParse(market.MinimumBaseAmount, NumberStyles.Number, CultureInfo.InvariantCulture, out decimal minimum) && RequestedXrpQuantity < minimum)
            await _output.WriteLineAsync($"   Warning: exchange metadata currently advertises a minimum XRP size of {minimum.ToString(CultureInfo.InvariantCulture)}.");

        long baseAmount = ScaleToInt64(RequestedXrpQuantity, market.SupportedSizeDecimals, "XRP quantity");
        long scaledPrice = ScaleToInt64(RequestedPrice, market.SupportedPriceDecimals, "order price");
        if (scaledPrice > uint.MaxValue)
            throw new InvalidOperationException("The scaled order price is too large.");

        long clientOrderIndex = _timeProvider.GetUtcNow().ToUnixTimeMilliseconds();
        long nonce = await _apiClient.GetNextNonceAsync(_credentials.AccountIndex, _credentials.KeyIndex, cancellationToken);
        SignedTransaction createOrder = _signer.SignCreateOrder(
            new OrderRequest(
                market.MarketId,
                clientOrderIndex,
                baseAmount,
                (uint)scaledPrice,
                IsAsk: false,
                Type: 0,
                TimeInForce: 1,
                ReduceOnly: false,
                TriggerPrice: 0,
                OrderExpiry: _timeProvider.GetUtcNow().AddDays(28).ToUnixTimeMilliseconds()),
            nonce);
        await WriteOutgoingTransactionAsync("Create order request", createOrder);
        SendTransactionResponse createResponse = await _apiClient.SendTransactionAsync(createOrder, cancellationToken);
        await WriteExchangeResponseAsync("Create order response", createResponse);

        string authToken = _signer.CreateAuthToken(_timeProvider.GetUtcNow().AddMinutes(10));
        (OrdersResponse ordersAfterCreate, OpenOrder placedOrder) = await WaitForPlacedOrderAsync(clientOrderIndex, authToken, cancellationToken);
        await _output.WriteLineAsync($"2. Placed order ID: {placedOrder.OrderId}");
        await _output.WriteLineAsync($"   Exchange order index: {placedOrder.OrderIndex}");
        await _output.WriteLineAsync($"3. Open orders count: {ordersAfterCreate.Orders.Count}");

        bool containsPlacedOrder = ordersAfterCreate.Orders.Any(order => string.Equals(order.OrderId, placedOrder.OrderId, StringComparison.Ordinal));
        if (!containsPlacedOrder)
            throw new InvalidOperationException("The placed order ID was not present in open orders.");

        await _output.WriteLineAsync("4. Placed order ID is present in open orders: yes");

        SignedTransaction cancelOrder = _signer.SignCancelOrder(placedOrder.MarketIndex, placedOrder.OrderIndex, checked(nonce + 1));
        await WriteOutgoingTransactionAsync("Cancel order request", cancelOrder);
        SendTransactionResponse cancelResponse = await _apiClient.SendTransactionAsync(cancelOrder, cancellationToken);
        await WriteExchangeResponseAsync("Cancel order response", cancelResponse);
        await _output.WriteLineAsync($"5. Cancel submitted for exchange order ID: {placedOrder.OrderId}");

        OrdersResponse ordersAfterCancel = await WaitForOrderRemovalAsync(placedOrder.OrderId, authToken, cancellationToken);
        await _output.WriteLineAsync($"6. Open orders count: {ordersAfterCancel.Orders.Count}");

        bool stillPresent = ordersAfterCancel.Orders.Any(order => string.Equals(order.OrderId, placedOrder.OrderId, StringComparison.Ordinal));
        if (stillPresent)
            throw new InvalidOperationException("The canceled order ID remained in open orders.");

        await _output.WriteLineAsync("7. Placed order ID is absent from open orders: yes");
    }

    private async Task<(OrdersResponse Response, OpenOrder Order)> WaitForPlacedOrderAsync(long clientOrderIndex, string authToken, CancellationToken cancellationToken)
    {
        for (int attempt = 0; attempt < MaximumPollAttempts; attempt++)
        {
            OrdersResponse response = await _apiClient.GetOpenOrdersAsync(_credentials.AccountIndex, authToken, cancellationToken);
            OpenOrder? order = response.Orders.SingleOrDefault(candidate => candidate.ClientOrderIndex == clientOrderIndex);
            if (order is not null)
            {
                if (order.OrderIndex <= 0 || string.IsNullOrWhiteSpace(order.OrderId))
                    throw new InvalidOperationException("The exchange returned an incomplete order identity.");

                return (response, order);
            }

            await DelayBeforeRetryAsync(attempt, cancellationToken);
        }

        throw new TimeoutException("The placed order did not appear in open orders.");
    }

    private async Task<OrdersResponse> WaitForOrderRemovalAsync(string orderId, string authToken, CancellationToken cancellationToken)
    {
        for (int attempt = 0; attempt < MaximumPollAttempts; attempt++)
        {
            OrdersResponse response = await _apiClient.GetOpenOrdersAsync(_credentials.AccountIndex, authToken, cancellationToken);
            if (response.Orders.All(order => !string.Equals(order.OrderId, orderId, StringComparison.Ordinal)))
                return response;

            await DelayBeforeRetryAsync(attempt, cancellationToken);
        }

        throw new TimeoutException("The canceled order remained in open orders.");
    }

    private Task DelayBeforeRetryAsync(int attempt, CancellationToken cancellationToken) =>
        attempt == MaximumPollAttempts - 1
            ? Task.CompletedTask
            : _delay(TimeSpan.FromSeconds(1), cancellationToken);

    private async Task WriteOutgoingTransactionAsync(string label, SignedTransaction transaction)
    {
        string safeTransactionInfo = RedactTransactionInfo(transaction.TransactionInfo);
        await _output.WriteLineAsync($"   {label} (credential fields redacted): tx_type={transaction.TransactionType}, tx_info={safeTransactionInfo}");
    }

    private async Task WriteExchangeResponseAsync(string label, SendTransactionResponse response)
    {
        await _output.WriteLineAsync($"   {label}: code={response.Code}, message={response.Message ?? "success"}, tx_hash={response.TransactionHash}");
    }

    private static long ScaleToInt64(decimal value, int decimalPlaces, string fieldName)
    {
        if (decimalPlaces is < 0 or > 18)
            throw new InvalidOperationException($"The {fieldName} decimal precision is unsupported.");

        decimal scale = 1m;
        for (int index = 0; index < decimalPlaces; index++)
        {
            scale *= 10m;
        }

        decimal scaled = value * scale;
        if (scaled != decimal.Truncate(scaled) || scaled > long.MaxValue)
            throw new InvalidOperationException($"The {fieldName} cannot be represented exactly.");

        return (long)scaled;
    }

    private static string RedactTransactionInfo(string transactionInfo)
    {
        try
        {
            if (JsonNode.Parse(transactionInfo) is not JsonObject payload)
                return "[UNAVAILABLE]";

            foreach (string property in new[] { "AccountIndex", "FromAccountIndex", "ApiKeyIndex", "Sig", "L1Sig" })
            {
                if (payload.ContainsKey(property))
                    payload[property] = "[REDACTED]";
            }

            return payload.ToJsonString(new JsonSerializerOptions { WriteIndented = false });
        }
        catch (JsonException)
        {
            return "[UNAVAILABLE]";
        }
    }
}
