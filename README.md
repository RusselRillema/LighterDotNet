# Lighter.Signer.Net

[![CI](https://github.com/RusselRillema/LighterDotNet/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/RusselRillema/LighterDotNet/actions/workflows/ci.yml)
[![.NET 8 and 10](https://img.shields.io/badge/.NET-8.0%20%7C%2010.0-512BD4)](https://dotnet.microsoft.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/RusselRillema/LighterDotNet/blob/master/LICENSE)

A fully managed, dependency-free .NET signer for [Lighter](https://lighter.xyz/) authentication tokens and transactions.

`Lighter.Signer.Net` implements the Goldilocks, Poseidon2, ECgFp5, and Schnorr signing path in C#. It accepts prepared transaction parameters and returns payloads ready for submission to the exchange. This is an unofficial community project and is not affiliated with Lighter.

## At a glance

| Property | Value |
|---|---|
| Supported operations | Authentication, create order, modify order, cancel order, update leverage, approve integrator, sub-account transfer, L2 transaction attributes |
| Implementation | Fully managed C#; no native libraries |
| Package dependencies | None |
| Target frameworks | .NET 8 and .NET 10; compatible with .NET 9 via the .NET 8 asset |
| Package status | Preview |

## Installation

```bash
dotnet add package Lighter.Signer.Net --version 0.2.0-preview.1
```

To install a package built from this repository:

```bash
dotnet pack src/Lighter.Signer.Net/Lighter.Signer.Net.csproj -c Release -o artifacts
dotnet add package Lighter.Signer.Net --version 0.2.0-preview.1 --source artifacts
```

## Quick start

```csharp
using Lighter.Signer;
using Lighter.Signer.Transactions;

var privateKey = Environment.GetEnvironmentVariable("LIGHTER_PRIVATE_KEY")
    ?? throw new InvalidOperationException("LIGHTER_PRIVATE_KEY is required.");

var signer = new LighterSigner(
    privateKeyHex: privateKey,
    accountIndex: 123,
    apiKeyIndex: 0,
    chainId: 304);

var authToken = signer.CreateAuthToken(DateTimeOffset.UtcNow.AddMinutes(10));

var signedOrder = signer.SignCreateOrder(
    new OrderRequest(
        MarketIndex: 7,
        ClientOrderIndex: 123456,
        BaseAmount: 20_000_000,
        Price: 1_000_000,
        IsAsk: false,
        Type: 0,
        TimeInForce: 1,
        ReduceOnly: false,
        TriggerPrice: 0,
        OrderExpiry: LighterSigner.Default28DayOrderExpiry),
    nonce: 42);

// Submit signedOrder.TransactionType and signedOrder.TransactionInfo
// through your application's Lighter API client.
```

The values above are illustrative. Amounts and prices must be scaled using the target market's supported decimal precision.

`OrderRequest` takes raw `byte` fields, so consumers can plug in their own models. The
`OrderType`, `OrderTimeInForce`, `SelfTradeBehavior`, `SelfTradeEquality`, and `MarginMode`
enums are optional conveniences; `OrderRequest.Create(...)` accepts the enums directly:

```csharp
var order = OrderRequest.Create(
    marketIndex: 7,
    clientOrderIndex: 123456,
    baseAmount: 20_000_000,
    price: 1_000_000,
    isAsk: false,
    type: OrderType.Limit,
    timeInForce: OrderTimeInForce.GoodTillTime,
    reduceOnly: false,
    triggerPrice: 0,
    orderExpiry: LighterSigner.Default28DayOrderExpiry);
```

An `OrderExpiry` of `-1` (`LighterSigner.Default28DayOrderExpiry`) signs the order with a
28-day expiry, matching the official signers. All order types are supported — limit, market,
stop-loss, stop-loss limit, take-profit, take-profit limit, and TWAP — with the same
per-type validation rules as the Go signer; spot markets accept limit, market, and TWAP
orders, while trigger orders and reduce-only are perpetual-market-only.

## Supported operations

| Method | Result |
|---|---|
| `CreateAuthToken(deadline)` | Time-limited authentication token |
| `SignCreateOrder(order, nonce, attributes?)` | Signed create-order transaction |
| `SignModifyOrder(modify, nonce, attributes?)` | Signed modify-order transaction |
| `SignCancelOrder(marketIndex, exchangeOrderIndex, nonce, attributes?)` | Signed cancel-order transaction |
| `SignUpdateLeverage(marketIndex, initialMarginFraction, marginMode, nonce, attributes?)` | Signed update-leverage transaction |
| `SignApproveIntegrator(approval, nonce, attributes?)` | Signed approve-integrator transaction |
| `SignTransfer(transfer, nonce, attributes?)` | Signed sub-account transfer transaction |

Each transaction-signing method returns a `SignedTransaction` containing:

- `TransactionType` — Lighter transaction type identifier.
- `TransactionInfo` — serialized signed payload for submission.
- `TransactionHash` — hexadecimal hash of the signed transaction fields.
- `L1SignatureBody` — for approve-integrator transactions, the human-readable message an
  account's L1 (Ethereum) key signs to authorize the approval; `null` otherwise.

The transfer memo is a string carrying exactly 32 bytes: 32 raw characters, or 64 hex
characters (optionally `0x`-prefixed). Matching the official signers, shorter memos are not
padded automatically.

The signer expects prepared inputs, including the correct chain ID, nonce, scaled market values, and exchange order index. Retrieving those values and submitting the resulting payload are responsibilities of the calling application. `ExchangeConstants` exposes the exchange's protocol bounds (market index ranges, order index limits, fee tick, and so on) for client-side validation.

### L2 transaction attributes

Every transaction-signing method accepts an optional `L2TxAttributes` for integrator fees,
nonce skipping, self-trade behavior, and modify-order versions. Set only the fields you need —
at most four per transaction — and leave the rest `null`:

```csharp
var signedWithAttributes = signer.SignCreateOrder(order, nonce, new L2TxAttributes
{
    SelfTradeBehaviorMode = (byte)SelfTradeBehavior.CancelBoth,
});
```

Attributes at their default values (for example a fee of `0`) appear in the payload but,
matching the Go signer, do not change the transaction hash.

`OrderVersion` mirrors the Python SDK's `order_version` for modify orders. The exchange applies a
versioned modify only when the version is greater than the order's current one, so stale or retried
modifies cannot overwrite a newer one. A millisecond timestamp is the usual choice:

```csharp
SignedTransaction versioned = signer.SignModifyOrder(modify, nonce, new L2TxAttributes
{
    OrderVersion = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
});
```

### Transaction expiry

Signed transactions expire `LighterSigner.DefaultTransactionExpiry` (ten minutes less a
second) after signing. Adjust it per signer instance:

```csharp
signer.TransactionExpiry = TimeSpan.FromMinutes(5);
```

## Security

- Never commit, print, or transmit private keys outside the intended signing environment.
- Treat authentication tokens and signed payloads as sensitive data.
- Validate chain IDs, nonces, amounts, prices, destination accounts, and expiry times before signing.
- Keep transaction submission and error handling separate from signing.

## Live sample

> [!WARNING]
> The console sample submits real transactions. Review its constants and target endpoint before running it.

The non-packaged sample demonstrates an end-to-end REST workflow. It retrieves account data and a nonce, submits a 20 XRP limit buy at $1 to satisfy the exchange minimum, confirms the order is open, cancels it, and confirms its removal.

Create an uncommitted `APIKEY` file in the repository root:

```text
Public Key: XXX
Private Key: XXX
Account Index: XXX

L1 Address: XXX
Key Index: XXX
```

Then run:

```bash
dotnet run --project samples/Lighter.Signer.Net.Console/Lighter.Signer.Net.Console.csproj -c Release -f net10.0
```

The sample's REST client, credential reader, endpoint discovery, and trading workflow are not included in the NuGet package. Its outgoing logs redact credential-derived fields and signatures. The `APIKEY` file is ignored by source control and must never be committed.

## Repository layout

```text
src/Lighter.Signer.Net/                 Signer library and NuGet package
samples/Lighter.Signer.Net.Console/     Non-packaged live REST sample
tests/Lighter.Signer.Net.Tests/         Cryptographic, transaction, REST, and workflow tests
```

## Build and test

```bash
dotnet build Lighter.Signer.Net.sln -c Release
dotnet run --project tests/Lighter.Signer.Net.Tests/Lighter.Signer.Net.Tests.csproj -c Release -f net8.0
dotnet run --project tests/Lighter.Signer.Net.Tests/Lighter.Signer.Net.Tests.csproj -c Release -f net10.0
dotnet pack src/Lighter.Signer.Net/Lighter.Signer.Net.csproj -c Release -o artifacts
```

The test suite includes official cryptographic vectors, transaction hashes generated by the official Go signer, REST wire-contract checks, and the complete place/list/cancel workflow against a stateful fake exchange.

## References

- [Lighter API documentation](https://apidocs.lighter.xyz/docs/get-started)
- [Official `lighter-go` implementation](https://github.com/elliottech/lighter-go)

## License

Licensed under the [MIT License](https://github.com/RusselRillema/LighterDotNet/blob/master/LICENSE).
