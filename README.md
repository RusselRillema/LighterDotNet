# Lighter.Signer.Net

[![CI](https://github.com/RusselRillema/LighterDotNet/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/RusselRillema/LighterDotNet/actions/workflows/ci.yml)
[![.NET 8 and 10](https://img.shields.io/badge/.NET-8.0%20%7C%2010.0-512BD4)](https://dotnet.microsoft.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/RusselRillema/LighterDotNet/blob/master/LICENSE)

A fully managed, dependency-free .NET signer for [Lighter](https://lighter.xyz/) authentication tokens and transactions.

`Lighter.Signer.Net` implements the Goldilocks, Poseidon2, ECgFp5, and Schnorr signing path in C#. It accepts prepared transaction parameters and returns payloads ready for submission to the exchange. This is an unofficial community project and is not affiliated with Lighter.

## At a glance

| Property | Value |
|---|---|
| Supported operations | Authentication, create order, cancel order, sub-account transfer |
| Implementation | Fully managed C#; no native libraries |
| Package dependencies | None |
| Target frameworks | .NET 8 and .NET 10; compatible with .NET 9 via the .NET 8 asset |
| Package status | Preview |

## Installation

```bash
dotnet add package Lighter.Signer.Net --version 0.1.0-preview.1
```

To install a package built from this repository:

```bash
dotnet pack src/Lighter.Signer.Net/Lighter.Signer.Net.csproj -c Release -o artifacts
dotnet add package Lighter.Signer.Net --version 0.1.0-preview.1 --source artifacts
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
        OrderExpiry: DateTimeOffset.UtcNow.AddDays(28).ToUnixTimeMilliseconds()),
    nonce: 42);

// Submit signedOrder.TransactionType and signedOrder.TransactionInfo
// through your application's Lighter API client.
```

The values above are illustrative. Amounts and prices must be scaled using the target market's supported decimal precision.

## Supported operations

| Method | Result |
|---|---|
| `CreateAuthToken(deadline)` | Time-limited authentication token |
| `SignCreateOrder(order, nonce)` | Signed create-order transaction |
| `SignCancelOrder(marketIndex, exchangeOrderIndex, nonce)` | Signed cancel-order transaction |
| `SignTransfer(transfer, nonce)` | Signed sub-account transfer transaction |

Each transaction-signing method returns a `SignedTransaction` containing:

- `TransactionType` — Lighter transaction type identifier.
- `TransactionInfo` — serialized signed payload for submission.
- `TransactionHash` — hexadecimal hash of the signed transaction fields.

The signer expects prepared inputs, including the correct chain ID, nonce, scaled market values, and exchange order index. Retrieving those values and submitting the resulting payload are responsibilities of the calling application.

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
