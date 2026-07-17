# Lighter native signing for .NET

A REST-only .NET 9 console application with a dependency-free managed implementation of the Lighter Goldilocks/Poseidon2/ECgFp5/Schnorr signing path.

The reusable implementation is under `src/LighterNativeSigning/Signing`. It supports authentication tokens, create-order, cancel-order, and sub-account transfer payloads. The console workflow retrieves balance/position counts, places a limit order, finds its exchange-issued identity in active orders, cancels it, and verifies its removal.

## Run tests

```bash
dotnet run --project tests/LighterNativeSigning.Tests/LighterNativeSigning.Tests.csproj -c Release
```

## Run the live workflow

Place the uncommitted `APIKEY` file in the repository root using the format described in `Task.md`, then run:

```bash
dotnet run --project src/LighterNativeSigning/LighterNativeSigning.csproj -c Release
```

The live command submits real transactions. The user explicitly authorized changing the test order from 10 XRP to the current mainnet minimum of 20 XRP at $1 on 2026-07-17. The place/list/cancel/list workflow completed successfully; see `Progress.md` for the seven live results.

Endpoint discovery checks official mainnet and testnet automatically. A custom endpoint can be selected with both `LIGHTER_BASE_URL` and `LIGHTER_CHAIN_ID`.

Outgoing payload logs redact credential-derived fields and signatures. Never commit or publish `APIKEY`.
