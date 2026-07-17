# Implementation progress

Last updated: 2026-07-17

## Completed

- Reviewed the current official `elliottech/lighter-go` transaction, Poseidon2, Goldilocks, ECgFp5, and Schnorr implementations.
- Implemented a dependency-free managed C# signer for authentication tokens, create-order, cancel-order, and sub-account transfer transactions.
- Implemented REST-only clients for account balances/positions, API-key endpoint matching, market metadata, next nonce, active orders, and transaction submission.
- Implemented the console workflow for a hard-coded limit buy at $1 and cancellation by the exchange-supplied order identity. The user authorized increasing the live quantity from 10 to 20 XRP on 2026-07-17 to satisfy the exchange minimum.
- Added credential-safe console formatting. Credential-file fields and transaction signatures are redacted from outgoing-payload logs.
- Added deterministic tests against official Go/Poseidon vectors and stateful workflow tests for every one of the seven goal transitions.

## Verification evidence

The Release build has zero warnings. The executable test suite currently proves:

1. The Poseidon2 permutation matches the official Plonky2/Goldilocks vector.
2. Schnorr signing matches the official deterministic vector.
3. Create-order and cancel-order hashes match values produced by the official Go signer.
4. Sub-account transfer hashing and JSON encoding match a value produced by the official Go signer.
5. REST requests use the expected form body and authorization header, and preserve structured exchange errors.
6. A stateful fake exchange completes all seven required workflow states and proves cancellation uses the exchange order index rather than the client order index.

## Live verification

An initial exact 10 XRP attempt was rejected because mainnet advertised a 20 XRP minimum and no XRP spot alternative existed. The user then explicitly authorized the 20 XRP minimum. The authorized mainnet run completed on 2026-07-17 with both transaction submissions returning code 200:

1. Retrieved **6 balances** and **18 positions**.
2. Placed the 20 XRP limit buy at $1; the exchange supplied order ID **2533274333458918**.
3. Retrieved **1 open order** after placement.
4. Confirmed exchange order ID **2533274333458918** was in the open-order response.
5. Canceled using the exchange-supplied order index associated with that same order ID; cancellation returned code 200.
6. Retrieved **0 open orders** after cancellation.
7. Confirmed exchange order ID **2533274333458918** was absent from the final open-order response.

The console output included the redacted outgoing create/cancel payload structures and the successful exchange responses. No live order from the verification run remained open.

## Credential handling

`APIKEY` is ignored by source control. Its contents are read only by the console application at runtime and are not inspected by the implementation workflow. No credential values are recorded in this file.

## Primary references

- <https://github.com/elliottech/lighter-go>
- <https://apidocs.lighter.xyz/docs>
- <https://apidocs.lighter.xyz/docs/api-keys>
