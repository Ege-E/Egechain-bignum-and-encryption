# Egechain-bignum-and-encryption

Egechain Phase I + Phase II prototype in C++.

Checklist before Phase III:
> Need novel solution to generate key pairs in Wallet.cpp
> Within serializing private keys, I need someone smarter than I am.
> The gossip network needs to be redone before implementing P2P. 

## What is implemented

### Phase I (existing)
- String-oriented big-number handling (`Bignum`)
- LISP-style parser and arithmetic evaluator (`LispParser`)
- Transaction hashing and reversible lightweight encryption (`LightweightCrypto`)
- Block/transaction data model (`Block`)

### Phase II (new)
- **State engine (account model):** deterministic account balances using decimal strings (no floating-point / unsafe narrowing)
- **Transaction validation:** sender/receiver checks, positive amount checks, canonical hash checks, encrypted-hash integrity checks, overspending rejection
- **Mining + consensus:** simple PoW (`difficulty = leading zero hex chars`), PoW verification, linkage/index/timestamp/merkle validation, and heaviest-chain selection by cumulative work (`sum(difficulty+1)`)
- **Tie-breaker:** when cumulative work and height match, lexicographically smaller tip block hash wins deterministically
- **Mempool:** pending transaction queue with pre-validation, duplicate prevention, and aggregate overspend prevention against tip state
- **Persistence:** chain + mempool + consensus config saved with sized fields, strict parsing, malformed-file rejection, and atomic write via `*.tmp` rename
- **Node lifecycle API:** integrated `EgechainNode` and a CLI node mode



## Build

```bash
cd /home/runner/work/Egechain-bignum-and-encryption/Egechain-bignum-and-encryption/Egechain
cmake -S . -B build
cmake --build build
```

## Run

### Default mode
Runs internal Phase I/II assertions, then tries to evaluate `src/expressions.txt`.

```bash
./build/Egechain
```

### Node mode
Runs internal assertions, then starts an interactive ledger node.

```bash
./build/Egechain node [state_file_path]
```

Default state file path in node mode: `egechain_state.dat` in the current working directory.

Commands:
- `genesis <recipient> <amountExpr>`
- `tx <sender> <receiver> <amountExpr>`
- `mine <miner>`
- `balance <account>`
- `chain`
- `save <path>`
- `load <path>`
- `exit`

## Notes / assumptions

- Account model is used (not UTXO).
- Genesis can contain `SYSTEM`-funded allocation transactions.
- Non-genesis blocks must begin with one coinbase (`SYSTEM -> miner`) matching configured mining reward.
- Difficulty is fixed by node config for this prototype.
