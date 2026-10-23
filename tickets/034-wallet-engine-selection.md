# Ticket 034: Wallet Engine Selection (BDK Spike)

## Summary

Decide what code builds, signs, and tracks transactions inside the in-app wallet, before any wallet code is written. Ticket 020 decided on a hand-rolled wallet built from `bitcoin` + `miniscript` + `bip39`, not BDK (`020-in-app-wallet.md:256`). The README stack table still lists "Wallet API: BDK (future)". This ticket resolves that contradiction with a short, time-boxed spike and a written decision.

The recommendation going in: **don't hand-roll the parts of a wallet that lose money when they're wrong.** Descriptor derivation, coin selection, fee/change calculation, PSBT construction, and signing are where wallet bugs become lost funds. Those should come from heavily used, independently audited libraries, whichever wallet-state model we end up with.

Status: decision ticket. The output is a decision record in this file plus a throwaway prototype, not production code.

## Background

### What BDK is

**BDK (Bitcoin Dev Kit)** is a family of Rust crates for building Bitcoin wallets:

| Crate | What it does |
|---|---|
| `bdk_wallet` | Full wallet: descriptors → addresses, tracks UTXOs/txs, builds txs (`TxBuilder`), coin selection, change, fee calc, PSBT, signing |
| `bdk_chain` | Lower-level: `TxGraph`, `LocalChain`, indexed script tracking. Chain-source agnostic |
| `bdk_coin_select` | Standalone coin selection (branch-and-bound + metrics like waste) |
| `bdk_electrum` / `bdk_esplora` / `bdk_bitcoind_rpc` | Optional chain-source adapters. **We would use none of these** |
| `miniscript` (rust-miniscript) | Descriptor parsing, address derivation, satisfaction/signing logic. BDK depends on it |

BDK is **chain-source agnostic**: the wallet core doesn't care where blocks come from. `bdk_wallet` exposes block-application APIs (in 1.x I believe they are `Wallet::apply_block` / `apply_block_connected_to`, plus `apply_unconfirmed_txs` for mempool txs. **Unverified: confirm the names against current docs.rs during the spike**). That means Hercules could feed BDK the blocks it has just validated, with no Electrum or Esplora server involved.

BDK is used in production wallets. I believe Proton Wallet is built on it, but **confirm before citing publicly**. It is maintained by a team funded by Spiral and other sponsors, and it has had external review.

### Why 020 rejected it, and why that should be revisited

020's argument: "BDK is designed for the wallet-talks-to-remote-backend model; our wallet shares a process with the node, so BDK's `ChainSource` abstraction is fighting our actual architecture."

That was true of BDK 0.x. Since 1.0, the chain source has been decoupled. The real question is no longer architecture fit. It is one specific data-model question (below).

020 also plans ~400 lines of hand-written BnB + knapsack coin selection. That is exactly the kind of code where an off-by-one in change/dust handling silently overpays fees or produces non-standard txs.

## The spike question

**Can `bdk_wallet` represent coins discovered by walking our UTXO set, without having their parent transactions?**

This is the crux. Hercules starts from an AssumeUTXO snapshot (height 943,500). When a user restores a seed or imports an xpub (035), we find their coins by scanning the UTXO set. We get `(outpoint, value, scriptPubKey, height, coinbase)` per coin, **but not the full funding transaction**. That transaction was in a block we never downloaded.

BDK's wallet model is transaction-graph based: a UTXO is "an output of a tx in my graph that no other tx in my graph spends." Things to test:

1. Does `TxGraph::insert_txout(outpoint, txout)` (floating txouts) let those coins count toward balance and be selected for spending? Or is it only used for fee calculation of foreign inputs? I suspect the latter. **Verify.**
2. If not, can we synthesize a minimal anchor or "virtual" tx? That would be a hack and is probably a no.
3. Can PSBT signing work with only `witness_utxo` (no `non_witness_utxo`) for segwit inputs? Yes for segwit v0/v1 by spec. Confirm BDK doesn't require the full parent for P2WPKH/P2TR.

## Proposed design: two outcomes

### Outcome A: BDK can hold parentless coins
- `bdk_wallet::Wallet` per wallet (main, each watch-only, each open passphrase wallet; see 037/038)
- Persistence via BDK's changeset model into our wallet DB (SQLite file, separate from chain data; see 037)
- Feed validated blocks from the single block-connect path (035)
- Feed mempool txs via `apply_unconfirmed_txs` (040)
- Use `TxBuilder` for sends, BDK's signer for signing (036 controls when the seed is in memory)

### Outcome B: it can't
- Our own wallet state (outpoint set, tx records, labels) in `wallet.rs` / `wallet_store.rs` as 020 planned
- **But** use library code for everything risky:
  - `miniscript` for descriptors → scripts/addresses
  - `bdk_coin_select` for coin selection (no hand-written BnB)
  - `bitcoin::psbt` + `miniscript`'s PSBT finalizer for construction and finalization
  - `bitcoin::bip32` for derivation, `bip39` crate for mnemonics
  - `secp256k1` (already transitive via `bitcoin 0.32`) for signing

Either way, 020's line "Coin selection (~400 lines BnB+knapsack) we write ourselves" is struck.

### Silent payments (for 043)

BIP352 needs sender-side output derivation and receiver-side per-block scanning. Library options to evaluate (all **unverified maturity**): `rust-silentpayments` (cygnet), and any BDK-ecosystem SP work. If nothing is mature, SP derivation is small enough to implement against BIP352's official test vectors. That is the one place we may hand-roll, with test vectors as the safety net.

## Files touched

| File | Action |
|---|---|
| `tickets/034-wallet-engine-selection.md` | Add "Decision" section with outcome + evidence |
| `spikes/wallet-engine/` (throwaway, not merged to main) | Prototype crate |
| `tickets/020-in-app-wallet.md` | Update dependency section to point here (after decision) |
| `README.md` | Stack table row (handled by 044) |

## Dependencies

- None. This should run **first** among the wallet tickets, because 035–040 all assume a wallet engine.

## Estimated effort

3–5 days, time-boxed:
- 1 day: read current `bdk_wallet` / `bdk_chain` API, answer the parentless-coin question on paper
- 2 days: prototype: derive BIP84 receive/change addresses from a test mnemonic, inject a parentless coin, build + sign a spend on **regtest**, broadcast to a local `bitcoind -regtest` and confirm it mines
- 1 day: write the decision, measure binary-size delta for the iOS static lib

## Verification

- Prototype derives the BIP84 test-vector addresses (BIP84 spec vectors) exactly
- Prototype spends a coin that was injected without its parent tx, and regtest `bitcoind` accepts and mines it
- Decision section lists: chosen outcome, crates + pinned versions, binary-size delta, known limitations

## Open questions

- **Binary size / compile time.** Does `bdk_wallet` materially grow the iOS framework? Measure, don't guess.
- **Persistence.** BDK's changesets vs. our own SQLite schema. Both fit; prefer whatever keeps wallet data in a file separate from chain data (030/037).
- **Multi-wallet scaling.** One BDK `Wallet` per wallet, or one shared indexer with keychains per wallet? Matters for scanning cost in push wakes (035, 028).
- **Who owns the decision if outcome is ambiguous** (e.g. parentless coins work but awkwardly)? Recommendation: prefer B over fighting BDK internals.

## Roadmap position

First wallet ticket. **034 → 035 → 036 (design) → 037 → …**. Can run in parallel with the Tier 0 node-safety tickets (022–027), since it touches no node code.
