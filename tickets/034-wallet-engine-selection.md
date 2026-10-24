# Ticket 034: Wallet Engine — Library Stack (No BDK)

## Decisions (2026-10-24)

- **Decided: no BDK.** The wallet is our own, built directly on the same Rust libraries BDK itself is built on. This reaffirms ticket 020's original decision (`020-in-app-wallet.md:256`).
- **Decided: the wallet does not hand-roll cryptography or script logic.** Every money-critical primitive comes from a widely used library. The only code we write is wallet *state* (which coins are ours, labels, history) and a port of Bitcoin Core's coin selection algorithms, tested against Core's own test cases.
- Watching / coin discovery is ticket 035 (our own scanner, same model as Bitcoin Core's built-in wallet).

## Summary

Pin down exactly which code builds, signs, and tracks transactions in the in-app wallet, and prove the stack end-to-end on regtest before ticket 035+ build on it. The output is a short decision record in this file plus a throwaway prototype, not production code.

## Background

### Why not Bitcoin Core's wallet code directly

Bitcoin Core's wallet (coin selection, fee/change, signing) lives inside `bitcoind`'s C++ wallet module. It is **not shipped as a library**:
- `libbitcoinconsensus` (which Hercules uses for script verification, v26.0 via patches) only verifies scripts, and it was removed from Core in v28.
- `libbitcoinkernel`, Core's library effort, deliberately covers validation only, not the wallet.

So Core's wallet can't be linked in. What we *can* do is port its **coin selection algorithms** (well documented, with extensive unit tests) to Rust.

"libbitcoin" is an unrelated C++ project, not part of Bitcoin Core. It has a much smaller user base and would need C++ FFI. Not recommended.

### "Legacy" terminology

- **Legacy addresses** (`1…`, P2PKH): fully supported by this stack. `rust-bitcoin` computes legacy sighashes; `miniscript` handles `pkh()` descriptors. Bitcoin Core also still signs them (`pkh()` descriptors).
- **Legacy wallets** in Core means the old BDB wallet *file format*, removed from Core in favor of descriptor wallets. Irrelevant to us; we are descriptor-based from day one.

The real limitation for legacy *spends* is **data, not library support**. Signing a legacy (non-segwit) input, or giving a PSBT to most hardware wallets, needs the full previous transaction. Coins found by the UTXO-set walk (035) only have `(outpoint, value, scriptPubKey, height, coinbase)`. Bitcoin Core on a pruned node has the same limitation: it can't rescan pruned blocks either. Fix, owned by 035:
1. Going forward, the scanner stores the full funding transaction for every wallet coin it sees in a block.
2. For pre-snapshot coins that need a parent tx, fetch that single historical block (height is in the UTXO entry) from an archival peer, verify it against our own header chain and merkle root, and extract the tx. Trustless; no server.

Native segwit (BIP84) and Taproot (BIP86) spends from our own hot wallet need only `witness_utxo` (amount + script), which the UTXO set already provides.

## The stack

| Concern | Library | Notes |
|---|---|---|
| Keys, BIP32 derivation, addresses, scripts, sighash, PSBT | `bitcoin` (rust-bitcoin, already a dependency at 0.32) | Same crate Hercules already uses for consensus data |
| ECDSA / Schnorr signing | `secp256k1` (libsecp256k1 bindings, transitive via `bitcoin`) | The same C library Bitcoin Core uses |
| Descriptors → scripts, satisfaction, PSBT finalization | `miniscript` (rust-miniscript) | Canonical Rust descriptor implementation |
| Mnemonics, BIP39 passphrases | `bip39` | Small, widely used |
| Coin selection | **Our port of Bitcoin Core's algorithms** (BnB, CoinGrinder, Knapsack, SRD + waste metric) | Port Core's `coinselector_tests` cases as Rust tests; diff behavior against Core on regtest |
| Fee / change / dust | Ours, on top of the above | Small; tested against Core regtest via `walletcreatefundedpsbt` comparisons |
| Silent payments (043) | Evaluate `rust-silentpayments`; otherwise implement against BIP352's official test vectors | Maturity **unverified** |

## Spike plan

1. Derive BIP84 and BIP86 addresses from the official BIP test-vector mnemonics; match byte-for-byte.
2. Build a PSBT spending a coin known only from `(outpoint, value, scriptPubKey)` (no parent tx), sign with `secp256k1`, finalize with `miniscript`, broadcast to `bitcoind -regtest`, confirm it mines.
3. Same for a P2PKH input with the parent tx supplied (proves the legacy path).
4. Port BnB + one fallback algorithm from Core with a handful of Core's test cases; check selected sets match.
5. Measure iOS static-lib size delta.

## Files touched

| File | Action |
|---|---|
| `tickets/034-wallet-engine-selection.md` | Record spike results (crates + pinned versions, size delta, gaps) |
| `spikes/wallet-engine/` (throwaway, not merged to main) | Prototype crate |
| `tickets/020-in-app-wallet.md` | Point its engine section here |
| `README.md` | Remove "Wallet API: BDK (future)" (handled by 044) |

## Dependencies

None. Can run in parallel with the node-safety tier (023–027).

## Estimated effort

2–4 days for the spike. The production coin-selection port is roughly 1 week including test porting, and lands with the send flow (020 Phase 2).

## Verification

- BIP84/BIP86 test vectors match exactly
- Regtest `bitcoind` accepts and mines the segwit spend built without a parent tx, and the legacy spend built with one
- Ported coin-selection tests pass and agree with Core on the sampled cases

## Open questions

- **Which Core coin-selection algorithms to port first.** Recommendation: BnB (changeless) + CoinGrinder or Knapsack fallback; SRD later.
- **Hardware-wallet PSBTs (020 Phase 3):** confirm which signers require `non_witness_utxo` even for segwit, and therefore when the historical-block fetch above is needed.

## Roadmap position

First wallet ticket: **034 → 035 → 036 (design) → 037 → …**. Touches no node code.
