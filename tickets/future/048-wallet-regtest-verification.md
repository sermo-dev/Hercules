# Ticket 048: Wallet Stack — Regtest End-to-End Verification

## Summary

Finish the one leg of the ticket 034 spike that couldn't run: prove that transactions built and signed by the no-BDK wallet stack are accepted by a real Bitcoin Core mempool and mined, on regtest. The 034 spike already proved addresses (BIP84/BIP86 vectors), PSBT construction, signing, and script validity (every input verified against libbitcoinconsensus with negative controls). What remains unverified is **policy** (standardness, `testmempoolaccept`), broadcast, and mining.

## Background

- Spike code: branch `spike/034-wallet-stack` (commit `aa65188`), crate `spikes/wallet-engine/`.
- Not run because `bitcoind` was not installed on the development machine.

## Plan

1. Install Bitcoin Core (`brew install bitcoin`, or a pinned release binary) on a dev machine or CI runner.
2. Start `bitcoind -regtest`, mine 101 blocks to a Core wallet.
3. Fund spike-derived BIP84 (P2WPKH), BIP86 (P2TR) and BIP44 (P2PKH) addresses from Core.
4. Spend each with the spike (segwit/taproot from outpoint + value + script only; P2PKH with parent tx), plus one mixed-input tx and one coin-selected multi-input tx with change.
5. For each: `testmempoolaccept` → `sendrawtransaction` → mine 1 block → confirm via `gettransaction` / `gettxout`.
6. Compare fee/vsize against Core's own `walletcreatefundedpsbt` for the same inputs/outputs (sanity check of size estimation).

## Verification

All spends accepted by `testmempoolaccept` and mined; vsize within estimate; results recorded in this ticket.

## Dependencies

034 (complete). Should run before 020 Phase 2 (send flow) ships. Can become a CI job once ticket 027's regtest infrastructure exists.

## Estimated effort

~1 day.
