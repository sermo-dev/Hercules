# Ticket 035: Wallet Chain Scanner

## Decisions (2026-10-23)

- **Decided (2026-10-24):** the BIP158 filter-serving phase is dropped from this ticket. Its only consumer was external wallets via ticket 014's custom onion API, which no existing wallet speaks. This ticket is the in-app scanner only. If filter serving is ever wanted, it gets its own ticket.
- **Note:** a prototype of Phase 1 already exists as uncommitted work on branch `ticket-020-in-app-wallet` (`wallet.rs`, `wallet_store.rs`, `process_block` hooks). Reuse it rather than starting fresh.

- **Added (2026-10-24):** the scanner stores the full funding transaction for every wallet coin it sees in a block, and can fetch a single historical block from an archival peer (height comes from the UTXO entry; verify against our headers + merkle root) when a pre-snapshot coin needs its parent tx for a legacy or hardware-wallet spend (see 034).

## Summary

Build the component that answers "which coins belong to my wallets?" from data the node already has. It has three entry points:

1. **Per-block hook.** Every validated block is checked against all unlocked wallets' scripts during block connect.
2. **UTXO-set walk.** On import, restore, or passphrase-unlock, scan the LMDB UTXO set once to find current coins.
3. **Recent-block rescan.** Re-check the last ≤288 stored blocks (e.g. when gap-limit lookahead extends).

BIP158 compact filters are **not** part of this ticket. The in-app wallet doesn't need them (see below), which corrects ticket 020. This is the same model Bitcoin Core's built-in wallet uses: the node notifies the wallet of each connected block and the wallet matches against its own script set.

## Background

### What BIP158 is

A BIP158 **compact block filter** is a small per-block summary, typically tens of KB. It is a Golomb-coded set of every scriptPubKey *created* in the block and every scriptPubKey *spent* by it. A light wallet downloads filters from full nodes and tests its own addresses against each one locally. A "maybe" means it downloads that whole block. False positives are possible, false negatives aren't.

It's the private replacement for BIP37 bloom filters. With BIP37 the wallet sends *its* addresses to the node, which leaks them. With BIP158 the node sends the *same* filter to everyone, and the matching happens on the wallet's side. Node operators serve them via BIP157 (`getcfilters`) or by RPC.

### 020's premise is wrong

020 says "BIP158 filter computation is already happening for SPV serving" (`020-in-app-wallet.md:67`, also :33 and :84). **It isn't.** No filter code exists. The only reference is a stub returning "compact filter serving not yet implemented" (`hercules-core/src/wallet_rpc.rs:545-551`).

### Why filters aren't the right primary tool anyway

Filters exist so a client *without* the block can decide whether it needs the block. Hercules always has the full block, with every spent coin's scriptPubKey already resolved during validation. `UtxoSet::apply_block` (`hercules-core/src/utxo.rs:235`) reads each spent entry from `utxos` to write undo data. Building a filter only to test it immediately against our own address set is strictly slower than a direct hash-set lookup. For the in-app wallet: **match scripts directly**.

## Proposed design

### WatchSet

In memory, rebuilt on unlock/import:

```
WatchSet {
    scripts: HashMap<ScriptBuf, (WalletId, Keychain, u32 /*index*/)>,
    outpoints: HashMap<OutPoint, WalletId>,   // coins we own (to detect spends)
}
```

- Contains every **currently loaded** wallet's derived scripts, receive + change, through `last_used + gap_limit` (default 20).
- When a match lands at index *i* near the end of the lookahead, derive further and extend the set (and trigger the recent-block rescan, below).
- Passphrase wallets (038) are added only while unlocked and removed on lock. Watch-only and main wallets are always loaded once their metadata is readable (see 036 for what's readable while the phone is locked).

### Block hook (single connect path)

Today validate + apply is duplicated in three places: the main sync loop (`sync.rs:1115-1120`), the push-wake `validate_latest_block` (`sync.rs:2301-2308`), and `catch_up_blocks` (`sync.rs:2578-2583`). Prerequisite refactor: a single `connect_block(block, height)` that validates, applies, stores, then calls the wallet hook. 022/025 want the same consolidation.

Hook output is a list of `WalletEvent { wallet, kind: Received|Spent, outpoint, value, txid, height }`, persisted in the same logical step as the UTXO apply. If the wallet DB is a separate file (037), use a "last scanned height" checkpoint per wallet, so a crash replays at most one block.

Matching cost: one hash lookup per output plus one per input, ~5–10k lookups per block. Microseconds. Safe inside a push wake (028).

Reorgs (025): on `rollback_block`, emit inverse events for the disconnected heights. Wallet records carry height so they can be unwound.

### UTXO-set walk (import / restore / passphrase unlock)

The UTXO set is keyed by outpoint, so finding coins by script is a full table scan. 150M+ entries at current mainnet (**verify the count from the snapshot header**). 020 estimated 30–120 s. **Measure on a real device**, cold and warm page cache. Design:

- Read-only LMDB txn over `utxos`, test each entry's script against the WatchSet
- Progress callback to Swift (percentage by key-space position), cancellable
- Checkpointed by key, so it can resume after a crash
- Multiple wallets in one pass (restore + several watch-only imports share one walk)
- Must not hold a read txn across a block apply for minutes. LMDB readers block page reuse, so the map grows. Either pause sync during the walk, or walk in chunks with fresh txns and then rescan the blocks applied meanwhile.

### Recent-block rescan

The block store keeps the last ~288 blocks (`block_store.rs`). Rescan them when the lookahead extends or a wallet is added mid-session, so payments in the window aren't missed.

### What users see about history

- **Balance is always correct**, because the UTXO set is complete.
- **History starts at the snapshot height** (or wallet creation, whichever is later). Coins received and spent before the snapshot are invisible. Show "History available since block 943,500" in the UI. A coin found by the walk gets a synthetic "received before history start" row.

## Files touched

| File | Action |
|---|---|
| `hercules-core/src/wallet_scan.rs` | **New**: WatchSet, block hook, UTXO walk, rescan |
| `hercules-core/src/sync.rs` | Consolidate three validate+apply paths into `connect_block`; call hook |
| `hercules-core/src/utxo.rs` | Expose spent-entry info from `apply_block` / `rollback_block` to hook; chunked walk iterator |
| `hercules.udl` / `lib.rs` | Scan progress + cancel; wallet events |

## Dependencies

- **034** (wallet engine): determines where events are persisted
- **022 / 025**: share the `connect_block` refactor; do them first or together
- **037**: wallet DB location; **038**: passphrase wallets loaded/unloaded at runtime

## Estimated effort

- 1.5–2 weeks (refactor 2–3 days, hook + WatchSet 3 days, walk + checkpoint + progress 3–4 days, device benchmarking 1 day)

## Verification

- Regtest: wallet receives in block N → event emitted, balance updated; spends in block N+1 → spent event
- Reorg test via 027's mock peer: event unwound and replayed
- Gap-limit: payment to index 25 with gap 20 found after the earlier index-19 payment extends lookahead
- Mainnet: import a known xpub with a known balance → walk reports exact balance; record on-device timing (iPhone model, cold/warm)
- Kill the app mid-walk → resumes from checkpoint
- Push-wake budget: hook adds <50 ms to block connect with 5 wallets loaded

## Open questions

- Walk timing on oldest supported iPhone. If minutes, do we need a script-hash index (extra ~GB of storage)? Default: no index unless measurements force it.
- Should watch-only wallets be scanned in push wakes at all? Owner may want them gated (037). Scanning is harmless, but notifications reveal them.
- Silent payments (043) need a different scan (per-tx tweak computation). Will that live here or in its own module? Likely here, as a second matcher.

## Roadmap position

Right after 034. Blocks 037–040 and 021.
