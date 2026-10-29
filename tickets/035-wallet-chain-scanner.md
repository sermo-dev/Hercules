# Ticket 035: Wallet Chain Scanner

## Decisions (2026-10-23)

- **Decided (2026-10-24):** the BIP158 filter-serving phase is dropped from this ticket. Its only consumer was external wallets via ticket 014's custom onion API, which no existing wallet speaks. This ticket is the in-app scanner only. If filter serving is ever wanted, it gets its own ticket.
- **Superseded (2026-10-28):** ~~a prototype of Phase 1 exists on branch `ticket-020-in-app-wallet`; reuse it.~~ Don't reuse the code (see Review update). Keep only its ideas, listed there.

- **Added (2026-10-24):** the scanner stores the full funding transaction for every wallet coin it sees in a block, and can fetch a single historical block from an archival peer (height comes from the UTXO entry; verify against our headers + merkle root) when a pre-snapshot coin needs its parent tx for a legacy or hardware-wallet spend (see 034).

## Review update (2026-10-28)

From the wallet-readiness review of main @ 7732755. These corrections take precedence over the design below where they conflict.

**Prerequisites:**
- **050:** `connect_block`, with `apply_block` returning spent coins, and the prune lock.
- **025:** disconnect hook and hash-keyed block_store.
- **054:** a wake's `caught_up` means peers agreed.

The "consolidate three paths" refactor in this ticket's design is done by 050, not here. 033's `on_block_connected` (`sync.rs:2192-2197`) already exists and is the model for the wallet hook.

**Scope is the node half only** (milestone M1). No wallet UI is built until it exists.

**Corrections:**

1. **History start.** "History starts at the snapshot height" is wrong for restore and import on an established node: blocks between the snapshot and the last ~288 are already pruned, so history starts at the oldest stored block. The snapshot-height claim holds only if, on a fresh install, the wallet is registered and walked *at the snapshot height, before catch-up*. Specify that ordering, and show the real starting block in the UI. (Same fix in 039.)
2. **Gap limit.** Gap-limit discovery can't work from a UTXO walk: the set can't show used-but-now-empty addresses, so "lookahead 20, extend on a hit" misses coins beyond a run of spent addresses. Walk with a large fixed lookahead (≥1,000 per chain per script family); it only costs HashMap entries. Accept that a restored wallet may reuse an address it handed out before.
3. **Wallet history is not a rebuildable cache on a pruned node.** Keep history rows on a chain-data wipe and reset only the scan checkpoint (fixes 037's "rebuilt by rescan"). 039's transfer bundle must include history and stored funding transactions.
4. **Hook contract.** The hook receives spent prevouts (from 050) and is delivered at-least-once and idempotently: crash recovery re-runs it (`sync.rs:1741-1758`). The disconnect hook comes from 025. Wallet events go into `WakeReport` so a wake can post "received".
5. **Chunked UTXO walk.** One long read txn is not an option: every read holds `read_gate` (`utxo.rs:544`) and map growth takes it exclusively (`utxo.rs:566-567`). Walk in chunks with fresh txns, returning `best_block` (height and hash) from the same txn, then rescan blocks applied meanwhile.
6. **Gated reads.** Reads and the walk refuse until the snapshot is verified and active. Today `rpc_get_utxo` (`sync.rs:1286`, `wallet_rpc.rs:468`) answers mid-import, and its `null` looks like "spent". `rpc_get_block` returns orphaned blocks by hash, so rescans check hashes against the header chain.
7. **By-height block read.** `block_store.rs:68` only has `get_block_by_hash`.
8. **Prune lock.** Never prune above the oldest registered wallet's last-scanned height (bounded); otherwise fall back to a UTXO walk. The API comes from 050.
9. **Silent payments (043).** Scanning in wakes needs the scan *private* key, which conflicts with 036's "wakes never touch key material". Owner decision: classify the scan key as watch-level, or limit SP detection to the foreground.

**Before writing the hook:**
- Run the walk benchmark on the oldest supported iPhone (~1 day). It decides whether passphrase wallets (038) are usable and whether a script index is needed.
- Run 048's regtest leg (~1 day).

**t20 WIP verdict: discard the code, keep the ideas.**
- **Why discard:** it is 85 commits behind, its hook sites no longer exist, and it contradicts later decisions: a single xpub, BIP84 only, hand-parsed SLIP-132 instead of descriptors (034), and an LMDB wallet store where 037 decided SQLite.
- **Bugs to avoid repeating:**
  - Balance bug: a coin received and spent in the same block is never marked spent. Spends are looked up (`wallet.rs:283`) before that block's batch is written (`:327`).
  - One history row per block, using a representative txid.
  - A single-txn walk with a lookahead of 20.
  - Hook errors swallowed with `warn!`.
  - Addresses copied to the shared pasteboard without `localOnly` or expiry.
- **Keep:**
  - the `attach_wallet` catch-up policy: walk if the wallet is behind the stored-block window, otherwise replay stored blocks;
  - the `wallet_store` test cases, as a checklist;
  - the CoreImage QR snippet.

**Testkit additions:**
- a test setting that makes pruning run (from 050);
- MockPeer transaction relay, for 040;
- wallet-derived scripts paid via `FixtureChain::spend` (`fixture_chain.rs:249`);
- reorgs via `fork_at` (`:226`);
- "walk at the anchor, then hook" via the pending-snapshot fixture (`sync_integration.rs:393`).

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

After the pre-wallet hardening block (**049 → 050 → 053 → 054 → 052 → 025**) and alongside 055's workspace split; this is wallet milestone M1 (node half). Blocks 037–040 and 021.
