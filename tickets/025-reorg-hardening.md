# Ticket 025: Reorg Hardening — Validate the New Branch Before Abandoning the Old One

## Review update (2026-10-28)

The team review of main @ 7732755 raised this ticket's priority and found gaps in its scope. **Priority: High, before wallet work.** Today any 1-block reorg of our tip makes every background wake fail until the user opens the app: `sync.rs:4639` builds a single-hash locator, and `4676-4681` gives up with "reorg?". That breaks arrival notifications and leaves stale confirmations, exactly what 035/040 will display. **Revised estimate: 1–1.5 weeks.**

Parts of the background below are out of date:
- 024 already added `rollback_utxo_to` and the UTXO `best_block` marker.
- Line numbers have moved; the reorg is now `apply_reorg` (`sync.rs:1560-1615`).
- 050 introduces the shared `connect_block` that the revert path should reuse.

**Added to scope:**

1. **Hash-keyed block_store.** Blocks are keyed by height with `INSERT OR REPLACE` (`block_store.rs:36-41, 59-62`). Connecting a new-branch block deletes the old-branch block at that height, so "reconnect our old blocks from block_store" can't work.
   - Change to a hash-keyed schema (several blocks per height, with an active flag), with a migration (uses 050's schema versions).
   - Cope with missing rows: the store runs `synchronous=NORMAL` and can lose recent blocks on power loss, so the revert must be able to refetch them.
2. **Undo records carry hash and prev-hash.** Store each applied block's hash and prev-hash with its undo data in LMDB, so rollback sets `best_block` from the UTXO set's own record (drop the `UNKNOWN_BLOCK_HASH` workaround).
3. **One SQLite transaction for the header switch.** `apply_reorg` currently uses three: delete, `set_validated_height`, store.
4. **Disconnect hook.** `on_block_disconnected(height, block, spent_coins)` alongside 050's connect hooks. Today a reorg only calls `own_txs.demote_confirmed_above` (`sync.rs:1612`). 035's inverse wallet events depend on it.
5. **Mempool after a reorg (Core's `removeForReorg`).** Re-add disconnected transactions (already in scope), then re-check finality and BIP 68 for every mempool entry against the new tip. This was deferred from 026. Emit the removals on 053's event stream.
6. **Prune/reorg coupling enforced in code**, via 050's `undo_pruned_below` guard, not just the comment at `sync.rs:44-53`.

**Dependencies added:** 050 (`connect_block`, schema versions, undo guard) and 053 (mempool event stream).

## Summary

Hercules handles chain reorganizations in the main sync loop, but in the wrong order. It validates the new branch's *headers*, then immediately rolls back the UTXO set and deletes our headers above the fork point. Only after that does it start downloading and validating the new branch's *blocks*. If those blocks are withheld or invalid, the node is left rolled back with no valid tip.

Three related problems:

- The mempool is wiped on every reorg instead of re-adding the disconnected transactions.
- The push-wake path can't follow a reorg at all.
- The catch-up path can't follow a reorg either.

This ticket reorders the flow so it is safe, keeps transactions from the disconnected blocks, and teaches the background paths to handle the common 1–2 block case.

**Severity: Medium.** Reorgs are routine, so the background-path gap affects real users regularly. The rollback ordering only matters when a peer is malicious or broken, but when it does, the node is stuck.

## What a reorg is

Two miners sometimes find a valid block at the same height within seconds of each other. For a short time the network is split: some nodes see block A as the tip, others see block B. The tie breaks when the next block is found, because whichever branch it builds on now has more total work and wins.

Nodes that were following the losing branch must **reorganize**:

1. Undo the stale block: restore the coins it spent, delete the coins it created.
2. Apply the winning block(s) in order.

One-block reorgs happen every few weeks on mainnet. Two-block reorgs are rare, and deeper ones essentially don't happen without an attack.

For a wallet user, a reorg means a payment that had "1 confirmation" briefly has 0. That payment usually returns in the winning branch, because the same transaction gets mined again. If your node discards it from the mempool, though, your wallet will wrongly show it as gone until it's re-mined.

## Background

### Main loop: rollback happens before the new blocks are validated

The reorg path is in `HeaderSync::sync`, `hercules-core/src/sync.rs:~1368-1560`:

1. **Fork detection** (`sync.rs:1372`): `headers[0].prev_blockhash != tip_hash`. The loop walks forward to find `fork_at` and computes `reorg_depth`. If the depth is over `MAX_REORG_DEPTH = 288` (`sync.rs:46`) it is rejected.
2. **Work comparison** (`sync.rs:~1440`): the new chain must have strictly more work. This only compares the headers **within the received batch** against ours above the fork.
3. **Header validation** (`sync.rs:~1474-1486`): the new headers are validated against the fork point. On failure the peer gets `misbehaving(.., 50)` and our chain is untouched. ✅
4. **Destructive steps** (`sync.rs:~1490-1525`): `utxo.rollback_block(h)` for every validated block above the fork, then `delete_headers_above(fork_at)`, then `set_validated_height(min(current, fork_at))`, then `store_headers(new_headers)`.
5. **Mempool wipe** (`sync.rs:~1532-1545`): every transaction is removed. ("Clear the mempool — transactions may reference UTXOs that no longer exist.")
6. The loop `continue`s, and later iterations download and validate the new blocks as a normal extension.

The problem sits between steps 4 and 6. At that point:

- our old blocks' UTXO effects are gone,
- our old headers are deleted, and
- the new branch's blocks have never been seen.

If the peer that sent the more-work headers then withholds the blocks, or serves invalid ones, the node is stuck at `fork_at`. Today step 6 will also hit the `Err`-and-halt behavior that ticket 024 fixes. An attacker with no mining power can't make the headers valid. But a buggy or malicious peer, or a real but invalid chain that has PoW, can strand us.

### Background paths have no reorg handling

`validate_latest_block` (`sync.rs:2134`) and `catch_up_blocks` (`sync.rs:2350`) request headers with the one-entry locator `vec![tip_hash]` (`sync.rs:2188` and `sync.rs:2418`). They do not use the full exponential locator that `store.get_locator_hashes()` (`store.rs:252`) already builds. If our tip was reorged out, the peer doesn't consider it part of its active chain. It falls back to an earlier common point and sends headers that don't connect to `tip_hash`. `validate_headers` then fails with `ValidationError::BadPrevHash` (`validation.rs:213`), returned as `SyncError::Validation`.

The push wake reports an error, and the node waits until the next foreground session. A routine 1-block reorg turns every subsequent wake into a failure until the user opens the app.

## Proposed fix

### 1. Validate the new branch first, then switch ("connect-before-commit")

In the main loop, after the header validation step:

1. Download the new branch's blocks, from `fork_at + 1` to the new tip, into memory or a staging area. This is bounded: depth ≤ 288, and realistically 1–2 blocks.
2. Disconnect our blocks back to the fork point using the undo data (`rollback_block`), the same as today.
3. Connect the new blocks one at a time with full `validate_block` + `validate_block_scripts` + `apply_block`.
4. **On any failure while connecting:**
   - roll back the new blocks applied so far,
   - reconnect our old blocks from `block_store`, which keeps the last ~288 blocks for exactly this reason,
   - restore our old headers,
   - mark the failing block as failed (ticket 024's `failed_blocks`), and
   - penalize the source peer.
5. Only after the new tip is fully connected: commit the header switch and update `validated_height`.

Header storage changes should become a single "switch active chain to X" operation, so a crash in the middle is recoverable. A simple reorg-in-progress marker, like the snapshot loading marker in `utxo.rs`, records the fork point and both tips.

### 2. Keep the user's transactions on reorg

Replace the mempool wipe with what Core does:

- Collect the non-coinbase transactions from the disconnected blocks.
- After the new chain is connected, try to re-add each one to the mempool with `accept_tx` against the new UTXO set, in block order. Anything that conflicts or is already confirmed in the new chain is dropped naturally.
- Then re-check the existing mempool entries and evict any whose inputs are now missing or conflicted.

This also matters for the wallet's outgoing-transaction tracker (ticket 033). Our own transaction should survive a reorg and keep being rebroadcast.

### 3. Background paths: handle shallow reorgs within budget

- Use the existing exponential locator, `store.get_locator_hashes()`, instead of `vec![tip_hash]`. The peer's response then connects at the true fork point.
- If the fork is ≤ 2 deep and the 30-second wake budget allows, run the same connect-before-commit flow.
- Otherwise, store nothing destructive and return a `ReorgPending { depth }` status. The Live Activity and widget show "Chain reorganized — open Hercules to finish" (rare), and the foreground loop handles it.

### 4. Strengthen the work comparison

Compare **cumulative chainwork** (using ticket 023's stored running chainwork) rather than only the batch. A peer can then never trigger a reorg with a partial batch that only *looks* heavier.

## Files touched

| File | Action |
|---|---|
| `hercules-core/src/sync.rs` | Reorg path reordered (download → disconnect → connect → commit / revert); shared `reorganize_to(fork_at, new_headers)` used by `sync`, `validate_latest_block` and `catch_up_blocks`; background paths switch to `get_locator_hashes()` |
| `hercules-core/src/store.rs` | Atomic active-chain switch; reorg-in-progress marker |
| `hercules-core/src/utxo.rs` | No API change expected. Confirm that `rollback_block` + `apply_block` round-trip correctly at the prune boundary |
| `hercules-core/src/block_store.rs` | Fetch old-branch blocks for reconnection; keep orphaned-branch blocks until the reorg commits |
| `hercules-core/src/mempool.rs` | `readd_disconnected(txs)`; post-reorg re-check of existing entries |
| `hercules-core/src/lib.rs` / `hercules.udl` | `ReorgPending` status for the wake paths |
| `HerculesApp/HerculesApp/NotificationManager.swift` | Show the reorg-pending state in the Live Activity and notifications |

## Dependencies

- **024**: failed-block marking and peer penalties for the revert path.
- **023**: cumulative chainwork storage, and the rule that no reorg may cross the snapshot anchor.
- **027**: required for testing. A reorg can't be reproduced on demand on mainnet.

## Estimated effort

About 3–4 days. The main-loop reorder plus revert is about 2 days, the mempool re-add about 0.5 day, the wake-path support about 1 day, and tests are spread across all of it.

## Verification

All of these run through the 027 harness on regtest:

- **1-block reorg in the foreground.** Node at tip A₁; a peer presents B₁→B₂ forking at A₀. Node ends on B₂, the UTXO set equals a fresh sync of B₂, and txs that were in A₁ but not B₁/B₂ are back in the mempool.
- **Withheld blocks.** Valid B headers are served but `getdata` for B₁ is never answered. The node stays on A₁ with A's UTXO set intact, and is never left at `fork_at`.
- **Invalid new branch.** B₂ overpays the coinbase. The node reverts to A₁, B₂ is marked failed, and the peer is penalized.
- **Crash mid-reorg.** Kill the process after disconnect and before connect. On restart the marker is detected and the node completes or reverts cleanly.
- **Reorg at the prune boundary.** Fork exactly 288 deep. The undo data and `block_store` blocks are present; one deeper is rejected.
- **Push wake, 1-block reorg.** `validate_latest_block` follows it within budget and returns `validated: true` for the new tip.
- **Push wake, deep reorg.** Returns `ReorgPending` without touching state.

## Open questions

- **Staging large reorgs.** For depth > 2 in the foreground, hold the downloaded blocks in memory (≤ 288 × 4 MB worst case, which is too much on iOS) or stage them to `block_store`. Recommendation: stage to `block_store` under a "pending" flag. Blocks are only promoted when the switch commits.
- **What the user sees.** Should a reorg that removes a confirmation from one of the user's own wallet transactions trigger a notification? Recommendation: yes, but phrase it calmly ("Your payment's confirmation was reshuffled; it's back in the queue"). Decide in the wallet tickets.

## Roadmap position

Pre-wallet hardening block, last before 035: **049 → 050 → 053 → 054 → 052 → 025**, then 035. (Originally: safety tier after 024 and 027; 026 has since landed.)
