# Ticket 050: One Block-Connect Path, Pruning That Runs, and Safe Resets

## Summary

Blocks are connected in three places: the foreground sync loop, the push-wake `validate_latest_block`, and `catch_up_blocks`. Only the foreground loop prunes, and only when the block it just validated is exactly a multiple of 1000. Phones kept current by background wakes therefore never prune, and storage grows by GBs a month until the low-disk guard stops the node.

Separately, an interrupted `reset_database` can leave a UTXO set that the next launch rolls back past its pruned undo data. That corrupts the set and condemns the honest chain.

This ticket:

1. Consolidates the three connect paths into one `connect_block`. Pruning, the own-tx hook, and later the wallet hook (035) and reorg handling (025) live there.
2. Makes pruning run on every path, triggered by how much is stored rather than by a modulo.
3. Makes reset and snapshot activation safe against interruption, and enforces the prune/reorg coupling in code.

**Severity: High.**
- **Pruning:** certain, slow-burn storage exhaustion for typical users.
- **Reset:** rare but catastrophic (stuck node with a corrupt UTXO set).

Found by the chainstate and wallet reviewers (2026-10-28 team review of main @ 7732755). Pruning on every connect path was item 3 of the earlier whole-repo review, where this ticket number was reserved.

## Background

Line numbers are at main 7732755.

### Pruning almost never runs

- `sync.rs:3047-3055` is the only caller of `utxo.prune_undo_below` and `block_store.prune_below`. It runs inside `run_sync`, and only when `next_height % 1000 == 0`.
- `catch_up_blocks_in` (`sync.rs:4927-4950`) and `validate_latest_block_in` (`4533-4561`) never prune. The recovered-block path `continue`s past the prune (`2968-2981`).
- Wakes don't run while the app is in the foreground, so every block that arrives in the background goes through a wake. If height N×1000 is validated by a wake, that whole epoch is never pruned: about 1.6 GB of blocks in `blocks.sqlite3` and 0.5 GB of undo in `data.mdb`, which never shrink.
- Tests never reach a height divisible by 1000, so pruning is untested end to end.

### Three connect paths

`on_block_connected` (`sync.rs:2192-2197`, from 033) is already called from all three apply sites (`3023`, `4534`, `4929`). Validation, apply, block storage, the hook and `set_validated_height` are still written out three times with small differences. 025 and 035 both need one path.

### Interrupted reset corrupts the set

`lib.rs:113-150` (`reset_database`) deletes the headers DB first and the LMDB env last. If the reset is killed, or an earlier `remove_file` errors and returns, after the headers are gone but before `utxo-lmdb` is removed, then on relaunch:

1. `needs_snapshot` is false (count > 0), so header sync runs from genesis.
2. `activate_pending_snapshot` (`sync.rs:1020-1074`) sees `validated (0) < floor` and sets `validated = floor` without checking `utxo.best_block()`.
3. `utxo_has_block` then rolls the set from its real height H back to the floor. `rollback_block_txn` (`utxo.rs:987-1078`) doesn't check that undo data exists. For every height whose undo was pruned, it deletes the created coins and restores nothing, then sets `best_block` to the anchor hash.
4. Block floor+1 fails with `MissingUtxo`, which counts as a consensus failure. `utxo_out_of_step` sees the set as in step, so the honest block is recorded as failed, its announcer is banned, and the node is stuck.

### Smaller storage gaps

- **`reset_database` doesn't remove `own_txs.sqlite3`.** Own transactions from the old chain state survive the reset.
- **No `MDB_MAP_FULL` retry when pruning undo, and none in `clear_all`.** `utxo.rs:1617-1631`: if a failed snapshot load's cleanup also hits `MapFull`, the marker stays but the reused node treats the partial set as genesis-mode (`needs_snapshot() == false`) until the next launch wipes it.
- **`blocks.sqlite3` never shrinks after deletes** (no `auto_vacuum`), and `block_store.prune_below` isn't in a transaction with anything.
- **No schema versions.** There is no `schema_version` in LMDB `meta` and no `PRAGMA user_version` in the SQLite stores. 025 needs a block_store migration and 035/037 add wallet tables, so versioning must exist first.

## Proposed fix

### 1. `connect_block`

One function used by all three paths:

```
connect_block(block, height, ctx) -> Result<Connected, ConnectError>
  check_block (mutation, structure)  → validate_block → validate_block_scripts
  utxo.apply_block                    (one LMDB txn, writes best_block)
  block_store.store_block
  hooks: own_txs.on_block_connected   (035 adds the wallet hook here)
  store.set_validated_height
  maybe_prune(validated)
```

- **Kill safety:** keep today's crash-recovery behavior between steps; the existing tests for the main loop now cover every path.
- **Spent coins:** `apply_block` returns the spent coins it already writes to undo (`utxo.rs:732-737`). 035 (wallet events), 041 (per-tx fees) and 043 (BIP352 input pubkeys) need them; returning them now costs nothing.

### 2. Pruning by stored size

- `maybe_prune` runs after every connect, on every path. It prunes when `block_store.lowest_height() < validated - KEEP - SLACK` (`KEEP` = 288, `SLACK` ≈ 144), not on a modulo.
- Prune undo and block_store in a bounded step per call, so a wake that inherits a large backlog spends a capped amount of time pruning.
- Test hook: a `cfg(test)` way to set `KEEP`/`SLACK` small, so the harness exercises pruning.
- `PRAGMA auto_vacuum = INCREMENTAL` on `blocks.sqlite3` (migration: one-time `VACUUM` in a processing task), and `incremental_vacuum` after pruning.
- `MDB_MAP_FULL` during pruning grows the map and retries, as `apply_block` does.
- **Prune lock (for 035):** an API to hold back pruning above a height (`set_prune_floor(height)`). It is inert until a wallet registers. It is designed here because `maybe_prune` is written here.

### 3. Safe reset and activation

- **`reset_database`:** write `utxo-lmdb.loading` before any unlink, delete the LMDB env first, then the other stores including `own_txs.sqlite3`. An interrupted reset is then always finished by the next open.
- **`activate_pending_snapshot`:** require `utxo.best_block() == (floor, snapshot hash)` before setting `validated = floor`. Otherwise the set is not the snapshot's: wipe it via the marker protocol and require a re-import.
- **Undo floor:** record `undo_pruned_below` in LMDB `meta` in the same txn as `prune_undo_below`. `rollback_block` refuses heights below it with a local error, never a consensus one.
- **Partial set after a failed load:** `needs_snapshot` and activation honour the `.loading` marker; `clear_all` grows the map and retries on `MapFull`.

### 4. Schema versions

- `schema_version` key in LMDB `meta`; `PRAGMA user_version` in `headers.sqlite3`, `blocks.sqlite3`, `own_txs.sqlite3` and `peers.sqlite3`.
- On open: refuse a newer version with a clear error (the app was downgraded); migrate an older one.
- Starting values describe today's layout, so this is a no-op for existing installs.

## Files touched

| File | Action |
|---|---|
| `hercules-core/src/sync.rs` | `connect_block` used by the three paths; `maybe_prune`; activation check |
| `hercules-core/src/utxo.rs` | `apply_block` returns spent coins; `undo_pruned_below`; rollback guard; MapFull retry in prune/`clear_all`; `schema_version` |
| `hercules-core/src/block_store.rs` | Transactional prune; `auto_vacuum`; `user_version` |
| `hercules-core/src/store.rs`, `own_tx_store.rs`, `peer_store.rs` | `user_version` |
| `hercules-core/src/lib.rs` | Reset order; remove `own_txs` |
| `hercules-core/src/testkit/` | Configurable prune window; kill points on all three paths |

## Dependencies

- **024**: `best_block` marker and failed-block classification, both relied on here.
- **027**: harness.
- **Blocks:** 025 (reorg revert reuses `connect_block`) and 035 (wallet hook and prune lock).

## Estimated effort

4–5 days:
- `connect_block` consolidation: 1.5 days
- pruning and vacuum: 1 day
- reset and activation safety: 1 day
- schema versions: 0.5 day
- tests: throughout

## Verification

- **Pruning in wakes:** `catch_up_blocks` across several prune windows (small `cfg(test)` window). `block_store.lowest_height()` and the undo count stay bounded; the same for `validate_latest_block`.
- **Interrupted reset:** remove only the headers DB, keep an env whose undo is pruned past the floor, then sync. No block is marked failed, and the set is wiped and re-imported (or refused).
- **Rollback guard:** `rollback_block` below `undo_pruned_below` errors (today it silently succeeds).
- **Round trip on a snapshot-loaded set:** apply N blocks that spend snapshot coins, roll back N; MuHash equals the original.
- **Prune boundary:** a reorg exactly 288 deep right after a prune is followed; 289 is refused cleanly.
- **Kill points:** between apply, `store_block`, the hook and `set_validated_height`, on all three paths.
- **Activation:** `activate_pending_snapshot` with `best_block ≠ (floor, hash)` wipes instead of activating.
- **Schema:** opening a store with a newer `user_version` fails with a clear error.

## Open questions

- **`SLACK` size:** larger means fewer, bigger prunes. 144 (about a day) is a reasonable start; measure prune time on a device.
- **Existing over-grown installs:** the first `maybe_prune` after the update may delete GBs. Recommendation: do the first large prune in a processing task (power and Wi-Fi), bounded per call elsewhere.

## Roadmap position

Second in the pre-wallet hardening block: **049 → 050 → 053 → 054 → 052 → 025**, then 035. 050 must land before 025 and 035 because both build on `connect_block`.
