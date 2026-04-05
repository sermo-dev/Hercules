# Ticket 006: Chain Reorganization Handling

## Summary

Implement detection and handling of blockchain reorganizations (reorgs) so Hercules can follow the heaviest valid chain when competing blocks exist at the same height.

## Background

- **Current behavior:** Hercules follows a single chain linearly. If the network experiences a reorg, we have no mechanism to detect it or switch to the winning chain.
- **Risk:** Without reorg handling, the node could get stuck on a stale fork, permanently diverging from consensus.
- **Frequency:** 1-block reorgs happen a few times per month on mainnet. Deeper reorgs (2-3 blocks) are rare but have occurred.

## Requirements

### Detection

- During header sync, detect when a peer provides headers that fork from our stored chain (i.e., a header whose `prev_block_hash` matches one of our headers but at a height where we already have a different header).
- Compare cumulative work (not height) between our chain and the fork to determine which is heavier.

### Rollback

- **UTXO rollback:** `rollback_block()` already exists in `utxo.rs` and restores spent outputs from the undo table. This needs to be called for each block being unwound, in reverse height order.
- **Header store:** `store.rs` needs a method to delete headers above a given height (rolling back the header chain to the fork point).
- **Validated height:** Must be rolled back to the fork point so validation resumes from the correct block.

### Replay

- After rolling back to the fork point, re-download and validate the winning chain's blocks from the fork point forward.
- The sync loop should naturally handle this once the header chain and validated height are rewound.

### Depth limit

- Enforce a maximum reorg depth (e.g., 6 blocks) to bound the rollback cost and prevent abuse. Reorgs deeper than this threshold should be flagged as errors requiring manual intervention.
- This is especially important on iPhone where disk I/O is constrained and we want bounded worst-case latency.

## Design Considerations

- **Undo data retention:** Currently `prune_undo_before()` deletes undo data for blocks older than the pruning window. The pruning depth must be >= the reorg depth limit, or we lose the ability to roll back.
- **Atomic rollback:** Header deletion + UTXO rollback + validated height update should ideally be atomic. Since headers are in one SQLite DB and UTXOs in another, consider a two-phase approach: rollback UTXOs first (idempotent via `INSERT OR IGNORE`), then delete headers, then update validated height.
- **Peer coordination:** After detecting a reorg, we may need headers from a different peer than the one that served the stale chain. The peer pool's `best_peer()` selection should factor in which peer is on the winning chain.
- **UI notification:** Surface reorg events to the user via `SyncStatus` (e.g., a `reorg_depth: Option<u32>` field).

## Testing Strategy

- Unit tests: Create a header chain, fork it, verify rollback + replay produces the correct final state.
- Integration test: Simulate a 1-block reorg with UTXO set, verify balances are correct after the reorg.
- Edge cases: Reorg at exactly the pruning boundary, reorg while validation is paused, reorg deeper than the depth limit.

## Estimated Effort

Medium-large. Touches `store.rs`, `utxo.rs`, `sync.rs`, and `lib.rs`/UDL for the status update. The UTXO rollback path exists but hasn't been exercised in the sync loop yet.
