# Ticket 024: Bad Data From a Peer Penalizes the Peer — It Doesn't Halt the Node

## Status (2026-10-26)

**Done.** Merged in PR #24 (merge commit 3347a37) after five review rounds; 505 Rust tests pass, 3 ignored.

### Follow-ups
- **Colluding stale witnesses.** Peers with valid but stale headers can still outvote an honest peer in the cross-check. They can no longer get it banned: disagreement only lowers its ranking (demerits are never persisted and never count toward a ban). Revisit if ranking manipulation proves practical.
- **Progress messages use the error banner.** "Checking a peer's headers…" and "Checking a competing header chain…" go through `status.error`, like the existing "Reorg: rolled back…" text, so they show in the red banner. A neutral status line would read better.
- **Still-ignored tests:** `wake_path_follows_one_block_reorg` and `withheld_reorg_blocks_leave_node_on_old_tip` belong to **025**; `bip34_accepts_core_encoding_at_low_heights` belongs to **026**.
- **026 interaction:** when 026 lands, classify its new error variants under this ticket's scheme (e.g. `MissingContext` is a local fault, not a consensus failure).


## Summary

Today, if a single peer serves a bad block or a bad header batch, the whole sync stops. Every block and header validation failure in the main sync loop and in `catch_up_blocks` is returned as `Err` out of the function. The offending peer is never penalized, the loop exits, and the next attempt may pick the same peer again.

This ticket classifies failures into three kinds:

- **Bad delivery:** the peer's fault, and the block may still be fine.
- **Invalid block:** a consensus failure, which permanently invalidates that chain.
- **Local fault:** a disk or database error.

Each kind gets its own response. Peers are penalized and the node retries from someone else. Invalid blocks are remembered so they are never followed again. Only local faults still stop sync.

**Severity: High.** One malicious or buggy peer can currently stall the node indefinitely. That is a cheap denial of service against exactly the users who rely on Hercules for verification.


## Amendment (2026-10-24, findings from the 027 harness)

The 027 harness (`hercules-core/src/testkit/`) has `#[ignore]`d tests for each of these; un-ignore them as they're fixed.

- **Empty-headers stall.** A peer that advertises a higher height but answers `getheaders` with zero headers keeps being picked as the sync peer. The node concludes it is synced and never asks the honest peers.
- **Two-peer cross-check.** With exactly two peers that disagree, the witness is banned and the survivor's headers are then accepted with no cross-check at all. Require a fresh second opinion (or stay unsynced) instead.
- **Stripped witness misclassified.** A block delivered with its witness data removed fails as a consensus error (block marked invalid) instead of as a bad delivery (re-request from another peer, penalize the sender). Distinguish by checking the witness commitment / wtxid merkle root before script validation.
- **Network magic not checked on incoming messages.** The 4-byte magic of received messages is never compared with the chain's magic.

## Background

### Where the node halts

The main loop in `HeaderSync::sync` (`hercules-core/src/sync.rs`) has four exits of this kind:

| Line | Failure | Current handling |
|---|---|---|
| `sync.rs:1073` | Block hash ≠ requested header | `return Err(SyncError::Validation(...))` |
| `sync.rs:1111-1112` | `validate_block` fails | `.map_err(SyncError::Validation)?` |
| `sync.rs:1115-1116` | `validate_block_scripts` fails | `.map_err(SyncError::Validation)?` |
| `sync.rs:~1580-1588` | `validate_headers` fails on a normal extension | `.map_err(SyncError::Validation)?` |

`catch_up_blocks` repeats the same pattern at `sync.rs:2544` (hash mismatch), `sync.rs:2574-2575` (`validate_block`) and `sync.rs:2578-2579` (scripts).

None of these calls `pool.misbehaving(...)`. By contrast, block-download *errors* are handled well: the peer is removed and the loop continues (`sync.rs:~1047-1065`). The fork path also handles bad reorg headers well, with `misbehaving(.., 50)` and `continue` (`sync.rs:~1478-1486`). The validation failures are the outlier.

`SyncError` (`sync.rs:2673`) has only `NoPeers | Peer(String) | Validation(String) | Store(String)`. A `Validation` string can't tell "this peer sent garbage" apart from "this block breaks consensus".

### Why the distinction matters

If a block whose hash matches our header fails validation, there are two very different explanations.

1. **Mutated delivery.** The block hash covers only the 80-byte header. A peer can strip or alter witness data, or send a CVE-2012-2459-style duplicated transaction list, and the hash still matches. The block on the network may be perfectly valid, and only this peer's copy is bad. In this case: penalize the peer, re-fetch from another peer, and **do not** mark the block invalid. If we did, an attacker could permanently blind us to a valid chain. Bitcoin Core handles this with `IsBlockMutated`: merkle and witness-commitment failures count as delivery problems.
2. **Genuinely invalid block.** The structure is intact (merkle root and witness commitment correct), but it breaks a consensus rule: a bad script, too much coinbase value, spending a missing input. Then the header chain itself is invalid. Mark the block and all its descendants as failed, the equivalent of Core's `BLOCK_FAILED_VALID`/`FAILED_CHILD`. Never request or follow it again, and fall back to the best valid chain. Whether to penalize the peer that served it depends on context. Core does not punish a peer for relaying an invalid block it didn't create, *unless* it announced that block via compact blocks or sent its headers as the best chain.

Today Hercules does neither. It stops.

## Proposed fix

1. **Typed failure classes.** Introduce `BlockFailure`:
   - `Delivery { reason }`: hash mismatch, merkle failure, witness-commitment failure, duplicate txids, malformed data.
   - `Consensus { reason }`: any other `validate_block` / `validate_block_scripts` failure on a non-mutated block.
   - `Local(StoreError)`: LMDB, SQLite or filesystem errors.

   `validate_block` returns `BlockValidationError` variants. Map them to `Delivery` vs `Consensus` with an explicit `is_mutation()` method next to the enum in `block_validation.rs`, so adding a new variant forces someone to decide which class it belongs to.
2. **Invalid-block cache.** Add a `failed_blocks` table to `store.rs`. When a block fails `Consensus`, record its hash. Descendants are implied, because anything building on it fails linkage against a known-failed parent.
   - Header sync refuses headers that connect to a failed block.
   - The block-fetch loop never requests a failed hash.
   - When our current header chain is invalidated, roll headers back to the fork point. Reuse ticket 025's rollback-ordering work rather than writing a second rollback path.
3. **Response matrix in `sync()` and `catch_up_blocks()`:**

| Class | Peer | Block/chain | Loop |
|---|---|---|---|
| `Delivery` | `misbehaving(addr, 20)` (hash mismatch already gets a penalty via 022) | not marked | retry the same height from a different peer |
| `Consensus` | `misbehaving(addr, 100)` only if this peer announced that header chain to us; otherwise none | mark failed; drop headers above the fork | re-sync headers from the remaining peers |
| `Local` | none | not marked | propagate `Err` as today |
| invalid extending headers | `misbehaving(addr, 50)` (matches the fork path) | not stored | `continue` |

4. **Attempt cap.** If every connected peer gives `Delivery` failures for the same height N times in a row, surface a clear status ("peers are serving corrupted blocks at height X") instead of looping forever. Rotating to new peers through addrman is the remedy.
5. **Surface failures.** `make_status` / `CatchUpStatus` gets an `invalid_chain_detected: bool` plus a message. The UI can then show "Rejected an invalid block from the network" instead of a generic error.

### Follow-up from ticket 023 review: recovering from a fake low-work header chain

Ticket 023 stops a fresh node from *accepting* a fake low-difficulty header chain (anchor check at height 943,500 + minimum-work gate), but an eclipsed fresh install can still get **stuck**. If every early peer is hostile and feeds min-difficulty headers that stop just below the anchor, those headers are stored. When honest peers appear, their chain forks near genesis, and the reorg path refuses it (depth far beyond `MAX_REORG_DEPTH = 288`, and the batch-vs-stored chainwork comparison can't see the honest chain's real work from one 2,000-header batch).

Block validation is already gated on minimum work (023), so headers stored while below minimum work have never been used for anything. Options:

1. **Headers presync (Bitcoin Core's approach, net_processing):** download a peer's headers in a first pass that only tracks cumulative work (storing a compact commitment, not the headers), and only store them in a second pass once that chain has proven `min_chain_work`. A fake low-work chain is never stored at all. Most robust; most work.
2. **Treat below-min-work headers as scratch:** while `!has_min_chain_work()`, lift `MAX_REORG_DEPTH` and, when a peer's headers fork from ours, replace the stored headers above the fork point (strict 2-peer cross-check still applies). Worst case is ping-pong between chains until the honest one reaches the anchor. Small change.
3. **Wipe on anchor conflict:** when a batch conflicts with the anchor while below minimum work, delete all stored headers and restart header sync with fresh peers. Simplest; costs one re-download of headers (~75 MB) per incident.

Recommendation: ship option 2 (or 3) with this ticket; consider option 1 later. This is P2P-layer logic, so libbitcoinkernel (047) doesn't cover it either way. Test with ticket 027's mock peers: hostile peer feeds a cheap chain to anchor−1, then honest peers connect, and the node must reach and activate the anchor.

## Files touched

| File | Action |
|---|---|
| `hercules-core/src/block_validation.rs` | `BlockValidationError::is_mutation()` |
| `hercules-core/src/sync.rs` | `BlockFailure` classification; the response matrix at the 7 sites above; retry-from-another-peer helper shared by `sync` and `catch_up_blocks` |
| `hercules-core/src/store.rs` | `failed_blocks` table plus `is_failed(hash)` / `mark_failed(hash)` |
| `hercules-core/src/lib.rs` / `hercules.udl` | Status flag for invalid-chain detection |
| `HerculesApp/HerculesApp/ContentView.swift` | Show the invalid-block / corrupted-peers status |

## Dependencies

- **022** should land first. It fixes the hash binding inside `get_block`, which removes most `Delivery` hash-mismatch cases at the source.
- **025** (reorg hardening) shares the "drop headers above a fork point and reconnect" machinery. Whichever lands first builds it, and the other reuses it.
- **027** is needed to test this meaningfully. Each row of the matrix is a mock-peer behavior.

## Estimated effort

About 2–3 days, including classification, the failed-block store and tests.

## Verification

All of these run through the 027 mock-peer harness:

- A peer serves a block with stripped witness data. The peer is penalized, the block is fetched from a second peer and validates, and sync continues. The block is **not** in `failed_blocks`.
- A peer serves a structurally intact block that overpays the coinbase. The block is marked failed, its headers are dropped, and the node follows the honest peer's chain.
- A peer sends invalid extending headers (bad PoW). It is penalized and sync continues with other peers.
- Every peer serves corrupted blocks at height X. After N attempts, the status shows the corrupted-peers message and the loop doesn't spin.
- An LMDB write failure (injected) is still returned as `Err`, with no peer penalty.
- After a restart, a failed block is still refused.

## Open questions

- **Penalty values.** The values above follow the existing scale (`HEADER_DIVERGENCE_PENALTY = 50`, `BAN_LOW_THRESHOLD = 20` in `peer_pool.rs:467`). Tune them after 027 shows how often honest peers trip `Delivery` failures over Tor.
- **Should a consensus-invalid block alert the user?** An invalid block with real proof-of-work is a notable event: either an attack or a consensus bug on our side. Recommendation: show a visible but non-alarming status, and add an entry to the notification history.
- **Mempool:** a recently-rejected *transaction* filter is related but deliberately out of scope here. It belongs with the mempool memory work in ticket 030 (on-device storage and memory).

## Roadmap position

Safety tier step 3: **022 → 023 → 024 → 027 → 025/026**. In practice this lands together with 027, since every row of the response matrix needs a mock-peer test.
