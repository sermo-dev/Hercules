# Ticket 004: Phase 2 — Pruned Validating Node

## Overview

Transform Hercules from a header-only client into a fully-validating pruned Bitcoin node. This is the largest phase and is broken into four sub-phases.

## Key Design Decisions (from discussion)

- **Storage cost accepted:** ~10-12GB (8GB UTXO set + 2-4GB pruned blocks). Target users are power users who understand and accept this.
- **AssumeUTXO for onboarding:** Download ~8GB UTXO snapshot over WiFi on first launch. No full historical sync required.
- **Foreground validation for Phase 2:** Full block validation while app is in foreground. Background/push-triggered validation deferred to Phase 4.
- **UTXO set is complete:** Cannot prune "spam" UTXOs — consensus requires the full set. Relay policy (what we propagate) is separate from consensus (what blocks we accept).
- **Historical validation:** Trust the AssumeUTXO snapshot for now. Cooperative historical validation tracked separately (Ticket 003).

---

## Phase 2a: Block Download & Structural Validation

**Goal:** Download full blocks from peers and validate block structure.

### Changes

- **p2p.rs**: Add `getdata` message (request full blocks by hash), handle `block` message response
- **New: block_validation.rs**: Structural validation:
  - Recompute merkle root from transactions, verify it matches header
  - Verify coinbase transaction structure (only one, must be first)
  - Verify block reward: coinbase output <= block subsidy + total fees
  - Verify block weight/size limits
  - Verify witness commitment (SegWit blocks)
  - Transaction format validation (no empty inputs/outputs, reasonable sizes)
- **sync.rs**: After header sync, download full blocks from tip
- **store.rs**: Store raw block data temporarily (needed for pruning later)
- **UI**: Show "Downloading blocks..." progress

### Does NOT include
- Script validation (Phase 2b)
- UTXO set management (Phase 2c)

### Estimated effort: 3-4 weeks

---

## Phase 2b: Script Validation via libbitcoinconsensus

**Goal:** Validate transaction scripts using Bitcoin Core's consensus library.

### Changes

- **Cargo.toml**: Add `bitcoinconsensus` crate dependency (bundles the C library)
- **build-ios.sh**: Verify C cross-compilation works for iOS targets (may need cc crate configuration)
- **New: consensus.rs**: Wrapper around libbitcoinconsensus FFI:
  - `verify_script(script_pubkey, tx, input_index, flags) -> Result<(), ConsensusError>`
  - Determine correct script verification flags per block height (BIP activation schedule)
- **block_validation.rs**: Add script validation to block validation pipeline:
  - For each transaction input, verify the script against the previous output's scriptPubKey
  - Handle P2SH, SegWit v0, Taproot (v1) script types via appropriate flags
- **Testing**: Validate against Bitcoin Core's script test vectors (tx_valid.json, tx_invalid.json)

### BIP activation heights to handle
- BIP 16 (P2SH): block 173,805
- BIP 34 (coinbase height): block 227,931
- BIP 65 (CHECKLOCKTIMEVERIFY): block 388,381
- BIP 66 (strict DER): block 363,725
- BIP 68/112/113 (sequence locks, CSV, MTP): block 419,328
- BIP 141/143 (SegWit): block 481,824
- BIP 341/342 (Taproot): block 709,632

### Estimated effort: 2-3 weeks

---

## Phase 2c: UTXO Set Management

**Goal:** Maintain the unspent transaction output set for full block validation.

This is the hardest sub-phase.

### Database Selection

Benchmark LMDB vs SQLite for the UTXO workload:
- Write-heavy: ~3,000-5,000 inserts/deletes per block
- Read-heavy during validation: random lookups by (txid, vout)
- Total size: ~8GB, ~100M entries
- Must handle iOS memory pressure (no loading full set into memory)

LMDB is the likely winner (memory-mapped, zero-copy reads, crash-safe, single-writer/multi-reader).

### Data Model

UTXO entry key: `txid (32 bytes) || vout_index (4 bytes)` = 36 bytes
UTXO entry value: `amount (8 bytes) || script_pubkey (variable, typically 22-34 bytes) || height (4 bytes) || is_coinbase (1 byte)`

### Changes

- **Cargo.toml**: Add LMDB dependency (e.g., `heed` crate — Rust-safe LMDB wrapper)
- **New: utxo.rs**: UTXO set manager:
  - `open(path) -> UtxoSet`
  - `get(outpoint) -> Option<UtxoEntry>` — look up a UTXO
  - `apply_block(block, height) -> Result<(), UtxoError>` — spend inputs, create outputs
  - `rollback_block(block, height) -> Result<(), UtxoError>` — undo a block (for reorgs)
  - Batch writes within a single LMDB transaction per block
- **block_validation.rs**: Full validation pipeline:
  1. For each transaction input: look up UTXO, verify it exists, verify script (Phase 2b)
  2. Verify no double-spends within the block
  3. Verify total input value >= total output value (no inflation)
  4. Verify coinbase value <= subsidy + fees
  5. Apply block to UTXO set (remove spent, add new)
- **Testing**: Critical — validate against known UTXO set hashes at checkpoint heights

### Memory Management

- LMDB memory-maps the database file; iOS manages page eviction
- Set conservative map size (12GB max to allow growth)
- No application-level caching needed — LMDB's mmap handles it
- Monitor memory pressure via iOS `os_proc_available_memory()`

### Estimated effort: 4-6 weeks

---

## Phase 2d: AssumeUTXO & Pruning

**Goal:** Bootstrap from a UTXO snapshot and prune old block data.

### AssumeUTXO

- **Hardcode snapshot metadata**: block height, block hash, UTXO set hash, total UTXO count
- **Snapshot format**: Serialize UTXO set as sorted (outpoint → entry) pairs, compress with zstd
- **Download flow**:
  1. First launch: detect empty UTXO database
  2. Prompt user to download snapshot (WiFi only, show estimated size ~4-5GB compressed)
  3. Download from CDN/mirror (support resume on interruption)
  4. Decompress and load into LMDB
  5. Verify the UTXO set hash matches the hardcoded value
  6. Begin validating new blocks from the snapshot height
- **Snapshot hosting**: CDN, BitTorrent, or IPFS — decision needed closer to implementation

### Pruning

- **Configurable retention window**: keep last N blocks (default 288 = ~2 days)
- **After validation**: delete raw block data older than the retention window
- **Keep forever**: block headers (Phase 1), UTXO set (Phase 2c)
- **store.rs**: Add `prune_blocks_below(height)` method
- **Disk monitoring**: warn user if available storage drops below threshold

### Catch-up Logic

- On app foreground: check if tip is behind network tip
- Download and validate missed blocks sequentially
- Show progress in UI: "Catching up: 5 blocks behind..."
- If more than ~100 blocks behind, show estimated time

### Estimated effort: 3-4 weeks

---

## Total Phase 2 Estimate: 12-17 weeks

## Acceptance Criteria

- [ ] Full blocks downloaded and structurally validated (merkle root, coinbase, weight)
- [ ] Transaction scripts validated via libbitcoinconsensus
- [ ] UTXO set maintained in LMDB, all spends verified
- [ ] AssumeUTXO snapshot loads and verifies on first launch
- [ ] New blocks validated in real-time while app is foregrounded
- [ ] Old block data pruned, storage stays within ~10-12GB
- [ ] Catch-up works after hours/days offline
- [ ] UI shows block validation status, UTXO set size, storage usage

## Files to Create/Modify

- **New:** `hercules-core/src/block_validation.rs` — full block validation pipeline
- **New:** `hercules-core/src/consensus.rs` — libbitcoinconsensus wrapper + BIP flag logic
- **New:** `hercules-core/src/utxo.rs` — UTXO set manager (LMDB)
- **Modify:** `hercules-core/src/p2p.rs` — add getdata/block messages
- **Modify:** `hercules-core/src/sync.rs` — block download + validation loop
- **Modify:** `hercules-core/src/store.rs` — block storage + pruning
- **Modify:** `hercules-core/Cargo.toml` — add bitcoinconsensus, heed (LMDB)
- **Modify:** `hercules-core/src/hercules.udl` — expose block sync status to UI
- **Modify:** `HerculesApp/ContentView.swift` — block sync UI, storage dashboard
