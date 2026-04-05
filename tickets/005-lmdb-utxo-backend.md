# Ticket 005: LMDB UTXO Set Backend

## Summary

Migrate the UTXO set storage backend from SQLite to LMDB (Lightning Memory-Mapped Database) to reduce write amplification, eliminate SQL parsing overhead, and improve sync throughput — particularly during initial block download where UTXO churn is the bottleneck.

## Background

- **Current backend:** SQLite in WAL mode with 16MB cache, `synchronous=NORMAL`
- **UTXO set size at chain tip:** ~100M entries, ~8GB on disk
- **Workload profile:** Heavy random reads (input resolution), batch inserts (new outputs), batch deletes (spent outputs), all within per-block transactions
- **Pain point:** SQLite's SQL parsing, query planning, B-tree page splits, and journal overhead add latency that compounds over ~900K blocks during initial sync

## Why LMDB

LMDB is a B+ tree key-value store with memory-mapped I/O, purpose-built for the read-heavy, transaction-safe workload that a UTXO set demands.

| Dimension | SQLite (current) | LMDB |
|---|---|---|
| Read path | SQL parse → plan → B-tree seek | Direct memory-mapped page access (zero-copy) |
| Write path | Journal + WAL + B-tree rebalance | Copy-on-write B+ tree, single `msync` |
| Write amplification | High (WAL + checkpointing) | Low (append-only, no WAL) |
| Concurrency | Single-writer, multi-reader (WAL) | Single-writer, multi-reader (MVCC) |
| Transaction safety | ACID via journal/WAL | ACID via copy-on-write pages |
| Crash recovery | WAL replay | Instant (no recovery step) |
| Memory overhead | Page cache (configurable) | OS page cache (zero-copy reads) |
| Disk overhead | ~1.5-2x data size (WAL + indexes) | ~1x data size |
| Dependencies | `rusqlite` (C lib) | `heed` or `lmdb-rkv` (C lib) |

## Key Design Decisions

### Key Format
Concatenate `txid (32 bytes) || vout (4 bytes LE)` into a single 36-byte key. This is the natural lookup key for UTXO resolution and avoids any serialization overhead.

### Value Format
Pack `amount (8 bytes) || height (4 bytes) || is_coinbase (1 byte) || script_pubkey (variable)` into a compact binary value. No schema, no column names, no type metadata.

### Undo Data
Separate LMDB database (named sub-database) keyed by `height (4 bytes BE) || index (4 bytes BE)`, storing the same binary UTXO value format. Big-endian height enables efficient range deletion during pruning.

### Transaction Boundaries
One LMDB read-write transaction per block, matching current SQLite behavior. LMDB's copy-on-write means the entire block's UTXO changes are atomically visible or not.

## Migration Path

1. **Abstract the storage interface** — introduce a `UtxoBackend` trait with `get()`, `insert()`, `delete()`, `begin_tx()`, `commit()`, keeping SQLite as the default
2. **Implement LMDB backend** — `LmdbUtxoBackend` behind the same trait, using `heed` (safe Rust LMDB bindings)
3. **Benchmark** — compare sync speed over blocks 0–200K (UTXO-heavy era) between backends
4. **Switch default** — if LMDB shows meaningful improvement, make it the default for new syncs
5. **Drop SQLite backend** — once validated, remove the SQLite UTXO code to reduce maintenance surface

## Action Items

- [ ] Define `UtxoBackend` trait abstracting current `UtxoSet` public interface
- [ ] Add `heed` dependency and implement `LmdbUtxoBackend`
- [ ] Port undo data storage to LMDB sub-database
- [ ] Benchmark: measure blocks/sec and disk I/O for initial sync (blocks 0–200K)
- [ ] Evaluate `max_map_size` strategy for iOS (LMDB requires pre-declared max DB size for mmap)
- [ ] Test on-device: confirm LMDB mmap behavior is well-supported on iOS/arm64
- [ ] Migrate or deprecate SQLite UTXO path

## Risks

- **iOS mmap limits:** LMDB memory-maps the entire database. iOS imposes per-process virtual memory limits that may require careful `max_map_size` tuning or periodic remap.
- **Database size pre-declaration:** LMDB requires setting `max_map_size` upfront. Too small and writes fail; too large may waste address space. Need a grow-and-reopen strategy.
- **Single file:** LMDB stores everything in one file (`data.mdb`). Corruption recovery is all-or-nothing vs SQLite's more granular WAL recovery.

## References

- LMDB documentation: http://www.lmdb.tech/doc/
- `heed` (Rust bindings): https://github.com/meilisearch/heed
- Howard Chu, "The Lightning Memory-Mapped Database" (2014)
- Bitcoin Core's LevelDB usage (similar key-value pattern, different engine)
