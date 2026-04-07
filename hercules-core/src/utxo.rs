use std::fs;
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use bitcoin::block::Block;
use bitcoin::hashes::Hash;
use bitcoin::Txid;
use heed::types::{Bytes, Unit};
use heed::{Database, Env, EnvFlags, EnvOpenOptions, FlagSetMode, PutFlags};
use sha2::{Digest, Sha256};

use log::{info, warn};

/// Snapshot file magic bytes: "HUTX"
const SNAPSHOT_MAGIC: [u8; 4] = [b'H', b'U', b'T', b'X'];

/// Current snapshot format version.
const SNAPSHOT_VERSION: u32 = 1;

/// Maximum allowed amount per UTXO (Bitcoin's MAX_MONEY in satoshis).
/// Used as a sanity bound on read so a corrupt value doesn't propagate
/// silently into fee math or hash inputs.
const MAX_MONEY: u64 = 21_000_000 * 100_000_000;

/// Initial LMDB map size: 64 GB. LMDB's `map_size` is *virtual* address space,
/// not on-disk reservation — actual file growth is lazy. 64 GB gives plenty of
/// headroom over Bitcoin's ~12 GB UTXO set plus undo data, and easily fits in
/// the 64-bit virtual address space available on iOS / macOS.
const INITIAL_MAP_SIZE: usize = 64 * 1024 * 1024 * 1024;

/// Number of named DBs we open inside the env. heed requires this up-front.
const MAX_DBS: u32 = 8;

/// LMDB key length for the `utxos` DB: txid (32) + vout (4 BE).
const UTXO_KEY_LEN: usize = 36;

/// LMDB key length for the `height_index` DB: height (4 BE) + txid (32) + vout (4 BE).
const HEIGHT_INDEX_KEY_LEN: usize = 40;

/// Header bytes in a serialized utxos value: amount(8) + height(4) + flags(1).
const UTXO_VALUE_HEADER_LEN: usize = 13;

/// `flags` bit indicating the UTXO came from a coinbase tx.
const FLAG_COINBASE: u8 = 1 << 0;

/// Header bytes in a serialized undo entry value: txid(32) + vout(4) + amount(8) + orig_height(4) + flags(1).
const UNDO_VALUE_HEADER_LEN: usize = 49;

/// Bulk-load batch size: commit and reopen the write txn every N entries
/// during snapshot load. Bounds dirty-page accumulation in LMDB's per-txn
/// dirty list so it doesn't grow past available RAM and trigger the mmap
/// eviction death spiral on iOS. APPEND ordering is preserved across
/// commits since the snapshot stream is monotonically sorted.
///
/// Lowered to a tiny value under `cfg(test)` so the test suite actually
/// exercises the periodic-commit code path with handfuls of entries instead
/// of needing a million-entry stream.
#[cfg(not(test))]
const SNAPSHOT_LOAD_BATCH: u64 = 1_000_000;
#[cfg(test)]
const SNAPSHOT_LOAD_BATCH: u64 = 4;

/// Buffered reader capacity for snapshot streams (256 KiB). Larger than the
/// default 8 KiB to reduce syscall + gzip-decoder overhead during the
/// hours-long iPhone import.
const SNAPSHOT_READ_BUF: usize = 256 * 1024;

/// Sentinel filename written next to the LMDB env directory while a
/// snapshot load is in progress. Its presence on `UtxoSet::open` means a
/// previous load was interrupted (process killed, OS reboot) and the
/// on-disk state is partial / unverified — we wipe and start fresh.
const SNAPSHOT_LOADING_MARKER_SUFFIX: &str = ".loading";

/// Metadata about a loaded or expected UTXO snapshot.
#[derive(Debug, Clone)]
pub struct SnapshotMeta {
    pub height: u32,
    pub block_hash: [u8; 32],
    pub utxo_count: u64,
    pub utxo_hash: [u8; 32],
}

/// A single unspent transaction output.
#[derive(Debug, Clone)]
pub struct UtxoEntry {
    pub amount: u64,
    pub script_pubkey: Vec<u8>,
    pub height: u32,
    pub is_coinbase: bool,
}

/// Persistent UTXO set backed by LMDB (via the `heed` crate).
///
/// Three named databases live inside one env:
///
/// * `utxos` — `key = txid(32) || vout(4 BE)`, value = `amount(8 LE) || height(4 LE) || flags(1) || script`.
///   Big-endian vout makes the natural lex sort match `(txid, vout)`, so a
///   single cursor scan reproduces the snapshot iteration order without an
///   ORDER BY.
///
/// * `undo` — `key = block_height(4 BE) || idx(4 BE)`, value = the spent UTXO
///   we'll need to restore on rollback. Keying by height puts every block's
///   undo records together, so prune-below and rollback both range-scan a
///   contiguous chunk.
///
/// * `height_index` — `key = block_height(4 BE) || txid(32) || vout(4 BE)`,
///   value = empty. Lets us answer "which UTXOs were created at this height?"
///   in O(matches) instead of scanning the full set, which rollback needs.
///   Also gives `has_utxos_at_height` a single cursor seek.
///
/// All schema versioning is implicit in the snapshot format hash check —
/// loading a snapshot computed under different on-disk semantics will fail
/// the SHA256 verification before any data lands.
pub struct UtxoSet {
    env: Env,
    utxos: Database<Bytes, Bytes>,
    undo: Database<Bytes, Bytes>,
    height_index: Database<Bytes, Unit>,
}

impl UtxoSet {
    /// Open or create a UTXO LMDB env at `path`. `path` is treated as a
    /// directory — heed creates `data.mdb` and `lock.mdb` inside it.
    ///
    /// If a `<path>.loading` marker exists, a previous snapshot load was
    /// interrupted: the env on disk is partial and unverified. We wipe it
    /// before opening so the caller sees an empty set and can re-import.
    pub fn open(path: &str) -> Result<UtxoSet, UtxoError> {
        let path_buf = PathBuf::from(path);
        let marker = loading_marker_path(&path_buf);

        if marker.exists() {
            warn!(
                "Detected interrupted UTXO snapshot load at {} — wiping partial env",
                path_buf.display()
            );
            if path_buf.exists() {
                fs::remove_dir_all(&path_buf).map_err(|e| {
                    UtxoError(format!("wipe partial env {}: {}", path_buf.display(), e))
                })?;
            }
            fs::remove_file(&marker).map_err(|e| {
                UtxoError(format!("remove loading marker {}: {}", marker.display(), e))
            })?;
        }

        fs::create_dir_all(&path_buf)
            .map_err(|e| UtxoError(format!("create utxo dir {}: {}", path, e)))?;
        Self::open_at(&path_buf)
    }

    fn open_at(path: &Path) -> Result<UtxoSet, UtxoError> {
        // SAFETY: heed marks `open` unsafe because LMDB requires the same
        // mmap'd file isn't simultaneously opened with conflicting flags from
        // another process. We're a single-process iOS app and never share the
        // env directory across processes, so this contract holds.
        let env = unsafe {
            EnvOpenOptions::new()
                .map_size(INITIAL_MAP_SIZE)
                .max_dbs(MAX_DBS)
                .open(path)
        }
        .map_err(|e| UtxoError(format!("open env at {}: {}", path.display(), e)))?;

        let mut wtxn = env
            .write_txn()
            .map_err(|e| UtxoError(format!("begin create-tx: {}", e)))?;
        let utxos: Database<Bytes, Bytes> = env
            .create_database(&mut wtxn, Some("utxos"))
            .map_err(|e| UtxoError(format!("create utxos db: {}", e)))?;
        let undo: Database<Bytes, Bytes> = env
            .create_database(&mut wtxn, Some("undo"))
            .map_err(|e| UtxoError(format!("create undo db: {}", e)))?;
        let height_index: Database<Bytes, Unit> = env
            .create_database(&mut wtxn, Some("height_index"))
            .map_err(|e| UtxoError(format!("create height_index db: {}", e)))?;
        wtxn.commit()
            .map_err(|e| UtxoError(format!("commit create-tx: {}", e)))?;

        info!(
            "UTXO LMDB env opened at {} (map_size={} GB)",
            path.display(),
            INITIAL_MAP_SIZE / (1 << 30)
        );

        Ok(UtxoSet {
            env,
            utxos,
            undo,
            height_index,
        })
    }

    /// Look up an unspent output by txid and output index.
    pub fn get(&self, txid: &Txid, vout: u32) -> Result<Option<UtxoEntry>, UtxoError> {
        let key = utxo_key(&txid.to_byte_array(), vout);
        let rtxn = self
            .env
            .read_txn()
            .map_err(|e| UtxoError(format!("read tx: {}", e)))?;
        let val = self
            .utxos
            .get(&rtxn, &key)
            .map_err(|e| UtxoError(format!("get utxo: {}", e)))?;
        match val {
            Some(bytes) => Ok(Some(decode_utxo_value(bytes)?)),
            None => Ok(None),
        }
    }

    /// Apply a validated block to the UTXO set.
    /// Removes spent outputs and adds new unspent outputs.
    /// Handles in-block spends correctly (outputs created and spent
    /// within the same block never touch the database).
    pub fn apply_block(&self, block: &Block, height: u32) -> Result<(), UtxoError> {
        // Phase 1: Analyze the block to find in-block spends so we can skip
        // writing then immediately deleting outputs that are spent in the
        // same block. (`HashSet` of (txid, vout) since we only need
        // membership checks.)
        let mut created: std::collections::HashSet<(Txid, u32)> =
            std::collections::HashSet::new();
        let mut in_block_spent: std::collections::HashSet<(Txid, u32)> =
            std::collections::HashSet::new();

        for tx in &block.txdata {
            let txid = tx.compute_txid();
            for (vout, output) in tx.output.iter().enumerate() {
                if !output.script_pubkey.is_op_return() {
                    created.insert((txid, vout as u32));
                }
            }
            if !tx.is_coinbase() {
                for input in &tx.input {
                    let key = (input.previous_output.txid, input.previous_output.vout);
                    if created.contains(&key) {
                        in_block_spent.insert(key);
                    }
                }
            }
        }

        let mut wtxn = self
            .env
            .write_txn()
            .map_err(|e| UtxoError(format!("begin tx: {}", e)))?;

        // Index inside the block for the undo key — multiple inputs can be
        // recorded against the same height, so we tie-break with a counter.
        let mut undo_idx: u32 = 0;

        // Phase 2a: copy each spent UTXO into `undo` then delete it from `utxos`
        // (and from `height_index`, where it was registered when created).
        for tx in &block.txdata {
            if tx.is_coinbase() {
                continue;
            }
            for input in &tx.input {
                let prev_txid = input.previous_output.txid;
                let prev_vout = input.previous_output.vout;
                let okey = (prev_txid, prev_vout);
                if in_block_spent.contains(&okey) {
                    continue;
                }
                let prev_txid_bytes = prev_txid.to_byte_array();
                let utxo_k = utxo_key(&prev_txid_bytes, prev_vout);
                let val = self
                    .utxos
                    .get(&wtxn, &utxo_k)
                    .map_err(|e| UtxoError(format!("get for spend: {}", e)))?
                    .ok_or_else(|| {
                        UtxoError(format!(
                            "apply_block: missing utxo {}:{}",
                            hex::encode(prev_txid_bytes),
                            prev_vout
                        ))
                    })?
                    .to_vec();
                let entry = decode_utxo_value(&val)?;

                let undo_k = undo_key(height, undo_idx);
                undo_idx = undo_idx
                    .checked_add(1)
                    .ok_or_else(|| UtxoError("undo idx overflow".into()))?;
                let undo_v = encode_undo_value(&prev_txid_bytes, prev_vout, &entry);
                self.undo
                    .put(&mut wtxn, &undo_k, &undo_v)
                    .map_err(|e| UtxoError(format!("put undo: {}", e)))?;

                self.utxos
                    .delete(&mut wtxn, &utxo_k)
                    .map_err(|e| UtxoError(format!("delete utxo: {}", e)))?;

                let hi_k = height_index_key(entry.height, &prev_txid_bytes, prev_vout);
                self.height_index
                    .delete(&mut wtxn, &hi_k)
                    .map_err(|e| UtxoError(format!("delete height_index: {}", e)))?;
            }
        }

        // Phase 2b: write the new outputs (skipping in-block-spent and
        // OP_RETURN) plus their `height_index` entries.
        for tx in &block.txdata {
            let txid = tx.compute_txid();
            let txid_bytes = txid.to_byte_array();
            let is_cb = tx.is_coinbase();

            for (vout, output) in tx.output.iter().enumerate() {
                if output.script_pubkey.is_op_return() {
                    continue;
                }
                let vout = vout as u32;
                if in_block_spent.contains(&(txid, vout)) {
                    continue;
                }
                let entry = UtxoEntry {
                    amount: output.value.to_sat(),
                    script_pubkey: output.script_pubkey.as_bytes().to_vec(),
                    height,
                    is_coinbase: is_cb,
                };
                let utxo_k = utxo_key(&txid_bytes, vout);
                let utxo_v = encode_utxo_value(&entry);
                self.utxos
                    .put(&mut wtxn, &utxo_k, &utxo_v)
                    .map_err(|e| UtxoError(format!("put utxo: {}", e)))?;

                let hi_k = height_index_key(height, &txid_bytes, vout);
                self.height_index
                    .put(&mut wtxn, &hi_k, &())
                    .map_err(|e| UtxoError(format!("put height_index: {}", e)))?;
            }
        }

        wtxn.commit()
            .map_err(|e| UtxoError(format!("commit: {}", e)))?;
        Ok(())
    }

    /// Undo a block's UTXO changes. Must be called from the chain tip downward.
    ///
    /// 1. Removes all outputs created at this height (via `height_index`).
    /// 2. Restores all outputs that were spent at this height (from `undo`).
    /// 3. Deletes the undo data for this height.
    pub fn rollback_block(&self, height: u32) -> Result<(), UtxoError> {
        let mut wtxn = self
            .env
            .write_txn()
            .map_err(|e| UtxoError(format!("begin tx: {}", e)))?;

        // Step 1: collect (txid, vout) pairs created at this height.
        // We can't delete during iteration in heed, so buffer first.
        let prefix = height.to_be_bytes();
        let mut to_delete: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        {
            let iter = self
                .height_index
                .prefix_iter(&wtxn, &prefix)
                .map_err(|e| UtxoError(format!("prefix iter: {}", e)))?;
            for r in iter {
                let (k, _) =
                    r.map_err(|e| UtxoError(format!("height_index iter: {}", e)))?;
                if k.len() != HEIGHT_INDEX_KEY_LEN {
                    return Err(UtxoError(format!(
                        "corrupt height_index key len {}",
                        k.len()
                    )));
                }
                // Extract the (txid, vout) suffix as the utxo key.
                let utxo_k = k[4..].to_vec();
                to_delete.push((k.to_vec(), utxo_k));
            }
        }
        for (hi_k, utxo_k) in &to_delete {
            self.utxos
                .delete(&mut wtxn, utxo_k.as_slice())
                .map_err(|e| UtxoError(format!("delete utxo: {}", e)))?;
            self.height_index
                .delete(&mut wtxn, hi_k.as_slice())
                .map_err(|e| UtxoError(format!("delete height_index: {}", e)))?;
        }

        // Step 2 & 3: walk undo entries for this height, then restore each
        // spent UTXO into `utxos` + `height_index` and delete the undo
        // record. heed's iterator borrows the txn immutably for as long as
        // it's alive, so we collect first then mutate.
        let mut restorations: Vec<(Vec<u8>, [u8; 32], u32, UtxoEntry)> = Vec::new();
        {
            let iter = self
                .undo
                .prefix_iter(&wtxn, &prefix)
                .map_err(|e| UtxoError(format!("undo prefix iter: {}", e)))?;
            for r in iter {
                let (k, v) = r.map_err(|e| UtxoError(format!("undo iter: {}", e)))?;
                let (txid, vout, entry) = decode_undo_value(v)?;
                restorations.push((k.to_vec(), txid, vout, entry));
            }
        }
        for (undo_k, txid, vout, entry) in restorations {
            let utxo_k = utxo_key(&txid, vout);
            let utxo_v = encode_utxo_value(&entry);
            self.utxos
                .put(&mut wtxn, &utxo_k, &utxo_v)
                .map_err(|e| UtxoError(format!("restore utxo: {}", e)))?;
            let hi_k = height_index_key(entry.height, &txid, vout);
            self.height_index
                .put(&mut wtxn, &hi_k, &())
                .map_err(|e| UtxoError(format!("restore height_index: {}", e)))?;
            self.undo
                .delete(&mut wtxn, undo_k.as_slice())
                .map_err(|e| UtxoError(format!("delete undo: {}", e)))?;
        }

        wtxn.commit()
            .map_err(|e| UtxoError(format!("commit rollback: {}", e)))?;
        Ok(())
    }

    /// Delete undo data for blocks below the given height.
    /// Call this to reclaim disk space for deeply-buried blocks
    /// that will never be rolled back.
    pub fn prune_undo_below(&self, height: u32) -> Result<(), UtxoError> {
        let mut wtxn = self
            .env
            .write_txn()
            .map_err(|e| UtxoError(format!("begin tx: {}", e)))?;

        // Range delete: [0..height_be).
        let upper = height.to_be_bytes();
        let lower = [0u8; 4];
        let range = (
            std::ops::Bound::Included(&lower[..]),
            std::ops::Bound::Excluded(&upper[..]),
        );
        self.undo
            .delete_range(&mut wtxn, &range)
            .map_err(|e| UtxoError(format!("prune undo: {}", e)))?;
        wtxn.commit()
            .map_err(|e| UtxoError(format!("commit prune: {}", e)))?;
        Ok(())
    }

    // ── Snapshot support ─────────────────────────────────────────────

    /// Compute a deterministic SHA256 hash over the entire UTXO set.
    /// Iterates all UTXOs in (txid, vout) order and hashes each entry.
    pub fn compute_hash(&self) -> Result<[u8; 32], UtxoError> {
        let rtxn = self
            .env
            .read_txn()
            .map_err(|e| UtxoError(format!("read tx: {}", e)))?;
        let mut hasher = Sha256::new();
        let iter = self
            .utxos
            .iter(&rtxn)
            .map_err(|e| UtxoError(format!("iter: {}", e)))?;
        for r in iter {
            let (k, v) = r.map_err(|e| UtxoError(format!("hash iter: {}", e)))?;
            if k.len() != UTXO_KEY_LEN {
                return Err(UtxoError(format!("corrupt utxo key len {}", k.len())));
            }
            let entry = decode_utxo_value(v)?;
            if entry.script_pubkey.len() > u16::MAX as usize {
                return Err(UtxoError(format!(
                    "script too long for hash: {} bytes",
                    entry.script_pubkey.len()
                )));
            }
            // Same field order as the snapshot file's hash chain — see
            // `load_snapshot` for the matching feed sequence.
            let txid = &k[..32];
            let vout_be = &k[32..36];
            let vout = u32::from_be_bytes([vout_be[0], vout_be[1], vout_be[2], vout_be[3]]);
            hasher.update(txid);
            hasher.update(&vout.to_le_bytes());
            hasher.update(&entry.amount.to_le_bytes());
            hasher.update(&(entry.script_pubkey.len() as u16).to_le_bytes());
            hasher.update(&entry.script_pubkey);
            hasher.update(&entry.height.to_le_bytes());
            hasher.update(&[entry.is_coinbase as u8]);
        }
        Ok(hasher.finalize().into())
    }

    /// Write the entire UTXO set to a snapshot file.
    ///
    /// Format:
    /// - Header: magic (4) + version (4) + height (4) + block_hash (32) + utxo_count (8) + utxo_hash (32)
    /// - Entries: txid (32) + vout (4) + amount (8) + height (4) + is_coinbase (1) + script_len (2) + script
    pub fn write_snapshot<W: Write>(
        &self,
        writer: W,
        height: u32,
        block_hash: &[u8; 32],
    ) -> Result<SnapshotMeta, UtxoError> {
        let utxo_count = self.count()?;
        let utxo_hash = self.compute_hash()?;

        let mut w = BufWriter::new(writer);

        // Header
        w.write_all(&SNAPSHOT_MAGIC)
            .map_err(|e| UtxoError(format!("write magic: {}", e)))?;
        w.write_all(&SNAPSHOT_VERSION.to_le_bytes())
            .map_err(|e| UtxoError(format!("write version: {}", e)))?;
        w.write_all(&height.to_le_bytes())
            .map_err(|e| UtxoError(format!("write height: {}", e)))?;
        w.write_all(block_hash)
            .map_err(|e| UtxoError(format!("write block_hash: {}", e)))?;
        w.write_all(&utxo_count.to_le_bytes())
            .map_err(|e| UtxoError(format!("write count: {}", e)))?;
        w.write_all(&utxo_hash)
            .map_err(|e| UtxoError(format!("write hash: {}", e)))?;

        // Entries — natural cursor order is `(txid, vout)` because vout is BE
        // in the key.
        let rtxn = self
            .env
            .read_txn()
            .map_err(|e| UtxoError(format!("read tx: {}", e)))?;
        let iter = self
            .utxos
            .iter(&rtxn)
            .map_err(|e| UtxoError(format!("snapshot iter: {}", e)))?;
        for r in iter {
            let (k, v) = r.map_err(|e| UtxoError(format!("snapshot iter row: {}", e)))?;
            if k.len() != UTXO_KEY_LEN {
                return Err(UtxoError(format!("corrupt utxo key len {}", k.len())));
            }
            let entry = decode_utxo_value(v)?;
            let txid = &k[..32];
            let vout = u32::from_be_bytes([k[32], k[33], k[34], k[35]]);

            w.write_all(txid)
                .map_err(|e| UtxoError(format!("write txid: {}", e)))?;
            w.write_all(&vout.to_le_bytes())
                .map_err(|e| UtxoError(format!("write vout: {}", e)))?;
            w.write_all(&entry.amount.to_le_bytes())
                .map_err(|e| UtxoError(format!("write amount: {}", e)))?;
            w.write_all(&entry.height.to_le_bytes())
                .map_err(|e| UtxoError(format!("write entry height: {}", e)))?;
            w.write_all(&[entry.is_coinbase as u8])
                .map_err(|e| UtxoError(format!("write is_coinbase: {}", e)))?;
            if entry.script_pubkey.len() > u16::MAX as usize {
                return Err(UtxoError(format!(
                    "script too long for snapshot format: {} bytes (max {})",
                    entry.script_pubkey.len(),
                    u16::MAX
                )));
            }
            let script_len = entry.script_pubkey.len() as u16;
            w.write_all(&script_len.to_le_bytes())
                .map_err(|e| UtxoError(format!("write script_len: {}", e)))?;
            w.write_all(&entry.script_pubkey)
                .map_err(|e| UtxoError(format!("write script: {}", e)))?;
        }

        w.flush()
            .map_err(|e| UtxoError(format!("flush snapshot: {}", e)))?;

        let meta = SnapshotMeta {
            height,
            block_hash: *block_hash,
            utxo_count,
            utxo_hash,
        };

        info!(
            "Wrote UTXO snapshot: height={}, utxos={}, hash={}",
            height,
            utxo_count,
            hex::encode(utxo_hash)
        );

        Ok(meta)
    }

    /// Load a UTXO snapshot from a reader. Verifies the UTXO hash after loading.
    /// The UTXO set must be empty before calling this.
    ///
    /// `on_progress` is called periodically with (loaded_count, total_count).
    ///
    /// ## Performance and crash safety
    ///
    /// The naive "single huge write txn" form of this loop took hours on
    /// iPhone because (a) every entry triggered a random `height_index.put`
    /// across an unsorted B+ tree, and (b) the per-txn dirty page list grew
    /// past available RAM, evicting the mmap and faulting cold pages back
    /// in on every subsequent put. Three changes fix it:
    ///
    /// 1. **Skip `height_index` for snapshot rows.** The index is only used
    ///    by rollback, and rollback past the snapshot height is forbidden by
    ///    design (the snapshot is the assume-valid floor). Halves the LMDB
    ///    write count and eliminates *all* of the random-write work.
    /// 2. **Periodic mid-stream commits.** Every `SNAPSHOT_LOAD_BATCH`
    ///    entries we commit and reopen the wtxn so dirty pages flush to the
    ///    OS page cache instead of accumulating in LMDB's per-txn list.
    ///    APPEND ordering survives across commits because each new key is
    ///    still strictly greater than the existing max.
    /// 3. **`NO_META_SYNC` for the load window.** Defers the meta-page
    ///    fsync between batches; data pages still fsync at each commit, so
    ///    a crash loses at most the last batch — never corrupts the env.
    ///    `NO_SYNC` was *not* used because it can leave LMDB structurally
    ///    broken on a process kill.
    ///
    /// Periodic commits introduce a new failure mode: if the process dies
    /// after batch N has committed but before verification finishes, the
    /// env contains unverified partial state. To prevent that from
    /// masquerading as a complete UTXO set, we write a `<env>.loading`
    /// marker file before the first batch and delete it only after a
    /// successful `force_sync`. `UtxoSet::open` checks for the marker on
    /// startup and wipes the env if found.
    pub fn load_snapshot<R: std::io::Read, F>(
        &self,
        reader: R,
        expected_hash: Option<&[u8; 32]>,
        on_progress: F,
    ) -> Result<SnapshotMeta, UtxoError>
    where
        F: Fn(u64, u64),
    {
        let mut r = BufReader::with_capacity(SNAPSHOT_READ_BUF, reader);

        // ── Header ─────────────────────────────────────────────────
        let mut magic = [0u8; 4];
        r.read_exact(&mut magic)
            .map_err(|e| UtxoError(format!("read magic: {}", e)))?;
        if magic != SNAPSHOT_MAGIC {
            return Err(UtxoError("invalid snapshot magic".into()));
        }

        let mut buf4 = [0u8; 4];
        r.read_exact(&mut buf4)
            .map_err(|e| UtxoError(format!("read version: {}", e)))?;
        let version = u32::from_le_bytes(buf4);
        if version != SNAPSHOT_VERSION {
            return Err(UtxoError(format!(
                "unsupported snapshot version {}",
                version
            )));
        }

        r.read_exact(&mut buf4)
            .map_err(|e| UtxoError(format!("read height: {}", e)))?;
        let height = u32::from_le_bytes(buf4);

        let mut block_hash = [0u8; 32];
        r.read_exact(&mut block_hash)
            .map_err(|e| UtxoError(format!("read block_hash: {}", e)))?;

        let mut buf8 = [0u8; 8];
        r.read_exact(&mut buf8)
            .map_err(|e| UtxoError(format!("read count: {}", e)))?;
        let utxo_count = u64::from_le_bytes(buf8);

        let mut file_hash = [0u8; 32];
        r.read_exact(&mut file_hash)
            .map_err(|e| UtxoError(format!("read hash: {}", e)))?;

        if let Some(expected) = expected_hash {
            if file_hash != *expected {
                return Err(UtxoError(format!(
                    "snapshot hash mismatch: file={}, expected={}",
                    hex::encode(file_hash),
                    hex::encode(expected)
                )));
            }
        }

        info!(
            "Loading UTXO snapshot: height={}, utxos={}, hash={}",
            height,
            utxo_count,
            hex::encode(file_hash)
        );

        // ── NO_META_SYNC for the load window ──────────────────────
        // SAFETY: NO_META_SYNC is documented as integrity-preserving (a
        // crash may undo the last committed transaction but cannot corrupt
        // the env). The FlagGuard's Drop unconditionally restores the
        // default sync mode for any subsequent operations on this env.
        //
        // Done *before* the marker write so a set_flags failure can't
        // orphan a marker file on an env that was never touched.
        let _flag_guard = unsafe {
            self.env
                .set_flags(EnvFlags::NO_META_SYNC, FlagSetMode::Enable)
                .map_err(|e| UtxoError(format!("enable NO_META_SYNC: {}", e)))?;
            FlagGuard {
                env: &self.env,
                flags_to_clear: EnvFlags::NO_META_SYNC,
            }
        };

        // ── Crash-recovery marker ─────────────────────────────────
        // Write the marker before touching the env so an interrupted load
        // is always detectable on next open. We won't delete it until the
        // final force_sync returns.
        let marker = loading_marker_path(self.env.path());
        fs::write(&marker, b"snapshot load in progress\n").map_err(|e| {
            UtxoError(format!(
                "write loading marker {}: {}",
                marker.display(),
                e
            ))
        })?;

        // ── Bulk-load loop (in a closure so error paths funnel through
        //     the cleanup block below) ──────────────────────────────
        let load_result: Result<(), UtxoError> = (|| {
            let mut wtxn = self
                .env
                .write_txn()
                .map_err(|e| UtxoError(format!("begin snapshot tx: {}", e)))?;

            // TOCTOU-safe emptiness check inside the (initial) write txn.
            if !self
                .utxos
                .is_empty(&wtxn)
                .map_err(|e| UtxoError(format!("is_empty check: {}", e)))?
            {
                return Err(UtxoError(
                    "UTXO set must be empty before loading snapshot".into(),
                ));
            }

            let mut txid = [0u8; 32];
            let mut buf2 = [0u8; 2];
            let mut buf4 = [0u8; 4];
            let mut buf8 = [0u8; 8];
            let mut hasher = Sha256::new();
            let mut prev_key: Option<[u8; UTXO_KEY_LEN]> = None;
            // Reuse a single allocation for the value buffer across the inner loop.
            let mut value_buf: Vec<u8> = Vec::with_capacity(UTXO_VALUE_HEADER_LEN + 64);

            for i in 0..utxo_count {
                r.read_exact(&mut txid)
                    .map_err(|e| UtxoError(format!("read txid at {}: {}", i, e)))?;
                r.read_exact(&mut buf4)
                    .map_err(|e| UtxoError(format!("read vout at {}: {}", i, e)))?;
                let vout = u32::from_le_bytes(buf4);

                r.read_exact(&mut buf8)
                    .map_err(|e| UtxoError(format!("read amount at {}: {}", i, e)))?;
                let amount = u64::from_le_bytes(buf8);
                if amount > MAX_MONEY {
                    return Err(UtxoError(format!(
                        "snapshot entry {}: amount {} exceeds MAX_MONEY",
                        i, amount
                    )));
                }

                r.read_exact(&mut buf4)
                    .map_err(|e| UtxoError(format!("read entry height at {}: {}", i, e)))?;
                let entry_height = u32::from_le_bytes(buf4);

                let mut cb_byte = [0u8; 1];
                r.read_exact(&mut cb_byte)
                    .map_err(|e| UtxoError(format!("read is_coinbase at {}: {}", i, e)))?;
                let is_coinbase = cb_byte[0] != 0;

                r.read_exact(&mut buf2)
                    .map_err(|e| UtxoError(format!("read script_len at {}: {}", i, e)))?;
                let script_len = u16::from_le_bytes(buf2) as usize;

                let mut script = vec![0u8; script_len];
                r.read_exact(&mut script)
                    .map_err(|e| UtxoError(format!("read script at {}: {}", i, e)))?;

                // Build the LMDB key and assert strictly-ascending order so the
                // APPEND optimization stays valid across commits. (LMDB's APPEND
                // would error out anyway, but our message is clearer.)
                let key = utxo_key(&txid, vout);
                if let Some(ref prev) = prev_key {
                    if key.as_slice() <= prev.as_slice() {
                        return Err(UtxoError(
                            "snapshot entries not sorted by (txid, vout)".into(),
                        ));
                    }
                }
                prev_key = Some(key);

                // Feed the canonical hash format BEFORE writing — a stream
                // corruption detected on read aborts before the *current*
                // batch is committed. Earlier already-committed batches are
                // wiped by the cleanup block on the way out.
                hasher.update(&txid);
                hasher.update(&vout.to_le_bytes());
                hasher.update(&amount.to_le_bytes());
                hasher.update(&(script_len as u16).to_le_bytes());
                hasher.update(&script);
                hasher.update(&entry_height.to_le_bytes());
                hasher.update(&[is_coinbase as u8]);

                // Encode the value.
                value_buf.clear();
                value_buf.extend_from_slice(&amount.to_le_bytes());
                value_buf.extend_from_slice(&entry_height.to_le_bytes());
                value_buf.push(if is_coinbase { FLAG_COINBASE } else { 0 });
                value_buf.extend_from_slice(&script);

                self.utxos
                    .put_with_flags(&mut wtxn, PutFlags::APPEND, &key, &value_buf)
                    .map_err(|e| UtxoError(format!("append utxo {}: {}", i, e)))?;

                // Note: `height_index` is intentionally NOT populated for
                // snapshot rows — see the doc comment on this function.

                // Periodic commit + reopen so LMDB's per-txn dirty list
                // doesn't pile up. The next key in the stream is still
                // strictly greater than the new max key in the DB, so
                // APPEND keeps working in the new txn.
                let next_i = i + 1;
                if next_i < utxo_count && next_i % SNAPSHOT_LOAD_BATCH == 0 {
                    wtxn.commit().map_err(|e| {
                        UtxoError(format!("commit batch at {}: {}", next_i, e))
                    })?;
                    wtxn = self.env.write_txn().map_err(|e| {
                        UtxoError(format!("reopen tx at {}: {}", next_i, e))
                    })?;
                }

                if i % 100_000 == 0 {
                    on_progress(i, utxo_count);
                }
            }

            // Verify hash BEFORE the final commit. If this fails, the
            // in-flight wtxn rolls back and the cleanup block wipes any
            // earlier batched commits.
            let loaded_hash: [u8; 32] = hasher.finalize().into();
            if loaded_hash != file_hash {
                return Err(UtxoError(format!(
                    "snapshot verification failed: loaded={}, expected={}",
                    hex::encode(loaded_hash),
                    hex::encode(file_hash)
                )));
            }

            wtxn.commit()
                .map_err(|e| UtxoError(format!("commit snapshot: {}", e)))?;
            Ok(())
        })();

        // ── Cleanup / commit ──────────────────────────────────────
        match load_result {
            Ok(()) => {
                // Force a synchronous flush of all data + meta pages so
                // the marker file can be removed safely. NO_META_SYNC
                // doesn't disable explicit force_sync.
                self.env
                    .force_sync()
                    .map_err(|e| UtxoError(format!("force_sync after load: {}", e)))?;
                // Marker removal proves the load completed end-to-end.
                fs::remove_file(&marker).map_err(|e| {
                    UtxoError(format!(
                        "remove loading marker {}: {}",
                        marker.display(),
                        e
                    ))
                })?;
            }
            Err(e) => {
                // Wipe any partial state so the next load can start from
                // empty. The marker is only removed if BOTH the wipe and
                // the sync succeed — otherwise we leave it on disk so
                // `open()` will wipe again on next start. Removing the
                // marker after a failed clear_all would strand partial
                // data with no recovery signal, which is unrecoverable
                // without manual intervention.
                let cleanup_ok =
                    self.clear_all().is_ok() && self.env.force_sync().is_ok();
                if cleanup_ok {
                    let _ = fs::remove_file(&marker);
                }
                return Err(e);
            }
        }

        on_progress(utxo_count, utxo_count);

        info!(
            "UTXO snapshot loaded and verified: {} utxos at height {}",
            utxo_count, height
        );

        Ok(SnapshotMeta {
            height,
            block_hash,
            utxo_count,
            utxo_hash: file_hash,
        })
    }

    /// Wipe every named DB inside the env in a single transaction. Used by
    /// the snapshot-load error path to clear partial state from earlier
    /// batched commits before returning the error to the caller.
    fn clear_all(&self) -> Result<(), UtxoError> {
        let mut wtxn = self
            .env
            .write_txn()
            .map_err(|e| UtxoError(format!("clear_all begin tx: {}", e)))?;
        self.utxos
            .clear(&mut wtxn)
            .map_err(|e| UtxoError(format!("clear_all utxos: {}", e)))?;
        self.undo
            .clear(&mut wtxn)
            .map_err(|e| UtxoError(format!("clear_all undo: {}", e)))?;
        self.height_index
            .clear(&mut wtxn)
            .map_err(|e| UtxoError(format!("clear_all height_index: {}", e)))?;
        wtxn.commit()
            .map_err(|e| UtxoError(format!("clear_all commit: {}", e)))?;
        Ok(())
    }

    /// Check if any UTXOs exist at the given block height.
    /// Used for crash recovery: if UTXOs from a block exist but validated_height
    /// wasn't updated, the block was already applied.
    pub fn has_utxos_at_height(&self, height: u32) -> Result<bool, UtxoError> {
        let rtxn = self
            .env
            .read_txn()
            .map_err(|e| UtxoError(format!("read tx: {}", e)))?;
        let prefix = height.to_be_bytes();
        let mut iter = self
            .height_index
            .prefix_iter(&rtxn, &prefix)
            .map_err(|e| UtxoError(format!("prefix iter: {}", e)))?;
        match iter.next() {
            Some(Ok(_)) => Ok(true),
            Some(Err(e)) => Err(UtxoError(format!("prefix iter row: {}", e))),
            None => Ok(false),
        }
    }

    /// Get the number of UTXOs in the set.
    pub fn count(&self) -> Result<u64, UtxoError> {
        let rtxn = self
            .env
            .read_txn()
            .map_err(|e| UtxoError(format!("read tx: {}", e)))?;
        self.utxos
            .len(&rtxn)
            .map_err(|e| UtxoError(format!("len: {}", e)))
    }
}

impl Drop for UtxoSet {
    /// Force heed to actually close the LMDB env when the last `UtxoSet`
    /// reference goes away.
    ///
    /// Without this, heed's process-global `OPENED_ENV` cache holds an
    /// extra `Arc<EnvInner>` for every opened path, so the underlying env
    /// stays mapped for the lifetime of the process — even after every
    /// user-facing `Env` handle has been dropped. That's harmless for a
    /// long-running iOS node, but it breaks two important cases:
    ///
    /// 1. **Crash-recovery wipe in `open()`** — if a process restart
    ///    detects a stale `<env>.loading` marker, we `remove_dir_all` the
    ///    env directory and reopen. With heed's stale cache entry still
    ///    around, the reopen would return the *old* `Env` (still mmap'd to
    ///    the now-unlinked file) instead of a fresh empty one.
    /// 2. **Tests** that simulate restart by dropping a `UtxoSet` and
    ///    reopening the same path.
    ///
    /// `prepare_for_closing` takes the cache's `Arc` out (replacing it with
    /// `None`) so subsequent opens of the same path are guaranteed cache
    /// misses. The actual `mdb_env_close` happens once our last `Arc`
    /// (`self.env`) drops as part of normal field destruction below.
    fn drop(&mut self) {
        let _ = self.env.clone().prepare_for_closing();
    }
}

// ── Encoding helpers ────────────────────────────────────────────────

/// Path of the "snapshot load in progress" sentinel for an LMDB env at
/// `env_dir`. Stored as a sibling file (`<env_dir><suffix>`) rather than
/// inside the env directory so it can't collide with LMDB's own files
/// and survives a `remove_dir_all(env_dir)` wipe.
fn loading_marker_path(env_dir: &Path) -> PathBuf {
    let mut p = env_dir.to_path_buf();
    let new_name = match env_dir.file_name() {
        Some(name) => {
            let mut s = name.to_os_string();
            s.push(SNAPSHOT_LOADING_MARKER_SUFFIX);
            s
        }
        None => std::ffi::OsString::from(SNAPSHOT_LOADING_MARKER_SUFFIX),
    };
    p.set_file_name(new_name);
    p
}

/// RAII guard that restores the env's default sync flags when dropped, no
/// matter how the snapshot-load function exits. Constructed only after the
/// caller has *enabled* one or more "unsafe" flags (e.g. `NO_META_SYNC`)
/// and trusts the guard to disable them again.
struct FlagGuard<'a> {
    env: &'a Env,
    flags_to_clear: EnvFlags,
}

impl Drop for FlagGuard<'_> {
    fn drop(&mut self) {
        // SAFETY: Disabling NO_SYNC / NO_META_SYNC restores conservative
        // defaults — the unsafety in `set_flags` is on the *enable* side.
        // Errors here are ignored because Drop has nowhere to report them
        // and leaving a flag enabled is no worse than the current state.
        unsafe {
            let _ = self
                .env
                .set_flags(self.flags_to_clear, FlagSetMode::Disable);
        }
    }
}

/// `txid(32) || vout(4 BE)` — BE so the natural lex sort matches the
/// `(txid, vout)` ordering used by snapshots.
fn utxo_key(txid: &[u8; 32], vout: u32) -> [u8; UTXO_KEY_LEN] {
    let mut k = [0u8; UTXO_KEY_LEN];
    k[..32].copy_from_slice(txid);
    k[32..].copy_from_slice(&vout.to_be_bytes());
    k
}

/// `block_height(4 BE) || idx(4 BE)` — BE on both fields so undo entries
/// scan as a contiguous range per height for prune/rollback.
fn undo_key(height: u32, idx: u32) -> [u8; 8] {
    let mut k = [0u8; 8];
    k[..4].copy_from_slice(&height.to_be_bytes());
    k[4..].copy_from_slice(&idx.to_be_bytes());
    k
}

/// `height(4 BE) || txid(32) || vout(4 BE)` — height-prefixed so a single
/// `prefix_iter` returns every UTXO created at that block height.
fn height_index_key(height: u32, txid: &[u8; 32], vout: u32) -> [u8; HEIGHT_INDEX_KEY_LEN] {
    let mut k = [0u8; HEIGHT_INDEX_KEY_LEN];
    k[..4].copy_from_slice(&height.to_be_bytes());
    k[4..36].copy_from_slice(txid);
    k[36..].copy_from_slice(&vout.to_be_bytes());
    k
}

/// `amount(8 LE) || height(4 LE) || flags(1) || script(rest)`
fn encode_utxo_value(entry: &UtxoEntry) -> Vec<u8> {
    let mut v = Vec::with_capacity(UTXO_VALUE_HEADER_LEN + entry.script_pubkey.len());
    v.extend_from_slice(&entry.amount.to_le_bytes());
    v.extend_from_slice(&entry.height.to_le_bytes());
    v.push(if entry.is_coinbase { FLAG_COINBASE } else { 0 });
    v.extend_from_slice(&entry.script_pubkey);
    v
}

fn decode_utxo_value(bytes: &[u8]) -> Result<UtxoEntry, UtxoError> {
    if bytes.len() < UTXO_VALUE_HEADER_LEN {
        return Err(UtxoError(format!(
            "corrupt utxo value: len {} < {}",
            bytes.len(),
            UTXO_VALUE_HEADER_LEN
        )));
    }
    let amount = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
    if amount > MAX_MONEY {
        return Err(UtxoError(format!(
            "corrupt UTXO: amount {} exceeds MAX_MONEY",
            amount
        )));
    }
    let height = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
    let flags = bytes[12];
    let is_coinbase = (flags & FLAG_COINBASE) != 0;
    let script_pubkey = bytes[UTXO_VALUE_HEADER_LEN..].to_vec();
    Ok(UtxoEntry {
        amount,
        script_pubkey,
        height,
        is_coinbase,
    })
}

/// `txid(32) || vout(4 LE) || amount(8 LE) || orig_height(4 LE) || flags(1) || script`
fn encode_undo_value(txid: &[u8; 32], vout: u32, entry: &UtxoEntry) -> Vec<u8> {
    let mut v = Vec::with_capacity(UNDO_VALUE_HEADER_LEN + entry.script_pubkey.len());
    v.extend_from_slice(txid);
    v.extend_from_slice(&vout.to_le_bytes());
    v.extend_from_slice(&entry.amount.to_le_bytes());
    v.extend_from_slice(&entry.height.to_le_bytes());
    v.push(if entry.is_coinbase { FLAG_COINBASE } else { 0 });
    v.extend_from_slice(&entry.script_pubkey);
    v
}

fn decode_undo_value(bytes: &[u8]) -> Result<([u8; 32], u32, UtxoEntry), UtxoError> {
    if bytes.len() < UNDO_VALUE_HEADER_LEN {
        return Err(UtxoError(format!(
            "corrupt undo value: len {} < {}",
            bytes.len(),
            UNDO_VALUE_HEADER_LEN
        )));
    }
    let mut txid = [0u8; 32];
    txid.copy_from_slice(&bytes[0..32]);
    let vout = u32::from_le_bytes(bytes[32..36].try_into().unwrap());
    let amount = u64::from_le_bytes(bytes[36..44].try_into().unwrap());
    if amount > MAX_MONEY {
        return Err(UtxoError(format!(
            "corrupt undo: amount {} exceeds MAX_MONEY",
            amount
        )));
    }
    let orig_height = u32::from_le_bytes(bytes[44..48].try_into().unwrap());
    let flags = bytes[48];
    let is_coinbase = (flags & FLAG_COINBASE) != 0;
    let script_pubkey = bytes[UNDO_VALUE_HEADER_LEN..].to_vec();
    Ok((
        txid,
        vout,
        UtxoEntry {
            amount,
            script_pubkey,
            height: orig_height,
            is_coinbase,
        },
    ))
}

#[derive(Debug)]
pub struct UtxoError(pub String);

impl std::fmt::Display for UtxoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "utxo error: {}", self.0)
    }
}

impl std::error::Error for UtxoError {}

// ── Test helpers ────────────────────────────────────────────────────
//
// These exist only under `cfg(test)` so we can write surgical state-setup
// in tests that exercised raw SQL inserts in the SQLite version. Production
// code goes through `apply_block` / `rollback_block` exclusively.

#[cfg(test)]
impl UtxoSet {
    /// Insert a UTXO directly. Bypasses block validation; tests use this to
    /// simulate "this UTXO existed before the block we're about to roll back".
    /// `pub(crate)` so the mempool test suite can build a populated UTXO set
    /// without going through `apply_block`.
    pub(crate) fn test_insert_utxo(
        &self,
        txid: [u8; 32],
        vout: u32,
        entry: UtxoEntry,
    ) -> Result<(), UtxoError> {
        let mut wtxn = self
            .env
            .write_txn()
            .map_err(|e| UtxoError(format!("begin: {}", e)))?;
        let key = utxo_key(&txid, vout);
        let val = encode_utxo_value(&entry);
        self.utxos
            .put(&mut wtxn, &key, &val)
            .map_err(|e| UtxoError(format!("put: {}", e)))?;
        let hi_k = height_index_key(entry.height, &txid, vout);
        self.height_index
            .put(&mut wtxn, &hi_k, &())
            .map_err(|e| UtxoError(format!("put hi: {}", e)))?;
        wtxn.commit()
            .map_err(|e| UtxoError(format!("commit: {}", e)))?;
        Ok(())
    }

    /// Insert raw bytes into the utxos DB. For corruption-detection tests
    /// that need to plant a value the encoder would reject.
    fn test_insert_raw_utxo(
        &self,
        txid: [u8; 32],
        vout: u32,
        raw_value: &[u8],
    ) -> Result<(), UtxoError> {
        let mut wtxn = self
            .env
            .write_txn()
            .map_err(|e| UtxoError(format!("begin: {}", e)))?;
        let key = utxo_key(&txid, vout);
        self.utxos
            .put(&mut wtxn, &key, raw_value)
            .map_err(|e| UtxoError(format!("put: {}", e)))?;
        wtxn.commit()
            .map_err(|e| UtxoError(format!("commit: {}", e)))?;
        Ok(())
    }

    /// Insert an undo entry directly. Used to set up rollback tests without
    /// going through a real apply_block first.
    fn test_insert_undo(
        &self,
        block_height: u32,
        idx: u32,
        txid: [u8; 32],
        vout: u32,
        entry: UtxoEntry,
    ) -> Result<(), UtxoError> {
        let mut wtxn = self
            .env
            .write_txn()
            .map_err(|e| UtxoError(format!("begin: {}", e)))?;
        let k = undo_key(block_height, idx);
        let v = encode_undo_value(&txid, vout, &entry);
        self.undo
            .put(&mut wtxn, &k, &v)
            .map_err(|e| UtxoError(format!("put: {}", e)))?;
        wtxn.commit()
            .map_err(|e| UtxoError(format!("commit: {}", e)))?;
        Ok(())
    }

    /// Count of undo entries currently persisted (across all heights).
    fn test_count_undo(&self) -> Result<u64, UtxoError> {
        let rtxn = self
            .env
            .read_txn()
            .map_err(|e| UtxoError(format!("read tx: {}", e)))?;
        self.undo
            .len(&rtxn)
            .map_err(|e| UtxoError(format!("len: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::block::Block;
    use bitcoin::consensus::deserialize;
    use tempfile::TempDir;

    /// Open a fresh UtxoSet backed by a temp directory. The TempDir is
    /// returned so the caller keeps it alive (drop = cleanup).
    fn fresh() -> (UtxoSet, TempDir) {
        let dir = TempDir::new().unwrap();
        let utxo = UtxoSet::open(dir.path().to_str().unwrap()).unwrap();
        (utxo, dir)
    }

    /// Build a synthetic snapshot byte stream containing `n` distinct UTXOs
    /// with strictly increasing txids (`[0;32]`, `[1;32]`, ...). The
    /// returned `expected_hash` is the snapshot's content hash, suitable
    /// for passing to `load_snapshot` as `Some(&hash)`.
    ///
    /// Used by the periodic-commit and clear_all tests to drive
    /// `SNAPSHOT_LOAD_BATCH` (which is lowered to 4 under cfg(test))
    /// across multiple batch boundaries with a small entry count.
    fn make_snapshot_with_n_utxos(n: u8) -> (Vec<u8>, [u8; 32]) {
        let (utxo, _dir) = fresh();
        for i in 0..n {
            let mut txid = [0u8; 32];
            txid[0] = i;
            utxo.test_insert_utxo(
                txid,
                0,
                UtxoEntry {
                    amount: 1000 + i as u64,
                    script_pubkey: vec![0xac],
                    height: 1,
                    is_coinbase: false,
                },
            )
            .unwrap();
        }
        let mut buf = Vec::new();
        let meta = utxo.write_snapshot(&mut buf, 1, &[0u8; 32]).unwrap();
        (buf, meta.utxo_hash)
    }

    /// The full genesis block (header + coinbase transaction).
    fn genesis_block() -> Block {
        let raw = hex::decode(
            "0100000000000000000000000000000000000000000000000000000000000000\
             000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa\
             4b1e5e4a29ab5f49ffff001d1dac2b7c\
             01\
             01000000010000000000000000000000000000000000000000000000000000000000000000\
             ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f323030\
             39204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e6420\
             6261696c6f757420666f722062616e6b73ffffffff0100f2052a010000004341\
             0496b538e853519c726a2c91e61ec11600ae1390813a627c66fb8be7947be63c\
             52da7589379515d4e0a604f8141781e62294721166bf621e73a82cbf2342c858\
             eeac00000000",
        )
        .unwrap();
        deserialize(&raw).unwrap()
    }

    #[test]
    fn empty_utxo_set_has_zero_count() {
        let (utxo, _dir) = fresh();
        assert_eq!(utxo.count().unwrap(), 0);
    }

    #[test]
    fn get_missing_utxo_returns_none() {
        let (utxo, _dir) = fresh();
        let txid = Txid::from_byte_array([0u8; 32]);
        assert!(utxo.get(&txid, 0).unwrap().is_none());
    }

    #[test]
    fn apply_genesis_creates_one_utxo() {
        let (utxo, _dir) = fresh();
        let genesis = genesis_block();

        utxo.apply_block(&genesis, 0).unwrap();
        assert_eq!(utxo.count().unwrap(), 1);

        let coinbase_txid = genesis.txdata[0].compute_txid();
        let entry = utxo.get(&coinbase_txid, 0).unwrap().unwrap();
        assert_eq!(entry.amount, 50 * 100_000_000);
        assert!(entry.is_coinbase);
        assert_eq!(entry.height, 0);
    }

    #[test]
    fn rollback_genesis_restores_empty_set() {
        let (utxo, _dir) = fresh();
        let genesis = genesis_block();

        utxo.apply_block(&genesis, 0).unwrap();
        assert_eq!(utxo.count().unwrap(), 1);

        utxo.rollback_block(0).unwrap();
        assert_eq!(utxo.count().unwrap(), 0);

        let coinbase_txid = genesis.txdata[0].compute_txid();
        assert!(utxo.get(&coinbase_txid, 0).unwrap().is_none());
    }

    #[test]
    fn apply_and_rollback_roundtrip() {
        let (utxo, _dir) = fresh();
        let genesis = genesis_block();

        utxo.apply_block(&genesis, 0).unwrap();
        assert_eq!(utxo.count().unwrap(), 1);
        utxo.rollback_block(0).unwrap();
        assert_eq!(utxo.count().unwrap(), 0);
    }

    #[test]
    fn rollback_restores_spent_utxos() {
        let (utxo, _dir) = fresh();

        // Plant a UTXO at height 5 (the "previous" output) and an undo entry
        // at height 10 saying "block 10 spent it". Then plant the new output
        // block 10 created. Rolling back block 10 should remove the new
        // output and restore the old one.
        let old_entry = UtxoEntry {
            amount: 1000,
            script_pubkey: vec![0x76, 0xa9],
            height: 5,
            is_coinbase: false,
        };
        let new_entry = UtxoEntry {
            amount: 500,
            script_pubkey: vec![0x76, 0xa9],
            height: 10,
            is_coinbase: false,
        };

        utxo.test_insert_undo(10, 0, [1u8; 32], 0, old_entry.clone())
            .unwrap();
        utxo.test_insert_utxo([2u8; 32], 0, new_entry).unwrap();

        let txid_old = Txid::from_byte_array([1u8; 32]);
        let txid_new = Txid::from_byte_array([2u8; 32]);
        assert_eq!(utxo.count().unwrap(), 1);
        assert!(utxo.get(&txid_old, 0).unwrap().is_none());
        assert!(utxo.get(&txid_new, 0).unwrap().is_some());

        utxo.rollback_block(10).unwrap();

        assert_eq!(utxo.count().unwrap(), 1);
        let restored = utxo.get(&txid_old, 0).unwrap().unwrap();
        assert_eq!(restored.amount, 1000);
        assert_eq!(restored.height, 5);
        assert!(!restored.is_coinbase);
        assert!(utxo.get(&txid_new, 0).unwrap().is_none());
    }

    #[test]
    fn prune_undo_removes_old_data() {
        let (utxo, _dir) = fresh();
        let dummy = UtxoEntry {
            amount: 100,
            script_pubkey: vec![0xac],
            height: 0,
            is_coinbase: false,
        };
        for h in [5u32, 10, 15, 20] {
            utxo.test_insert_undo(h, 0, [h as u8; 32], 0, dummy.clone())
                .unwrap();
        }

        utxo.prune_undo_below(15).unwrap();
        assert_eq!(utxo.test_count_undo().unwrap(), 2); // heights 15 and 20
    }

    #[test]
    fn corrupt_amount_detected_on_read() {
        let (utxo, _dir) = fresh();
        // Plant a value with amount = MAX_MONEY + 1, which decode_utxo_value
        // must reject as a corruption indicator.
        let bad_amount: u64 = MAX_MONEY + 1;
        let mut raw = Vec::new();
        raw.extend_from_slice(&bad_amount.to_le_bytes());
        raw.extend_from_slice(&0u32.to_le_bytes()); // height
        raw.push(0); // flags
                     // No script bytes — header-only is fine for the decoder.
        utxo.test_insert_raw_utxo([9u8; 32], 0, &raw).unwrap();

        let txid = Txid::from_byte_array([9u8; 32]);
        let result = utxo.get(&txid, 0);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("exceeds MAX_MONEY"));
    }

    #[test]
    fn compute_hash_deterministic() {
        let (utxo, _dir) = fresh();
        let genesis = genesis_block();
        utxo.apply_block(&genesis, 0).unwrap();

        let hash1 = utxo.compute_hash().unwrap();
        let hash2 = utxo.compute_hash().unwrap();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn snapshot_write_and_load_roundtrip() {
        let (utxo1, _dir1) = fresh();
        let genesis = genesis_block();
        utxo1.apply_block(&genesis, 0).unwrap();
        assert_eq!(utxo1.count().unwrap(), 1);

        let block_hash = [0xABu8; 32];
        let mut buf = Vec::new();
        let meta = utxo1.write_snapshot(&mut buf, 0, &block_hash).unwrap();
        assert_eq!(meta.height, 0);
        assert_eq!(meta.block_hash, block_hash);
        assert_eq!(meta.utxo_count, 1);

        let (utxo2, _dir2) = fresh();
        let loaded = utxo2
            .load_snapshot(std::io::Cursor::new(&buf), Some(&meta.utxo_hash), |_, _| {})
            .unwrap();
        assert_eq!(loaded.height, 0);
        assert_eq!(loaded.utxo_count, 1);
        assert_eq!(utxo2.count().unwrap(), 1);

        let coinbase_txid = genesis.txdata[0].compute_txid();
        let entry = utxo2.get(&coinbase_txid, 0).unwrap().unwrap();
        assert_eq!(entry.amount, 50 * 100_000_000);
        assert!(entry.is_coinbase);
        assert_eq!(utxo1.compute_hash().unwrap(), utxo2.compute_hash().unwrap());
    }

    #[test]
    fn snapshot_rejects_wrong_hash() {
        let (utxo1, _dir1) = fresh();
        let genesis = genesis_block();
        utxo1.apply_block(&genesis, 0).unwrap();

        let mut buf = Vec::new();
        utxo1.write_snapshot(&mut buf, 0, &[0u8; 32]).unwrap();

        let (utxo2, _dir2) = fresh();
        let result = utxo2.load_snapshot(
            std::io::Cursor::new(&buf),
            Some(&[0xFFu8; 32]),
            |_, _| {},
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("hash mismatch"));
    }

    #[test]
    fn snapshot_rejects_nonempty_set() {
        let (utxo, _dir) = fresh();
        let genesis = genesis_block();
        utxo.apply_block(&genesis, 0).unwrap();

        let mut buf = Vec::new();
        utxo.write_snapshot(&mut buf, 0, &[0u8; 32]).unwrap();

        let result = utxo.load_snapshot(std::io::Cursor::new(&buf), None, |_, _| {});
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("must be empty"));
    }

    #[test]
    fn snapshot_rejects_bad_magic() {
        let (utxo, _dir) = fresh();
        let result = utxo.load_snapshot(
            std::io::Cursor::new(b"BADXsomegarbagedata"),
            None,
            |_, _| {},
        );
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("invalid snapshot magic"));
    }

    #[test]
    fn snapshot_load_does_not_populate_height_index() {
        // Confirm the optimization: snapshot rows must NOT land in
        // height_index, since rollback past the snapshot height is
        // forbidden by design.
        let (utxo1, _dir1) = fresh();
        let genesis = genesis_block();
        utxo1.apply_block(&genesis, 0).unwrap();

        let mut buf = Vec::new();
        let meta = utxo1.write_snapshot(&mut buf, 0, &[0u8; 32]).unwrap();

        let (utxo2, _dir2) = fresh();
        utxo2
            .load_snapshot(std::io::Cursor::new(&buf), Some(&meta.utxo_hash), |_, _| {})
            .unwrap();

        // utxos populated as expected.
        assert_eq!(utxo2.count().unwrap(), 1);
        // height_index empty: has_utxos_at_height should report false even
        // though height 0 has a UTXO in the main table.
        assert!(!utxo2.has_utxos_at_height(0).unwrap());
    }

    #[test]
    fn snapshot_load_removes_marker_on_success() {
        let (utxo1, _dir1) = fresh();
        let genesis = genesis_block();
        utxo1.apply_block(&genesis, 0).unwrap();
        let mut buf = Vec::new();
        let meta = utxo1.write_snapshot(&mut buf, 0, &[0u8; 32]).unwrap();

        let dir2 = TempDir::new().unwrap();
        let env_path = dir2.path().join("utxo");
        let utxo2 = UtxoSet::open(env_path.to_str().unwrap()).unwrap();
        utxo2
            .load_snapshot(std::io::Cursor::new(&buf), Some(&meta.utxo_hash), |_, _| {})
            .unwrap();

        // Marker must be gone after a clean load.
        let marker = loading_marker_path(&env_path);
        assert!(
            !marker.exists(),
            "loading marker should be removed on success"
        );
    }

    #[test]
    fn snapshot_load_does_not_write_marker_on_header_hash_failure() {
        let (utxo1, _dir1) = fresh();
        let genesis = genesis_block();
        utxo1.apply_block(&genesis, 0).unwrap();
        let mut buf = Vec::new();
        utxo1.write_snapshot(&mut buf, 0, &[0u8; 32]).unwrap();

        let dir2 = TempDir::new().unwrap();
        let env_path = dir2.path().join("utxo");
        let utxo2 = UtxoSet::open(env_path.to_str().unwrap()).unwrap();
        let result = utxo2.load_snapshot(
            std::io::Cursor::new(&buf),
            Some(&[0xFFu8; 32]),
            |_, _| {},
        );
        assert!(result.is_err());

        // The expected-hash check in the header runs before any flag/marker
        // setup, so the marker is never written and the env was never
        // touched. Both invariants matter: leaving a marker on a no-op
        // failure would force an unnecessary wipe on next open.
        let marker = loading_marker_path(&env_path);
        assert!(!marker.exists());
        assert_eq!(utxo2.count().unwrap(), 0);
    }

    #[test]
    fn open_wipes_env_when_loading_marker_present() {
        // Set up a populated env, then synthesize an interrupted-load
        // condition by writing the marker file. Reopening should wipe the
        // env to empty state and remove the marker.
        let dir = TempDir::new().unwrap();
        let env_path = dir.path().join("utxo");
        {
            let utxo = UtxoSet::open(env_path.to_str().unwrap()).unwrap();
            let genesis = genesis_block();
            utxo.apply_block(&genesis, 0).unwrap();
            assert_eq!(utxo.count().unwrap(), 1);
        } // drop closes the env

        let marker = loading_marker_path(&env_path);
        std::fs::write(&marker, b"interrupted\n").unwrap();
        assert!(marker.exists());

        let utxo = UtxoSet::open(env_path.to_str().unwrap()).unwrap();
        assert_eq!(
            utxo.count().unwrap(),
            0,
            "interrupted load marker should trigger a wipe"
        );
        assert!(!marker.exists(), "marker should be removed after wipe");
    }

    #[test]
    fn loading_marker_path_is_sibling_of_env_dir() {
        let p = loading_marker_path(Path::new("/tmp/foo/utxo-lmdb"));
        assert_eq!(p, PathBuf::from("/tmp/foo/utxo-lmdb.loading"));
    }

    #[test]
    fn snapshot_load_periodic_commits_persist_all_entries() {
        // SNAPSHOT_LOAD_BATCH is 4 under cfg(test), so loading 13 entries
        // forces 3 batch commits at i=4, 8, 12 plus a final commit. The
        // entire periodic-commit code path is exercised here — the whole
        // optimization being added — and every entry must round-trip.
        let (snapshot_bytes, expected_hash) = make_snapshot_with_n_utxos(13);

        let (utxo, _dir) = fresh();
        let meta = utxo
            .load_snapshot(
                std::io::Cursor::new(&snapshot_bytes),
                Some(&expected_hash),
                |_, _| {},
            )
            .unwrap();
        assert_eq!(meta.utxo_count, 13);
        assert_eq!(utxo.count().unwrap(), 13);

        // Spot-check entries on either side of every batch boundary.
        for i in 0u8..13 {
            let mut bytes = [0u8; 32];
            bytes[0] = i;
            let txid = Txid::from_byte_array(bytes);
            let entry = utxo.get(&txid, 0).unwrap().unwrap();
            assert_eq!(entry.amount, 1000 + i as u64);
            assert_eq!(entry.height, 1);
            assert!(!entry.is_coinbase);
            assert_eq!(entry.script_pubkey, vec![0xac]);
        }

        // The "skip height_index for snapshot rows" optimization holds
        // even across batched commits — height_index must still be empty.
        assert!(!utxo.has_utxos_at_height(1).unwrap());
    }

    #[test]
    fn snapshot_load_clears_partial_batches_on_post_commit_hash_failure() {
        // Build a 13-entry snapshot, then flip the last byte (the script
        // byte of entry 12) so the streaming hash check fails AFTER batch
        // commits at i=4, 8, 12 have already persisted 12 entries to disk.
        // The cleanup path must clear_all those persisted entries — leaving
        // a non-empty env without a marker would be unrecoverable. The
        // marker must also be removed, since cleanup_ok == true here.
        let (mut snapshot_bytes, expected_hash) = make_snapshot_with_n_utxos(13);
        let last = snapshot_bytes.len() - 1;
        snapshot_bytes[last] ^= 0xFF;

        let dir = TempDir::new().unwrap();
        let env_path = dir.path().join("utxo");
        let utxo = UtxoSet::open(env_path.to_str().unwrap()).unwrap();

        let result = utxo.load_snapshot(
            std::io::Cursor::new(&snapshot_bytes),
            Some(&expected_hash),
            |_, _| {},
        );
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("verification failed"));

        // clear_all wiped every previously committed batch.
        assert_eq!(utxo.count().unwrap(), 0);

        // cleanup_ok was true (clear_all and force_sync both succeeded),
        // so the marker must be gone — the env is back in a known-empty
        // state and a fresh load can proceed without going through
        // open()'s wipe path.
        let marker = loading_marker_path(&env_path);
        assert!(
            !marker.exists(),
            "marker should be removed when cleanup succeeds"
        );
    }

    #[test]
    fn has_utxos_at_height_after_apply() {
        let (utxo, _dir) = fresh();
        let genesis = genesis_block();
        utxo.apply_block(&genesis, 0).unwrap();
        assert!(utxo.has_utxos_at_height(0).unwrap());
        assert!(!utxo.has_utxos_at_height(1).unwrap());
    }

    #[test]
    fn has_utxos_at_height_clears_after_rollback() {
        let (utxo, _dir) = fresh();
        let genesis = genesis_block();
        utxo.apply_block(&genesis, 0).unwrap();
        utxo.rollback_block(0).unwrap();
        assert!(!utxo.has_utxos_at_height(0).unwrap());
    }
}
