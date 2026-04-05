use std::collections::{HashMap, HashSet};
use std::io::{BufReader, BufWriter, Read, Write};
use std::sync::Mutex;

use bitcoin::block::Block;
use bitcoin::hashes::Hash;
use bitcoin::Txid;
use rusqlite::{params, Connection};
use sha2::{Digest, Sha256};

use log::info;

/// Snapshot file magic bytes: "HUTX"
const SNAPSHOT_MAGIC: [u8; 4] = [b'H', b'U', b'T', b'X'];

/// Current snapshot format version.
const SNAPSHOT_VERSION: u32 = 1;

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

/// Persistent UTXO set backed by SQLite.
pub struct UtxoSet {
    conn: Mutex<Connection>,
}

impl UtxoSet {
    /// Open or create a UTXO set database at the given path.
    pub fn open(path: &str) -> Result<UtxoSet, UtxoError> {
        let conn =
            Connection::open(path).map_err(|e| UtxoError(format!("open: {}", e)))?;

        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS utxos (
                txid BLOB NOT NULL,
                vout INTEGER NOT NULL,
                amount INTEGER NOT NULL,
                script_pubkey BLOB NOT NULL,
                height INTEGER NOT NULL,
                is_coinbase INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY (txid, vout)
            );
            CREATE TABLE IF NOT EXISTS undo (
                block_height INTEGER NOT NULL,
                txid BLOB NOT NULL,
                vout INTEGER NOT NULL,
                amount INTEGER NOT NULL,
                script_pubkey BLOB NOT NULL,
                orig_height INTEGER NOT NULL,
                is_coinbase INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_undo_height ON undo(block_height);
            CREATE INDEX IF NOT EXISTS idx_utxos_height ON utxos(height);
            ",
        )
        .map_err(|e| UtxoError(format!("create tables: {}", e)))?;

        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| UtxoError(format!("set WAL: {}", e)))?;

        // Reduce fsync frequency for write-heavy workload (safe with WAL)
        conn.pragma_update(None, "synchronous", "NORMAL")
            .map_err(|e| UtxoError(format!("set synchronous: {}", e)))?;

        // 16MB page cache for random-access UTXO lookups
        conn.pragma_update(None, "cache_size", "-16000")
            .map_err(|e| UtxoError(format!("set cache_size: {}", e)))?;

        info!("UTXO set opened at {}", path);
        Ok(UtxoSet {
            conn: Mutex::new(conn),
        })
    }

    /// Look up an unspent output by txid and output index.
    pub fn get(&self, txid: &Txid, vout: u32) -> Result<Option<UtxoEntry>, UtxoError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| UtxoError(format!("lock: {}", e)))?;

        let result = conn.query_row(
            "SELECT amount, script_pubkey, height, is_coinbase FROM utxos WHERE txid = ?1 AND vout = ?2",
            params![txid.to_byte_array().as_slice(), vout],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, u32>(2)?,
                    row.get::<_, i32>(3)?,
                ))
            },
        );

        match result {
            Ok((amount_i64, script_pubkey, height, is_coinbase)) => {
                if amount_i64 < 0 {
                    return Err(UtxoError(format!(
                        "corrupt UTXO: negative amount {}",
                        amount_i64
                    )));
                }
                Ok(Some(UtxoEntry {
                    amount: amount_i64 as u64,
                    script_pubkey,
                    height,
                    is_coinbase: is_coinbase != 0,
                }))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(UtxoError(format!("get utxo: {}", e))),
        }
    }

    /// Apply a validated block to the UTXO set.
    /// Removes spent outputs and adds new unspent outputs.
    /// Handles in-block spends correctly (outputs created and spent
    /// within the same block never touch the database).
    pub fn apply_block(&self, block: &Block, height: u32) -> Result<(), UtxoError> {
        // Phase 1: Analyze the block to find in-block spends
        let mut created: HashMap<(Txid, u32), ()> = HashMap::new();
        let mut in_block_spent: HashSet<(Txid, u32)> = HashSet::new();

        for tx in &block.txdata {
            let txid = tx.compute_txid();

            // Register all non-OP_RETURN outputs as created
            for (vout, output) in tx.output.iter().enumerate() {
                if !output.script_pubkey.is_op_return() {
                    created.insert((txid, vout as u32), ());
                }
            }

            // Check if any input spends an output from this block
            if !tx.is_coinbase() {
                for input in &tx.input {
                    let key = (input.previous_output.txid, input.previous_output.vout);
                    if created.contains_key(&key) {
                        in_block_spent.insert(key);
                    }
                }
            }
        }

        // Phase 2: Apply changes in a single database transaction
        let mut conn = self
            .conn
            .lock()
            .map_err(|e| UtxoError(format!("lock: {}", e)))?;

        let db_tx = conn
            .transaction()
            .map_err(|e| UtxoError(format!("begin tx: {}", e)))?;

        // Save undo data and delete spent persistent UTXOs
        {
            // Copy each spent UTXO to the undo table before deleting
            let mut undo_stmt = db_tx
                .prepare_cached(
                    "INSERT INTO undo (block_height, txid, vout, amount, script_pubkey, orig_height, is_coinbase) \
                     SELECT ?1, txid, vout, amount, script_pubkey, height, is_coinbase \
                     FROM utxos WHERE txid = ?2 AND vout = ?3",
                )
                .map_err(|e| UtxoError(format!("prepare undo: {}", e)))?;

            let mut del_stmt = db_tx
                .prepare_cached("DELETE FROM utxos WHERE txid = ?1 AND vout = ?2")
                .map_err(|e| UtxoError(format!("prepare delete: {}", e)))?;

            for tx in &block.txdata {
                if tx.is_coinbase() {
                    continue;
                }
                for input in &tx.input {
                    let key = (input.previous_output.txid, input.previous_output.vout);
                    if !in_block_spent.contains(&key) {
                        let txid_bytes = input.previous_output.txid.to_byte_array();

                        undo_stmt
                            .execute(params![
                                height,
                                txid_bytes.as_slice(),
                                input.previous_output.vout,
                            ])
                            .map_err(|e| UtxoError(format!("save undo: {}", e)))?;

                        del_stmt
                            .execute(params![
                                txid_bytes.as_slice(),
                                input.previous_output.vout,
                            ])
                            .map_err(|e| UtxoError(format!("delete utxo: {}", e)))?;
                    }
                }
            }
        }

        // Insert new UTXOs (skip in-block-spent outputs and OP_RETURN)
        {
            let mut ins_stmt = db_tx
                .prepare_cached(
                    "INSERT INTO utxos (txid, vout, amount, script_pubkey, height, is_coinbase) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                )
                .map_err(|e| UtxoError(format!("prepare insert: {}", e)))?;

            for tx in &block.txdata {
                let txid = tx.compute_txid();
                let is_cb = tx.is_coinbase();

                for (vout, output) in tx.output.iter().enumerate() {
                    if output.script_pubkey.is_op_return() {
                        continue;
                    }
                    let key = (txid, vout as u32);
                    if in_block_spent.contains(&key) {
                        continue;
                    }
                    ins_stmt
                        .execute(params![
                            txid.to_byte_array().as_slice(),
                            vout as u32,
                            output.value.to_sat() as i64,
                            output.script_pubkey.as_bytes(),
                            height,
                            is_cb as i32,
                        ])
                        .map_err(|e| UtxoError(format!("insert utxo: {}", e)))?;
                }
            }
        }

        db_tx
            .commit()
            .map_err(|e| UtxoError(format!("commit: {}", e)))?;

        Ok(())
    }

    /// Undo a block's UTXO changes. Must be called from the chain tip downward.
    ///
    /// 1. Removes all outputs created at this height
    /// 2. Restores all outputs that were spent at this height (from undo data)
    /// 3. Deletes the undo data for this height
    pub fn rollback_block(&self, height: u32) -> Result<(), UtxoError> {
        let mut conn = self
            .conn
            .lock()
            .map_err(|e| UtxoError(format!("lock: {}", e)))?;

        let db_tx = conn
            .transaction()
            .map_err(|e| UtxoError(format!("begin tx: {}", e)))?;

        // Remove outputs created at this height
        db_tx
            .execute("DELETE FROM utxos WHERE height = ?1", params![height])
            .map_err(|e| UtxoError(format!("delete created: {}", e)))?;

        // Restore spent outputs from undo data (OR IGNORE in case of
        // PK conflict from an interrupted previous rollback)
        db_tx
            .execute(
                "INSERT OR IGNORE INTO utxos (txid, vout, amount, script_pubkey, height, is_coinbase) \
                 SELECT txid, vout, amount, script_pubkey, orig_height, is_coinbase \
                 FROM undo WHERE block_height = ?1",
                params![height],
            )
            .map_err(|e| UtxoError(format!("restore undo: {}", e)))?;

        // Clean up undo data
        db_tx
            .execute(
                "DELETE FROM undo WHERE block_height = ?1",
                params![height],
            )
            .map_err(|e| UtxoError(format!("delete undo: {}", e)))?;

        db_tx
            .commit()
            .map_err(|e| UtxoError(format!("commit rollback: {}", e)))?;

        Ok(())
    }

    /// Delete undo data for blocks below the given height.
    /// Call this to reclaim disk space for deeply-buried blocks
    /// that will never be rolled back.
    pub fn prune_undo_below(&self, height: u32) -> Result<(), UtxoError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| UtxoError(format!("lock: {}", e)))?;

        conn.execute(
            "DELETE FROM undo WHERE block_height < ?1",
            params![height],
        )
        .map_err(|e| UtxoError(format!("prune undo: {}", e)))?;

        Ok(())
    }

    // ── Snapshot support ─────────────────────────────────────────────

    /// Compute a deterministic SHA256 hash over the entire UTXO set.
    /// Iterates all UTXOs in (txid, vout) order and hashes each entry.
    pub fn compute_hash(&self) -> Result<[u8; 32], UtxoError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| UtxoError(format!("lock: {}", e)))?;

        let mut stmt = conn
            .prepare(
                "SELECT txid, vout, amount, script_pubkey, height, is_coinbase \
                 FROM utxos ORDER BY txid, vout",
            )
            .map_err(|e| UtxoError(format!("prepare hash query: {}", e)))?;

        let mut hasher = Sha256::new();

        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, u32>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, u32>(4)?,
                    row.get::<_, i32>(5)?,
                ))
            })
            .map_err(|e| UtxoError(format!("hash query: {}", e)))?;

        for row in rows {
            let (txid, vout, amount, script, height, is_cb) =
                row.map_err(|e| UtxoError(format!("hash row: {}", e)))?;
            if script.len() > u16::MAX as usize {
                return Err(UtxoError(format!(
                    "script too long for hash: {} bytes",
                    script.len()
                )));
            }
            hasher.update(&txid);
            hasher.update(&vout.to_le_bytes());
            hasher.update(&amount.to_le_bytes());
            hasher.update(&(script.len() as u16).to_le_bytes());
            hasher.update(&script);
            hasher.update(&height.to_le_bytes());
            hasher.update(&[is_cb as u8]);
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

        // Write header
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

        // Write entries
        let conn = self
            .conn
            .lock()
            .map_err(|e| UtxoError(format!("lock: {}", e)))?;

        let mut stmt = conn
            .prepare(
                "SELECT txid, vout, amount, script_pubkey, height, is_coinbase \
                 FROM utxos ORDER BY txid, vout",
            )
            .map_err(|e| UtxoError(format!("prepare snapshot query: {}", e)))?;

        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, u32>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, u32>(4)?,
                    row.get::<_, i32>(5)?,
                ))
            })
            .map_err(|e| UtxoError(format!("snapshot query: {}", e)))?;

        for row in rows {
            let (txid, vout, amount, script, h, is_cb) =
                row.map_err(|e| UtxoError(format!("snapshot row: {}", e)))?;

            w.write_all(&txid)
                .map_err(|e| UtxoError(format!("write txid: {}", e)))?;
            w.write_all(&vout.to_le_bytes())
                .map_err(|e| UtxoError(format!("write vout: {}", e)))?;
            w.write_all(&amount.to_le_bytes())
                .map_err(|e| UtxoError(format!("write amount: {}", e)))?;
            w.write_all(&h.to_le_bytes())
                .map_err(|e| UtxoError(format!("write entry height: {}", e)))?;
            w.write_all(&[is_cb as u8])
                .map_err(|e| UtxoError(format!("write is_coinbase: {}", e)))?;
            if script.len() > u16::MAX as usize {
                return Err(UtxoError(format!(
                    "script too long for snapshot format: {} bytes (max {})",
                    script.len(),
                    u16::MAX
                )));
            }
            let script_len = script.len() as u16;
            w.write_all(&script_len.to_le_bytes())
                .map_err(|e| UtxoError(format!("write script_len: {}", e)))?;
            w.write_all(&script)
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
    pub fn load_snapshot<R: std::io::Read, F>(
        &self,
        reader: R,
        expected_hash: Option<&[u8; 32]>,
        on_progress: F,
    ) -> Result<SnapshotMeta, UtxoError>
    where
        F: Fn(u64, u64),
    {
        let mut r = BufReader::new(reader);

        // Read header
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

        // Verify against expected hash if provided
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

        // Bulk-load entries with incremental hash verification.
        // Hash is computed during insertion and verified BEFORE commit
        // so corrupt data never persists.
        let mut conn = self
            .conn
            .lock()
            .map_err(|e| UtxoError(format!("lock: {}", e)))?;

        // Emptiness check inside the lock to prevent TOCTOU race with apply_block
        let current: i64 = conn
            .query_row("SELECT COUNT(*) FROM utxos", [], |row| row.get(0))
            .map_err(|e| UtxoError(format!("count for snapshot check: {}", e)))?;
        if current > 0 {
            return Err(UtxoError(
                "UTXO set must be empty before loading snapshot".into(),
            ));
        }

        let db_tx = conn
            .transaction()
            .map_err(|e| UtxoError(format!("begin tx: {}", e)))?;

        {
            let mut stmt = db_tx
                .prepare_cached(
                    "INSERT INTO utxos (txid, vout, amount, script_pubkey, height, is_coinbase) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                )
                .map_err(|e| UtxoError(format!("prepare insert: {}", e)))?;

            let mut txid = [0u8; 32];
            let mut buf2 = [0u8; 2];
            let mut hasher = Sha256::new();
            let mut prev_key: Option<([u8; 32], u32)> = None;

            for i in 0..utxo_count {
                r.read_exact(&mut txid)
                    .map_err(|e| UtxoError(format!("read txid at {}: {}", i, e)))?;
                r.read_exact(&mut buf4)
                    .map_err(|e| UtxoError(format!("read vout at {}: {}", i, e)))?;
                let vout = u32::from_le_bytes(buf4);

                // Verify entries are sorted by (txid, vout) — required for
                // deterministic hash and matches DB ORDER BY
                let key = (txid, vout);
                if let Some(ref prev) = prev_key {
                    if key <= *prev {
                        return Err(UtxoError(
                            "snapshot entries not sorted by (txid, vout)".into(),
                        ));
                    }
                }
                prev_key = Some(key);

                r.read_exact(&mut buf8)
                    .map_err(|e| UtxoError(format!("read amount at {}: {}", i, e)))?;
                let amount = i64::from_le_bytes(buf8);

                r.read_exact(&mut buf4)
                    .map_err(|e| UtxoError(format!("read entry height at {}: {}", i, e)))?;
                let entry_height = u32::from_le_bytes(buf4);

                let mut cb_byte = [0u8; 1];
                r.read_exact(&mut cb_byte)
                    .map_err(|e| UtxoError(format!("read is_coinbase at {}: {}", i, e)))?;
                let is_coinbase = cb_byte[0] as i32;

                r.read_exact(&mut buf2)
                    .map_err(|e| UtxoError(format!("read script_len at {}: {}", i, e)))?;
                let script_len = u16::from_le_bytes(buf2) as usize;

                let mut script = vec![0u8; script_len];
                r.read_exact(&mut script)
                    .map_err(|e| UtxoError(format!("read script at {}: {}", i, e)))?;

                // Feed to hasher in same format/order as compute_hash()
                hasher.update(&txid);
                hasher.update(&vout.to_le_bytes());
                hasher.update(&amount.to_le_bytes());
                hasher.update(&(script_len as u16).to_le_bytes());
                hasher.update(&script);
                hasher.update(&entry_height.to_le_bytes());
                hasher.update(&[is_coinbase as u8]);

                stmt.execute(params![
                    txid.as_slice(),
                    vout,
                    amount,
                    script,
                    entry_height,
                    is_coinbase,
                ])
                .map_err(|e| UtxoError(format!("insert snapshot utxo {}: {}", i, e)))?;

                if i % 100_000 == 0 {
                    on_progress(i, utxo_count);
                }
            }

            // Verify hash BEFORE commit — reject corrupt data without persisting
            let loaded_hash: [u8; 32] = hasher.finalize().into();
            if loaded_hash != file_hash {
                // db_tx is dropped without commit → automatic rollback
                return Err(UtxoError(format!(
                    "snapshot verification failed: loaded={}, expected={}",
                    hex::encode(loaded_hash),
                    hex::encode(file_hash)
                )));
            }
        }

        db_tx
            .commit()
            .map_err(|e| UtxoError(format!("commit snapshot: {}", e)))?;

        drop(conn);

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

    /// Check if any UTXOs exist at the given block height.
    /// Used for crash recovery: if UTXOs from a block exist but validated_height
    /// wasn't updated, the block was already applied.
    pub fn has_utxos_at_height(&self, height: u32) -> Result<bool, UtxoError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| UtxoError(format!("lock: {}", e)))?;
        let result = conn.query_row(
            "SELECT 1 FROM utxos WHERE height = ?1 LIMIT 1",
            params![height],
            |_| Ok(()),
        );
        match result {
            Ok(()) => Ok(true),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(false),
            Err(e) => Err(UtxoError(format!("check height {}: {}", height, e))),
        }
    }

    /// Get the number of UTXOs in the set.
    pub fn count(&self) -> Result<u64, UtxoError> {
        let conn = self
            .conn
            .lock()
            .map_err(|e| UtxoError(format!("lock: {}", e)))?;
        let count: i64 = conn
            .query_row("SELECT COUNT(*) FROM utxos", [], |row| row.get(0))
            .map_err(|e| UtxoError(format!("count: {}", e)))?;
        Ok(count as u64)
    }
}

#[derive(Debug)]
pub struct UtxoError(pub String);

impl std::fmt::Display for UtxoError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "utxo error: {}", self.0)
    }
}

impl std::error::Error for UtxoError {}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::block::Block;
    use bitcoin::consensus::deserialize;

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
        let utxo = UtxoSet::open(":memory:").unwrap();
        assert_eq!(utxo.count().unwrap(), 0);
    }

    #[test]
    fn get_missing_utxo_returns_none() {
        let utxo = UtxoSet::open(":memory:").unwrap();
        let txid = Txid::from_byte_array([0u8; 32]);
        assert!(utxo.get(&txid, 0).unwrap().is_none());
    }

    #[test]
    fn apply_genesis_creates_one_utxo() {
        let utxo = UtxoSet::open(":memory:").unwrap();
        let genesis = genesis_block();

        utxo.apply_block(&genesis, 0).unwrap();
        assert_eq!(utxo.count().unwrap(), 1);

        // The genesis coinbase output should be 50 BTC
        let coinbase_txid = genesis.txdata[0].compute_txid();
        let entry = utxo.get(&coinbase_txid, 0).unwrap().unwrap();
        assert_eq!(entry.amount, 50 * 100_000_000);
        assert!(entry.is_coinbase);
        assert_eq!(entry.height, 0);
    }

    #[test]
    fn rollback_genesis_restores_empty_set() {
        let utxo = UtxoSet::open(":memory:").unwrap();
        let genesis = genesis_block();

        utxo.apply_block(&genesis, 0).unwrap();
        assert_eq!(utxo.count().unwrap(), 1);

        utxo.rollback_block(0).unwrap();
        assert_eq!(utxo.count().unwrap(), 0);

        // The UTXO should be gone
        let coinbase_txid = genesis.txdata[0].compute_txid();
        assert!(utxo.get(&coinbase_txid, 0).unwrap().is_none());
    }

    #[test]
    fn apply_and_rollback_roundtrip() {
        let utxo = UtxoSet::open(":memory:").unwrap();
        let genesis = genesis_block();

        // Apply block 0
        utxo.apply_block(&genesis, 0).unwrap();
        assert_eq!(utxo.count().unwrap(), 1);

        // Apply block 0 again at height 1 (reuses genesis block for simplicity)
        // This adds another UTXO with the same txid but different height tracking
        // (INSERT would conflict on PK, so this tests the duplicate handling)
        // Actually, same txid+vout = PK conflict. Let me just test rollback at height 0.

        // Rollback block 0
        utxo.rollback_block(0).unwrap();
        assert_eq!(utxo.count().unwrap(), 0);
    }

    #[test]
    fn rollback_restores_spent_utxos() {
        let utxo = UtxoSet::open(":memory:").unwrap();

        // Manually insert a UTXO (simulating a previous block's output)
        {
            let conn = utxo.conn.lock().unwrap();
            conn.execute(
                "INSERT INTO utxos (txid, vout, amount, script_pubkey, height, is_coinbase) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    [1u8; 32].as_slice(),
                    0u32,
                    1000i64,
                    vec![0x76u8, 0xa9],
                    5u32,
                    0i32,
                ],
            )
            .unwrap();

            // Simulate undo data for block 10 having spent this UTXO
            conn.execute(
                "INSERT INTO undo (block_height, txid, vout, amount, script_pubkey, orig_height, is_coinbase) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                params![10u32, [1u8; 32].as_slice(), 0u32, 1000i64, vec![0x76u8, 0xa9], 5u32, 0i32],
            )
            .unwrap();

            // Also simulate block 10 having created a new output
            conn.execute(
                "INSERT INTO utxos (txid, vout, amount, script_pubkey, height, is_coinbase) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![
                    [2u8; 32].as_slice(),
                    0u32,
                    500i64,
                    vec![0x76u8, 0xa9],
                    10u32,
                    0i32,
                ],
            )
            .unwrap();
        }

        // Before rollback: 1 UTXO at height 10 (the old one was spent)
        // Plus the manually inserted UTXO we're pretending was spent
        // Actually we have 2 UTXOs: the old one at height 5 is NOT in the table
        // (it was "spent"), and block 10's output IS in the table.
        // Wait, I inserted both. Let me reconsider.

        // State: utxos has the height-5 entry AND the height-10 entry = 2 UTXOs
        // But conceptually, the height-5 entry was spent by block 10 and should not be there.
        // Let me remove it to simulate the correct state.
        {
            let conn = utxo.conn.lock().unwrap();
            conn.execute(
                "DELETE FROM utxos WHERE txid = ?1 AND vout = ?2",
                params![[1u8; 32].as_slice(), 0u32],
            )
            .unwrap();
        }

        // Now: 1 UTXO (height 10), undo data says height-5 UTXO was spent
        assert_eq!(utxo.count().unwrap(), 1);

        let txid_old = Txid::from_byte_array([1u8; 32]);
        let txid_new = Txid::from_byte_array([2u8; 32]);
        assert!(utxo.get(&txid_old, 0).unwrap().is_none());
        assert!(utxo.get(&txid_new, 0).unwrap().is_some());

        // Rollback block 10
        utxo.rollback_block(10).unwrap();

        // After rollback: height-10 output removed, height-5 output restored
        assert_eq!(utxo.count().unwrap(), 1);
        let restored = utxo.get(&txid_old, 0).unwrap().unwrap();
        assert_eq!(restored.amount, 1000);
        assert_eq!(restored.height, 5);
        assert!(!restored.is_coinbase);

        assert!(utxo.get(&txid_new, 0).unwrap().is_none());
    }

    #[test]
    fn prune_undo_removes_old_data() {
        let utxo = UtxoSet::open(":memory:").unwrap();

        // Insert undo data at various heights
        {
            let conn = utxo.conn.lock().unwrap();
            for h in [5u32, 10, 15, 20] {
                conn.execute(
                    "INSERT INTO undo (block_height, txid, vout, amount, script_pubkey, orig_height, is_coinbase) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![h, [h as u8; 32].as_slice(), 0u32, 100i64, vec![0xacu8], 0u32, 0i32],
                )
                .unwrap();
            }
        }

        // Prune below height 15 — should remove heights 5 and 10
        utxo.prune_undo_below(15).unwrap();

        // Verify: rollback at 5 and 10 should be no-ops (no undo data)
        // rollback at 15 and 20 should still work
        let conn = utxo.conn.lock().unwrap();
        let remaining: i64 = conn
            .query_row("SELECT COUNT(*) FROM undo", [], |row| row.get(0))
            .unwrap();
        assert_eq!(remaining, 2); // heights 15 and 20
    }

    #[test]
    fn negative_amount_detected_on_read() {
        let utxo = UtxoSet::open(":memory:").unwrap();

        // Manually insert a corrupted UTXO with negative amount
        {
            let conn = utxo.conn.lock().unwrap();
            conn.execute(
                "INSERT INTO utxos (txid, vout, amount, script_pubkey, height, is_coinbase) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![[9u8; 32].as_slice(), 0u32, -1i64, vec![0xacu8], 0u32, 0i32],
            )
            .unwrap();
        }

        let txid = Txid::from_byte_array([9u8; 32]);
        let result = utxo.get(&txid, 0);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("negative amount"));
    }

    #[test]
    fn compute_hash_deterministic() {
        let utxo = UtxoSet::open(":memory:").unwrap();
        let genesis = genesis_block();
        utxo.apply_block(&genesis, 0).unwrap();

        let hash1 = utxo.compute_hash().unwrap();
        let hash2 = utxo.compute_hash().unwrap();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn snapshot_write_and_load_roundtrip() {
        let utxo1 = UtxoSet::open(":memory:").unwrap();
        let genesis = genesis_block();
        utxo1.apply_block(&genesis, 0).unwrap();
        assert_eq!(utxo1.count().unwrap(), 1);

        let block_hash = [0xABu8; 32];
        let mut buf = Vec::new();
        let meta = utxo1.write_snapshot(&mut buf, 0, &block_hash).unwrap();
        assert_eq!(meta.height, 0);
        assert_eq!(meta.block_hash, block_hash);
        assert_eq!(meta.utxo_count, 1);

        let utxo2 = UtxoSet::open(":memory:").unwrap();
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
        let utxo1 = UtxoSet::open(":memory:").unwrap();
        let genesis = genesis_block();
        utxo1.apply_block(&genesis, 0).unwrap();

        let mut buf = Vec::new();
        utxo1.write_snapshot(&mut buf, 0, &[0u8; 32]).unwrap();

        let utxo2 = UtxoSet::open(":memory:").unwrap();
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
        let utxo = UtxoSet::open(":memory:").unwrap();
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
        let utxo = UtxoSet::open(":memory:").unwrap();
        let result = utxo.load_snapshot(
            std::io::Cursor::new(b"BADXsomegarbagedata"),
            None,
            |_, _| {},
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("invalid snapshot magic"));
    }
}
