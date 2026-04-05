use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use bitcoin::block::Block;
use bitcoin::hashes::Hash;
use bitcoin::Txid;
use rusqlite::{params, Connection};

use log::info;

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
            ",
        )
        .map_err(|e| UtxoError(format!("create table: {}", e)))?;

        conn.pragma_update(None, "journal_mode", "WAL")
            .map_err(|e| UtxoError(format!("set WAL: {}", e)))?;

        // Reduce fsync frequency for write-heavy workload (safe with WAL)
        conn.pragma_update(None, "synchronous", "NORMAL")
            .map_err(|e| UtxoError(format!("set synchronous: {}", e)))?;

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

        // Delete spent persistent UTXOs
        {
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
                        del_stmt
                            .execute(params![
                                input.previous_output.txid.to_byte_array().as_slice(),
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
}
