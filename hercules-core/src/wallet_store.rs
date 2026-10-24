use std::path::Path;

use heed::types::{Bytes, Unit};
use heed::{Database, Env, EnvOpenOptions};
use log::info;

/// LMDB map size for the wallet env. 1 GB virtual — wallet state is tiny
/// (a few hundred KB even for heavy-use wallets) but LMDB requires an
/// upfront virtual address reservation.
const MAP_SIZE: usize = 1 << 30;

/// Maximum named databases inside the wallet LMDB env.
const MAX_DBS: u32 = 8;

// ── UTXO value encoding ────────────────────────────────────────────────
// amount(8 LE) || height(4 LE) || deriv_index(4 LE) || is_change(1) || script_pubkey(var)
const UTXO_HEADER_LEN: usize = 8 + 4 + 4 + 1; // 17

// ── Address value encoding ─────────────────────────────────────────────
// deriv_index(4 LE) || is_change(1) || used(1)
const ADDR_VALUE_LEN: usize = 4 + 1 + 1; // 6

// ── Transaction value encoding ─────────────────────────────────────────
// timestamp(4 LE) || net_value(8 LE signed)
const TX_VALUE_LEN: usize = 4 + 8; // 12

// ── Transaction key encoding ───────────────────────────────────────────
// height(4 BE) || txid(32)
const TX_KEY_LEN: usize = 4 + 32; // 36

/// Height sentinel for unconfirmed (mempool) transactions. Sorts last
/// in big-endian iteration so confirmed txs appear first chronologically.
const UNCONFIRMED_HEIGHT: u32 = 0xFFFF_FFFF;

// ── Undo key encoding ──────────────────────────────────────────────────
// height(4 BE) || txid(32) || vout(4 BE)
const UNDO_KEY_LEN: usize = 4 + 32 + 4; // 40

#[derive(Debug)]
pub struct WalletStoreError(pub String);

impl std::fmt::Display for WalletStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "WalletStoreError: {}", self.0)
    }
}

/// Persistent wallet state backed by its own LMDB environment.
pub struct WalletStore {
    env: Env,
    /// `"xpub"`, `"network"`, `"scan_height"`, `"next_receive_index"`,
    /// `"next_change_index"` — small key-value metadata.
    meta: Database<Bytes, Bytes>,
    /// Key: raw scriptPubKey bytes. Value: derivation metadata.
    addresses: Database<Bytes, Bytes>,
    /// Key: txid(32)||vout(4 BE). Value: UTXO details.
    utxos: Database<Bytes, Bytes>,
    /// Key: height(4 BE)||txid(32). Value: tx summary.
    transactions: Database<Bytes, Bytes>,
    /// Key: height(4 BE)||txid(32)||vout(4 BE). Value: full spent UTXO
    /// for rollback. Pruned after 288 blocks.
    undo: Database<Bytes, Bytes>,
}

// ── Public address info returned by queries ─────────────────────────────

#[derive(Debug, Clone)]
pub struct StoredAddress {
    pub script_pubkey: Vec<u8>,
    pub derivation_index: u32,
    pub is_change: bool,
    pub used: bool,
}

#[derive(Debug, Clone)]
pub struct StoredUtxo {
    pub txid: [u8; 32],
    pub vout: u32,
    pub amount: u64,
    pub height: u32, // 0 = unconfirmed
    pub derivation_index: u32,
    pub is_change: bool,
    pub script_pubkey: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct StoredTx {
    pub txid: [u8; 32],
    pub height: Option<u32>, // None = unconfirmed
    pub timestamp: u32,
    pub net_value: i64,
}

// ── Batch input for atomic block application ────────────────────────────

pub struct BlockBatch {
    pub new_utxos: Vec<StoredUtxo>,
    pub spent_outpoints: Vec<([u8; 32], u32)>,
    /// Undo entries: the full UTXO that was spent, so rollback can restore it.
    pub undo_entries: Vec<StoredUtxo>,
    pub tx: Option<StoredTx>,
    pub used_scripts: Vec<Vec<u8>>,
    pub new_scan_height: u32,
}

impl WalletStore {
    /// Open (or create) the wallet LMDB environment at `path`.
    pub fn open(path: &str) -> Result<WalletStore, WalletStoreError> {
        let p = Path::new(path);
        if !p.exists() {
            std::fs::create_dir_all(p)
                .map_err(|e| WalletStoreError(format!("mkdir {}: {}", path, e)))?;
        }

        let env = unsafe {
            EnvOpenOptions::new()
                .map_size(MAP_SIZE)
                .max_dbs(MAX_DBS)
                .open(p)
        }
        .map_err(|e| WalletStoreError(format!("open env: {}", e)))?;

        let mut wtxn = env
            .write_txn()
            .map_err(|e| WalletStoreError(format!("write txn: {}", e)))?;

        let meta: Database<Bytes, Bytes> = env
            .create_database(&mut wtxn, Some("meta"))
            .map_err(|e| WalletStoreError(format!("create meta db: {}", e)))?;
        let addresses: Database<Bytes, Bytes> = env
            .create_database(&mut wtxn, Some("addresses"))
            .map_err(|e| WalletStoreError(format!("create addresses db: {}", e)))?;
        let utxos: Database<Bytes, Bytes> = env
            .create_database(&mut wtxn, Some("utxos"))
            .map_err(|e| WalletStoreError(format!("create utxos db: {}", e)))?;
        let transactions: Database<Bytes, Bytes> = env
            .create_database(&mut wtxn, Some("transactions"))
            .map_err(|e| WalletStoreError(format!("create transactions db: {}", e)))?;
        let undo: Database<Bytes, Bytes> = env
            .create_database(&mut wtxn, Some("undo"))
            .map_err(|e| WalletStoreError(format!("create undo db: {}", e)))?;

        wtxn.commit()
            .map_err(|e| WalletStoreError(format!("commit: {}", e)))?;

        info!("Wallet LMDB env opened at {}", path);

        Ok(WalletStore {
            env,
            meta,
            addresses,
            utxos,
            transactions,
            undo,
        })
    }

    // ── Meta helpers ────────────────────────────────────────────────────

    pub fn get_meta(&self, key: &str) -> Result<Option<Vec<u8>>, WalletStoreError> {
        let rtxn = self
            .env
            .read_txn()
            .map_err(|e| WalletStoreError(format!("read txn: {}", e)))?;
        let val = self
            .meta
            .get(&rtxn, key.as_bytes())
            .map_err(|e| WalletStoreError(format!("get meta {}: {}", key, e)))?;
        Ok(val.map(|v| v.to_vec()))
    }

    pub fn set_meta(&self, key: &str, value: &[u8]) -> Result<(), WalletStoreError> {
        let mut wtxn = self
            .env
            .write_txn()
            .map_err(|e| WalletStoreError(format!("write txn: {}", e)))?;
        self.meta
            .put(&mut wtxn, key.as_bytes(), value)
            .map_err(|e| WalletStoreError(format!("put meta {}: {}", key, e)))?;
        wtxn.commit()
            .map_err(|e| WalletStoreError(format!("commit: {}", e)))?;
        Ok(())
    }

    pub fn get_scan_height(&self) -> Result<u32, WalletStoreError> {
        match self.get_meta("scan_height")? {
            Some(v) if v.len() == 4 => Ok(u32::from_le_bytes(v[..4].try_into().unwrap())),
            _ => Ok(0),
        }
    }

    pub fn get_next_receive_index(&self) -> Result<u32, WalletStoreError> {
        match self.get_meta("next_receive_index")? {
            Some(v) if v.len() == 4 => Ok(u32::from_le_bytes(v[..4].try_into().unwrap())),
            _ => Ok(0),
        }
    }

    pub fn get_next_change_index(&self) -> Result<u32, WalletStoreError> {
        match self.get_meta("next_change_index")? {
            Some(v) if v.len() == 4 => Ok(u32::from_le_bytes(v[..4].try_into().unwrap())),
            _ => Ok(0),
        }
    }

    // ── Address methods ─────────────────────────────────────────────────

    pub fn put_address(
        &self,
        script: &[u8],
        index: u32,
        is_change: bool,
    ) -> Result<(), WalletStoreError> {
        let mut wtxn = self
            .env
            .write_txn()
            .map_err(|e| WalletStoreError(format!("write txn: {}", e)))?;
        let val = encode_addr_value(index, is_change, false);
        self.addresses
            .put(&mut wtxn, script, &val)
            .map_err(|e| WalletStoreError(format!("put address: {}", e)))?;
        wtxn.commit()
            .map_err(|e| WalletStoreError(format!("commit: {}", e)))?;
        Ok(())
    }

    pub fn is_watched(&self, script: &[u8]) -> Result<bool, WalletStoreError> {
        let rtxn = self
            .env
            .read_txn()
            .map_err(|e| WalletStoreError(format!("read txn: {}", e)))?;
        let val = self
            .addresses
            .get(&rtxn, script)
            .map_err(|e| WalletStoreError(format!("get address: {}", e)))?;
        Ok(val.is_some())
    }

    /// Returns all stored scriptPubKeys (for rebuilding the in-memory watch set).
    pub fn all_scripts(&self) -> Result<Vec<Vec<u8>>, WalletStoreError> {
        let rtxn = self
            .env
            .read_txn()
            .map_err(|e| WalletStoreError(format!("read txn: {}", e)))?;
        let iter = self
            .addresses
            .iter(&rtxn)
            .map_err(|e| WalletStoreError(format!("iter addresses: {}", e)))?;
        let mut scripts = Vec::new();
        for result in iter {
            let (k, _v) = result.map_err(|e| WalletStoreError(format!("iter: {}", e)))?;
            scripts.push(k.to_vec());
        }
        Ok(scripts)
    }

    /// Look up derivation metadata for a scriptPubKey.
    pub fn get_address_info(&self, script: &[u8]) -> Result<Option<StoredAddress>, WalletStoreError> {
        let rtxn = self
            .env
            .read_txn()
            .map_err(|e| WalletStoreError(format!("read txn: {}", e)))?;
        let val = self
            .addresses
            .get(&rtxn, script)
            .map_err(|e| WalletStoreError(format!("get address: {}", e)))?;
        match val {
            Some(v) => Ok(Some(decode_addr_value(script, v)?)),
            None => Ok(None),
        }
    }

    // ── UTXO methods ────────────────────────────────────────────────────

    fn utxo_key(txid: &[u8; 32], vout: u32) -> [u8; 36] {
        let mut key = [0u8; 36];
        key[..32].copy_from_slice(txid);
        key[32..36].copy_from_slice(&vout.to_be_bytes());
        key
    }

    pub fn put_utxo(&self, utxo: &StoredUtxo) -> Result<(), WalletStoreError> {
        let mut wtxn = self
            .env
            .write_txn()
            .map_err(|e| WalletStoreError(format!("write txn: {}", e)))?;
        let key = Self::utxo_key(&utxo.txid, utxo.vout);
        let val = encode_utxo_value(utxo);
        self.utxos
            .put(&mut wtxn, &key, &val)
            .map_err(|e| WalletStoreError(format!("put utxo: {}", e)))?;
        wtxn.commit()
            .map_err(|e| WalletStoreError(format!("commit: {}", e)))?;
        Ok(())
    }

    pub fn get_utxo(&self, txid: &[u8; 32], vout: u32) -> Result<Option<StoredUtxo>, WalletStoreError> {
        let rtxn = self
            .env
            .read_txn()
            .map_err(|e| WalletStoreError(format!("read txn: {}", e)))?;
        let key = Self::utxo_key(txid, vout);
        let val = self
            .utxos
            .get(&rtxn, &key)
            .map_err(|e| WalletStoreError(format!("get utxo: {}", e)))?;
        match val {
            Some(v) => Ok(Some(decode_utxo_value(txid, vout, v)?)),
            None => Ok(None),
        }
    }

    pub fn all_utxos(&self) -> Result<Vec<StoredUtxo>, WalletStoreError> {
        let rtxn = self
            .env
            .read_txn()
            .map_err(|e| WalletStoreError(format!("read txn: {}", e)))?;
        let iter = self
            .utxos
            .iter(&rtxn)
            .map_err(|e| WalletStoreError(format!("iter utxos: {}", e)))?;
        let mut out = Vec::new();
        for result in iter {
            let (k, v) = result.map_err(|e| WalletStoreError(format!("iter: {}", e)))?;
            if k.len() < 36 {
                continue;
            }
            let mut txid = [0u8; 32];
            txid.copy_from_slice(&k[..32]);
            let vout = u32::from_be_bytes(k[32..36].try_into().unwrap());
            out.push(decode_utxo_value(&txid, vout, v)?);
        }
        Ok(out)
    }

    // ── Transaction methods ─────────────────────────────────────────────

    fn tx_key(height: Option<u32>, txid: &[u8; 32]) -> [u8; TX_KEY_LEN] {
        let mut key = [0u8; TX_KEY_LEN];
        let h = height.unwrap_or(UNCONFIRMED_HEIGHT);
        key[..4].copy_from_slice(&h.to_be_bytes());
        key[4..36].copy_from_slice(txid);
        key
    }

    pub fn get_transactions(
        &self,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<StoredTx>, WalletStoreError> {
        let rtxn = self
            .env
            .read_txn()
            .map_err(|e| WalletStoreError(format!("read txn: {}", e)))?;
        let iter = self
            .transactions
            .rev_iter(&rtxn)
            .map_err(|e| WalletStoreError(format!("rev_iter txs: {}", e)))?;

        let mut out = Vec::new();
        let mut skipped = 0u32;
        for result in iter {
            let (k, v) = result.map_err(|e| WalletStoreError(format!("iter: {}", e)))?;
            if skipped < offset {
                skipped += 1;
                continue;
            }
            if out.len() as u32 >= limit {
                break;
            }
            if k.len() < TX_KEY_LEN || v.len() < TX_VALUE_LEN {
                continue;
            }
            out.push(decode_tx_entry(k, v)?);
        }
        Ok(out)
    }

    // ── Undo methods ────────────────────────────────────────────────────

    fn undo_key(height: u32, txid: &[u8; 32], vout: u32) -> [u8; UNDO_KEY_LEN] {
        let mut key = [0u8; UNDO_KEY_LEN];
        key[..4].copy_from_slice(&height.to_be_bytes());
        key[4..36].copy_from_slice(txid);
        key[36..40].copy_from_slice(&vout.to_be_bytes());
        key
    }

    /// Remove all undo entries below `height` (called periodically to
    /// match the node's 288-block undo horizon).
    pub fn prune_undo_below(&self, height: u32) -> Result<(), WalletStoreError> {
        let mut wtxn = self
            .env
            .write_txn()
            .map_err(|e| WalletStoreError(format!("write txn: {}", e)))?;
        let upper = height.to_be_bytes();
        let lower = [0u8; UNDO_KEY_LEN];
        let range = (
            std::ops::Bound::Included(lower.as_slice()),
            std::ops::Bound::Excluded(upper.as_slice()),
        );
        self.undo
            .delete_range(&mut wtxn, &range)
            .map_err(|e| WalletStoreError(format!("prune undo: {}", e)))?;
        wtxn.commit()
            .map_err(|e| WalletStoreError(format!("commit: {}", e)))?;
        Ok(())
    }

    // ── Atomic block batch ──────────────────────────────────────────────

    /// Apply all wallet state changes from a single block atomically.
    pub fn apply_block_batch(&self, batch: &BlockBatch) -> Result<(), WalletStoreError> {
        let mut wtxn = self
            .env
            .write_txn()
            .map_err(|e| WalletStoreError(format!("write txn: {}", e)))?;

        // 1. Write undo entries for spent UTXOs (before removing them).
        for undo_utxo in &batch.undo_entries {
            let key = Self::undo_key(batch.new_scan_height, &undo_utxo.txid, undo_utxo.vout);
            let val = encode_utxo_value(undo_utxo);
            self.undo
                .put(&mut wtxn, &key, &val)
                .map_err(|e| WalletStoreError(format!("put undo: {}", e)))?;
        }

        // 2. Remove spent outpoints from wallet UTXOs.
        for (txid, vout) in &batch.spent_outpoints {
            let key = Self::utxo_key(txid, *vout);
            self.utxos
                .delete(&mut wtxn, &key)
                .map_err(|e| WalletStoreError(format!("delete utxo: {}", e)))?;
        }

        // 3. Add new UTXOs.
        for utxo in &batch.new_utxos {
            let key = Self::utxo_key(&utxo.txid, utxo.vout);
            let val = encode_utxo_value(utxo);
            self.utxos
                .put(&mut wtxn, &key, &val)
                .map_err(|e| WalletStoreError(format!("put utxo: {}", e)))?;
        }

        // 4. Record the transaction.
        if let Some(ref tx) = batch.tx {
            let key = Self::tx_key(tx.height, &tx.txid);
            let val = encode_tx_value(tx);
            self.transactions
                .put(&mut wtxn, &key, &val)
                .map_err(|e| WalletStoreError(format!("put tx: {}", e)))?;
        }

        // 5. Mark used addresses.
        for script in &batch.used_scripts {
            if let Some(existing) = self
                .addresses
                .get(&wtxn, script)
                .map_err(|e| WalletStoreError(format!("get addr: {}", e)))?
            {
                if existing.len() >= ADDR_VALUE_LEN {
                    let mut val = existing.to_vec();
                    val[5] = 1; // set used flag
                    self.addresses
                        .put(&mut wtxn, script, &val)
                        .map_err(|e| WalletStoreError(format!("put addr: {}", e)))?;
                }
            }
        }

        // 6. Update scan height.
        self.meta
            .put(
                &mut wtxn,
                "scan_height".as_bytes(),
                &batch.new_scan_height.to_le_bytes(),
            )
            .map_err(|e| WalletStoreError(format!("put scan_height: {}", e)))?;

        wtxn.commit()
            .map_err(|e| WalletStoreError(format!("commit batch: {}", e)))?;
        Ok(())
    }

    /// Rollback wallet state for a block at `height`. Returns the undo
    /// entries so the caller can restore UTXOs and remove added ones.
    pub fn rollback_block(&self, height: u32) -> Result<Vec<StoredUtxo>, WalletStoreError> {
        let mut wtxn = self
            .env
            .write_txn()
            .map_err(|e| WalletStoreError(format!("write txn: {}", e)))?;

        // 1. Read undo entries for this height.
        let prefix = height.to_be_bytes();
        let mut restored_utxos = Vec::new();
        let mut undo_keys = Vec::new();
        {
            let iter = self
                .undo
                .prefix_iter(&wtxn, &prefix)
                .map_err(|e| WalletStoreError(format!("prefix_iter undo: {}", e)))?;
            for result in iter {
                let (k, v) = result.map_err(|e| WalletStoreError(format!("iter: {}", e)))?;
                undo_keys.push(k.to_vec());
                if k.len() >= UNDO_KEY_LEN {
                    let mut txid = [0u8; 32];
                    txid.copy_from_slice(&k[4..36]);
                    let vout = u32::from_be_bytes(k[36..40].try_into().unwrap());
                    restored_utxos.push(decode_utxo_value(&txid, vout, v)?);
                }
            }
        }

        // 2. Restore spent UTXOs.
        for utxo in &restored_utxos {
            let key = Self::utxo_key(&utxo.txid, utxo.vout);
            let val = encode_utxo_value(utxo);
            self.utxos
                .put(&mut wtxn, &key, &val)
                .map_err(|e| WalletStoreError(format!("restore utxo: {}", e)))?;
        }

        // 3. Remove UTXOs added at this height (they're invalidated by reorg).
        let mut utxo_keys_to_remove = Vec::new();
        {
            let iter = self
                .utxos
                .iter(&wtxn)
                .map_err(|e| WalletStoreError(format!("iter utxos: {}", e)))?;
            for result in iter {
                let (k, v) = result.map_err(|e| WalletStoreError(format!("iter: {}", e)))?;
                if v.len() >= UTXO_HEADER_LEN {
                    let h = u32::from_le_bytes(v[8..12].try_into().unwrap());
                    if h == height {
                        utxo_keys_to_remove.push(k.to_vec());
                    }
                }
            }
        }
        for k in &utxo_keys_to_remove {
            self.utxos
                .delete(&mut wtxn, k)
                .map_err(|e| WalletStoreError(format!("delete utxo: {}", e)))?;
        }

        // 4. Remove transaction entries at this height.
        let tx_prefix = height.to_be_bytes();
        let mut tx_keys_to_remove = Vec::new();
        {
            let iter = self
                .transactions
                .prefix_iter(&wtxn, &tx_prefix)
                .map_err(|e| WalletStoreError(format!("prefix_iter txs: {}", e)))?;
            for result in iter {
                let (k, _) = result.map_err(|e| WalletStoreError(format!("iter: {}", e)))?;
                tx_keys_to_remove.push(k.to_vec());
            }
        }
        for k in &tx_keys_to_remove {
            self.transactions
                .delete(&mut wtxn, k)
                .map_err(|e| WalletStoreError(format!("delete tx: {}", e)))?;
        }

        // 5. Remove undo entries for this height.
        for k in &undo_keys {
            self.undo
                .delete(&mut wtxn, k)
                .map_err(|e| WalletStoreError(format!("delete undo: {}", e)))?;
        }

        // 6. Update scan height to height - 1.
        if height > 0 {
            let new_height = height - 1;
            self.meta
                .put(
                    &mut wtxn,
                    "scan_height".as_bytes(),
                    &new_height.to_le_bytes(),
                )
                .map_err(|e| WalletStoreError(format!("put scan_height: {}", e)))?;
        }

        wtxn.commit()
            .map_err(|e| WalletStoreError(format!("commit rollback: {}", e)))?;
        Ok(restored_utxos)
    }
}

// ── Encoding / decoding helpers ─────────────────────────────────────────

fn encode_addr_value(index: u32, is_change: bool, used: bool) -> [u8; ADDR_VALUE_LEN] {
    let mut v = [0u8; ADDR_VALUE_LEN];
    v[..4].copy_from_slice(&index.to_le_bytes());
    v[4] = if is_change { 1 } else { 0 };
    v[5] = if used { 1 } else { 0 };
    v
}

fn decode_addr_value(script: &[u8], v: &[u8]) -> Result<StoredAddress, WalletStoreError> {
    if v.len() < ADDR_VALUE_LEN {
        return Err(WalletStoreError("short address value".into()));
    }
    Ok(StoredAddress {
        script_pubkey: script.to_vec(),
        derivation_index: u32::from_le_bytes(v[..4].try_into().unwrap()),
        is_change: v[4] != 0,
        used: v[5] != 0,
    })
}

fn encode_utxo_value(utxo: &StoredUtxo) -> Vec<u8> {
    let mut v = Vec::with_capacity(UTXO_HEADER_LEN + utxo.script_pubkey.len());
    v.extend_from_slice(&utxo.amount.to_le_bytes());
    v.extend_from_slice(&utxo.height.to_le_bytes());
    v.extend_from_slice(&utxo.derivation_index.to_le_bytes());
    v.push(if utxo.is_change { 1 } else { 0 });
    v.extend_from_slice(&utxo.script_pubkey);
    v
}

fn decode_utxo_value(
    txid: &[u8; 32],
    vout: u32,
    v: &[u8],
) -> Result<StoredUtxo, WalletStoreError> {
    if v.len() < UTXO_HEADER_LEN {
        return Err(WalletStoreError("short utxo value".into()));
    }
    Ok(StoredUtxo {
        txid: *txid,
        vout,
        amount: u64::from_le_bytes(v[..8].try_into().unwrap()),
        height: u32::from_le_bytes(v[8..12].try_into().unwrap()),
        derivation_index: u32::from_le_bytes(v[12..16].try_into().unwrap()),
        is_change: v[16] != 0,
        script_pubkey: v[UTXO_HEADER_LEN..].to_vec(),
    })
}

fn encode_tx_value(tx: &StoredTx) -> [u8; TX_VALUE_LEN] {
    let mut v = [0u8; TX_VALUE_LEN];
    v[..4].copy_from_slice(&tx.timestamp.to_le_bytes());
    v[4..12].copy_from_slice(&tx.net_value.to_le_bytes());
    v
}

fn decode_tx_entry(k: &[u8], v: &[u8]) -> Result<StoredTx, WalletStoreError> {
    if k.len() < TX_KEY_LEN {
        return Err(WalletStoreError("short tx key".into()));
    }
    if v.len() < TX_VALUE_LEN {
        return Err(WalletStoreError("short tx value".into()));
    }
    let raw_height = u32::from_be_bytes(k[..4].try_into().unwrap());
    let height = if raw_height == UNCONFIRMED_HEIGHT {
        None
    } else {
        Some(raw_height)
    };
    let mut txid = [0u8; 32];
    txid.copy_from_slice(&k[4..36]);
    Ok(StoredTx {
        txid,
        height,
        timestamp: u32::from_le_bytes(v[..4].try_into().unwrap()),
        net_value: i64::from_le_bytes(v[4..12].try_into().unwrap()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a fake 22-byte p2wpkh scriptPubKey: `OP_0 PUSH20 <fill*20>`.
    fn fake_spk(fill: u8) -> Vec<u8> {
        let mut v = vec![0x00, 0x14];
        v.extend_from_slice(&[fill; 20]);
        v
    }

    fn tmp_store() -> (tempfile::TempDir, WalletStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = WalletStore::open(dir.path().to_str().unwrap()).unwrap();
        (dir, store)
    }

    #[test]
    fn test_meta_round_trip() {
        let (_dir, store) = tmp_store();
        assert_eq!(store.get_scan_height().unwrap(), 0);
        store
            .set_meta("scan_height", &42u32.to_le_bytes())
            .unwrap();
        assert_eq!(store.get_scan_height().unwrap(), 42);
    }

    #[test]
    fn test_address_put_and_query() {
        let (_dir, store) = tmp_store();
        let script = fake_spk(0xAA); // fake p2wpkh
        store.put_address(&script, 0, false).unwrap();
        assert!(store.is_watched(&script).unwrap());
        assert!(!store.is_watched(&[0x00]).unwrap());

        let info = store.get_address_info(&script).unwrap().unwrap();
        assert_eq!(info.derivation_index, 0);
        assert!(!info.is_change);
        assert!(!info.used);
    }

    #[test]
    fn test_utxo_put_get_all() {
        let (_dir, store) = tmp_store();
        let utxo = StoredUtxo {
            txid: [0xAA; 32],
            vout: 1,
            amount: 50_000,
            height: 800_000,
            derivation_index: 3,
            is_change: false,
            script_pubkey: fake_spk(0xBB),
        };
        store.put_utxo(&utxo).unwrap();

        let got = store.get_utxo(&[0xAA; 32], 1).unwrap().unwrap();
        assert_eq!(got.amount, 50_000);
        assert_eq!(got.height, 800_000);
        assert_eq!(got.derivation_index, 3);
        assert!(!got.is_change);

        assert!(store.get_utxo(&[0xBB; 32], 0).unwrap().is_none());

        let all = store.all_utxos().unwrap();
        assert_eq!(all.len(), 1);
    }

    #[test]
    fn test_apply_block_batch() {
        let (_dir, store) = tmp_store();

        // Pre-populate an existing UTXO that will be spent.
        let existing = StoredUtxo {
            txid: [0x11; 32],
            vout: 0,
            amount: 100_000,
            height: 700_000,
            derivation_index: 0,
            is_change: false,
            script_pubkey: fake_spk(0xCC),
        };
        store.put_utxo(&existing).unwrap();

        // Put a watched address so we can mark it used.
        let script = fake_spk(0xDD);
        store.put_address(&script, 1, false).unwrap();

        let new_utxo = StoredUtxo {
            txid: [0x22; 32],
            vout: 0,
            amount: 90_000,
            height: 800_001,
            derivation_index: 1,
            is_change: false,
            script_pubkey: script.clone(),
        };

        let batch = BlockBatch {
            new_utxos: vec![new_utxo],
            spent_outpoints: vec![([0x11; 32], 0)],
            undo_entries: vec![existing.clone()],
            tx: Some(StoredTx {
                txid: [0x22; 32],
                height: Some(800_001),
                timestamp: 1700000000,
                net_value: -10_000, // spent 100k, received 90k
            }),
            used_scripts: vec![script.clone()],
            new_scan_height: 800_001,
        };

        store.apply_block_batch(&batch).unwrap();

        // Old UTXO should be gone.
        assert!(store.get_utxo(&[0x11; 32], 0).unwrap().is_none());
        // New UTXO should exist.
        assert!(store.get_utxo(&[0x22; 32], 0).unwrap().is_some());
        // Scan height updated.
        assert_eq!(store.get_scan_height().unwrap(), 800_001);
        // Address marked used.
        let info = store.get_address_info(&script).unwrap().unwrap();
        assert!(info.used);
        // Transaction recorded.
        let txs = store.get_transactions(10, 0).unwrap();
        assert_eq!(txs.len(), 1);
        assert_eq!(txs[0].net_value, -10_000);
    }

    #[test]
    fn test_rollback_block() {
        let (_dir, store) = tmp_store();

        // Simulate: at height 100, we spent a UTXO and gained a new one.
        let spent_utxo = StoredUtxo {
            txid: [0x11; 32],
            vout: 0,
            amount: 50_000,
            height: 50,
            derivation_index: 0,
            is_change: false,
            script_pubkey: fake_spk(0xAA),
        };
        let new_utxo = StoredUtxo {
            txid: [0x22; 32],
            vout: 0,
            amount: 45_000,
            height: 100,
            derivation_index: 1,
            is_change: false,
            script_pubkey: fake_spk(0xBB),
        };

        let batch = BlockBatch {
            new_utxos: vec![new_utxo.clone()],
            spent_outpoints: vec![([0x11; 32], 0)],
            undo_entries: vec![spent_utxo.clone()],
            tx: Some(StoredTx {
                txid: [0x22; 32],
                height: Some(100),
                timestamp: 1700000000,
                net_value: -5_000,
            }),
            used_scripts: vec![],
            new_scan_height: 100,
        };
        store.apply_block_batch(&batch).unwrap();

        // Verify pre-rollback state.
        assert!(store.get_utxo(&[0x11; 32], 0).unwrap().is_none());
        assert!(store.get_utxo(&[0x22; 32], 0).unwrap().is_some());
        assert_eq!(store.get_scan_height().unwrap(), 100);

        // Rollback.
        let restored = store.rollback_block(100).unwrap();
        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].txid, [0x11; 32]);

        // Spent UTXO should be restored.
        let got = store.get_utxo(&[0x11; 32], 0).unwrap().unwrap();
        assert_eq!(got.amount, 50_000);
        // New UTXO should be removed.
        assert!(store.get_utxo(&[0x22; 32], 0).unwrap().is_none());
        // Transaction should be removed.
        assert!(store.get_transactions(10, 0).unwrap().is_empty());
        // Scan height should be 99.
        assert_eq!(store.get_scan_height().unwrap(), 99);
    }

    #[test]
    fn test_all_scripts() {
        let (_dir, store) = tmp_store();
        let s1 = fake_spk(0x01);
        let s2 = fake_spk(0x02);
        store.put_address(&s1, 0, false).unwrap();
        store.put_address(&s2, 1, true).unwrap();

        let scripts = store.all_scripts().unwrap();
        assert_eq!(scripts.len(), 2);
    }

    #[test]
    fn test_transactions_ordering() {
        let (_dir, store) = tmp_store();

        // Insert txs at different heights — should come back in reverse order.
        let batch1 = BlockBatch {
            new_utxos: vec![],
            spent_outpoints: vec![],
            undo_entries: vec![],
            tx: Some(StoredTx {
                txid: [0x01; 32],
                height: Some(100),
                timestamp: 1000,
                net_value: 50_000,
            }),
            used_scripts: vec![],
            new_scan_height: 100,
        };
        store.apply_block_batch(&batch1).unwrap();

        let batch2 = BlockBatch {
            new_utxos: vec![],
            spent_outpoints: vec![],
            undo_entries: vec![],
            tx: Some(StoredTx {
                txid: [0x02; 32],
                height: Some(200),
                timestamp: 2000,
                net_value: 30_000,
            }),
            used_scripts: vec![],
            new_scan_height: 200,
        };
        store.apply_block_batch(&batch2).unwrap();

        let txs = store.get_transactions(10, 0).unwrap();
        assert_eq!(txs.len(), 2);
        // Most recent first (reverse iteration).
        assert_eq!(txs[0].height, Some(200));
        assert_eq!(txs[1].height, Some(100));
    }
}
