use std::collections::HashMap;
use std::time::Instant;

use bitcoin::block::Block;
use bitcoin::consensus::serialize;
use bitcoin::{Transaction, Txid};

use log::{debug, info};

use crate::utxo::UtxoSet;

/// Default maximum mempool size in bytes (50 MB).
const DEFAULT_MAX_SIZE: usize = 50_000_000;

/// Minimum relay fee rate in sat/vB.
const MIN_RELAY_FEE_RATE: f64 = 1.0;

/// Maximum standard transaction weight (400,000 WU).
const MAX_TX_WEIGHT: u64 = 400_000;

/// Coinbase maturity: 100 blocks before coinbase outputs are spendable.
const COINBASE_MATURITY: u32 = 100;

/// Maximum transaction expiry time (14 days).
const MAX_TX_AGE: std::time::Duration = std::time::Duration::from_secs(14 * 24 * 3600);

/// Dust threshold in satoshis (Bitcoin Core default for P2PKH).
const DUST_THRESHOLD: u64 = 546;

/// Maximum OP_RETURN output size (matches Bitcoin Core MAX_OP_RETURN_RELAY).
const MAX_OP_RETURN_SIZE: usize = 83;

/// A transaction in the mempool with fee metadata.
struct MempoolEntry {
    tx: Transaction,
    fee: u64,
    weight: u64,
    fee_rate: f64, // sat/vB = fee / (weight / 4)
    size: usize,   // serialized byte size
    added_at: Instant,
}

/// In-memory transaction pool for unconfirmed transactions.
pub struct Mempool {
    txs: HashMap<Txid, MempoolEntry>,
    /// Reverse index: which mempool tx spends each outpoint.
    spends: HashMap<(Txid, u32), Txid>,
    /// Total serialized size of all transactions.
    total_size: usize,
    /// Maximum total size in bytes.
    max_size: usize,
}

impl Mempool {
    /// Create a new mempool with the default 50 MB size cap.
    pub fn new() -> Mempool {
        Mempool {
            txs: HashMap::new(),
            spends: HashMap::new(),
            total_size: 0,
            max_size: DEFAULT_MAX_SIZE,
        }
    }

    /// Create a new mempool with a custom size cap.
    pub fn with_max_size(max_size: usize) -> Mempool {
        Mempool {
            txs: HashMap::new(),
            spends: HashMap::new(),
            total_size: 0,
            max_size,
        }
    }

    /// Validate and accept a transaction into the mempool.
    ///
    /// Checks:
    /// 1. Not already in mempool
    /// 2. No input double-spends a mempool transaction
    /// 3. All inputs exist in the UTXO set
    /// 4. Coinbase maturity (100 blocks)
    /// 5. Script validation via libbitcoinconsensus
    /// 6. No value inflation (inputs >= outputs)
    /// 7. Fee rate >= minimum relay fee (1 sat/vB)
    /// 8. Weight <= 400,000 WU (standard tx limit)
    /// 9. No dust outputs (< 546 sats)
    ///
    /// If the pool exceeds max_size after insertion, evicts lowest-fee-rate txs.
    pub fn accept_tx(
        &mut self,
        tx: Transaction,
        utxo_set: &UtxoSet,
        current_height: u32,
    ) -> Result<Txid, MempoolError> {
        let txid = tx.compute_txid();

        // 0. Reject coinbase transactions (only valid in blocks)
        if tx.is_coinbase() {
            return Err(MempoolError::CoinbaseTx);
        }

        // 1. Already in mempool?
        if self.txs.contains_key(&txid) {
            return Err(MempoolError::AlreadyInMempool);
        }

        // 2. Check for double-spends against mempool
        for input in &tx.input {
            let outpoint_key = (input.previous_output.txid, input.previous_output.vout);
            if let Some(conflicting) = self.spends.get(&outpoint_key) {
                return Err(MempoolError::ConflictsWith(*conflicting));
            }
        }

        // 8. Weight check (do early — cheap)
        let weight = tx.weight().to_wu();
        if weight > MAX_TX_WEIGHT {
            return Err(MempoolError::OversizedTx { weight });
        }

        // 9. Dust check on outputs
        for (i, output) in tx.output.iter().enumerate() {
            if output.script_pubkey.is_op_return() {
                continue; // OP_RETURN outputs are allowed to be zero-value
            }
            if output.value.to_sat() < DUST_THRESHOLD {
                return Err(MempoolError::DustOutput {
                    index: i,
                    amount: output.value.to_sat(),
                });
            }
        }

        // 10. Standard script type check (matches Bitcoin Core's IsStandard)
        for (i, output) in tx.output.iter().enumerate() {
            let spk = &output.script_pubkey;
            let is_standard = spk.is_p2pkh()
                || spk.is_p2sh()
                || spk.is_witness_program() // covers P2WPKH, P2WSH, P2TR, future witness versions
                || spk.is_p2pk()
                || spk.is_multisig()
                || (spk.is_op_return() && spk.len() <= MAX_OP_RETURN_SIZE);

            if !is_standard {
                return Err(MempoolError::NonStandardScript { index: i });
            }
        }

        // 3-5. Validate inputs against UTXO set
        let serialized_tx = serialize(&tx);
        let flags = bitcoinconsensus::height_to_flags(current_height);
        let mut input_sum: u64 = 0;

        for (input_idx, input) in tx.input.iter().enumerate() {
            let prev_txid = &input.previous_output.txid;
            let prev_vout = input.previous_output.vout;

            let utxo = utxo_set
                .get(prev_txid, prev_vout)
                .map_err(|e| MempoolError::UtxoLookup(format!("{}", e)))?
                .ok_or(MempoolError::MissingInput {
                    txid: *prev_txid,
                    vout: prev_vout,
                })?;

            // 4. Coinbase maturity
            if utxo.is_coinbase && current_height.saturating_sub(utxo.height) < COINBASE_MATURITY {
                return Err(MempoolError::ImmatureCoinbase {
                    input_index: input_idx,
                    coinbase_height: utxo.height,
                });
            }

            // 5. Script validation
            bitcoinconsensus::verify_with_flags(
                &utxo.script_pubkey,
                utxo.amount,
                &serialized_tx,
                input_idx,
                flags,
            )
            .map_err(|e| MempoolError::ScriptFailure {
                input_index: input_idx,
                error: format!("{:?}", e),
            })?;

            input_sum = input_sum.checked_add(utxo.amount).ok_or(
                MempoolError::Inflation,
            )?;
        }

        // 6. No value inflation
        let output_sum: u64 = tx
            .output
            .iter()
            .map(|o| o.value.to_sat())
            .try_fold(0u64, |acc, v| acc.checked_add(v))
            .ok_or(MempoolError::Inflation)?;

        if input_sum < output_sum {
            return Err(MempoolError::Inflation);
        }

        let fee = input_sum - output_sum;

        // 7. Minimum fee rate (1 sat/vB)
        let vsize = weight as f64 / 4.0;
        let fee_rate = fee as f64 / vsize;
        if fee_rate < MIN_RELAY_FEE_RATE {
            return Err(MempoolError::InsufficientFee {
                fee_rate,
                min_rate: MIN_RELAY_FEE_RATE,
            });
        }

        // All checks passed — insert
        let size = serialized_tx.len();

        // Update spend index
        for input in &tx.input {
            self.spends.insert(
                (input.previous_output.txid, input.previous_output.vout),
                txid,
            );
        }

        self.total_size += size;
        self.txs.insert(
            txid,
            MempoolEntry {
                tx,
                fee,
                weight,
                fee_rate,
                size,
                added_at: Instant::now(),
            },
        );

        debug!("Mempool: accepted tx {} (fee_rate={:.1} sat/vB, size={})", txid, fee_rate, size);

        // Evict lowest-fee-rate txs if over capacity
        while self.total_size > self.max_size && !self.txs.is_empty() {
            self.evict_lowest_feerate();
        }

        Ok(txid)
    }

    /// Remove transactions confirmed in a block, plus any that conflict
    /// (spend the same inputs as a confirmed transaction).
    pub fn remove_confirmed(&mut self, block: &Block) {
        let mut removed = 0;

        for tx in &block.txdata {
            let txid = tx.compute_txid();

            // Remove the confirmed tx itself
            if self.remove_tx(&txid) {
                removed += 1;
            }

            // Remove any mempool txs that conflict (double-spend the same inputs)
            for input in &tx.input {
                let key = (input.previous_output.txid, input.previous_output.vout);
                if let Some(conflicting_txid) = self.spends.get(&key).copied() {
                    if conflicting_txid != txid {
                        if self.remove_tx(&conflicting_txid) {
                            removed += 1;
                        }
                    }
                }
            }
        }

        if removed > 0 {
            info!(
                "Mempool: removed {} txs after block, {} remaining",
                removed,
                self.txs.len()
            );
        }
    }

    /// Remove a transaction by txid. Returns true if it was present.
    pub fn remove_tx(&mut self, txid: &Txid) -> bool {
        if let Some(entry) = self.txs.remove(txid) {
            self.total_size -= entry.size;
            // Clean up spend index
            for input in &entry.tx.input {
                let key = (input.previous_output.txid, input.previous_output.vout);
                if self.spends.get(&key) == Some(txid) {
                    self.spends.remove(&key);
                }
            }
            true
        } else {
            false
        }
    }

    /// Check if a transaction is in the mempool.
    pub fn contains(&self, txid: &Txid) -> bool {
        self.txs.contains_key(txid)
    }

    /// Get a transaction from the mempool.
    pub fn get(&self, txid: &Txid) -> Option<&Transaction> {
        self.txs.get(txid).map(|e| &e.tx)
    }

    /// Get the fee rate (sat/vB) for a transaction in the mempool.
    pub fn fee_rate(&self, txid: &Txid) -> Option<f64> {
        self.txs.get(txid).map(|e| e.fee_rate)
    }

    /// Get all transaction IDs in the mempool.
    pub fn get_all_txids(&self) -> Vec<Txid> {
        self.txs.keys().copied().collect()
    }

    /// Remove expired transactions (older than 14 days).
    pub fn expire_old(&mut self) {
        let expired: Vec<Txid> = self
            .txs
            .iter()
            .filter(|(_, e)| e.added_at.elapsed() > MAX_TX_AGE)
            .map(|(txid, _)| *txid)
            .collect();

        for txid in &expired {
            self.remove_tx(txid);
        }
        if !expired.is_empty() {
            info!("Mempool: expired {} old transactions", expired.len());
        }
    }

    /// Evict the transaction with the lowest fee rate.
    fn evict_lowest_feerate(&mut self) {
        let worst = self
            .txs
            .iter()
            .min_by(|a, b| a.1.fee_rate.partial_cmp(&b.1.fee_rate).unwrap())
            .map(|(txid, _)| *txid);

        if let Some(txid) = worst {
            debug!("Mempool: evicting lowest-feerate tx {}", txid);
            self.remove_tx(&txid);
        }
    }

    /// Total serialized size of all mempool transactions (bytes).
    pub fn size(&self) -> usize {
        self.total_size
    }

    /// Number of transactions in the mempool.
    pub fn count(&self) -> usize {
        self.txs.len()
    }

    /// Minimum fee rate in the mempool (sat/vB), or 0.0 if empty.
    pub fn min_fee_rate(&self) -> f64 {
        if self.txs.is_empty() {
            return 0.0;
        }
        self.txs
            .values()
            .map(|e| e.fee_rate)
            .fold(f64::INFINITY, f64::min)
    }
}

/// Errors from mempool transaction validation.
#[derive(Debug)]
pub enum MempoolError {
    CoinbaseTx,
    AlreadyInMempool,
    ConflictsWith(Txid),
    MissingInput { txid: Txid, vout: u32 },
    ImmatureCoinbase { input_index: usize, coinbase_height: u32 },
    ScriptFailure { input_index: usize, error: String },
    Inflation,
    InsufficientFee { fee_rate: f64, min_rate: f64 },
    OversizedTx { weight: u64 },
    DustOutput { index: usize, amount: u64 },
    NonStandardScript { index: usize },
    UtxoLookup(String),
}

impl std::fmt::Display for MempoolError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MempoolError::CoinbaseTx => write!(f, "coinbase transactions are not allowed in mempool"),
            MempoolError::AlreadyInMempool => write!(f, "transaction already in mempool"),
            MempoolError::ConflictsWith(txid) => {
                write!(f, "conflicts with mempool tx {}", txid)
            }
            MempoolError::MissingInput { txid, vout } => {
                write!(f, "input {}:{} not found in UTXO set", txid, vout)
            }
            MempoolError::ImmatureCoinbase { input_index, coinbase_height } => {
                write!(
                    f,
                    "input {} spends immature coinbase from height {}",
                    input_index, coinbase_height
                )
            }
            MempoolError::ScriptFailure { input_index, error } => {
                write!(f, "script validation failed for input {}: {}", input_index, error)
            }
            MempoolError::Inflation => write!(f, "outputs exceed inputs"),
            MempoolError::InsufficientFee { fee_rate, min_rate } => {
                write!(
                    f,
                    "fee rate {:.2} sat/vB below minimum {:.2}",
                    fee_rate, min_rate
                )
            }
            MempoolError::OversizedTx { weight } => {
                write!(f, "transaction weight {} exceeds limit {}", weight, MAX_TX_WEIGHT)
            }
            MempoolError::DustOutput { index, amount } => {
                write!(
                    f,
                    "output {} is dust ({} sats, min {})",
                    index, amount, DUST_THRESHOLD
                )
            }
            MempoolError::NonStandardScript { index } => {
                write!(f, "output {} has non-standard script type", index)
            }
            MempoolError::UtxoLookup(e) => write!(f, "UTXO lookup error: {}", e),
        }
    }
}

impl std::error::Error for MempoolError {}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;

    #[test]
    fn new_mempool_is_empty() {
        let pool = Mempool::new();
        assert_eq!(pool.count(), 0);
        assert_eq!(pool.size(), 0);
    }

    #[test]
    fn custom_max_size() {
        let pool = Mempool::with_max_size(1024);
        assert_eq!(pool.max_size, 1024);
    }

    #[test]
    fn contains_and_get_empty() {
        let pool = Mempool::new();
        let fake_txid = Txid::all_zeros();
        assert!(!pool.contains(&fake_txid));
        assert!(pool.get(&fake_txid).is_none());
    }

    #[test]
    fn get_all_txids_empty() {
        let pool = Mempool::new();
        assert!(pool.get_all_txids().is_empty());
    }

    #[test]
    fn remove_tx_nonexistent() {
        let mut pool = Mempool::new();
        let fake_txid = Txid::all_zeros();
        assert!(!pool.remove_tx(&fake_txid));
    }

    #[test]
    fn min_fee_rate_empty() {
        let pool = Mempool::new();
        // Empty pool should return 0.0
        assert_eq!(pool.min_fee_rate(), 0.0);
    }

    #[test]
    fn expire_old_empty_pool() {
        let mut pool = Mempool::new();
        pool.expire_old(); // should not panic
    }

    #[test]
    fn remove_confirmed_empty_block() {
        let mut pool = Mempool::new();
        // Create a minimal block with just a coinbase
        let raw = hex::decode(
            "0100000000000000000000000000000000000000000000000000000000000000\
             000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa\
             4b1e5e4a29ab5f49ffff001d1dac2b7c\
             01\
             01000000010000000000000000000000000000000000000000000000000000000000000000\
             ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f323030392043\
             68616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f7574\
             20666f722062616e6b73ffffffff\
             0100f2052a0100000043410467e6e15a2fd55bfccfc89481e77dfe6a9f055e65106e82\
             1e022e084a27a7626cfe82510d2e593a0f1ee44bca55f8c0e28d57e87b5f0c9b6e46a3\
             d6d23df9a13eac\
             00000000",
        ).unwrap();
        let block: Block = bitcoin::consensus::deserialize(&raw).unwrap();
        pool.remove_confirmed(&block); // should not panic
    }

    // Integration tests for accept_tx require a populated UTXO set with real
    // transactions. These will be covered when we wire the mempool into the
    // sync loop and can test against the actual blockchain state.
}
