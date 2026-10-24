use std::collections::HashSet;
use std::str::FromStr;
use std::sync::RwLock;

use bitcoin::address::{Address, KnownHrp};
use bitcoin::bip32::{ChildNumber, Xpub};
use bitcoin::block::Block;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::CompressedPublicKey;

/// Standard BIP32 xpub version bytes (mainnet).
const XPUB_VERSION: [u8; 4] = [0x04, 0x88, 0xB2, 0x1E];
/// BIP84 zpub version bytes (mainnet).
const ZPUB_VERSION: [u8; 4] = [0x04, 0xB2, 0x47, 0x46];
/// BIP49 ypub version bytes (mainnet).
const YPUB_VERSION: [u8; 4] = [0x04, 0x9D, 0x7C, 0xB2];

use log::{debug, info, warn};

use crate::utxo::UtxoSet;
use crate::wallet_store::{BlockBatch, StoredTx, StoredUtxo, WalletStore, WalletStoreError};

/// BIP84 native segwit gap limit: number of consecutive unused addresses
/// before we stop deriving more.
const GAP_LIMIT: u32 = 20;

/// UTXO value header length in the main UTXO set (amount 8 + height 4 + flags 1).
const UTXO_VALUE_HEADER: usize = 13;

#[derive(Debug)]
pub enum WalletError {
    InvalidXpub(String),
    Store(String),
    Derivation(String),
    NoWallet,
}

impl std::fmt::Display for WalletError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WalletError::InvalidXpub(s) => write!(f, "invalid xpub: {}", s),
            WalletError::Store(s) => write!(f, "wallet store: {}", s),
            WalletError::Derivation(s) => write!(f, "derivation: {}", s),
            WalletError::NoWallet => write!(f, "no wallet loaded"),
        }
    }
}

impl From<WalletStoreError> for WalletError {
    fn from(e: WalletStoreError) -> Self {
        WalletError::Store(e.0)
    }
}

/// Public wallet balance for the UI.
pub struct WalletBalance {
    pub confirmed: u64,
    pub unconfirmed: u64,
}

/// Public transaction summary for the UI.
pub struct WalletTx {
    pub txid: [u8; 32],
    pub height: Option<u32>,
    pub timestamp: Option<u32>,
    pub net_value: i64,
}

/// Public address info for the UI.
pub struct WalletAddressInfo {
    pub address: String,
    pub derivation_index: u32,
    pub is_change: bool,
    pub used: bool,
}

/// Summary info about the wallet.
pub struct WalletInfo {
    pub xpub: String,
    pub balance: WalletBalance,
    pub scan_height: u32,
    pub address_count: u32,
}

/// Phase 1 watch-only wallet. Imports an xpub, derives BIP84 addresses,
/// scans the UTXO set, and tracks new blocks for wallet-relevant activity.
pub struct Wallet {
    store: WalletStore,
    xpub: Xpub,
    /// Cached set of watched scriptPubKeys for O(1) lookup during block scanning.
    watch_scripts: RwLock<HashSet<Vec<u8>>>,
}

impl Wallet {
    /// Open or create a wallet from an xpub/zpub/ypub string.
    ///
    /// On first open: derives initial addresses (GAP_LIMIT receive + change).
    /// On subsequent opens: reloads watch set from the store.
    pub fn open(xpub_str: &str, store_path: &str) -> Result<Wallet, WalletError> {
        let xpub = parse_extended_pubkey(xpub_str)?;

        let store = WalletStore::open(store_path)?;

        // Check if this is a fresh wallet or an existing one.
        let existing_xpub = store.get_meta("xpub")?;
        if existing_xpub.is_none() {
            // First time — store the xpub and derive initial addresses.
            store.set_meta("xpub", xpub_str.as_bytes())?;
            info!("New wallet created, deriving initial addresses");
        } else {
            let stored = String::from_utf8(existing_xpub.unwrap()).unwrap_or_default();
            if stored != xpub_str {
                return Err(WalletError::InvalidXpub(
                    "xpub does not match existing wallet".into(),
                ));
            }
        }

        let wallet = Wallet {
            store,
            xpub,
            watch_scripts: RwLock::new(HashSet::new()),
        };

        // Derive addresses up to GAP_LIMIT if needed.
        wallet.ensure_gap_limit(false)?; // receive
        wallet.ensure_gap_limit(true)?; // change

        // Rebuild in-memory watch set from store.
        wallet.rebuild_watch_set()?;

        {
            let scripts = wallet.watch_scripts.read().unwrap();
            info!(
                "Wallet opened: {} watched scripts, scan_height={}",
                scripts.len(),
                wallet.store.get_scan_height()?
            );
        }

        Ok(wallet)
    }

    /// Perform the initial full UTXO set scan. Iterates every UTXO and
    /// checks its scriptPubKey against our watch set. Called once after
    /// import or when scan_height is 0.
    pub fn scan_utxo_set(
        &self,
        utxo_set: &UtxoSet,
        validated_height: u32,
    ) -> Result<u32, WalletError> {
        let watch = self.watch_scripts.read().unwrap();
        if watch.is_empty() {
            return Ok(0);
        }

        info!(
            "Starting UTXO set scan ({} watched scripts)...",
            watch.len()
        );

        let mut found = 0u32;
        let mut new_utxos: Vec<StoredUtxo> = Vec::new();
        let mut used_scripts: Vec<Vec<u8>> = Vec::new();

        utxo_set
            .for_each_utxo(|key, value| {
                // Extract scriptPubKey from the UTXO value (after the 13-byte header).
                if value.len() <= UTXO_VALUE_HEADER {
                    return true; // skip malformed
                }
                let script = &value[UTXO_VALUE_HEADER..];

                if watch.contains(script) {
                    // Parse the full UTXO entry.
                    if key.len() >= 36 {
                        let mut txid = [0u8; 32];
                        txid.copy_from_slice(&key[..32]);
                        let vout = u32::from_be_bytes(key[32..36].try_into().unwrap());
                        let amount = u64::from_le_bytes(value[..8].try_into().unwrap());
                        let height = u32::from_le_bytes(value[8..12].try_into().unwrap());

                        // Look up derivation info.
                        if let Ok(Some(addr_info)) = self.store.get_address_info(script) {
                            new_utxos.push(StoredUtxo {
                                txid,
                                vout,
                                amount,
                                height,
                                derivation_index: addr_info.derivation_index,
                                is_change: addr_info.is_change,
                                script_pubkey: script.to_vec(),
                            });
                            if !addr_info.used {
                                used_scripts.push(script.to_vec());
                            }
                            found += 1;
                        }
                    }
                }
                true // continue
            })
            .map_err(|e| WalletError::Store(format!("UTXO scan: {}", e)))?;

        // Write all found UTXOs in a single batch.
        if !new_utxos.is_empty() || !used_scripts.is_empty() {
            let batch = BlockBatch {
                new_utxos,
                spent_outpoints: vec![],
                undo_entries: vec![],
                tx: None,
                used_scripts,
                new_scan_height: validated_height,
            };
            self.store.apply_block_batch(&batch)?;
        } else {
            // No UTXOs found, but still record scan_height.
            self.store
                .set_meta("scan_height", &validated_height.to_le_bytes())?;
        }

        // Extend gap limit in case we found used addresses near the edge.
        self.ensure_gap_limit(false)?;
        self.ensure_gap_limit(true)?;
        self.rebuild_watch_set()?;

        info!(
            "UTXO scan complete: {} UTXOs found, scan_height={}",
            found, validated_height
        );
        Ok(found)
    }

    /// Process a validated block, scanning for wallet-relevant transactions.
    pub fn process_block(&self, block: &Block, height: u32) -> Result<(), WalletError> {
        let watch = self.watch_scripts.read().unwrap();
        if watch.is_empty() {
            return Ok(());
        }

        let mut new_utxos = Vec::new();
        let mut spent_outpoints = Vec::new();
        let mut undo_entries = Vec::new();
        let mut used_scripts = Vec::new();
        let mut net_value: i64 = 0;
        let mut is_relevant = false;

        for tx in &block.txdata {
            let txid_bytes = tx.compute_txid().to_byte_array();

            // Check outputs: new UTXOs paying us.
            for (vout, output) in tx.output.iter().enumerate() {
                let script = output.script_pubkey.as_bytes();
                if watch.contains(script) {
                    if let Ok(Some(addr_info)) = self.store.get_address_info(script) {
                        new_utxos.push(StoredUtxo {
                            txid: txid_bytes,
                            vout: vout as u32,
                            amount: output.value.to_sat(),
                            height,
                            derivation_index: addr_info.derivation_index,
                            is_change: addr_info.is_change,
                            script_pubkey: script.to_vec(),
                        });
                        net_value += output.value.to_sat() as i64;
                        is_relevant = true;
                        if !addr_info.used {
                            used_scripts.push(script.to_vec());
                        }
                    }
                }
            }

            // Check inputs: UTXOs being spent from our wallet.
            // Skip coinbase (no inputs to check).
            if !tx.is_coinbase() {
                for input in &tx.input {
                    let prev_txid = input.previous_output.txid.to_byte_array();
                    let prev_vout = input.previous_output.vout;

                    if let Ok(Some(existing)) =
                        self.store.get_utxo(&prev_txid, prev_vout)
                    {
                        spent_outpoints.push((prev_txid, prev_vout));
                        net_value -= existing.amount as i64;
                        undo_entries.push(existing);
                        is_relevant = true;
                    }
                }
            }
        }

        if !is_relevant {
            // No wallet activity in this block — just bump scan_height.
            self.store
                .set_meta("scan_height", &height.to_le_bytes())?;
            return Ok(());
        }

        // Build a single transaction record summarizing this block's wallet activity.
        // Use the first relevant txid as the representative. For blocks with multiple
        // wallet txs, we create one record per block for simplicity in Phase 1.
        let representative_txid = if !new_utxos.is_empty() {
            new_utxos[0].txid
        } else if !spent_outpoints.is_empty() {
            spent_outpoints[0].0
        } else {
            [0u8; 32]
        };

        let timestamp = block.header.time;

        let batch = BlockBatch {
            new_utxos,
            spent_outpoints,
            undo_entries,
            tx: Some(StoredTx {
                txid: representative_txid,
                height: Some(height),
                timestamp,
                net_value,
            }),
            used_scripts,
            new_scan_height: height,
        };
        self.store.apply_block_batch(&batch)?;

        // Extend gap limit if we used addresses near the boundary.
        drop(watch); // release read lock before potentially writing
        self.ensure_gap_limit(false)?;
        self.ensure_gap_limit(true)?;
        self.rebuild_watch_set()?;

        debug!(
            "Wallet: block {} processed, net_value={} sats",
            height, net_value
        );
        Ok(())
    }

    /// Rollback wallet state for a block (during reorg).
    pub fn rollback_block(&self, height: u32) -> Result<(), WalletError> {
        self.store.rollback_block(height)?;
        self.rebuild_watch_set()?;
        info!("Wallet: rolled back block {}", height);
        Ok(())
    }

    /// Get the current scan height.
    pub fn scan_height(&self) -> Result<u32, WalletError> {
        Ok(self.store.get_scan_height()?)
    }

    /// Get the wallet balance (confirmed + unconfirmed).
    pub fn balance(&self) -> Result<WalletBalance, WalletError> {
        let utxos = self.store.all_utxos()?;
        let mut confirmed = 0u64;
        let mut unconfirmed = 0u64;
        for u in &utxos {
            if u.height > 0 {
                confirmed += u.amount;
            } else {
                unconfirmed += u.amount;
            }
        }
        Ok(WalletBalance {
            confirmed,
            unconfirmed,
        })
    }

    /// Get transaction history, most recent first.
    pub fn transactions(&self, limit: u32, offset: u32) -> Result<Vec<WalletTx>, WalletError> {
        let stored = self.store.get_transactions(limit, offset)?;
        Ok(stored
            .into_iter()
            .map(|t| WalletTx {
                txid: t.txid,
                height: t.height,
                timestamp: if t.timestamp > 0 {
                    Some(t.timestamp)
                } else {
                    None
                },
                net_value: t.net_value,
            })
            .collect())
    }

    /// Get the next unused receive address (lowest derivation index).
    pub fn next_receive_address(&self) -> Result<WalletAddressInfo, WalletError> {
        let next_index = self.store.get_next_receive_index()?;

        // Walk receive addresses in derivation order to find the first unused.
        for i in 0..next_index {
            let (script, _) = self.derive_address(i, false)?;
            if let Some(info) = self.store.get_address_info(&script)? {
                if !info.used {
                    let address = self.script_to_address(&script)?;
                    return Ok(WalletAddressInfo {
                        address,
                        derivation_index: i,
                        is_change: false,
                        used: false,
                    });
                }
            }
        }

        // All addresses used — derive more and return the first new one.
        self.ensure_gap_limit(false)?;
        self.rebuild_watch_set()?;

        let new_next = self.store.get_next_receive_index()?;
        let idx = next_index; // first newly derived
        let (script, _) = self.derive_address(idx, false)?;
        let address = self.script_to_address(&script)?;
        Ok(WalletAddressInfo {
            address,
            derivation_index: idx,
            is_change: false,
            used: false,
        })
    }

    /// Get summary info about the wallet.
    pub fn info(&self) -> Result<WalletInfo, WalletError> {
        let balance = self.balance()?;
        let scan_height = self.store.get_scan_height()?;
        let scripts = self.store.all_scripts()?;
        let xpub_str = match self.store.get_meta("xpub")? {
            Some(v) => String::from_utf8_lossy(&v).to_string(),
            None => String::new(),
        };
        Ok(WalletInfo {
            xpub: xpub_str,
            balance,
            scan_height,
            address_count: scripts.len() as u32,
        })
    }

    /// Delete this wallet's on-disk state.
    pub fn delete_store(store_path: &str) -> Result<(), WalletError> {
        if std::path::Path::new(store_path).exists() {
            std::fs::remove_dir_all(store_path)
                .map_err(|e| WalletError::Store(format!("delete wallet: {}", e)))?;
        }
        Ok(())
    }

    // ── Internal derivation ─────────────────────────────────────────────

    /// Derive a single BIP84 address and return (scriptPubKey, bech32 address).
    fn derive_address(
        &self,
        index: u32,
        is_change: bool,
    ) -> Result<(Vec<u8>, String), WalletError> {
        let secp = Secp256k1::verification_only();
        let chain = if is_change { 1u32 } else { 0u32 };
        let chain_child =
            ChildNumber::from_normal_idx(chain).map_err(|e| WalletError::Derivation(format!("{}", e)))?;
        let index_child =
            ChildNumber::from_normal_idx(index).map_err(|e| WalletError::Derivation(format!("{}", e)))?;

        let derived = self
            .xpub
            .derive_pub(&secp, &[chain_child, index_child])
            .map_err(|e| WalletError::Derivation(format!("{}", e)))?;

        let pubkey = CompressedPublicKey(derived.public_key);
        let address = Address::p2wpkh(&pubkey, KnownHrp::Mainnet);
        let script = address.script_pubkey().to_bytes();

        Ok((script, address.to_string()))
    }

    /// Ensure we have at least GAP_LIMIT unused addresses for the given chain.
    fn ensure_gap_limit(&self, is_change: bool) -> Result<(), WalletError> {
        let next_index = if is_change {
            self.store.get_next_change_index()?
        } else {
            self.store.get_next_receive_index()?
        };

        // Count consecutive unused addresses from the end.
        let mut unused_count = 0u32;
        for i in (0..next_index).rev() {
            let (script, _) = self.derive_address(i, is_change)?;
            match self.store.get_address_info(&script)? {
                Some(info) if !info.used => unused_count += 1,
                _ => break,
            }
        }

        // Derive more if needed.
        if unused_count < GAP_LIMIT {
            let need = GAP_LIMIT - unused_count;
            let start = next_index;
            for i in 0..need {
                let idx = start + i;
                let (script, _addr) = self.derive_address(idx, is_change)?;
                // Only insert if not already present.
                if !self.store.is_watched(&script)? {
                    self.store.put_address(&script, idx, is_change)?;
                }
            }
            let new_next = start + need;
            let meta_key = if is_change {
                "next_change_index"
            } else {
                "next_receive_index"
            };
            self.store.set_meta(meta_key, &new_next.to_le_bytes())?;
        }

        Ok(())
    }

    /// Rebuild the in-memory watch set from the store.
    fn rebuild_watch_set(&self) -> Result<(), WalletError> {
        let scripts = self.store.all_scripts()?;
        let mut set = self.watch_scripts.write().unwrap();
        set.clear();
        for s in scripts {
            set.insert(s);
        }
        Ok(())
    }

    /// Convert a raw scriptPubKey to a bech32 address string.
    fn script_to_address(&self, script: &[u8]) -> Result<String, WalletError> {
        let script_buf = bitcoin::ScriptBuf::from_bytes(script.to_vec());
        let address = Address::from_script(&script_buf, bitcoin::Network::Bitcoin)
            .map_err(|e| WalletError::Derivation(format!("script to address: {}", e)))?;
        Ok(address.to_string())
    }
}

/// Parse an extended public key in xpub, zpub, or ypub format.
/// zpub (BIP84) and ypub (BIP49) are converted to xpub by swapping
/// the version bytes before parsing with the bitcoin crate.
fn parse_extended_pubkey(s: &str) -> Result<Xpub, WalletError> {
    if s.starts_with("xpub") {
        return Xpub::from_str(s).map_err(|e| WalletError::InvalidXpub(format!("{}", e)));
    }

    // Decode base58check, swap version bytes to xpub, re-encode.
    let decoded = bitcoin::base58::decode_check(s)
        .map_err(|e| WalletError::InvalidXpub(format!("base58: {}", e)))?;

    if decoded.len() != 78 {
        return Err(WalletError::InvalidXpub(format!(
            "expected 78 bytes, got {}",
            decoded.len()
        )));
    }

    let version: [u8; 4] = decoded[..4].try_into().unwrap();
    if version != ZPUB_VERSION && version != YPUB_VERSION {
        return Err(WalletError::InvalidXpub(format!(
            "unknown version: {:02x?}",
            version
        )));
    }

    // Replace version bytes with standard xpub.
    let mut xpub_bytes = decoded;
    xpub_bytes[..4].copy_from_slice(&XPUB_VERSION);

    let xpub_b58 = bitcoin::base58::encode_check(&xpub_bytes);
    Xpub::from_str(&xpub_b58).map_err(|e| WalletError::InvalidXpub(format!("{}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::consensus::deserialize;

    /// BIP84 test xpub from https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki
    /// Account 0 xpub for mnemonic "abandon abandon ... about" (all "abandon" except last).
    const TEST_XPUB: &str = "zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs";

    fn tmp_wallet() -> (tempfile::TempDir, Wallet) {
        let dir = tempfile::tempdir().unwrap();
        let store_path = dir.path().join("wallet-lmdb");
        let wallet = Wallet::open(TEST_XPUB, store_path.to_str().unwrap()).unwrap();
        (dir, wallet)
    }

    #[test]
    fn test_open_wallet_and_derive_addresses() {
        let (_dir, wallet) = tmp_wallet();

        // Should have derived GAP_LIMIT * 2 = 40 addresses.
        let scripts = wallet.store.all_scripts().unwrap();
        assert_eq!(scripts.len(), 40);

        // Watch set should match.
        let watch = wallet.watch_scripts.read().unwrap();
        assert_eq!(watch.len(), 40);
    }

    #[test]
    fn test_first_receive_address() {
        let (_dir, wallet) = tmp_wallet();
        let addr = wallet.next_receive_address().unwrap();

        // The first receive address should be a valid bech32 bc1q address.
        assert!(addr.address.starts_with("bc1q"), "address: {}", addr.address);
        assert_eq!(addr.derivation_index, 0);
        assert!(!addr.is_change);
        assert!(!addr.used);

        // Second call should return the same address (still unused).
        let addr2 = wallet.next_receive_address().unwrap();
        assert_eq!(addr.address, addr2.address);
    }

    #[test]
    fn test_balance_empty() {
        let (_dir, wallet) = tmp_wallet();
        let bal = wallet.balance().unwrap();
        assert_eq!(bal.confirmed, 0);
        assert_eq!(bal.unconfirmed, 0);
    }

    #[test]
    fn test_reopen_wallet() {
        let dir = tempfile::tempdir().unwrap();
        let store_path = dir.path().join("wallet-lmdb");
        let path_str = store_path.to_str().unwrap();

        // First open — creates addresses.
        {
            let wallet = Wallet::open(TEST_XPUB, path_str).unwrap();
            let scripts = wallet.store.all_scripts().unwrap();
            assert_eq!(scripts.len(), 40);
        }

        // Second open — reloads without re-deriving.
        {
            let wallet = Wallet::open(TEST_XPUB, path_str).unwrap();
            let scripts = wallet.store.all_scripts().unwrap();
            assert_eq!(scripts.len(), 40);
        }
    }

    #[test]
    fn test_wrong_xpub_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let store_path = dir.path().join("wallet-lmdb");
        let path_str = store_path.to_str().unwrap();

        Wallet::open(TEST_XPUB, path_str).unwrap();

        // Try opening with a different xpub — should fail.
        let result = Wallet::open(
            "zpub6jftahH18ngZxLmXaKw3GSZzZsszmt9WqedkyZdezFtWRFBZqsQH5hyUmb4pCEeZGmVfQuP5bedXTB8is6fTv19U1GQRyQUKQGUTzyHACMF",
            path_str,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_process_block_with_payment() {
        let (_dir, wallet) = tmp_wallet();

        // Get the first receive address script.
        let (script, _) = wallet.derive_address(0, false).unwrap();

        // Build a minimal block with a transaction paying to our address.
        // Use a real-ish coinbase + payment structure.
        use bitcoin::{Amount, ScriptBuf, Transaction, TxIn, TxOut, Witness};

        let payment_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: bitcoin::OutPoint {
                    txid: "0000000000000000000000000000000000000000000000000000000000000001"
                        .parse()
                        .unwrap(),
                    vout: 0,
                },
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_000),
                script_pubkey: ScriptBuf::from_bytes(script.clone()),
            }],
        };

        // Create a minimal valid block header.
        let block_bytes = bitcoin::consensus::serialize(&bitcoin::Block {
            header: bitcoin::block::Header {
                version: bitcoin::block::Version::from_consensus(0x20000000),
                prev_blockhash: bitcoin::BlockHash::all_zeros(),
                merkle_root: bitcoin::TxMerkleNode::all_zeros(),
                time: 1700000000,
                bits: bitcoin::CompactTarget::from_consensus(0x1d00ffff),
                nonce: 0,
            },
            txdata: vec![payment_tx],
        });
        let block: Block = deserialize(&block_bytes).unwrap();

        wallet.process_block(&block, 800_001).unwrap();

        // Balance should reflect the payment.
        let bal = wallet.balance().unwrap();
        assert_eq!(bal.confirmed, 50_000);

        // Transaction history should have one entry.
        let txs = wallet.transactions(10, 0).unwrap();
        assert_eq!(txs.len(), 1);
        assert_eq!(txs[0].net_value, 50_000);
        assert_eq!(txs[0].height, Some(800_001));

        // Address should now be marked as used.
        let addr_info = wallet.store.get_address_info(&script).unwrap().unwrap();
        assert!(addr_info.used);
    }

    #[test]
    fn test_scan_height_updates() {
        let (_dir, wallet) = tmp_wallet();

        // Process a block with no wallet activity — scan height should still advance.
        let block_bytes = bitcoin::consensus::serialize(&bitcoin::Block {
            header: bitcoin::block::Header {
                version: bitcoin::block::Version::from_consensus(0x20000000),
                prev_blockhash: bitcoin::BlockHash::all_zeros(),
                merkle_root: bitcoin::TxMerkleNode::all_zeros(),
                time: 1700000000,
                bits: bitcoin::CompactTarget::from_consensus(0x1d00ffff),
                nonce: 0,
            },
            txdata: vec![],
        });
        let block: Block = deserialize(&block_bytes).unwrap();

        wallet.process_block(&block, 800_000).unwrap();
        assert_eq!(wallet.scan_height().unwrap(), 800_000);
    }
}
