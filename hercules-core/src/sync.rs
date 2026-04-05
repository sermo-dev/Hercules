use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use bitcoin::block::Header;
use bitcoin::consensus::deserialize;
use bitcoin::hashes::Hash;
use bitcoin::BlockHash;

use log::{info, warn};

use crate::block_validation::{validate_block, validate_block_scripts};
use crate::peer_pool::{PeerInfo, PeerPool};
use crate::store::HeaderStore;
use crate::utxo::{SnapshotMeta, UtxoSet};
use crate::validation::validate_headers;

/// How often to poll for new blocks after initial sync (seconds).
const MONITOR_INTERVAL: Duration = Duration::from_secs(30);

/// Genesis block header (block 0).
fn genesis_header() -> Header {
    let raw = hex::decode(
        "0100000000000000000000000000000000000000000000000000000000000000\
         000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa\
         4b1e5e4a29ab5f49ffff001d1dac2b7c",
    )
    .unwrap();
    deserialize(&raw).unwrap()
}

/// Current sync status reported to the UI.
#[derive(Debug, Clone)]
pub struct SyncStatus {
    pub synced_headers: u32,
    pub peer_height: u32,
    pub peers: Vec<PeerInfo>,
    pub active_peer_addr: String,
    pub is_syncing: bool,
    pub validated_blocks: u32,
    pub error: Option<String>,
}

/// Sync block headers and validate full blocks from the Bitcoin P2P network.
pub struct HeaderSync {
    store: HeaderStore,
    utxo: UtxoSet,
    validation_paused: Arc<AtomicBool>,
}

impl HeaderSync {
    pub fn new(db_path: &str) -> Result<HeaderSync, SyncError> {
        let store =
            HeaderStore::open(db_path).map_err(|e| SyncError::Store(format!("{}", e)))?;

        // Derive UTXO database path from header database path
        let utxo_path = if db_path == ":memory:" {
            ":memory:".to_string()
        } else {
            db_path.replace("headers", "utxo")
        };
        let utxo =
            UtxoSet::open(&utxo_path).map_err(|e| SyncError::Store(format!("{}", e)))?;

        // Ensure genesis header is stored
        if store.count().map_err(|e| SyncError::Store(format!("{}", e)))? == 0 {
            let genesis = genesis_header();
            store
                .store_headers(&[genesis], 0)
                .map_err(|e| SyncError::Store(format!("{}", e)))?;
            info!("Stored genesis header");
        }

        // Handle upgrade from Phase 2a: if UTXO set is empty but blocks
        // were already structurally validated, reset to re-validate with scripts
        let validated = store
            .validated_height()
            .map_err(|e| SyncError::Store(format!("{}", e)))?;
        let utxo_count = utxo
            .count()
            .map_err(|e| SyncError::Store(format!("{}", e)))?;
        if validated > 0 && utxo_count == 0 {
            store
                .set_validated_height(0)
                .map_err(|e| SyncError::Store(format!("{}", e)))?;
            info!(
                "UTXO set empty but validated_height was {}, resetting to rebuild",
                validated
            );
        }

        Ok(HeaderSync {
            store,
            utxo,
            validation_paused: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Load a UTXO snapshot from a file path. Sets validated_height to the
    /// snapshot height so sync resumes from there.
    pub fn load_snapshot<F>(
        &self,
        snapshot_path: &str,
        expected_hash: Option<&[u8; 32]>,
        on_progress: F,
    ) -> Result<SnapshotMeta, SyncError>
    where
        F: Fn(u64, u64),
    {
        let file = std::fs::File::open(snapshot_path)
            .map_err(|e| SyncError::Store(format!("open snapshot: {}", e)))?;

        let meta = self
            .utxo
            .load_snapshot(file, expected_hash, on_progress)
            .map_err(|e| SyncError::Store(format!("{}", e)))?;

        self.store
            .set_validated_height(meta.height)
            .map_err(|e| SyncError::Store(format!("{}", e)))?;

        info!(
            "Loaded UTXO snapshot at height {}, {} utxos",
            meta.height, meta.utxo_count
        );

        Ok(meta)
    }

    /// Check if the UTXO set is empty (needs snapshot or full sync from genesis).
    pub fn needs_snapshot(&self) -> Result<bool, SyncError> {
        let count = self
            .utxo
            .count()
            .map_err(|e| SyncError::Store(format!("{}", e)))?;
        let validated = self
            .store
            .validated_height()
            .map_err(|e| SyncError::Store(format!("{}", e)))?;
        Ok(count == 0 && validated == 0)
    }

    /// Pause block validation. Header sync continues.
    pub fn set_validation_paused(&self, paused: bool) {
        self.validation_paused.store(paused, Ordering::Relaxed);
        info!("Block validation {}", if paused { "paused" } else { "resumed" });
    }

    /// Check if block validation is currently paused.
    pub fn is_validation_paused(&self) -> bool {
        self.validation_paused.load(Ordering::Relaxed)
    }

    /// Build a SyncStatus snapshot from the pool and current state.
    fn make_status(
        &self,
        synced_headers: u32,
        peer_height: u32,
        pool: &PeerPool,
        active_peer_addr: &str,
        is_syncing: bool,
        validated_blocks: u32,
        error: Option<String>,
    ) -> SyncStatus {
        SyncStatus {
            synced_headers,
            peer_height,
            peers: pool.peer_info(),
            active_peer_addr: active_peer_addr.to_string(),
            is_syncing,
            validated_blocks,
            error,
        }
    }

    /// Run header sync continuously. Calls `on_progress` with status updates.
    /// This is a blocking call that syncs to the chain tip and then monitors
    /// for new blocks every 30 seconds. It only returns on unrecoverable errors.
    pub fn sync<F>(&self, on_progress: F) -> Result<(), SyncError>
    where
        F: Fn(SyncStatus),
    {
        // Get our current height to report to peers
        let our_height = self
            .store
            .count()
            .map_err(|e| SyncError::Store(format!("{}", e)))?
            .saturating_sub(1);

        // Create the peer pool
        let mut pool = PeerPool::new(our_height).map_err(|e| {
            if format!("{}", e).contains("no peers discovered") {
                SyncError::NoPeers
            } else {
                SyncError::Peer(format!("{}", e))
            }
        })?;

        let peer_height = pool
            .peer_info()
            .iter()
            .map(|p| p.height)
            .max()
            .unwrap_or(0);

        let active_addr = pool.best_peer_addr().unwrap_or_default();

        info!(
            "PeerPool ready with {} peers, best height {}",
            pool.count(),
            peer_height,
        );

        let validated = self
            .store
            .validated_height()
            .map_err(|e| SyncError::Store(format!("{}", e)))?;

        // Report initial status
        on_progress(self.make_status(
            our_height,
            peer_height,
            &pool,
            &active_addr,
            true,
            validated,
            None,
        ));

        let mut peer_height = peer_height;

        loop {
            let (tip_height, tip_hash, tip_header) = self
                .store
                .tip()
                .map_err(|e| SyncError::Store(format!("{}", e)))?
                .ok_or_else(|| SyncError::Store("store has no headers".into()))?;

            let current_validated = self
                .store
                .validated_height()
                .map_err(|e| SyncError::Store(format!("{}", e)))?;

            // Get best peer for headers
            let best_peer = pool.best_peer();
            if best_peer.is_none() {
                warn!("No peers available, trying to refill pool");
                pool.maintain();
                if pool.count() == 0 {
                    return Err(SyncError::Peer("all peers disconnected".into()));
                }
                std::thread::sleep(Duration::from_secs(1));
                continue;
            }
            let mut peer = best_peer.unwrap();
            let active_addr = peer.addr().to_string();

            // Request headers from best peer
            let headers = match peer.get_headers(vec![tip_hash], BlockHash::all_zeros()) {
                Ok(h) => {
                    pool.return_peer(peer);
                    h
                }
                Err(e) => {
                    warn!("Peer {} error during get_headers: {}", active_addr, e);
                    pool.remove_peer(&active_addr);
                    pool.maintain();
                    if pool.count() == 0 {
                        return Err(SyncError::Peer("all peers disconnected".into()));
                    }
                    on_progress(self.make_status(
                        tip_height,
                        peer_height,
                        &pool,
                        "",
                        true,
                        current_validated,
                        Some(format!("Peer {} disconnected, using others", active_addr)),
                    ));
                    continue;
                }
            };

            if headers.is_empty() {
                // Headers caught up — download and validate blocks
                peer_height = std::cmp::max(peer_height, tip_height);

                let mut validated = self
                    .store
                    .validated_height()
                    .map_err(|e| SyncError::Store(format!("{}", e)))?;

                // Guard: if validated_height exceeds tip (e.g. after reorg), reset
                if validated > tip_height {
                    warn!(
                        "validated_height {} exceeds tip {}, resetting",
                        validated, tip_height
                    );
                    self.store
                        .set_validated_height(tip_height)
                        .map_err(|e| SyncError::Store(format!("{}", e)))?;
                    validated = tip_height;
                }

                if validated < tip_height
                    && !self.validation_paused.load(Ordering::Relaxed)
                {
                    // Download and validate next block
                    let next_height = validated + 1;
                    let block_hash = self
                        .store
                        .get_hash_at_height(next_height)
                        .map_err(|e| SyncError::Store(format!("{}", e)))?
                        .ok_or_else(|| {
                            SyncError::Store(format!("no hash at height {}", next_height))
                        })?;

                    // Use any available peer for block download
                    let block_peer = pool.any_peer();
                    if block_peer.is_none() {
                        warn!("No peers available for block download, refilling pool");
                        pool.maintain();
                        if pool.count() == 0 {
                            return Err(SyncError::Peer("all peers disconnected".into()));
                        }
                        std::thread::sleep(Duration::from_secs(1));
                        continue;
                    }
                    let mut block_peer = block_peer.unwrap();
                    let block_peer_addr = block_peer.addr().to_string();

                    let block = match block_peer.get_block(block_hash) {
                        Ok(b) => {
                            pool.return_peer(block_peer);
                            b
                        }
                        Err(e) => {
                            warn!(
                                "Block download error at height {} from {}: {}",
                                next_height, block_peer_addr, e
                            );
                            pool.remove_peer(&block_peer_addr);
                            pool.maintain();
                            if pool.count() == 0 {
                                return Err(SyncError::Peer("all peers disconnected".into()));
                            }
                            let best = pool.best_peer_addr().unwrap_or_default();
                            on_progress(self.make_status(
                                tip_height,
                                peer_height,
                                &pool,
                                &best,
                                false,
                                validated,
                                None,
                            ));
                            continue;
                        }
                    };

                    // Verify block hash matches our header chain
                    if block.block_hash() != block_hash {
                        return Err(SyncError::Validation(format!(
                            "block {} hash mismatch: expected {}, got {}",
                            next_height,
                            block_hash,
                            block.block_hash()
                        )));
                    }

                    // Crash recovery: if UTXOs from this block already exist in
                    // the set, the block was applied but validated_height wasn't
                    // updated (crash between the two). Just advance the height.
                    let already_applied = self
                        .utxo
                        .has_utxos_at_height(next_height)
                        .map_err(|e| SyncError::Store(format!("{}", e)))?;
                    if already_applied {
                        info!(
                            "Block {} already applied (crash recovery), advancing validated height",
                            next_height
                        );
                        self.store
                            .set_validated_height(next_height)
                            .map_err(|e| SyncError::Store(format!("{}", e)))?;
                        let best = pool.best_peer_addr().unwrap_or_default();
                        on_progress(self.make_status(
                            tip_height,
                            peer_height,
                            &pool,
                            &best,
                            false,
                            next_height,
                            None,
                        ));
                        continue;
                    }

                    // Structural validation
                    validate_block(&block, next_height)
                        .map_err(|e| SyncError::Validation(format!("{}", e)))?;

                    // Script validation + UTXO verification
                    validate_block_scripts(&block, next_height, &self.utxo)
                        .map_err(|e| SyncError::Validation(format!("{}", e)))?;

                    // Update UTXO set with this block's changes
                    self.utxo
                        .apply_block(&block, next_height)
                        .map_err(|e| SyncError::Store(format!("{}", e)))?;

                    self.store
                        .set_validated_height(next_height)
                        .map_err(|e| SyncError::Store(format!("{}", e)))?;

                    // Prune undo data for deeply-buried blocks (keep 288 for reorgs)
                    if next_height % 1000 == 0 && next_height > 288 {
                        self.utxo
                            .prune_undo_below(next_height - 288)
                            .map_err(|e| SyncError::Store(format!("{}", e)))?;
                    }

                    if next_height % 1000 == 0 {
                        info!("Validated block {}/{}", next_height, tip_height);
                    }

                    let best = pool.best_peer_addr().unwrap_or_default();
                    on_progress(self.make_status(
                        tip_height,
                        peer_height,
                        &pool,
                        &best,
                        false,
                        next_height,
                        None,
                    ));

                    continue; // Immediately download next block
                }

                // Fully synced and validated — monitor mode
                let best = pool.best_peer_addr().unwrap_or_default();
                on_progress(self.make_status(
                    tip_height,
                    peer_height,
                    &pool,
                    &best,
                    false,
                    validated,
                    None,
                ));

                // Service pings on all idle peers and maintain the pool
                pool.service_pings();
                pool.maintain();
                pool.update_our_height(tip_height);

                // Sleep for the monitor interval in small chunks so we can
                // service pings periodically
                let monitor_start = std::time::Instant::now();
                while monitor_start.elapsed() < MONITOR_INTERVAL {
                    let remaining = MONITOR_INTERVAL.saturating_sub(monitor_start.elapsed());
                    let wait = std::cmp::min(remaining, Duration::from_secs(5));
                    if wait.is_zero() {
                        break;
                    }
                    std::thread::sleep(wait);
                    pool.service_pings();
                }

                continue;
            }

            // We have new headers — validate and store them
            let batch_size = headers.len() as u32;

            let timestamps = self
                .store
                .last_timestamps(11)
                .map_err(|e| SyncError::Store(format!("{}", e)))?;

            let store = &self.store;
            let epoch_lookup = |height: u32| -> Result<u32, String> {
                store
                    .get_timestamp_at(height)
                    .map_err(|e| format!("{}", e))?
                    .ok_or_else(|| format!("no header at height {}", height))
            };

            validate_headers(
                &headers,
                tip_hash,
                tip_height,
                &timestamps,
                tip_header.bits,
                &epoch_lookup,
            )
            .map_err(|e| SyncError::Validation(format!("{}", e)))?;

            let new_start = tip_height + 1;
            self.store
                .store_headers(&headers, new_start)
                .map_err(|e| SyncError::Store(format!("{}", e)))?;

            let new_height = tip_height + batch_size;
            peer_height = std::cmp::max(peer_height, new_height);

            info!(
                "Synced headers {}-{} ({} total)",
                new_start, new_height, new_height
            );

            let validated = self
                .store
                .validated_height()
                .map_err(|e| SyncError::Store(format!("{}", e)))?;

            let best = pool.best_peer_addr().unwrap_or_default();
            on_progress(self.make_status(
                new_height,
                peer_height,
                &pool,
                &best,
                new_height < peer_height,
                validated,
                None,
            ));
        }
    }

    /// Get current sync status without syncing.
    pub fn status(&self) -> Result<SyncStatus, SyncError> {
        let count = self
            .store
            .count()
            .map_err(|e| SyncError::Store(format!("{}", e)))?;
        let height = count.saturating_sub(1);

        let validated = self
            .store
            .validated_height()
            .map_err(|e| SyncError::Store(format!("{}", e)))?;

        Ok(SyncStatus {
            synced_headers: height,
            peer_height: 0,
            peers: Vec::new(),
            active_peer_addr: String::new(),
            is_syncing: false,
            validated_blocks: validated,
            error: None,
        })
    }
}

#[derive(Debug)]
pub enum SyncError {
    NoPeers,
    Peer(String),
    Validation(String),
    Store(String),
}

impl std::fmt::Display for SyncError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SyncError::NoPeers => write!(f, "no peers found via DNS seeds"),
            SyncError::Peer(s) => write!(f, "peer error: {}", s),
            SyncError::Validation(s) => write!(f, "validation error: {}", s),
            SyncError::Store(s) => write!(f, "store error: {}", s),
        }
    }
}

impl std::error::Error for SyncError {}
