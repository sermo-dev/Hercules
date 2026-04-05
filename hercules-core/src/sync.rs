use std::net::SocketAddr;
use std::time::Duration;

use bitcoin::block::Header;
use bitcoin::consensus::deserialize;
use bitcoin::hashes::Hash;
use bitcoin::BlockHash;

use log::{info, warn};

use crate::block_validation::{validate_block, validate_block_scripts};
use crate::p2p::Peer;
use crate::store::HeaderStore;
use crate::utxo::UtxoSet;
use crate::validation::validate_headers;

/// How often to poll for new blocks after initial sync (seconds).
const MONITOR_INTERVAL: Duration = Duration::from_secs(30);

/// Delay before retrying peer connection after failure.
const RECONNECT_DELAY: Duration = Duration::from_secs(10);

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
    pub peer_addr: String,
    pub peer_user_agent: String,
    pub is_syncing: bool,
    pub validated_blocks: u32,
    pub error: Option<String>,
}

/// Sync block headers and validate full blocks from the Bitcoin P2P network.
pub struct HeaderSync {
    store: HeaderStore,
    utxo: UtxoSet,
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

        Ok(HeaderSync { store, utxo })
    }

    /// Run header sync continuously. Calls `on_progress` with status updates.
    /// This is a blocking call that syncs to the chain tip and then monitors
    /// for new blocks every 30 seconds. It only returns on unrecoverable errors.
    pub fn sync<F>(&self, on_progress: F) -> Result<(), SyncError>
    where
        F: Fn(SyncStatus),
    {
        // Discover peers
        let addrs = Peer::discover_peers();
        if addrs.is_empty() {
            return Err(SyncError::NoPeers);
        }

        // Get our current height to report to peers
        let our_height = self
            .store
            .count()
            .map_err(|e| SyncError::Store(format!("{}", e)))?
            .saturating_sub(1);

        // Connect to a peer
        let mut peer = self.connect_to_peer(&addrs, our_height)?;
        let mut peer_height = peer.peer_height().unwrap_or(0) as u32;
        let mut peer_user_agent = peer.peer_user_agent().unwrap_or_default();
        let mut peer_addr = peer.addr().to_string();

        info!(
            "Connected to {} ({}) at height {}",
            peer_addr, peer_user_agent, peer_height
        );

        let validated = self
            .store
            .validated_height()
            .map_err(|e| SyncError::Store(format!("{}", e)))?;

        // Report initial status
        on_progress(SyncStatus {
            synced_headers: our_height,
            peer_height,
            peer_addr: peer_addr.clone(),
            peer_user_agent: peer_user_agent.clone(),
            is_syncing: true,
            validated_blocks: validated,
            error: None,
        });

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

            // Request headers from peer
            let headers = match peer.get_headers(vec![tip_hash], BlockHash::all_zeros()) {
                Ok(h) => h,
                Err(e) => {
                    warn!("Peer error: {}", e);
                    // Try to reconnect
                    match self.reconnect(&addrs, tip_height, &on_progress, &peer_addr, &peer_user_agent, current_validated) {
                        Ok(new_peer) => {
                            peer_height = new_peer.peer_height().unwrap_or(0) as u32;
                            peer_user_agent = new_peer.peer_user_agent().unwrap_or_default();
                            peer_addr = new_peer.addr().to_string();
                            peer = new_peer;
                            info!("Reconnected to {} ({})", peer_addr, peer_user_agent);
                            continue;
                        }
                        Err(e) => return Err(e),
                    }
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

                if validated < tip_height {
                    // Download and validate next block
                    let next_height = validated + 1;
                    let block_hash = self
                        .store
                        .get_hash_at_height(next_height)
                        .map_err(|e| SyncError::Store(format!("{}", e)))?
                        .ok_or_else(|| {
                            SyncError::Store(format!("no hash at height {}", next_height))
                        })?;

                    let block = match peer.get_block(block_hash) {
                        Ok(b) => b,
                        Err(e) => {
                            warn!("Block download error at height {}: {}", next_height, e);
                            // Try to reconnect
                            match self.reconnect(
                                &addrs,
                                tip_height,
                                &on_progress,
                                &peer_addr,
                                &peer_user_agent,
                                validated,
                            ) {
                                Ok(new_peer) => {
                                    peer_height = new_peer.peer_height().unwrap_or(0) as u32;
                                    peer_user_agent =
                                        new_peer.peer_user_agent().unwrap_or_default();
                                    peer_addr = new_peer.addr().to_string();
                                    peer = new_peer;
                                    continue;
                                }
                                Err(e) => return Err(e),
                            }
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

                    if next_height % 1000 == 0 {
                        info!("Validated block {}/{}", next_height, tip_height);
                    }

                    on_progress(SyncStatus {
                        synced_headers: tip_height,
                        peer_height,
                        peer_addr: peer_addr.clone(),
                        peer_user_agent: peer_user_agent.clone(),
                        is_syncing: false,
                        validated_blocks: next_height,
                        error: None,
                    });

                    continue; // Immediately download next block
                }

                // Fully synced and validated — monitor mode
                on_progress(SyncStatus {
                    synced_headers: tip_height,
                    peer_height,
                    peer_addr: peer_addr.clone(),
                    peer_user_agent: peer_user_agent.clone(),
                    is_syncing: false,
                    validated_blocks: validated,
                    error: None,
                });

                let _ = peer.idle_wait(MONITOR_INTERVAL);
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

            on_progress(SyncStatus {
                synced_headers: new_height,
                peer_height,
                peer_addr: peer_addr.clone(),
                peer_user_agent: peer_user_agent.clone(),
                is_syncing: new_height < peer_height,
                validated_blocks: validated,
                error: None,
            });
        }
    }

    /// Attempt to reconnect to a peer after disconnection.
    fn reconnect<F>(
        &self,
        addrs: &[SocketAddr],
        tip_height: u32,
        on_progress: &F,
        old_addr: &str,
        old_ua: &str,
        validated: u32,
    ) -> Result<Peer, SyncError>
    where
        F: Fn(SyncStatus),
    {
        // Report disconnection but keep showing synced state
        on_progress(SyncStatus {
            synced_headers: tip_height,
            peer_height: tip_height,
            peer_addr: old_addr.to_string(),
            peer_user_agent: old_ua.to_string(),
            is_syncing: false,
            validated_blocks: validated,
            error: Some("Peer disconnected, reconnecting...".into()),
        });

        // Wait before retrying
        std::thread::sleep(RECONNECT_DELAY);

        self.connect_to_peer(addrs, tip_height)
    }

    /// Try connecting to peers until one succeeds.
    fn connect_to_peer(&self, addrs: &[SocketAddr], our_height: u32) -> Result<Peer, SyncError> {
        let mut last_err = String::new();
        for addr in addrs.iter().take(10) {
            match Peer::connect(*addr, our_height as i32) {
                Ok(peer) => return Ok(peer),
                Err(e) => {
                    warn!("Failed to connect to {}: {}", addr, e);
                    last_err = format!("{}", e);
                }
            }
        }
        Err(SyncError::Peer(format!(
            "could not connect to any peer, last error: {}",
            last_err
        )))
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
            peer_addr: String::new(),
            peer_user_agent: String::new(),
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
