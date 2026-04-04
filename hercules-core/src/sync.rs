use std::net::SocketAddr;

use bitcoin::block::Header;
use bitcoin::consensus::deserialize;
use bitcoin::hashes::Hash;
use bitcoin::BlockHash;

use log::{info, warn};

use crate::p2p::Peer;
use crate::store::HeaderStore;
use crate::validation::validate_headers;

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
    pub error: Option<String>,
}

/// Sync block headers from the Bitcoin P2P network.
pub struct HeaderSync {
    store: HeaderStore,
}

impl HeaderSync {
    pub fn new(db_path: &str) -> Result<HeaderSync, SyncError> {
        let store =
            HeaderStore::open(db_path).map_err(|e| SyncError::Store(format!("{}", e)))?;

        // Ensure genesis header is stored
        if store.count().map_err(|e| SyncError::Store(format!("{}", e)))? == 0 {
            let genesis = genesis_header();
            store
                .store_headers(&[genesis], 0)
                .map_err(|e| SyncError::Store(format!("{}", e)))?;
            info!("Stored genesis header");
        }

        Ok(HeaderSync { store })
    }

    /// Run header sync. Calls `on_progress` with status updates.
    /// This is a blocking call that runs until fully synced or an error occurs.
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

        // Try to connect to a peer
        let mut peer = self.connect_to_peer(&addrs, our_height)?;

        let peer_height = peer.peer_height().unwrap_or(0) as u32;
        let peer_user_agent = peer.peer_user_agent().unwrap_or_default();
        let peer_addr = peer.addr().to_string();

        info!(
            "Connected to {} ({}) at height {}",
            peer_addr, peer_user_agent, peer_height
        );

        // Report initial status
        let current_height = self
            .store
            .count()
            .map_err(|e| SyncError::Store(format!("{}", e)))?
            .saturating_sub(1);

        on_progress(SyncStatus {
            synced_headers: current_height,
            peer_height,
            peer_addr: peer_addr.clone(),
            peer_user_agent: peer_user_agent.clone(),
            is_syncing: true,
            error: None,
        });

        // Header sync loop
        loop {
            let (tip_height, tip_hash, tip_header) = self
                .store
                .tip()
                .map_err(|e| SyncError::Store(format!("{}", e)))?
                .expect("store should have at least genesis");

            if tip_height >= peer_height {
                info!("Fully synced at height {}", tip_height);
                on_progress(SyncStatus {
                    synced_headers: tip_height,
                    peer_height,
                    peer_addr: peer_addr.clone(),
                    peer_user_agent: peer_user_agent.clone(),
                    is_syncing: false,
                    error: None,
                });
                return Ok(());
            }

            // Request next batch of headers
            let headers = match peer.get_headers(vec![tip_hash], BlockHash::all_zeros()) {
                Ok(h) => h,
                Err(e) => {
                    // If we're close to the peer's reported height, treat disconnect as success
                    if tip_height + 10 >= peer_height {
                        info!("Peer disconnected near tip (height {}), treating as synced", tip_height);
                        on_progress(SyncStatus {
                            synced_headers: tip_height,
                            peer_height: tip_height,
                            peer_addr: peer_addr.clone(),
                            peer_user_agent: peer_user_agent.clone(),
                            is_syncing: false,
                            error: None,
                        });
                        return Ok(());
                    }
                    return Err(SyncError::Peer(format!("{}", e)));
                }
            };

            if headers.is_empty() {
                info!("Peer returned no headers, sync complete at height {}", tip_height);
                on_progress(SyncStatus {
                    synced_headers: tip_height,
                    peer_height: tip_height,
                    peer_addr: peer_addr.clone(),
                    peer_user_agent: peer_user_agent.clone(),
                    is_syncing: false,
                    error: None,
                });
                return Ok(());
            }

            let batch_size = headers.len() as u32;

            // Get timestamps for validation
            let timestamps = self
                .store
                .last_timestamps(11)
                .map_err(|e| SyncError::Store(format!("{}", e)))?;

            // Validate the batch (including difficulty adjustment at retarget boundaries)
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

            // Store validated headers
            let new_start = tip_height + 1;
            self.store
                .store_headers(&headers, new_start)
                .map_err(|e| SyncError::Store(format!("{}", e)))?;

            let new_height = tip_height + batch_size;
            info!(
                "Synced headers {}-{} ({} total)",
                new_start,
                new_height,
                new_height
            );

            on_progress(SyncStatus {
                synced_headers: new_height,
                peer_height,
                peer_addr: peer_addr.clone(),
                peer_user_agent: peer_user_agent.clone(),
                is_syncing: true,
                error: None,
            });
        }
    }

    /// Try connecting to peers until one succeeds.
    fn connect_to_peer(&self, addrs: &[SocketAddr], our_height: u32) -> Result<Peer, SyncError> {
        let mut last_err = String::new();
        // Try up to 10 peers
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

        Ok(SyncStatus {
            synced_headers: height,
            peer_height: 0,
            peer_addr: String::new(),
            peer_user_agent: String::new(),
            is_syncing: false,
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
