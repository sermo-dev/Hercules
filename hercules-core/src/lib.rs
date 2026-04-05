use std::path::PathBuf;
use std::sync::Arc;

use bitcoin::block::Header;
use bitcoin::consensus::deserialize;

mod block_validation;
mod p2p;
mod peer_pool;
mod store;
mod sync;
mod tor;
mod utxo;
mod validation;

use tor::TorManager;

uniffi::include_scaffolding!("hercules");

// ── Phase 0 types (block parsing) ──────────────────────────────────

#[derive(Debug, Clone)]
pub struct BlockInfo {
    pub block_hash: String,
    pub prev_block_hash: String,
    pub merkle_root: String,
    pub version: u32,
    pub timestamp: u32,
    pub timestamp_human: String,
    pub bits: u32,
    pub nonce: u32,
}

pub fn parse_block_header(hex_header: String) -> Result<BlockInfo, HerculesError> {
    let bytes = hex::decode(&hex_header).map_err(|e| HerculesError::SyncFailed {
        msg: format!("invalid hex: {}", e),
    })?;
    let header: Header = deserialize(&bytes).map_err(|e| HerculesError::SyncFailed {
        msg: format!("invalid block header: {}", e),
    })?;

    let timestamp = header.time;
    let datetime = chrono_format(timestamp);

    Ok(BlockInfo {
        block_hash: header.block_hash().to_string(),
        prev_block_hash: header.prev_blockhash.to_string(),
        merkle_root: header.merkle_root.to_string(),
        version: header.version.to_consensus() as u32,
        timestamp,
        timestamp_human: datetime,
        bits: header.bits.to_consensus(),
        nonce: header.nonce,
    })
}

pub fn hercules_version() -> String {
    "Hercules v0.1.0".to_string()
}

// ── Phase 1 types (header sync) ────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub addr: String,
    pub user_agent: String,
    pub height: u32,
}

impl From<peer_pool::PeerInfo> for PeerInfo {
    fn from(p: peer_pool::PeerInfo) -> Self {
        PeerInfo {
            addr: p.addr,
            user_agent: p.user_agent,
            height: p.height,
        }
    }
}

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

impl From<sync::SyncStatus> for SyncStatus {
    fn from(s: sync::SyncStatus) -> Self {
        SyncStatus {
            synced_headers: s.synced_headers,
            peer_height: s.peer_height,
            peers: s.peers.into_iter().map(|p| p.into()).collect(),
            active_peer_addr: s.active_peer_addr,
            is_syncing: s.is_syncing,
            validated_blocks: s.validated_blocks,
            error: s.error,
        }
    }
}

// ── Phase 3 types (Tor integration) ────────────────────────────────

#[derive(Debug, Clone)]
pub struct TorStatus {
    pub is_bootstrapped: bool,
    pub bootstrap_progress: u8,
    pub onion_address: Option<String>,
}

impl From<tor::TorStatus> for TorStatus {
    fn from(s: tor::TorStatus) -> Self {
        TorStatus {
            is_bootstrapped: s.is_bootstrapped,
            bootstrap_progress: s.bootstrap_progress,
            onion_address: s.onion_address,
        }
    }
}

// ── Phase 4 types (push notifications) ─────────────────────────────

#[derive(Debug, Clone)]
pub struct BlockNotification {
    pub height: u32,
    pub block_hash: String,
    pub prev_block_hash: String,
    pub timestamp: u32,
    pub timestamp_human: String,
    pub validated: bool,
    pub header_validated: bool,
    pub validation_error: Option<String>,
}

impl From<sync::BlockNotification> for BlockNotification {
    fn from(n: sync::BlockNotification) -> Self {
        BlockNotification {
            height: n.height,
            block_hash: n.block_hash,
            prev_block_hash: n.prev_block_hash,
            timestamp: n.timestamp,
            timestamp_human: n.timestamp_human,
            validated: n.validated,
            header_validated: n.header_validated,
            validation_error: n.validation_error,
        }
    }
}

// ── Errors ─────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum HerculesError {
    #[error("Sync failed: {msg}")]
    SyncFailed { msg: String },
    #[error("Storage error: {msg}")]
    StorageError { msg: String },
    #[error("Network error: {msg}")]
    NetworkError { msg: String },
    #[error("Tor error: {msg}")]
    TorError { msg: String },
}

pub trait SyncCallback: Send + Sync {
    fn on_progress(&self, status: SyncStatus);
}

pub struct HerculesNode {
    syncer: sync::HeaderSync,
    tor: Option<Arc<TorManager>>,
}

impl HerculesNode {
    /// Create a new Hercules node.
    ///
    /// If `tor_data_dir` is provided, all network connections will be routed
    /// through Tor. This blocks during Tor bootstrap (~5-15 seconds).
    pub fn new(db_path: String, tor_data_dir: Option<String>) -> Result<Self, HerculesError> {
        let tor = if let Some(ref dir) = tor_data_dir {
            let path = PathBuf::from(dir);
            let manager = TorManager::bootstrap(&path).map_err(|e| HerculesError::TorError {
                msg: format!("{}", e),
            })?;
            Some(Arc::new(manager))
        } else {
            None
        };

        let syncer =
            sync::HeaderSync::new(&db_path, tor.clone()).map_err(|e| HerculesError::StorageError {
                msg: format!("{}", e),
            })?;
        Ok(HerculesNode { syncer, tor })
    }

    pub fn get_status(&self) -> Result<SyncStatus, HerculesError> {
        let status = self
            .syncer
            .status()
            .map_err(|e| HerculesError::StorageError {
                msg: format!("{}", e),
            })?;
        Ok(status.into())
    }

    pub fn start_header_sync(&self, callback: Box<dyn SyncCallback>) -> Result<(), HerculesError> {
        self.syncer
            .sync(|status| {
                callback.on_progress(status.into());
            })
            .map_err(|e| match e {
                sync::SyncError::NoPeers => HerculesError::NetworkError {
                    msg: "no peers found".into(),
                },
                sync::SyncError::Peer(s) => HerculesError::NetworkError { msg: s },
                sync::SyncError::Validation(s) => HerculesError::SyncFailed { msg: s },
                sync::SyncError::Store(s) => HerculesError::StorageError { msg: s },
            })
    }

    /// Check if the node needs a UTXO snapshot before it can validate blocks efficiently.
    pub fn needs_snapshot(&self) -> Result<bool, HerculesError> {
        self.syncer
            .needs_snapshot()
            .map_err(|e| HerculesError::StorageError {
                msg: format!("{}", e),
            })
    }

    /// Load a UTXO snapshot from a file. After loading, block validation resumes
    /// from the snapshot height.
    pub fn load_snapshot(
        &self,
        snapshot_path: String,
        callback: Box<dyn SnapshotCallback>,
    ) -> Result<SnapshotInfo, HerculesError> {
        let meta = self
            .syncer
            .load_snapshot(&snapshot_path, None, |loaded, total| {
                callback.on_progress(loaded, total);
            })
            .map_err(|e| HerculesError::StorageError {
                msg: format!("{}", e),
            })?;

        Ok(SnapshotInfo {
            height: meta.height,
            utxo_count: meta.utxo_count,
            utxo_hash: hex::encode(meta.utxo_hash),
        })
    }

    /// Request the sync loop to stop cleanly. The blocking `start_header_sync`
    /// call will return on the next loop iteration.
    pub fn stop_sync(&self) {
        self.syncer.stop_sync();
    }

    /// Get the current Tor status. Returns None if Tor is not enabled.
    pub fn get_tor_status(&self) -> Option<TorStatus> {
        self.tor.as_ref().map(|t| t.status().into())
    }

    /// One-shot block validation for push notification background wake.
    /// Connects to a peer, checks for new headers/blocks within the timeout.
    pub fn validate_latest_block(
        &self,
        timeout_secs: u32,
    ) -> Result<BlockNotification, HerculesError> {
        self.syncer
            .validate_latest_block(timeout_secs)
            .map(|n| n.into())
            .map_err(|e| match e {
                sync::SyncError::NoPeers => HerculesError::NetworkError {
                    msg: "no peers found".into(),
                },
                sync::SyncError::Peer(s) => HerculesError::NetworkError { msg: s },
                sync::SyncError::Validation(s) => HerculesError::SyncFailed { msg: s },
                sync::SyncError::Store(s) => HerculesError::StorageError { msg: s },
            })
    }

    /// Pause or resume block validation. Header sync continues regardless.
    pub fn set_validation_paused(&self, paused: bool) {
        self.syncer.set_validation_paused(paused);
    }

    /// Check if block validation is currently paused.
    pub fn is_validation_paused(&self) -> bool {
        self.syncer.is_validation_paused()
    }
}

/// Callback for snapshot loading progress.
pub trait SnapshotCallback: Send + Sync {
    fn on_progress(&self, loaded: u64, total: u64);
}

/// Information about a loaded UTXO snapshot.
#[derive(Debug, Clone)]
pub struct SnapshotInfo {
    pub height: u32,
    pub utxo_count: u64,
    pub utxo_hash: String,
}

// ── Utilities ──────────────────────────────────────────────────────

fn chrono_format(timestamp: u32) -> String {
    let secs = timestamp as i64;
    let hours = (secs % 86400) / 3600;
    let mins = (secs % 3600) / 60;
    let secs_rem = secs % 60;

    let days = secs / 86400;
    let (year, month, day) = days_to_ymd(days);

    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC",
        year, month, day, hours, mins, secs_rem
    )
}

fn days_to_ymd(days: i64) -> (i64, i64, i64) {
    let z = days + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    const GENESIS_HEX: &str = "\
        0100000000000000000000000000000000000000000000000000000000000000\
        000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa\
        4b1e5e4a29ab5f49ffff001d1dac2b7c";

    #[test]
    fn parse_genesis_block_header() {
        let info = parse_block_header(GENESIS_HEX.into()).unwrap();

        assert_eq!(
            info.block_hash,
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        );
        assert_eq!(info.version, 1);
        assert_eq!(info.timestamp, 1231006505);
        assert_eq!(info.bits, 486604799); // 0x1d00ffff
        assert_eq!(info.nonce, 2083236893);
    }

    #[test]
    fn parse_invalid_hex_returns_error() {
        let result = parse_block_header("not_hex!!!".into());
        assert!(result.is_err());
    }

    #[test]
    fn parse_truncated_header_returns_error() {
        // Valid hex but too short to be a block header
        let result = parse_block_header("0100000000000000".into());
        assert!(result.is_err());
    }

    #[test]
    fn version_string() {
        let v = hercules_version();
        assert!(v.contains("Hercules"));
        assert!(v.contains("0.1.0"));
    }

    #[test]
    fn chrono_format_genesis_timestamp() {
        // Genesis block: 2009-01-03 18:15:05 UTC
        let formatted = chrono_format(1231006505);
        assert_eq!(formatted, "2009-01-03 18:15:05 UTC");
    }

    #[test]
    fn chrono_format_unix_epoch() {
        let formatted = chrono_format(0);
        assert_eq!(formatted, "1970-01-01 00:00:00 UTC");
    }

    #[test]
    fn node_new_and_status() {
        let node = HerculesNode::new(":memory:".into(), None).unwrap();
        let status = node.get_status().unwrap();

        // Fresh node has genesis stored, so synced_headers = 0 (count 1 minus 1)
        assert_eq!(status.synced_headers, 0);
        assert_eq!(status.peer_height, 0);
        assert!(!status.is_syncing);
        assert!(status.error.is_none());
    }

    #[test]
    fn sync_status_from_internal() {
        let internal = sync::SyncStatus {
            synced_headers: 100,
            peer_height: 800000,
            peers: vec![peer_pool::PeerInfo {
                addr: "1.2.3.4:8333".into(),
                user_agent: "/Satoshi:27.0.0/".into(),
                height: 800000,
            }],
            active_peer_addr: "1.2.3.4:8333".into(),
            is_syncing: true,
            validated_blocks: 50,
            error: None,
        };
        let external: SyncStatus = internal.into();
        assert_eq!(external.synced_headers, 100);
        assert_eq!(external.peer_height, 800000);
        assert_eq!(external.peers.len(), 1);
        assert_eq!(external.peers[0].addr, "1.2.3.4:8333");
        assert_eq!(external.active_peer_addr, "1.2.3.4:8333");
        assert!(external.is_syncing);
        assert_eq!(external.validated_blocks, 50);
    }
}
