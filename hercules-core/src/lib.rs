use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use bitcoin::block::Header;
use bitcoin::consensus::deserialize;

mod assumeutxo;
mod block_store;
mod block_validation;
mod mempool;
mod p2p;
mod peer_pool;
mod peer_store;
mod store;
mod sync;
mod tor;
mod tor_v3;
mod utxo;
mod validation;
mod wallet_rpc;

use tor::TorManager;
use wallet_rpc::WalletRpcServer;

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

/// Wipe all on-disk state for a Hercules node so the next launch starts from a
/// clean genesis. Deletes the headers DB plus the derived block-store and
/// peers SQLite files (and their -wal/-shm sidecars), and recursively removes
/// the LMDB UTXO directory. The caller MUST drop any live `HerculesNode` for
/// this `db_path` before calling this — open file handles will silently keep
/// the inodes alive on POSIX, leaving stale state behind.
pub fn reset_database(db_path: String) -> Result<(), HerculesError> {
    // Mirror the path-derivation logic in `HeaderSync::new`. Keep in sync.
    let utxo_dir = sync::derive_sibling_path(&db_path, "utxo-lmdb");
    let blocks_path = db_path.replace("headers", "blocks");
    let peers_path = db_path.replace("headers", "peers");

    // SQLite files (headers / blocks / peers) — three sidecars each.
    for base in [&db_path, &blocks_path, &peers_path] {
        for suffix in ["", "-wal", "-shm"] {
            let p = format!("{}{}", base, suffix);
            match std::fs::remove_file(&p) {
                Ok(_) => log::info!("reset_database: removed {}", p),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(HerculesError::StorageError {
                        msg: format!("failed to remove {}: {}", p, e),
                    });
                }
            }
        }
    }

    // LMDB env: a directory of mmapped files. Recursive removal.
    match std::fs::remove_dir_all(&utxo_dir) {
        Ok(_) => log::info!("reset_database: removed {}", utxo_dir),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(HerculesError::StorageError {
                msg: format!("failed to remove {}: {}", utxo_dir, e),
            });
        }
    }

    Ok(())
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

#[derive(Debug, Clone)]
pub struct CatchUpStatus {
    pub caught_up: bool,
    pub blocks_validated: u32,
    pub current_height: u32,
    pub target_height: u32,
    pub tip_block_hash: String,
    pub tip_timestamp: u32,
    pub error: Option<String>,
    pub tip_disagreement: bool,
}

impl From<sync::CatchUpStatus> for CatchUpStatus {
    fn from(s: sync::CatchUpStatus) -> Self {
        CatchUpStatus {
            caught_up: s.caught_up,
            blocks_validated: s.blocks_validated,
            current_height: s.current_height,
            target_height: s.target_height,
            tip_block_hash: s.tip_block_hash,
            tip_timestamp: s.tip_timestamp,
            error: s.error,
            tip_disagreement: s.tip_disagreement,
        }
    }
}

// ── Phase 5 types (fully participating node) ──────────────────────

#[derive(Debug, Clone)]
pub struct MempoolStatus {
    pub tx_count: u32,
    pub total_size: u64,
    pub max_size: u64,
}

#[derive(Debug, Clone)]
pub struct NodeStatus {
    pub inbound_peers: u32,
    pub outbound_peers: u32,
    pub blocks_served: u64,
    pub txs_relayed: u64,
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

/// State for a running wallet RPC server thread.
struct WalletRpcHandle {
    server: Arc<WalletRpcServer>,
    thread: Option<JoinHandle<()>>,
}

pub struct HerculesNode {
    syncer: Arc<sync::HeaderSync>,
    tor: Option<Arc<TorManager>>,
    wallet_rpc: Mutex<Option<WalletRpcHandle>>,
    /// Persisted auth token for wallet API connections.
    wallet_auth_token: Mutex<Option<String>>,
    /// Path to the directory where we persist wallet API secrets.
    data_dir: String,
}

impl HerculesNode {
    /// Create a new Hercules node.
    ///
    /// If `tor_data_dir` is provided, all network connections will be routed
    /// through Tor. This blocks during Tor bootstrap (~5-15 seconds).
    pub fn new(db_path: String, tor_data_dir: Option<String>) -> Result<Self, HerculesError> {
        let tor = if let Some(ref dir) = tor_data_dir {
            let path = PathBuf::from(dir);
            let mut manager = TorManager::bootstrap(&path).map_err(|e| HerculesError::TorError {
                msg: format!("{}", e),
            })?;

            // Start the onion hidden service so we can accept inbound connections.
            // Must be called before wrapping in Arc (requires &mut self).
            // The handle is stored internally on TorManager to keep the service alive.
            match manager.start_onion_service(8333) {
                Ok(addr) => {
                    log::info!("Onion service running at {}", addr);
                }
                Err(e) => {
                    log::warn!("Onion service failed to start (non-fatal): {}", e);
                }
            }

            Some(Arc::new(manager))
        } else {
            None
        };

        let syncer =
            sync::HeaderSync::new(&db_path, tor.clone()).map_err(|e| HerculesError::StorageError {
                msg: format!("{}", e),
            })?;

        // Derive data_dir from the db_path (parent directory of headers DB).
        let data_dir = std::path::Path::new(&db_path)
            .parent()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|| ".".to_string());

        Ok(HerculesNode {
            syncer: Arc::new(syncer),
            tor,
            wallet_rpc: Mutex::new(None),
            wallet_auth_token: Mutex::new(None),
            data_dir,
        })
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

    /// Load a UTXO snapshot from a file. The file is verified against the
    /// hardcoded `ASSUMEUTXO_HASH` trust anchor; mismatched files are rejected
    /// without modifying the database. Accepts either a raw `.hutx` file or a
    /// gzipped `.hutx.gz` (decompressed on the fly).
    ///
    /// After loading, block validation resumes from the snapshot height.
    pub fn load_snapshot(
        &self,
        snapshot_path: String,
        callback: Box<dyn SnapshotCallback>,
    ) -> Result<SnapshotInfo, HerculesError> {
        let meta = self
            .syncer
            .load_snapshot(
                &snapshot_path,
                Some(&assumeutxo::ASSUMEUTXO_HASH),
                |loaded, total| {
                    callback.on_progress(loaded, total);
                },
            )
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

    /// Budgeted multi-block catch-up for push notification background wakes.
    /// Validates up to `max_blocks` blocks within `budget_secs`, returning
    /// partial progress if the budget is exhausted.
    pub fn catch_up_blocks(
        &self,
        max_blocks: u32,
        budget_secs: u32,
    ) -> Result<CatchUpStatus, HerculesError> {
        self.syncer
            .catch_up_blocks(max_blocks, budget_secs)
            .map(|s| s.into())
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

    /// Get mempool status (transaction count, total size, max size).
    pub fn get_mempool_status(&self) -> MempoolStatus {
        self.syncer.get_mempool_status()
    }

    /// Get node serving/relay statistics.
    pub fn get_node_status(&self) -> NodeStatus {
        self.syncer.get_node_status()
    }

    // ── Wallet API ────────────────────────────────────────────────

    /// Start the wallet-facing JSON-RPC server on a dedicated Tor onion
    /// service. Returns the connection string: `<onion>:<port>/<auth_token>`.
    /// Calling this when the server is already running is a no-op that
    /// returns the existing connection string.
    pub fn start_wallet_api(&self) -> Result<String, HerculesError> {
        let tor = self.tor.as_ref().ok_or_else(|| HerculesError::TorError {
            msg: "Tor is not enabled — wallet API requires Tor".into(),
        })?;

        // If already running, return existing connection string.
        {
            let guard = self.wallet_rpc.lock().unwrap();
            if guard.is_some() {
                return self.get_wallet_api_connection_string();
            }
        }

        // Get or generate auth token.
        let token = self.get_or_create_auth_token()?;

        // Start the wallet onion service (separate from P2P onion).
        // Uses interior mutability, so &self is sufficient through Arc.
        let onion_addr = tor.start_wallet_onion_service(18443).map_err(|e| {
            HerculesError::TorError {
                msg: format!("wallet onion service: {}", e),
            }
        })?;

        let server = Arc::new(WalletRpcServer::new(
            Arc::clone(&self.syncer),
            Arc::clone(tor),
            token.clone(),
        ));

        let server_clone = Arc::clone(&server);
        let thread = std::thread::Builder::new()
            .name("wallet-rpc".into())
            .spawn(move || {
                server_clone.serve();
            })
            .map_err(|e| HerculesError::NetworkError {
                msg: format!("failed to spawn wallet RPC thread: {}", e),
            })?;

        *self.wallet_rpc.lock().unwrap() = Some(WalletRpcHandle {
            server,
            thread: Some(thread),
        });

        log::info!("Wallet API started at {}", onion_addr);

        // Connection string format: <addr_with_port>/<auth_token>
        // onion_addr already includes :18443 from start_wallet_onion_service.
        Ok(format!("{}/{}", onion_addr, token))
    }

    /// Stop the wallet API server and its onion service.
    pub fn stop_wallet_api(&self) {
        let handle = self.wallet_rpc.lock().unwrap().take();
        if let Some(mut h) = handle {
            h.server.stop();
            if let Some(thread) = h.thread.take() {
                let _ = thread.join();
            }
        }

        // Stop the wallet onion service.
        if let Some(ref tor) = self.tor {
            tor.stop_wallet_onion_service();
        }

        log::info!("Wallet API stopped");
    }

    /// Get the wallet API connection string, or None if not running.
    pub fn get_wallet_api_connection_string(&self) -> Result<String, HerculesError> {
        let guard = self.wallet_rpc.lock().unwrap();
        if guard.is_none() {
            return Err(HerculesError::NetworkError {
                msg: "wallet API is not running".into(),
            });
        }

        let tor = self.tor.as_ref().ok_or_else(|| HerculesError::TorError {
            msg: "Tor is not enabled".into(),
        })?;

        let onion_addr = tor.wallet_onion_address().ok_or_else(|| HerculesError::TorError {
            msg: "wallet onion service not available".into(),
        })?;

        let token = self.wallet_auth_token.lock().unwrap();
        let token = token.as_ref().ok_or_else(|| HerculesError::NetworkError {
            msg: "no auth token".into(),
        })?;

        Ok(format!("{}/{}", onion_addr, token))
    }

    /// Load or generate the persistent auth token for wallet API.
    fn get_or_create_auth_token(&self) -> Result<String, HerculesError> {
        // Check in-memory cache first.
        {
            let guard = self.wallet_auth_token.lock().unwrap();
            if let Some(ref t) = *guard {
                return Ok(t.clone());
            }
        }

        let token_path = format!("{}/wallet_auth_token", self.data_dir);

        // Try to read persisted token.
        if let Ok(contents) = std::fs::read_to_string(&token_path) {
            let token = contents.trim().to_string();
            if token.len() == 64 {
                *self.wallet_auth_token.lock().unwrap() = Some(token.clone());
                return Ok(token);
            }
        }

        // No valid token on disk — generate and persist.
        self.generate_and_persist_token()
    }

    /// Generate a fresh auth token, write it to disk, and update the
    /// in-memory cache. Shared by initial generation and rotation.
    fn generate_and_persist_token(&self) -> Result<String, HerculesError> {
        let token = generate_auth_token().map_err(|e| HerculesError::StorageError {
            msg: format!("failed to generate auth token: {}", e),
        })?;

        let token_path = format!("{}/wallet_auth_token", self.data_dir);

        // Persist with restrictive permissions (owner-only read/write).
        // On iOS the sandbox + Data Protection already encrypt at rest, but
        // 0600 is defense-in-depth for any future non-iOS target.
        {
            use std::io::Write;
            #[cfg(unix)]
            use std::os::unix::fs::OpenOptionsExt;

            let mut opts = std::fs::OpenOptions::new();
            opts.write(true).create(true).truncate(true);
            #[cfg(unix)]
            opts.mode(0o600);

            let mut f = opts.open(&token_path).map_err(|e| HerculesError::StorageError {
                msg: format!("failed to persist auth token: {}", e),
            })?;
            f.write_all(token.as_bytes()).map_err(|e| HerculesError::StorageError {
                msg: format!("failed to write auth token: {}", e),
            })?;
        }

        *self.wallet_auth_token.lock().unwrap() = Some(token.clone());
        Ok(token)
    }

    /// Rotate the wallet API auth token. Generates a new token, persists
    /// it, and restarts the wallet RPC server if it's running. The old
    /// token is immediately invalidated — any wallet using it will get
    /// 401 Unauthorized on its next request. Returns the new connection
    /// string if the server is running, or just the new token if it's not.
    pub fn rotate_wallet_auth_token(&self) -> Result<String, HerculesError> {
        let token = self.generate_and_persist_token()?;
        log::info!("Wallet API auth token rotated");

        // If the server is running, restart it with the new token.
        let was_running = self.wallet_rpc.lock().unwrap().is_some();
        if was_running {
            self.stop_wallet_api();
            return self.start_wallet_api();
        }

        Ok(token)
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

/// Generate a 64-char hex auth token from 32 bytes of OS entropy.
fn generate_auth_token() -> Result<String, std::io::Error> {
    let mut buf = [0u8; 32];
    // Works on macOS, iOS, Linux. /dev/urandom never blocks post-boot.
    let mut file = std::fs::File::open("/dev/urandom")?;
    std::io::Read::read_exact(&mut file, &mut buf)?;
    Ok(hex::encode(buf))
}

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
        // LMDB needs a real directory for the UTXO env, so we anchor every
        // store under a temp dir instead of the old `:memory:` sentinel.
        let dir = tempfile::TempDir::new().unwrap();
        let db_path = dir.path().join("hercules-headers.sqlite3");
        let node = HerculesNode::new(db_path.to_string_lossy().into_owned(), None).unwrap();
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
