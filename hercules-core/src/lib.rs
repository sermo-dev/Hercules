use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use bitcoin::block::Header;
use bitcoin::consensus::deserialize;

mod assumeutxo;
mod block_store;
mod block_validation;
mod chain_params;
mod contextual_checks;
mod mempool;
mod own_tx_store;
mod p2p;
mod peer_pool;
mod relay_policy;
mod script_verify;
mod peer_store;
mod store;
mod sync;
#[cfg(test)]
mod testkit;
mod tor;
mod tor_v3;
mod utxo;
mod validation;
mod wake;
mod wallet_rpc;

use tor::TorManager;
use wake::{TransportGate, TransportWait, WakePhase};
use wallet_rpc::WalletRpcServer;

pub use wake::WakeBudget;

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

/// The script verification library this build uses (ticket 047), e.g.
/// "libbitcoinkernel v32.0" or the legacy libbitcoinconsensus v26.
pub fn script_backend() -> String {
    script_verify::active_backend_name().to_string()
}

/// Wipe all on-disk state for a Hercules node so the next launch starts from a
/// clean genesis. Recursively removes the LMDB UTXO directory, then deletes
/// the headers DB plus the derived block-store, own-tx and peers SQLite files
/// (and their -wal/-shm sidecars), and the app's `migration-conflicts/`
/// directory of parked pre-migration copies. The caller MUST drop any live
/// `HerculesNode` for this `db_path` before calling this — open file handles
/// will silently keep the inodes alive on POSIX, leaving stale state behind.
///
/// Interruption-safe (ticket 050): the UTXO env's `.loading` marker is
/// written before anything is unlinked and removed only once everything
/// is, and the env goes first. A reset killed (or failing) partway leaves
/// the marker, so the next open wipes whatever is left of the env. A UTXO
/// set can therefore never outlive its headers: that state used to make the
/// next launch roll the set back past its pruned undo data, corrupting it
/// and condemning the honest chain.
pub fn reset_database(db_path: String) -> Result<(), HerculesError> {
    // Ticket 028: never unlink files under a live node. Its LMDB env would
    // keep the deleted inodes, and heed would hand that stale env to the
    // next open of the same path. The registry stays locked until the
    // deletes are done, so no node can open in between.
    let _no_open = PathClaim::lock_unclaimed(&db_path)?;
    // Mirror the path-derivation logic in `HeaderSync::new`. Keep in sync.
    let utxo_dir = sync::derive_sibling_path(&db_path, "utxo-lmdb");
    let blocks_path = sync::derive_sibling_path(&db_path, "blocks.sqlite3");
    let own_txs_path = sync::derive_sibling_path(&db_path, "own_txs.sqlite3");
    let peers_path = sync::derive_sibling_path(&db_path, "peers.sqlite3");
    // Orphans from builds before the sibling-path refactor / LMDB switch
    // (`hercules-blocks`, `hercules-peers`, `hercules-utxo`). Previously this
    // function used `db_path.replace("headers", ...)`, which pointed at
    // those stale names and left the live block store and peer DB behind.
    let legacy_blocks = sync::derive_sibling_path(&db_path, "hercules-blocks.sqlite3");
    let legacy_peers = sync::derive_sibling_path(&db_path, "hercules-peers.sqlite3");
    let legacy_utxo = sync::derive_sibling_path(&db_path, "hercules-utxo.sqlite3");
    let storage_error = |msg: String| HerculesError::StorageError { msg };

    // Marker first: from here on, an interrupted reset is finished by the
    // next `UtxoSet::open`.
    let marker = utxo::loading_marker_path(std::path::Path::new(&utxo_dir));
    match std::fs::write(&marker, b"reset in progress\n") {
        Ok(()) => {}
        // No directory: nothing was ever stored here.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(storage_error(format!("failed to write {}: {}", marker.display(), e))),
    }

    // LMDB env: a directory of mmapped files. Recursive removal, before the
    // headers it was validated against.
    match std::fs::remove_dir_all(&utxo_dir) {
        Ok(_) => log::info!("reset_database: removed {}", utxo_dir),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(storage_error(format!("failed to remove {}: {}", utxo_dir, e))),
    }

    // SQLite files (headers / blocks / own txs / peers) — three sidecars each.
    for base in [
        &db_path,
        &blocks_path,
        &own_txs_path,
        &peers_path,
        &legacy_blocks,
        &legacy_peers,
        &legacy_utxo,
    ] {
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

    // The app's `migration-conflicts/` (ticket 030): copies parked by the
    // Documents -> Chain/ migration are dead weight once the node is reset.
    let conflicts_dir = sync::derive_sibling_path(&db_path, "migration-conflicts");
    match std::fs::remove_dir_all(&conflicts_dir) {
        Ok(_) => log::info!("reset_database: removed {}", conflicts_dir),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(storage_error(format!("failed to remove {}: {}", conflicts_dir, e))),
    }

    std::fs::remove_file(&marker)
        .map_err(|e| storage_error(format!("failed to remove {}: {}", marker.display(), e)))
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
    pub invalid_chain_detected: bool,
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
            invalid_chain_detected: s.invalid_chain_detected,
        }
    }
}

// ── Wake types (ticket 028) ───────────────────────────────────────

/// How a `wake_catch_up` call ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WakeOutcome {
    /// Catch-up ran; `status` says how far it got.
    Completed,
    /// The transport wasn't up with enough budget left for one block, so
    /// no network work was attempted.
    TransportSlow,
    /// Another session (snapshot load, a sync loop that didn't stop in
    /// time, another wake) held the node for the whole budget.
    Busy,
    /// The budget was cancelled. `status` has partial progress if
    /// catch-up had started.
    Cancelled,
    /// The budget ran out before headers were checked against any peer
    /// (e.g. slow connects). `status` reflects only the local tip.
    TimedOut,
    /// Catch-up or transport failed; see `error`.
    Failed,
}

/// Milliseconds since wake receipt (the `WakeBudget`'s creation) at which
/// each Rust-side phase was reached.
#[derive(Debug, Clone, Default)]
pub struct WakePhaseTimings {
    pub transport_ready_ms: Option<u64>,
    pub peers_ready_ms: Option<u64>,
    pub headers_checked_ms: Option<u64>,
    pub blocks_downloaded_ms: Option<u64>,
    pub validated_ms: Option<u64>,
}

impl From<wake::PhaseMarks> for WakePhaseTimings {
    fn from(m: wake::PhaseMarks) -> Self {
        WakePhaseTimings {
            transport_ready_ms: m.transport_ready_ms,
            peers_ready_ms: m.peers_ready_ms,
            headers_checked_ms: m.headers_checked_ms,
            blocks_downloaded_ms: m.blocks_downloaded_ms,
            validated_ms: m.validated_ms,
        }
    }
}

#[derive(Debug, Clone)]
pub struct WakeReport {
    pub outcome: WakeOutcome,
    pub status: Option<CatchUpStatus>,
    pub timings: WakePhaseTimings,
    /// A running sync loop was asked to stop so this wake could run. The
    /// app restarts foreground sync when it next becomes active.
    pub preempted_sync: bool,
    pub error: Option<String>,
    /// Milliseconds since wake receipt when the call returned.
    pub elapsed_ms: u64,
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

// ── Trust info ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct TrustInfo {
    pub snapshot_height: u32,
    pub validated_height: u32,
    pub forward_validated_blocks: u32,
    pub muhash: Option<String>,
}

impl From<sync::TrustInfo> for TrustInfo {
    fn from(t: sync::TrustInfo) -> Self {
        TrustInfo {
            snapshot_height: t.snapshot_height,
            validated_height: t.validated_height,
            forward_validated_blocks: t.forward_validated_blocks,
            muhash: t.muhash,
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
    #[error("Snapshot rejected: {msg}")]
    SnapshotInvalid { msg: String },
    /// Another `HerculesNode` for this database is still alive in this
    /// process (ticket 028), or this node was closed.
    #[error("Node open: {msg}")]
    NodeOpen { msg: String },
}

pub trait SyncCallback: Send + Sync {
    fn on_progress(&self, status: SyncStatus);
}

fn map_sync_error(e: sync::SyncError) -> HerculesError {
    match e {
        sync::SyncError::NoPeers => HerculesError::NetworkError {
            msg: "no peers found".into(),
        },
        sync::SyncError::Peer(s) => HerculesError::NetworkError { msg: s },
        sync::SyncError::Validation(s) => HerculesError::SyncFailed { msg: s },
        sync::SyncError::Store(s) => HerculesError::StorageError { msg: s },
        sync::SyncError::SnapshotInvalid(s) => HerculesError::SnapshotInvalid { msg: s },
    }
}

/// Removes a `start_header_sync` session from `sync_sessions` on return.
struct SyncRegistration<'a> {
    node: &'a HerculesNode,
    id: u64,
}

impl Drop for SyncRegistration<'_> {
    fn drop(&mut self) {
        lock(&self.node.sync_sessions).retain(|s| s.id != self.id);
    }
}

/// Clears `running_sync` when the sync loop returns.
struct RunningSync<'a>(&'a HerculesNode);

impl Drop for RunningSync<'_> {
    fn drop(&mut self) {
        *lock(&self.0.running_sync) = None;
    }
}

/// A wake that ended in an error: cancelled, out of time (e.g. no peer
/// connected before the deadline), or a real failure.
fn wake_error_outcome(budget: &WakeBudget) -> WakeOutcome {
    if budget.is_cancelled() {
        WakeOutcome::Cancelled
    } else if budget.remaining().is_zero() {
        WakeOutcome::TimedOut
    } else {
        WakeOutcome::Failed
    }
}

/// Removes a wake's budget from `HerculesNode::wakes` when it returns.
struct WakeRegistration<'a> {
    node: &'a HerculesNode,
    budget: &'a Arc<WakeBudget>,
}

impl Drop for WakeRegistration<'_> {
    fn drop(&mut self) {
        // One entry: two wakes may share a budget.
        let mut wakes = lock(&self.node.wakes);
        if let Some(i) = wakes.iter().position(|b| Arc::ptr_eq(b, self.budget)) {
            wakes.remove(i);
        }
    }
}

/// How long the blocking paths (the legacy constructor, foreground sync)
/// wait for Tor. Arti gives up on its own after 120 s.
const FOREGROUND_TRANSPORT_WAIT: Duration = Duration::from_secs(150);

/// Tor client that bootstraps in the background (ticket 028).
type TorGate = TransportGate<Arc<TorManager>>;

/// Sets a flag for as long as it lives (`snapshot_loading`).
struct FlagGuard<'a>(&'a AtomicBool);

impl<'a> FlagGuard<'a> {
    fn set(flag: &'a AtomicBool) -> Self {
        flag.store(true, Ordering::SeqCst);
        FlagGuard(flag)
    }
}

impl Drop for FlagGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

/// Poison-tolerant lock: a panic elsewhere must not turn into a panic in
/// Drop or across the FFI.
fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

/// Registry key for a path: the parent directory canonicalized (the file
/// itself may not exist yet), as the UTXO env registry does, so two
/// spellings of one database are one claim. Stable whether or not the
/// path itself exists yet.
fn claim_key(path: impl AsRef<std::path::Path>) -> PathBuf {
    let p = path.as_ref();
    match (p.parent(), p.file_name()) {
        (Some(parent), Some(name)) => {
            let parent = if parent.as_os_str().is_empty() {
                std::path::Path::new(".")
            } else {
                parent
            };
            parent
                .canonicalize()
                .map(|c| c.join(name))
                .unwrap_or_else(|_| p.to_path_buf())
        }
        _ => p.to_path_buf(),
    }
}

/// Database paths with a live `HerculesNode` in this process.
static OPEN_NODES: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

/// One node per database per process (ticket 028). Shared by the node and
/// anything that can outlive it holding its stores (the wallet RPC
/// thread), so it is released only once the stores have closed.
struct PathClaim(PathBuf);

impl PathClaim {
    fn take(db_path: &str) -> Result<PathClaim, HerculesError> {
        let key = claim_key(db_path);
        let mut open = lock(&OPEN_NODES);
        if open.contains(&key) {
            return Err(HerculesError::NodeOpen {
                msg: format!("a node is already open for {}", db_path),
            });
        }
        open.push(key.clone());
        Ok(PathClaim(key))
    }

    /// The registry, locked, provided nothing holds `db_path`: while the
    /// guard lives no node can open it.
    fn lock_unclaimed(db_path: &str) -> Result<MutexGuard<'static, Vec<PathBuf>>, HerculesError> {
        let open = lock(&OPEN_NODES);
        if open.contains(&claim_key(db_path)) {
            return Err(HerculesError::NodeOpen {
                msg: format!("a node is still open for {}", db_path),
            });
        }
        Ok(open)
    }
}

impl Drop for PathClaim {
    fn drop(&mut self) {
        lock(&OPEN_NODES).retain(|p| p != &self.0);
    }
}

/// Arti state directories with a live (or bootstrapping) Tor client.
static OPEN_TOR_DIRS: Mutex<Vec<PathBuf>> = Mutex::new(Vec::new());

/// One Tor client per state directory (ticket 028). A node reopened after
/// a reset must not start Arti on the directory while the old node's
/// bootstrap is still running: its bootstrap waits for this instead. Held
/// by the `TorManager` for its lifetime.
struct TorDirClaim(PathBuf);

impl TorDirClaim {
    /// Wait until `dir` is free, then claim it. None if `cancelled` first.
    fn wait_take(dir: &std::path::Path, cancelled: impl Fn() -> bool) -> Option<TorDirClaim> {
        // Not `dir.canonicalize()`: that fails until Arti creates the
        // directory, so the key would change spelling once it exists.
        let key = claim_key(dir);
        let mut logged = false;
        loop {
            {
                let mut open = lock(&OPEN_TOR_DIRS);
                if !open.contains(&key) {
                    open.push(key.clone());
                    return Some(TorDirClaim(key));
                }
            }
            if cancelled() {
                return None;
            }
            if !logged {
                log::info!("Tor: waiting for the previous client on {} to exit", key.display());
                logged = true;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }
}

impl Drop for TorDirClaim {
    fn drop(&mut self) {
        lock(&OPEN_TOR_DIRS).retain(|p| p != &self.0);
    }
}

/// One foreground sync session's stop flag (ticket 028). Every
/// `start_header_sync` call gets its own, so a stop aimed at one session
/// never stops the next.
#[derive(Clone)]
struct SyncSession {
    id: u64,
    stop: Arc<AtomicBool>,
}

/// Wait for a thread for up to `timeout`; detach it (false) if it is still
/// running then.
fn join_within(thread: JoinHandle<()>, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while !thread.is_finished() {
        if Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let _ = thread.join();
    true
}

/// State for a running wallet RPC server thread.
struct WalletRpcHandle {
    server: Arc<WalletRpcServer>,
    thread: Option<JoinHandle<()>>,
}

pub struct HerculesNode {
    syncer: Arc<sync::HeaderSync>,
    /// Tor, when configured. Bootstraps in the background from `open`;
    /// waits are bounded by the caller's budget (ticket 028).
    tor: Option<Arc<TorGate>>,
    /// Held by whichever operation is changing chain state: the foreground
    /// sync loop, a snapshot load, or a wake catch-up. Two of them must
    /// never apply blocks at once (ticket 028; also what makes 033's
    /// open-time demotion safe, since no block is mid-apply at open).
    session: Mutex<()>,
    /// Every `start_header_sync` call in progress (waiting or running), so
    /// `stop_sync` and `close` reach all of them.
    sync_sessions: Mutex<Vec<SyncSession>>,
    /// The one holding `session`, so a wake stops exactly that loop.
    running_sync: Mutex<Option<SyncSession>>,
    next_sync_id: AtomicU64,
    /// True while `load_snapshot` holds `session`. It can't be preempted,
    /// so a wake gives up at once rather than wait out its budget.
    snapshot_loading: AtomicBool,
    /// Set by `close`: every later session is refused. Shared with the Tor
    /// bootstrap thread.
    closed: Arc<AtomicBool>,
    /// Budgets of the wakes running now, so `close` can cancel them.
    wakes: Mutex<Vec<Arc<WakeBudget>>>,
    wallet_rpc: Mutex<Option<WalletRpcHandle>>,
    /// Persisted auth token for wallet API connections.
    wallet_auth_token: Mutex<Option<String>>,
    /// Path to the directory where we persist wallet API secrets.
    data_dir: String,
    /// Last field, so it is released after the stores above have closed.
    /// Shared with the wallet RPC thread, which holds the stores too.
    claim: Arc<PathClaim>,
}

impl Drop for HerculesNode {
    fn drop(&mut self) {
        // The wallet RPC thread holds the syncer. Ask it to stop, but don't
        // block here for long: if it lingers it keeps the path claim, so a
        // reset still waits for it.
        let running = lock(&self.wallet_rpc).is_some();
        if running {
            self.stop_wallet_api_within(Duration::from_millis(500));
        }
    }
}

impl HerculesNode {
    /// Create a new Hercules node.
    ///
    /// If `tor_data_dir` is provided, all network connections will be routed
    /// through Tor. This blocks during Tor bootstrap (~5-15 seconds). Wakes
    /// use `open`, which doesn't.
    pub fn new(db_path: String, tor_data_dir: Option<String>) -> Result<Self, HerculesError> {
        let node = HerculesNode::open(db_path, tor_data_dir)?;
        if !node.wait_for_transport(FOREGROUND_TRANSPORT_WAIT.as_millis() as u32)? {
            return Err(HerculesError::TorError {
                msg: "Tor bootstrap timed out".into(),
            });
        }
        Ok(node)
    }

    /// Open the node without waiting for the network (ticket 028): opens
    /// the stores and, if `tor_data_dir` is set, starts Tor bootstrapping
    /// on a background thread. Peer sessions wait for it (bounded by
    /// their budget) and never fall back to clearnet.
    pub fn open(db_path: String, tor_data_dir: Option<String>) -> Result<Self, HerculesError> {
        // Before any store opens: a second node on these files would share
        // the first one's LMDB env (heed returns it) and race it.
        let claim = Arc::new(PathClaim::take(&db_path)?);
        let mut syncer =
            sync::HeaderSync::new(&db_path, None).map_err(|e| HerculesError::StorageError {
                msg: format!("{}", e),
            })?;
        if tor_data_dir.is_some() {
            syncer.require_tor();
        }
        let syncer = Arc::new(syncer);

        let closed = Arc::new(AtomicBool::new(false));
        let tor = tor_data_dir.map(|dir| {
            let path = PathBuf::from(dir);
            // Weak: a bootstrap still running when the node is dropped
            // must not keep the stores open (reset_database needs them
            // closed).
            let weak_syncer = Arc::downgrade(&syncer);
            let weak_claim = Arc::downgrade(&claim);
            let closed = Arc::clone(&closed);
            let gate = Arc::new(TorGate::new(move || {
                let is_closed = || closed.load(Ordering::SeqCst);
                // Never two Arti clients on one state dir: wait out a
                // previous node's client (e.g. still bootstrapping when it
                // was reset).
                let dir_claim = TorDirClaim::wait_take(&path, is_closed)
                    .ok_or_else(|| "node closed".to_string())?;
                if is_closed() {
                    return Err("node closed".into());
                }
                let mut manager = TorManager::bootstrap(&path).map_err(|e| format!("{}", e))?;
                manager.hold(Box::new(dir_claim));
                if is_closed() {
                    // Closed while bootstrapping: no onion service for a
                    // dead node. Dropping the client frees the directory.
                    return Err("node closed".into());
                }

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

                let manager = Arc::new(manager);
                // Hold the path claim across the syncer use: if the node
                // drops meanwhile, the stores close with our syncer ref
                // before the path is released.
                if let Some(_claim) = weak_claim.upgrade() {
                    if let Some(syncer) = weak_syncer.upgrade() {
                        syncer.attach_tor(Arc::clone(&manager));
                    }
                }
                Ok(manager)
            }));
            gate.start();
            gate
        });

        // Derive data_dir from the db_path (parent directory of headers DB).
        let data_dir = std::path::Path::new(&db_path)
            .parent()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|| ".".to_string());

        Ok(HerculesNode {
            syncer,
            tor,
            session: Mutex::new(()),
            sync_sessions: Mutex::new(Vec::new()),
            running_sync: Mutex::new(None),
            next_sync_id: AtomicU64::new(1),
            snapshot_loading: AtomicBool::new(false),
            closed,
            wakes: Mutex::new(Vec::new()),
            wallet_rpc: Mutex::new(None),
            wallet_auth_token: Mutex::new(None),
            data_dir,
            claim,
        })
    }

    /// Shut the node down for good, e.g. before a reset (ticket 028).
    /// Stops the sync loop, cancels running wakes, ends transport waits,
    /// stops the wallet API, and refuses every later session. Waits up to
    /// `timeout_ms` for the running session to end; true if it did.
    ///
    /// The files stay open until the last reference to the node is
    /// dropped; `reset_database` refuses until then.
    pub fn close(&self, timeout_ms: u32) -> bool {
        let deadline = Instant::now() + Duration::from_millis(timeout_ms as u64);
        self.closed.store(true, Ordering::SeqCst);
        log::info!("HerculesNode: closing");
        for budget in lock(&self.wakes).iter() {
            budget.cancel();
        }
        if lock(&self.wallet_rpc).is_some() {
            self.stop_wallet_api_within(deadline.saturating_duration_since(Instant::now()));
        }
        loop {
            self.stop_sync();
            if self.try_lock_session().is_some() {
                return true;
            }
            if Instant::now() >= deadline {
                log::warn!("HerculesNode: session still busy after {} ms", timeout_ms);
                return false;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    fn closed_error() -> HerculesError {
        HerculesError::NodeOpen {
            msg: "node closed".into(),
        }
    }

    fn lock_session(&self) -> MutexGuard<'_, ()> {
        self.session.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn try_lock_session(&self) -> Option<MutexGuard<'_, ()>> {
        match self.session.try_lock() {
            Ok(g) => Some(g),
            Err(std::sync::TryLockError::Poisoned(e)) => Some(e.into_inner()),
            Err(std::sync::TryLockError::WouldBlock) => None,
        }
    }

    fn busy_error() -> HerculesError {
        HerculesError::SyncFailed {
            msg: "node busy: another sync session is running".into(),
        }
    }

    /// The Tor client, once bootstrapped.
    fn tor_manager(&self) -> Option<Arc<TorManager>> {
        self.tor.as_ref().and_then(|g| g.get())
    }

    /// Wait up to `timeout_ms` for the transport. True when it's up (always,
    /// for clearnet), false on timeout; a failed Tor bootstrap is an error
    /// (the next wait retries it).
    /// Returns early with `NodeOpen` if the node is closed meanwhile.
    pub fn wait_for_transport(&self, timeout_ms: u32) -> Result<bool, HerculesError> {
        if self.is_closed() {
            return Err(Self::closed_error());
        }
        let Some(ref gate) = self.tor else {
            return Ok(true);
        };
        let deadline = Instant::now() + Duration::from_millis(timeout_ms as u64);
        match gate.wait_until(deadline, Duration::ZERO, || self.is_closed()) {
            Ok(_) => Ok(true),
            Err(TransportWait::Slow) => Ok(false),
            Err(TransportWait::Cancelled) => Err(Self::closed_error()),
            Err(e) => Err(HerculesError::TorError {
                msg: transport_wait_message(&e),
            }),
        }
    }

    /// Catch up for a background wake (ticket 028). `budget` was created
    /// when the wake arrived, so node open and Tor bootstrap already count
    /// against it.
    ///
    /// - Waits for the node's session, asking a running sync loop to stop
    ///   (the app restarts foreground sync when it is next active).
    /// - Waits for the transport. If it isn't up with `min_block_ms` of
    ///   budget left, returns `TransportSlow` without touching the network.
    /// - Runs `catch_up_blocks` against the budget, stopping between steps
    ///   on cancel.
    ///
    /// Never throws: errors come back as `Failed` with the phase timings
    /// reached so far.
    pub fn wake_catch_up(
        &self,
        budget: Arc<WakeBudget>,
        max_blocks: u32,
        min_block_ms: u32,
    ) -> WakeReport {
        let floor = Duration::from_millis(min_block_ms as u64);
        // Registered so `close` can cancel it; a closed node cancels at once.
        self.wakes
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(Arc::clone(&budget));
        let _registered = WakeRegistration { node: self, budget: &budget };
        if self.is_closed() {
            budget.cancel();
        }
        let report = |outcome, status: Option<CatchUpStatus>, preempted_sync, error| WakeReport {
            outcome,
            status,
            timings: budget.marks().into(),
            preempted_sync,
            error,
            elapsed_ms: budget.elapsed_ms(),
        };
        let cancelled_or = |otherwise| {
            if budget.is_cancelled() {
                WakeOutcome::Cancelled
            } else {
                otherwise
            }
        };

        // Stop the sync loop holding the session when the wake first looked,
        // and only that one: a session started after it (by the user) is
        // not this wake's to stop.
        let mut preempted = false;
        let mut target: Option<u64> = None;
        let session = wake::acquire_within(
            &budget,
            floor,
            || self.try_lock_session(),
            || {
                if self.snapshot_loading.load(Ordering::SeqCst) {
                    // Can't be stopped, and outlasts any wake budget.
                    return false;
                }
                let running = lock(&self.running_sync).clone();
                if let Some(sync) = running {
                    if *target.get_or_insert(sync.id) == sync.id {
                        if !preempted {
                            log::info!("wake: stopping the running sync loop");
                        }
                        preempted = true;
                        sync.stop.store(true, Ordering::SeqCst);
                    }
                }
                true
            },
        );
        let Some(_session) = session else {
            log::info!("wake: node busy for the whole budget");
            return report(cancelled_or(WakeOutcome::Busy), None, preempted, None);
        };

        if let Some(ref gate) = self.tor {
            match gate.wait_within(&budget, floor) {
                Ok(_) => {}
                Err(TransportWait::Cancelled) => {
                    return report(WakeOutcome::Cancelled, None, preempted, None);
                }
                Err(TransportWait::Slow) => {
                    return report(
                        WakeOutcome::TransportSlow,
                        None,
                        preempted,
                        Some(format!(
                            "Tor not ready with {} ms left (need {} ms)",
                            budget.remaining_ms(),
                            min_block_ms
                        )),
                    );
                }
                Err(e @ TransportWait::Failed(_)) => {
                    return report(
                        WakeOutcome::Failed,
                        None,
                        preempted,
                        Some(transport_wait_message(&e)),
                    );
                }
            }
        }
        budget.mark(WakePhase::TransportReady);
        if budget.is_cancelled() {
            return report(WakeOutcome::Cancelled, None, preempted, None);
        }
        if budget.remaining() < floor {
            return report(
                WakeOutcome::TransportSlow,
                None,
                preempted,
                Some(format!("{} ms left (need {} ms)", budget.remaining_ms(), min_block_ms)),
            );
        }

        match self.syncer.catch_up_blocks_in(max_blocks, &budget) {
            // Out of budget before any peer answered for the headers: the
            // status only reflects the local tip, so it is no "Validated".
            Ok(status) if budget.marks().headers_checked_ms.is_none() && !status.tip_disagreement => report(
                cancelled_or(WakeOutcome::TimedOut),
                Some(status.into()),
                preempted,
                Some("budget spent before headers were checked".into()),
            ),
            Ok(status) => report(
                cancelled_or(WakeOutcome::Completed),
                Some(status.into()),
                preempted,
                None,
            ),
            Err(e) => report(
                wake_error_outcome(&budget),
                None,
                preempted,
                Some(format!("{}", map_sync_error(e))),
            ),
        }
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

    /// Run the foreground sync loop. Blocks until stopped (or a wake
    /// preempts it in the background). Waits for the transport first, then
    /// for any wake still holding the node.
    ///
    /// Each call is its own session with its own stop token: a `stop_sync`
    /// issued while it waits is honored, and a wake's stop of an earlier
    /// session can't reach it.
    pub fn start_header_sync(&self, callback: Box<dyn SyncCallback>) -> Result<(), HerculesError> {
        let sync = SyncSession {
            id: self.next_sync_id.fetch_add(1, Ordering::SeqCst),
            stop: Arc::new(AtomicBool::new(false)),
        };
        lock(&self.sync_sessions).push(sync.clone());
        let _registered = SyncRegistration { node: self, id: sync.id };

        if !self.wait_for_transport(FOREGROUND_TRANSPORT_WAIT.as_millis() as u32)? {
            return Err(HerculesError::TorError {
                msg: "Tor bootstrap timed out".into(),
            });
        }
        let _session = self.lock_session();
        if self.is_closed() {
            return Err(Self::closed_error());
        }
        if sync.stop.load(Ordering::SeqCst) {
            log::info!("Sync stopped before it started");
            return Ok(());
        }
        *lock(&self.running_sync) = Some(sync.clone());
        let _running = RunningSync(self);
        self.syncer
            .run_sync(&sync.stop, |status| {
                callback.on_progress(status.into());
            })
            .map_err(map_sync_error)
    }

    /// Check if the node needs a UTXO snapshot before it can validate blocks efficiently.
    pub fn needs_snapshot(&self) -> Result<bool, HerculesError> {
        self.syncer
            .needs_snapshot()
            .map_err(|e| HerculesError::StorageError {
                msg: format!("{}", e),
            })
    }

    /// Fail fast, before the AssumeUTXO download, if this device can't map
    /// the UTXO env large enough to hold the snapshot (ticket 030). Grows
    /// the map now when it can.
    pub fn check_snapshot_capacity(&self) -> Result<(), HerculesError> {
        self.syncer
            .ensure_snapshot_map_capacity()
            .map_err(|e| HerculesError::StorageError {
                msg: match e {
                    sync::SyncError::Store(s) => s,
                    e => format!("{}", e),
                },
            })
    }

    /// Load a UTXO snapshot from a file. The file is verified against the
    /// hardcoded AssumeUTXO anchor (header height and block hash, plus
    /// `ASSUMEUTXO_HASH` over the entries); mismatched files are rejected
    /// without modifying the database. Accepts either a raw `.hutx` file or a
    /// gzipped `.hutx.gz` (decompressed on the fly).
    ///
    /// Safe to call before header sync: block validation resumes from the
    /// snapshot height once the header chain contains the anchor block.
    ///
    /// `callback.on_progress` returning `false` cancels the load. A bad file
    /// (corrupt, truncated, wrong anchor or hash) fails with
    /// `SnapshotInvalid` and should be deleted; any other error (map or disk
    /// full, cancelled) leaves the file usable for a retry.
    pub fn load_snapshot(
        &self,
        snapshot_path: String,
        callback: Box<dyn SnapshotCallback>,
    ) -> Result<SnapshotInfo, HerculesError> {
        let _session = self.lock_session();
        if self.is_closed() {
            return Err(Self::closed_error());
        }
        let _loading = FlagGuard::set(&self.snapshot_loading);
        // `close` cancels the import like the callback returning false.
        let meta = self
            .syncer
            .load_snapshot(&snapshot_path, |loaded, total| {
                !self.is_closed() && callback.on_progress(loaded, total)
            })
            .map_err(|e| match e {
                sync::SyncError::SnapshotInvalid(msg) => HerculesError::SnapshotInvalid { msg },
                e => HerculesError::StorageError {
                    msg: format!("{}", e),
                },
            })?;

        Ok(SnapshotInfo {
            height: meta.height,
            utxo_count: meta.utxo_count,
            utxo_hash: hex::encode(meta.utxo_hash),
        })
    }

    /// Request the sync loop to stop cleanly. The blocking `start_header_sync`
    /// call will return on the next loop iteration. Stops every session in
    /// progress, including one still waiting to start.
    pub fn stop_sync(&self) {
        for sync in lock(&self.sync_sessions).iter() {
            sync.stop.store(true, Ordering::SeqCst);
        }
        log::info!("Sync stop requested");
    }

    /// Get the current Tor status. Returns None if Tor is not enabled.
    pub fn get_tor_status(&self) -> Option<TorStatus> {
        self.tor.as_ref().map(|gate| match gate.get() {
            Some(t) => t.status().into(),
            None => TorStatus {
                is_bootstrapped: false,
                bootstrap_progress: 0,
                onion_address: None,
            },
        })
    }

    /// One-shot block validation for push notification background wake.
    /// Connects to a peer, checks for new headers/blocks within the timeout.
    /// Fails with "node busy" instead of running beside another session.
    pub fn validate_latest_block(
        &self,
        timeout_secs: u32,
    ) -> Result<BlockNotification, HerculesError> {
        let budget = WakeBudget::new(timeout_secs.saturating_mul(1000));
        let _session = self.try_lock_session().ok_or_else(Self::busy_error)?;
        if self.is_closed() {
            return Err(Self::closed_error());
        }
        self.wait_transport_for(&budget)?;
        self.syncer
            .validate_latest_block_in(&budget)
            .map(|n| n.into())
            .map_err(map_sync_error)
    }

    /// Budgeted multi-block catch-up for push notification background wakes.
    /// Validates up to `max_blocks` blocks within `budget_secs`, returning
    /// partial progress if the budget is exhausted.
    /// Fails with "node busy" instead of running beside another session.
    /// Wakes use `wake_catch_up`, whose budget starts at wake receipt.
    pub fn catch_up_blocks(
        &self,
        max_blocks: u32,
        budget_secs: u32,
    ) -> Result<CatchUpStatus, HerculesError> {
        let budget = WakeBudget::new(budget_secs.saturating_mul(1000));
        let _session = self.try_lock_session().ok_or_else(Self::busy_error)?;
        if self.is_closed() {
            return Err(Self::closed_error());
        }
        self.wait_transport_for(&budget)?;
        self.syncer
            .catch_up_blocks_in(max_blocks, &budget)
            .map(|s| s.into())
            .map_err(map_sync_error)
    }

    /// Wait for the transport within `budget` (legacy budgeted calls).
    fn wait_transport_for(&self, budget: &WakeBudget) -> Result<(), HerculesError> {
        match self.tor {
            Some(ref gate) => gate
                .wait_within(budget, Duration::ZERO)
                .map(|_| ())
                .map_err(|e| HerculesError::TorError {
                    msg: transport_wait_message(&e),
                }),
            None => Ok(()),
        }
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

    /// Forget every block recorded as consensus-invalid and lift the peer
    /// bans recorded because of them (ticket 024), e.g. from a Settings
    /// action after an update or a suspected false rejection. Returns the
    /// number of bans lifted.
    pub fn reconsider_invalid_blocks(&self) -> Result<u32, HerculesError> {
        self.syncer
            .reconsider_invalid_blocks()
            .map_err(|e| HerculesError::StorageError {
                msg: format!("{}", e),
            })
    }

    pub fn get_trust_info(&self) -> Result<TrustInfo, HerculesError> {
        self.syncer
            .get_trust_info()
            .map(Into::into)
            .map_err(|e| HerculesError::StorageError {
                msg: format!("{}", e),
            })
    }

    // ── Wallet API ────────────────────────────────────────────────

    /// Start the wallet-facing JSON-RPC server on a dedicated Tor onion
    /// service. Returns the connection string: `<onion>:<port>/<auth_token>`.
    /// Calling this when the server is already running is a no-op that
    /// returns the existing connection string.
    pub fn start_wallet_api(&self) -> Result<String, HerculesError> {
        if self.is_closed() {
            return Err(Self::closed_error());
        }
        let tor = self.tor_manager().ok_or_else(|| HerculesError::TorError {
            msg: if self.tor.is_some() {
                "Tor is still bootstrapping — try again shortly".into()
            } else {
                "Tor is not enabled — wallet API requires Tor".into()
            },
        })?;

        // If already running, return existing connection string.
        {
            let guard = lock(&self.wallet_rpc);
            if guard.is_some() {
                drop(guard);
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
            Arc::clone(&tor),
            token.clone(),
        ));

        let server_clone = Arc::clone(&server);
        // The thread holds the stores (via the server), so it holds the
        // path claim too, until they are dropped.
        let claim = Arc::clone(&self.claim);
        let thread = std::thread::Builder::new()
            .name("wallet-rpc".into())
            .spawn(move || {
                server_clone.serve();
                drop(server_clone);
                drop(claim);
            })
            .map_err(|e| HerculesError::NetworkError {
                msg: format!("failed to spawn wallet RPC thread: {}", e),
            })?;

        *lock(&self.wallet_rpc) = Some(WalletRpcHandle {
            server,
            thread: Some(thread),
        });

        log::info!("Wallet API started at {}", onion_addr);

        // Connection string format: <addr_with_port>/<auth_token>
        // onion_addr already includes :18443 from start_wallet_onion_service.
        Ok(format!("{}/{}", onion_addr, token))
    }

    /// Stop the wallet API server and its onion service. Waits up to 5 s
    /// for the server thread.
    pub fn stop_wallet_api(&self) {
        self.stop_wallet_api_within(Duration::from_secs(5));
    }

    /// Stop the wallet API, waiting up to `timeout` for the server thread;
    /// after that it is detached (it exits at its next shutdown check).
    fn stop_wallet_api_within(&self, timeout: Duration) {
        let handle = lock(&self.wallet_rpc).take();
        if let Some(mut h) = handle {
            h.server.stop();
            if let Some(thread) = h.thread.take() {
                if !join_within(thread, timeout) {
                    log::warn!("Wallet API thread still running after {:?}; detached", timeout);
                }
            }
        }

        // Stop the wallet onion service.
        if let Some(tor) = self.tor_manager() {
            tor.stop_wallet_onion_service();
        }

        log::info!("Wallet API stopped");
    }

    /// Get the wallet API connection string, or None if not running.
    pub fn get_wallet_api_connection_string(&self) -> Result<String, HerculesError> {
        let guard = lock(&self.wallet_rpc);
        if guard.is_none() {
            return Err(HerculesError::NetworkError {
                msg: "wallet API is not running".into(),
            });
        }

        let tor = self.tor_manager().ok_or_else(|| HerculesError::TorError {
            msg: "Tor is not enabled".into(),
        })?;

        let onion_addr = tor.wallet_onion_address().ok_or_else(|| HerculesError::TorError {
            msg: "wallet onion service not available".into(),
        })?;

        let token = lock(&self.wallet_auth_token);
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
        let was_running = lock(&self.wallet_rpc).is_some();
        if was_running {
            self.stop_wallet_api();
            return self.start_wallet_api();
        }

        Ok(token)
    }

    // ── Own transactions (ticket 033) ─────────────────────────────

    /// Submit one of the user's own signed transactions (raw hex). It is
    /// validated (consensus + network standardness; local relay policy
    /// is only a warning), persisted, announced immediately and
    /// rebroadcast until it confirms. `AlreadyKnown` means it was already
    /// in the mempool; it is tracked and re-announced anyway.
    pub fn submit_own_tx(&self, raw_tx_hex: String) -> Result<OwnTxReceipt, BroadcastError> {
        let raw = hex::decode(raw_tx_hex.trim()).map_err(|e| BroadcastError::Invalid {
            msg: format!("bad hex: {}", e),
        })?;
        self.syncer
            .submit_own_tx(&raw)
            .map(|r| OwnTxReceipt {
                txid: r.txid.to_string(),
                warnings: r.warnings,
            })
            .map_err(Into::into)
    }

    /// Tracker status of an own transaction, or None if not tracked.
    pub fn own_tx_status(&self, txid: String) -> Result<Option<OwnTxInfo>, HerculesError> {
        let txid = txid.parse::<bitcoin::Txid>().map_err(|e| HerculesError::SyncFailed {
            msg: format!("bad txid: {}", e),
        })?;
        self.syncer
            .own_tx_status(&txid)
            .map(|o| o.map(Into::into))
            .map_err(|e| HerculesError::StorageError { msg: format!("{}", e) })
    }

    /// All tracked own transactions, newest first.
    pub fn list_own_txs(&self) -> Result<Vec<OwnTxInfo>, HerculesError> {
        self.syncer
            .list_own_txs()
            .map(|v| v.into_iter().map(Into::into).collect())
            .map_err(|e| HerculesError::StorageError { msg: format!("{}", e) })
    }
}

fn transport_wait_message(e: &TransportWait) -> String {
    match e {
        TransportWait::Slow => "Tor bootstrap still in progress".into(),
        TransportWait::Cancelled => "cancelled".into(),
        TransportWait::Failed(msg) => msg.clone(),
    }
}

/// Successful own-transaction submission.
#[derive(Debug, Clone)]
pub struct OwnTxReceipt {
    pub txid: String,
    pub warnings: Vec<String>,
}

/// Tracker state of an own transaction. `status` is one of pending,
/// propagated, confirmed, replaced, conflicted, expired. Times are unix
/// seconds.
#[derive(Debug, Clone)]
pub struct OwnTxInfo {
    pub txid: String,
    pub status: String,
    pub confirmed_height: Option<u32>,
    /// Replacing / conflicting txid for replaced / conflicted.
    pub related_txid: Option<String>,
    pub first_sent_at: u64,
    pub last_sent_at: u64,
    pub next_attempt_at: u64,
    pub attempts: u32,
    pub seen_from_peers: u32,
    pub updated_at: u64,
}

impl From<own_tx_store::OwnTxRecord> for OwnTxInfo {
    fn from(r: own_tx_store::OwnTxRecord) -> Self {
        use own_tx_store::OwnTxStatus;
        let (confirmed_height, related_txid) = match &r.status {
            OwnTxStatus::Confirmed { height } => (Some(*height), None),
            OwnTxStatus::Replaced { by } | OwnTxStatus::Conflicted { by } => {
                (None, Some(by.to_string()))
            }
            _ => (None, None),
        };
        OwnTxInfo {
            txid: r.txid.to_string(),
            status: r.status.name().to_string(),
            confirmed_height,
            related_txid,
            first_sent_at: r.first_sent_at,
            last_sent_at: r.last_sent_at,
            next_attempt_at: r.next_attempt_at,
            attempts: r.attempts,
            seen_from_peers: r.seen_from_peers,
            updated_at: r.updated_at,
        }
    }
}

/// Why an own transaction was refused (FFI mirror of
/// `own_tx_store::SubmitError`).
#[derive(Debug, thiserror::Error)]
pub enum BroadcastError {
    #[error("Invalid transaction: {msg}")]
    Invalid { msg: String },
    #[error("Consensus-invalid: {msg}")]
    Consensus { msg: String },
    #[error("Not valid yet: {msg}")]
    NotYetFinal { msg: String },
    #[error("Non-standard: {msg}")]
    NonStandard { msg: String },
    #[error("Fee too low: {msg}")]
    FeeTooLow { msg: String },
    #[error("Absurd fee: {msg}")]
    AbsurdFee { msg: String },
    #[error("Conflict: {msg}")]
    Conflict { msg: String },
    #[error("Already known: {txid}")]
    AlreadyKnown { txid: String },
    #[error("Not synced: {msg}")]
    NotSynced { msg: String },
    #[error("Internal error: {msg}")]
    Internal { msg: String },
}

impl From<own_tx_store::SubmitError> for BroadcastError {
    fn from(e: own_tx_store::SubmitError) -> Self {
        use own_tx_store::SubmitError as S;
        let msg = e.to_string();
        match e {
            S::Decode(_) => BroadcastError::Invalid { msg },
            S::Consensus(_) => BroadcastError::Consensus { msg },
            S::NotYetFinal { .. } => BroadcastError::NotYetFinal { msg },
            S::NonStandard(_) => BroadcastError::NonStandard { msg },
            S::FeeTooLow { .. } => BroadcastError::FeeTooLow { msg },
            S::AbsurdFee { .. } => BroadcastError::AbsurdFee { msg },
            S::Conflict { .. } => BroadcastError::Conflict { msg },
            S::AlreadyKnown { txid } => BroadcastError::AlreadyKnown {
                txid: txid.to_string(),
            },
            S::NotSynced { .. } => BroadcastError::NotSynced { msg },
            S::Internal(_) => BroadcastError::Internal { msg },
        }
    }
}

/// Callback for snapshot loading progress.
pub trait SnapshotCallback: Send + Sync {
    /// Return `false` to cancel the load.
    fn on_progress(&self, loaded: u64, total: u64) -> bool;
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
mod wake_tests;

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

    /// Ticket 050: a reset killed after writing its marker (here, before
    /// any unlink) is finished by the next open: the UTXO env is wiped, so
    /// the node needs a snapshot again rather than keeping a set whose
    /// headers may be gone.
    #[test]
    fn interrupted_reset_is_finished_by_the_next_open() {
        let dir = tempfile::TempDir::new().unwrap();
        let db = dir.path().join("hercules-headers.sqlite3").to_string_lossy().into_owned();
        {
            let _node = HerculesNode::new(db.clone(), None).unwrap();
        }
        let env = sync::derive_sibling_path(&db, "utxo-lmdb");
        {
            let utxo = utxo::UtxoSet::open(&env).unwrap();
            let coin = utxo::UtxoEntry { amount: 1, script_pubkey: vec![0x51], height: 1, is_coinbase: false };
            utxo.test_insert_utxo([1; 32], 0, coin).unwrap();
        }
        {
            let node = HerculesNode::new(db.clone(), None).unwrap();
            assert!(!node.needs_snapshot().unwrap(), "test set not in place");
        }
        std::fs::write(format!("{}.loading", env), b"reset in progress\n").unwrap();

        let node = HerculesNode::new(db, None).unwrap();
        assert!(node.needs_snapshot().unwrap(), "interrupted reset left the UTXO set");
        assert!(!std::path::Path::new(&format!("{}.loading", env)).exists());
    }

    #[test]
    fn reset_database_removes_live_sibling_stores() {
        let dir = tempfile::TempDir::new().unwrap();
        let db_path = dir.path().join("hercules-headers.sqlite3");
        let db = db_path.to_string_lossy().into_owned();
        {
            let _node = HerculesNode::new(db.clone(), None).unwrap();
        }
        // Stand-ins for the files HeaderSync opens plus pre-refactor orphans.
        for name in ["blocks.sqlite3", "peers.sqlite3-wal", "hercules-blocks.sqlite3", "hercules-utxo.sqlite3"] {
            std::fs::write(dir.path().join(name), b"x").unwrap();
        }
        // Parked migration copies (ticket 030) go too.
        std::fs::create_dir(dir.path().join("migration-conflicts")).unwrap();
        std::fs::write(dir.path().join("migration-conflicts/peers.sqlite3.1700000000"), b"p").unwrap();
        // A file reset must NOT touch (wallet API secret).
        std::fs::write(dir.path().join("wallet_auth_token"), b"t").unwrap();

        reset_database(db).unwrap();

        for name in [
            "hercules-headers.sqlite3",
            "blocks.sqlite3",
            "own_txs.sqlite3",
            "peers.sqlite3",
            "peers.sqlite3-wal",
            "hercules-blocks.sqlite3",
            "hercules-utxo.sqlite3",
            "utxo-lmdb",
            "utxo-lmdb.loading",
            "migration-conflicts",
        ] {
            assert!(!dir.path().join(name).exists(), "{} survived reset", name);
        }
        assert!(dir.path().join("wallet_auth_token").exists());
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

    // ══ FFI surface (tests/network-app) ══════════════════════════════
    //
    // Every exported function: error mapping, no panic on bad input, and
    // behavior on a closed node. Nodes here are mainnet `open` nodes in a
    // temp dir; nothing below reaches the network (sessions are refused
    // on a closed node, and bad inputs fail before any I/O).

    use crate::testkit::{lmdb_slot, LmdbSlot};
    use proptest::prelude::*;

    struct Ffi {
        node: HerculesNode,
        dir: tempfile::TempDir,
        _slot: LmdbSlot,
    }

    fn ffi_node() -> Ffi {
        let slot = lmdb_slot();
        let dir = tempfile::TempDir::new().unwrap();
        let db = dir.path().join("headers.sqlite3").to_string_lossy().into_owned();
        let node = HerculesNode::open(db, None).unwrap();
        Ffi { node, dir, _slot: slot }
    }

    impl Ffi {
        fn db(&self) -> String {
            self.dir.path().join("headers.sqlite3").to_string_lossy().into_owned()
        }
    }

    struct Quiet;
    impl SyncCallback for Quiet {
        fn on_progress(&self, _status: SyncStatus) {}
    }
    struct Accept(bool);
    impl SnapshotCallback for Accept {
        fn on_progress(&self, _loaded: u64, _total: u64) -> bool {
            self.0
        }
    }

    fn is_node_open(e: &HerculesError) -> bool {
        matches!(e, HerculesError::NodeOpen { .. })
    }

    #[test]
    fn closed_node_refuses_every_session_and_keeps_answering_getters() {
        let f = ffi_node();
        assert!(f.node.close(1_000), "idle node didn't close");
        // Sessions: refused at once, before any network or disk work.
        let start = Instant::now();
        assert!(is_node_open(&f.node.wait_for_transport(10_000).unwrap_err()));
        assert!(is_node_open(&f.node.start_header_sync(Box::new(Quiet)).unwrap_err()));
        assert!(is_node_open(&f.node.validate_latest_block(25).unwrap_err()));
        assert!(is_node_open(&f.node.catch_up_blocks(10, 25).unwrap_err()));
        assert!(is_node_open(&f.node.load_snapshot("/nonexistent".into(), Box::new(Accept(true))).unwrap_err()));
        assert!(is_node_open(&f.node.start_wallet_api().unwrap_err()));
        let report = f.node.wake_catch_up(Arc::new(WakeBudget::new(20_000)), 10, 1_000);
        assert!(matches!(report.outcome, WakeOutcome::Cancelled), "{:?}", report.outcome);
        assert!(report.status.is_none());
        assert!(start.elapsed() < Duration::from_secs(2), "closed-node calls took {:?}", start.elapsed());

        // Read-only getters and controls still answer (the UI polls them
        // while a reset is in progress).
        assert_eq!(f.node.get_status().unwrap().synced_headers, 0);
        assert!(f.node.needs_snapshot().unwrap());
        assert_eq!(f.node.get_trust_info().unwrap().validated_height, 0);
        assert_eq!(f.node.get_mempool_status().tx_count, 0);
        let _ = f.node.get_node_status();
        assert!(f.node.get_tor_status().is_none(), "clearnet node reports a Tor status");
        f.node.set_validation_paused(true);
        assert!(f.node.is_validation_paused());
        f.node.stop_sync();
        f.node.stop_wallet_api();
        assert!(f.node.list_own_txs().unwrap().is_empty());
        assert_eq!(f.node.reconsider_invalid_blocks().unwrap(), 0);
        // Closing twice is fine.
        assert!(f.node.close(0));
    }

    #[test]
    fn reset_waits_for_the_last_node_reference_then_starts_fresh() {
        let f = ffi_node();
        let db = f.db();
        // Live node: refused, files untouched.
        assert!(is_node_open(&reset_database(db.clone()).unwrap_err()));
        assert!(f.node.close(1_000));
        assert!(is_node_open(&reset_database(db.clone()).unwrap_err()), "reset while the stores are still open");
        let Ffi { node, dir, _slot } = f;
        drop(node);
        reset_database(db.clone()).unwrap();
        // Idempotent on an already-clean directory.
        reset_database(db.clone()).unwrap();
        let again = HerculesNode::open(db, None).unwrap();
        assert_eq!(again.get_status().unwrap().synced_headers, 0);
        drop(again);
        drop(dir);
    }

    #[test]
    fn one_node_per_database_whatever_the_path_spelling() {
        let f = ffi_node();
        let dir = f.dir.path();
        for spelling in [
            dir.join("headers.sqlite3"),
            dir.join(".").join("headers.sqlite3"),
            dir.join("sub").join("..").join("headers.sqlite3"),
        ] {
            std::fs::create_dir_all(dir.join("sub")).unwrap();
            match HerculesNode::open(spelling.to_string_lossy().into_owned(), None) {
                Err(e) => assert!(is_node_open(&e), "{:?}: {}", spelling, e),
                Ok(_) => panic!("second node opened on {:?}", spelling),
            }
        }
    }

    #[test]
    fn open_reports_storage_errors_for_unusable_paths() {
        let _slot = lmdb_slot();
        let dir = tempfile::TempDir::new().unwrap();
        // A regular file where the database's directory should be.
        let file = dir.path().join("not-a-dir");
        std::fs::write(&file, b"x").unwrap();
        for db in [file.join("headers.sqlite3"), dir.path().join("missing").join("deeper").join("h.sqlite3")] {
            match HerculesNode::open(db.to_string_lossy().into_owned(), None) {
                Err(HerculesError::StorageError { .. }) => {}
                Err(e) => panic!("{:?}: wrong error {}", db, e),
                Ok(_) => panic!("{:?}: opened", db),
            }
        }
        // A failed open releases its claim: the path can be used later.
        let good = dir.path().join("h.sqlite3").to_string_lossy().into_owned();
        drop(HerculesNode::open(good.clone(), None).unwrap());
        drop(HerculesNode::open(good, None).unwrap());
    }

    #[test]
    fn string_inputs_are_validated_before_any_work() {
        let f = ffi_node();
        assert!(matches!(f.node.own_tx_status("zz".into()), Err(HerculesError::SyncFailed { .. })));
        assert!(matches!(f.node.own_tx_status(String::new()), Err(HerculesError::SyncFailed { .. })));
        assert!(f.node.own_tx_status("ab".repeat(32)).unwrap().is_none());
        for bad in ["zz", "0", "", "00", "deadbeef", " 0100 "] {
            match f.node.submit_own_tx(bad.into()) {
                Err(BroadcastError::Invalid { .. }) => {}
                other => panic!("{:?}: {:?}", bad, other.map(|r| r.txid)),
            }
        }
        // A well-formed tx on an unsynced node: NotSynced, not a crash or
        // a network attempt.
        let tx = "02000000000101".to_string()
            + &"11".repeat(32)
            + "00000000"
            + "00"
            + "ffffffff"
            + "01"
            + "e803000000000000"
            + "160014"
            + &"22".repeat(20)
            + "0100"
            + "00000000";
        match f.node.submit_own_tx(tx) {
            Err(BroadcastError::NotSynced { .. }) | Err(BroadcastError::Invalid { .. }) => {}
            other => panic!("{:?}", other.map(|r| r.txid)),
        }
    }

    #[test]
    fn snapshot_load_failures_are_typed_and_leave_the_node_usable() {
        let f = ffi_node();
        let garbage = f.dir.path().join("garbage.hutx");
        std::fs::write(&garbage, vec![0x5a; 4096]).unwrap();
        match f.node.load_snapshot(garbage.to_string_lossy().into_owned(), Box::new(Accept(true))) {
            Err(HerculesError::SnapshotInvalid { .. }) => {}
            other => panic!("garbage snapshot: {:?}", other.map(|i| i.height)),
        }
        match f.node.load_snapshot(f.dir.path().join("missing.hutx").to_string_lossy().into_owned(), Box::new(Accept(true))) {
            Err(HerculesError::SnapshotInvalid { .. }) | Err(HerculesError::StorageError { .. }) => {}
            other => panic!("missing snapshot: {:?}", other.map(|i| i.height)),
        }
        // Still a fresh, usable node.
        assert!(f.node.needs_snapshot().unwrap());
        assert_eq!(f.node.get_status().unwrap().validated_blocks, 0);
        assert!(f.node.close(1_000));
    }

    #[test]
    fn wallet_api_without_tor_errors_cleanly_and_rotation_persists_a_private_token() {
        let f = ffi_node();
        match f.node.start_wallet_api() {
            Err(HerculesError::TorError { msg }) => assert!(msg.contains("not enabled"), "{}", msg),
            other => panic!("{:?}", other),
        }
        assert!(matches!(f.node.get_wallet_api_connection_string(), Err(HerculesError::NetworkError { .. })));
        f.node.stop_wallet_api();
        let t1 = f.node.rotate_wallet_auth_token().unwrap();
        let t2 = f.node.rotate_wallet_auth_token().unwrap();
        for t in [&t1, &t2] {
            assert_eq!(t.len(), 64);
            assert!(t.bytes().all(|b| b.is_ascii_hexdigit()));
        }
        assert_ne!(t1, t2, "rotation returned the same token");
        let path = f.dir.path().join("wallet_auth_token");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), t2);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "auth token readable by others: {:o}", mode);
        }
    }

    #[test]
    fn sync_errors_map_to_the_documented_ffi_errors() {
        use sync::SyncError as S;
        assert!(matches!(map_sync_error(S::NoPeers), HerculesError::NetworkError { .. }));
        assert!(matches!(map_sync_error(S::Peer("x".into())), HerculesError::NetworkError { msg } if msg == "x"));
        assert!(matches!(map_sync_error(S::Validation("x".into())), HerculesError::SyncFailed { .. }));
        assert!(matches!(map_sync_error(S::Store("x".into())), HerculesError::StorageError { .. }));
        assert!(matches!(map_sync_error(S::SnapshotInvalid("x".into())), HerculesError::SnapshotInvalid { .. }));
    }

    #[test]
    fn wake_error_outcome_distinguishes_cancel_timeout_and_failure() {
        let live = WakeBudget::new(60_000);
        assert!(matches!(wake_error_outcome(&live), WakeOutcome::Failed));
        let spent = WakeBudget::new(0);
        assert!(matches!(wake_error_outcome(&spent), WakeOutcome::TimedOut));
        spent.cancel();
        assert!(matches!(wake_error_outcome(&spent), WakeOutcome::Cancelled), "cancel outranks timeout");
    }

    #[test]
    fn dates_match_an_independent_calendar() {
        // Reference values from Python's datetime (proleptic Gregorian):
        // leap days in 1972 and 2000, 2100 not a leap year, u32 max.
        for (t, s) in [
            (68_169_600u32, "1972-02-29 00:00:00 UTC"),
            (946_684_799, "1999-12-31 23:59:59 UTC"),
            (951_782_400, "2000-02-29 00:00:00 UTC"),
            (1_231_006_505, "2009-01-03 18:15:05 UTC"),
            (4_107_542_400, "2100-03-01 00:00:00 UTC"),
            (u32::MAX, "2106-02-07 06:28:15 UTC"),
        ] {
            assert_eq!(chrono_format(t), s, "{}", t);
        }
    }

    #[test]
    fn parse_block_header_requires_exactly_80_bytes() {
        let genesis = GENESIS_HEX.to_string();
        assert!(parse_block_header(genesis.clone()).is_ok());
        assert!(parse_block_header(genesis.to_uppercase()).is_ok(), "hex case should not matter");
        for bad in [String::new(), genesis[..158].to_string(), genesis.clone() + "00", genesis[..159].to_string(), " ".to_string() + &genesis] {
            assert!(matches!(parse_block_header(bad.clone()), Err(HerculesError::SyncFailed { .. })), "{:?}", bad.len());
        }
    }

    proptest! {
        #[test]
        fn prop_parse_block_header_never_panics(s in ".{0,200}", bytes in prop::collection::vec(any::<u8>(), 0..120)) {
            let _ = parse_block_header(s);
            let r = parse_block_header(hex::encode(&bytes));
            prop_assert_eq!(r.is_ok(), bytes.len() == 80);
        }

        #[test]
        fn prop_chrono_format_is_well_formed(t in any::<u32>()) {
            let s = chrono_format(t);
            prop_assert_eq!(s.len(), "YYYY-MM-DD HH:MM:SS UTC".len());
            let month: u32 = s[5..7].parse().unwrap();
            let day: u32 = s[8..10].parse().unwrap();
            prop_assert!((1..=12).contains(&month) && (1..=31).contains(&day), "{}", s);
        }
    }

    #[test]
    fn prop_string_ffi_inputs_never_panic() {
        let f = ffi_node();
        let mut runner = proptest::test_runner::TestRunner::new(proptest::test_runner::Config {
            cases: std::env::var("PROPTEST_CASES").ok().and_then(|c| c.parse().ok()).unwrap_or(128),
            ..Default::default()
        });
        runner
            .run(&(".{0,100}", prop::collection::vec(any::<u8>(), 0..300)), |(s, bytes)| {
                let _ = f.node.own_tx_status(s.clone());
                let _ = f.node.submit_own_tx(s);
                let _ = f.node.submit_own_tx(hex::encode(&bytes));
                Ok(())
            })
            .unwrap();
        // Nothing was tracked by any of it (nothing synced to validate).
        assert!(f.node.list_own_txs().unwrap().is_empty());
    }
}
