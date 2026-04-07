use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bitcoin::block::Header;
use bitcoin::consensus::deserialize;
use bitcoin::hashes::Hash;
use bitcoin::BlockHash;

use log::{debug, info, warn};

use std::collections::{HashMap, HashSet};

use bitcoin::p2p::message::NetworkMessage;
use bitcoin::p2p::message_blockdata::{GetHeadersMessage, Inventory};
use bitcoin::Txid;

use crate::block_store::BlockStore;
use crate::block_validation::{validate_block, validate_block_scripts};
use crate::mempool::Mempool;
use crate::p2p::msg_name;
use crate::peer_pool::{PeerInfo, PeerPool};
use crate::store::HeaderStore;
use crate::tor::TorManager;
use crate::utxo::{SnapshotMeta, UtxoSet};
use crate::validation::{chainwork_for_headers, u256_gt, validate_headers};

/// How often to poll for new blocks after initial sync (seconds).
const MONITOR_INTERVAL: Duration = Duration::from_secs(30);

/// Maximum reorg depth we'll accept (bounded by undo data retention window).
const MAX_REORG_DEPTH: u32 = 288;

/// Penalty applied to a peer that produced a divergent header batch when
/// cross-checked against the majority. Two strikes ban it (2 * 50 = 100,
/// score drops to 0).
const HEADER_DIVERGENCE_PENALTY: u32 = 50;

/// Lighter penalty for a 2-peer disagreement we can't break with a third
/// opinion — both peers get this since we don't know who's lying.
const HEADER_DISAGREEMENT_PENALTY: u32 = 10;

/// Cap on how many addresses we'll process from a single addr / addrv2
/// message. Bitcoin Core's MAX_ADDR_TO_SEND is 1000; we accept the same
/// limit so a chatty peer can't fill the gossip queue with one message.
const MAX_GOSSIP_ADDRS_PER_MSG: usize = 1000;

/// Outcome of cross-checking a header batch against independent peers.
enum HeaderCrossCheck {
    /// Agreement reached (or only one peer available — best-effort accept).
    Accept,
    /// Active peer's headers were contradicted by majority — reject the batch.
    Reject,
}

/// Format a legacy v1 `Address` from `addr` gossip into the `host:port`
/// string our AddrManager keys on. Returns `None` for unroutable entries
/// (Tor addresses encoded in the legacy form, port 0, etc.).
fn format_v1_address(addr: &bitcoin::p2p::Address) -> Option<String> {
    if addr.port == 0 {
        return None;
    }
    // socket_addr() rejects Tor addresses (returns AddrNotAvailable),
    // which is exactly what we want — we can't reach a v2 onion via TCP.
    let sock = addr.socket_addr().ok()?;
    if !is_routable(&sock) {
        return None;
    }
    Some(sock.to_string())
}

/// Format a BIP 155 `AddrV2Message` into a `host:port` string. Only the
/// IPv4/IPv6 variants are emitted; Tor v3 / I2P / Cjdns are skipped.
fn format_v2_address(msg: &bitcoin::p2p::address::AddrV2Message) -> Option<String> {
    if msg.port == 0 {
        return None;
    }
    let sock = msg.socket_addr().ok()?;
    if !is_routable(&sock) {
        return None;
    }
    Some(sock.to_string())
}

/// Reject obvious junk before we put an address into the AddrManager:
/// loopback, link-local, multicast, unspecified. We deliberately do NOT
/// filter RFC1918 here — a node operator with a self-hosted peer on the
/// LAN should still be able to talk to it.
fn is_routable(sock: &std::net::SocketAddr) -> bool {
    let ip = sock.ip();
    if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() {
        return false;
    }
    match ip {
        std::net::IpAddr::V4(v4) => !v4.is_link_local() && !v4.is_broadcast(),
        std::net::IpAddr::V6(_) => true,
    }
}

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

/// Result of a one-shot block validation (for push notification background wake).
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

impl BlockNotification {
    /// Create a "no update" notification when we're already at the tip.
    fn no_update(height: u32, header: &Header) -> Self {
        BlockNotification {
            height,
            block_hash: header.block_hash().to_string(),
            prev_block_hash: header.prev_blockhash.to_string(),
            timestamp: header.time,
            timestamp_human: crate::chrono_format(header.time),
            validated: false,
            header_validated: false,
            validation_error: None,
        }
    }
}

/// Sync block headers and validate full blocks from the Bitcoin P2P network.
/// Per-peer relay state tracking.
struct PeerRelayState {
    wants_sendheaders: bool,
    feefilter_rate: u64, // sat/kvB from BIP 133
    known_txids: HashSet<Txid>,
}

/// Pending transaction relay with Poisson delay.
struct RelayQueueEntry {
    txid: Txid,
    relay_at: Instant,
    from_peer: String, // don't relay back to sender
}

/// Counters for node serving activity.
pub struct NodeStats {
    pub blocks_served: u64,
    pub headers_served: u64,
    pub txs_relayed: u64,
}

pub struct HeaderSync {
    store: HeaderStore,
    utxo: UtxoSet,
    block_store: BlockStore,
    /// SQLite path for the persistent peer reputation/ban store. Threaded
    /// through to `PeerPool::new` on each sync session so scores survive a
    /// process restart. `None` for in-memory test sessions.
    peers_db_path: Option<String>,
    mempool: Mutex<Mempool>,
    validation_paused: Arc<AtomicBool>,
    shutdown_requested: Arc<AtomicBool>,
    tor: Option<Arc<TorManager>>,
    /// Per-peer relay metadata (keyed by peer address).
    relay_state: Mutex<HashMap<String, PeerRelayState>>,
    /// Queue of transactions waiting to be relayed with Poisson delay.
    relay_queue: Mutex<Vec<RelayQueueEntry>>,
    /// Addresses queued by `handle_peer_message` from inbound `addr` /
    /// `addrv2` gossip. Drained into the PeerPool's AddrManager after
    /// `service_peer_messages` returns, since the message handlers run
    /// inside `for_each_peer` (which already holds the slot Mutex) and
    /// can't safely take a `&mut PeerPool`.
    pending_gossip_addrs: Mutex<Vec<String>>,
    /// Cumulative serving counters.
    pub stats: Mutex<NodeStats>,
    /// Last-known peer counts (updated from monitor loop for UI access).
    inbound_peer_count: AtomicU32,
    outbound_peer_count: AtomicU32,
    /// Set by handle_inv when a new block is announced — breaks the monitor
    /// loop early so we fetch the new block immediately instead of waiting.
    new_block_announced: AtomicBool,
}

impl HeaderSync {
    pub fn new(db_path: &str, tor: Option<Arc<TorManager>>) -> Result<HeaderSync, SyncError> {
        let store =
            HeaderStore::open(db_path).map_err(|e| SyncError::Store(format!("{}", e)))?;

        // Derive UTXO database path from header database path. The UTXO set
        // is now LMDB (a directory of mmapped files), not SQLite, so the path
        // is a directory name sitting next to the headers SQLite file.
        let utxo_path = derive_sibling_path(db_path, "utxo-lmdb");
        let utxo =
            UtxoSet::open(&utxo_path).map_err(|e| SyncError::Store(format!("{}", e)))?;

        // Derive block store path for NODE_NETWORK_LIMITED serving
        let blocks_path = if db_path == ":memory:" {
            ":memory:".to_string()
        } else {
            db_path.replace("headers", "blocks")
        };
        let block_store =
            BlockStore::open(&blocks_path).map_err(|e| SyncError::Store(format!("{}", e)))?;

        // Derive peers DB path for persistent reputation scores and bans.
        // Skip persistence in :memory: mode (used by tests).
        let peers_db_path = if db_path == ":memory:" {
            None
        } else {
            Some(db_path.replace("headers", "peers"))
        };

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

        if tor.is_some() {
            info!("HeaderSync: Tor enabled — all connections routed through Tor");
        }

        Ok(HeaderSync {
            store,
            utxo,
            block_store,
            peers_db_path,
            mempool: Mutex::new(Mempool::new()),
            validation_paused: Arc::new(AtomicBool::new(false)),
            shutdown_requested: Arc::new(AtomicBool::new(false)),
            tor,
            relay_state: Mutex::new(HashMap::new()),
            relay_queue: Mutex::new(Vec::new()),
            pending_gossip_addrs: Mutex::new(Vec::new()),
            stats: Mutex::new(NodeStats {
                blocks_served: 0,
                headers_served: 0,
                txs_relayed: 0,
            }),
            inbound_peer_count: AtomicU32::new(0),
            outbound_peer_count: AtomicU32::new(0),
            new_block_announced: AtomicBool::new(false),
        })
    }

    /// Load a UTXO snapshot from a file path. Sets validated_height to the
    /// snapshot height so sync resumes from there.
    ///
    /// Accepts either a raw `.hutx` file or a `.hutx.gz` gzipped file.
    /// The `.gz` form is decompressed on the fly so we never need to write
    /// the (much larger) decompressed file to disk on mobile.
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

        let meta = if snapshot_path.ends_with(".gz") {
            let decoder = flate2::read::GzDecoder::new(file);
            self.utxo
                .load_snapshot(decoder, expected_hash, on_progress)
                .map_err(|e| SyncError::Store(format!("{}", e)))?
        } else {
            self.utxo
                .load_snapshot(file, expected_hash, on_progress)
                .map_err(|e| SyncError::Store(format!("{}", e)))?
        };

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

    /// Get mempool status for the UI.
    pub fn get_mempool_status(&self) -> crate::MempoolStatus {
        let pool = self.mempool.lock().unwrap();
        crate::MempoolStatus {
            tx_count: pool.count() as u32,
            total_size: pool.size() as u64,
            max_size: 50_000_000, // DEFAULT_MAX_SIZE
        }
    }

    /// Get node serving/relay statistics for the UI.
    pub fn get_node_status(&self) -> crate::NodeStatus {
        let stats = self.stats.lock().unwrap();
        crate::NodeStatus {
            inbound_peers: self.inbound_peer_count.load(Ordering::Relaxed),
            outbound_peers: self.outbound_peer_count.load(Ordering::Relaxed),
            blocks_served: stats.blocks_served,
            txs_relayed: stats.txs_relayed,
        }
    }

    /// Update cached peer counts from the pool (called from monitor loop).
    fn update_peer_counts(&self, pool: &PeerPool) {
        self.inbound_peer_count
            .store(pool.inbound_count() as u32, Ordering::Relaxed);
        self.outbound_peer_count
            .store(pool.outbound_count() as u32, Ordering::Relaxed);
    }

    /// Request the sync loop to stop. The loop will exit cleanly on its
    /// next iteration, returning Ok(()) from `sync()`.
    pub fn stop_sync(&self) {
        self.shutdown_requested.store(true, Ordering::Relaxed);
        info!("Sync stop requested");
    }

    /// Cross-check a freshly fetched header batch against one or two
    /// independent peers before storing it. This is the core eclipse-attack
    /// defense: even if our active peer is fully attacker-controlled, an
    /// honest second peer responding to the same locator will return a
    /// different first header hash, and we can detect the lie.
    ///
    /// Strategy:
    /// 1. Pick a single independent peer (different addr, not banned). Send
    ///    the same `getheaders` locator. Compare the first hash.
    /// 2. If they agree → accept. Both peers earn a small reward.
    /// 3. If they disagree → query a third peer to break the tie.
    ///    - If 2-of-3 agree, the divergent peer takes
    ///      `HEADER_DIVERGENCE_PENALTY`. Accept iff active peer is in the
    ///      majority; reject otherwise.
    ///    - If we have no third peer, we can't tell who is lying. Apply a
    ///      lighter `HEADER_DISAGREEMENT_PENALTY` to both and reject the
    ///      batch — refusing to commit dubious headers is the safer default.
    /// 4. If only one peer in the pool → best-effort accept (we logged a
    ///    warning at sync start; this is a degraded mode).
    fn cross_check_headers(
        &self,
        pool: &mut PeerPool,
        locator: &[BlockHash],
        active_addr: &str,
        active_first_hash: BlockHash,
    ) -> HeaderCrossCheck {
        // Step 1: pick an independent witness peer.
        let witness_addr = match pool.peer_addr_other_than(active_addr) {
            Some(a) => a,
            None => {
                debug!(
                    "cross-check skipped: only active peer {} available",
                    active_addr
                );
                return HeaderCrossCheck::Accept;
            }
        };

        let witness_first = match self.fetch_first_header_hash(pool, &witness_addr, locator) {
            Some(h) => h,
            None => {
                // Witness peer failed to respond — we can't conclude anything.
                // Don't penalize the active peer over a network failure.
                debug!(
                    "cross-check witness {} failed; accepting active peer's headers",
                    witness_addr
                );
                return HeaderCrossCheck::Accept;
            }
        };

        if witness_first == active_first_hash {
            // Two independent peers agree on the first header — accept.
            pool.reward(active_addr, 1);
            pool.reward(&witness_addr, 1);
            return HeaderCrossCheck::Accept;
        }

        warn!(
            "Header divergence: active {} returned {}, witness {} returned {} — escalating",
            active_addr, active_first_hash, witness_addr, witness_first
        );

        // Step 3: try to break the tie with a third peer.
        let exclude = [active_addr.to_string(), witness_addr.clone()];
        let tiebreaker_addr = pool.peer_addr_excluding(&exclude);

        if let Some(tb_addr) = tiebreaker_addr {
            if let Some(tb_first) = self.fetch_first_header_hash(pool, &tb_addr, locator) {
                if tb_first == active_first_hash {
                    // Active + tiebreaker agree → witness is the liar.
                    warn!(
                        "Header cross-check: penalizing divergent witness {}",
                        witness_addr
                    );
                    pool.misbehaving(&witness_addr, HEADER_DIVERGENCE_PENALTY);
                    return HeaderCrossCheck::Accept;
                } else if tb_first == witness_first {
                    // Witness + tiebreaker agree → active is the liar.
                    warn!(
                        "Header cross-check: penalizing divergent active peer {}",
                        active_addr
                    );
                    pool.misbehaving(active_addr, HEADER_DIVERGENCE_PENALTY);
                    return HeaderCrossCheck::Reject;
                } else {
                    // All three peers disagree — pathological case. Penalize
                    // active (it's our default trust target) and reject.
                    warn!(
                        "Header cross-check: 3-way disagreement, rejecting batch from {}",
                        active_addr
                    );
                    pool.misbehaving(active_addr, HEADER_DISAGREEMENT_PENALTY);
                    return HeaderCrossCheck::Reject;
                }
            }
        }

        // Step 4: only two peers in the pool and they disagree.
        warn!(
            "Header cross-check: 2-peer disagreement with no tiebreaker available; rejecting batch"
        );
        pool.misbehaving(active_addr, HEADER_DISAGREEMENT_PENALTY);
        pool.misbehaving(&witness_addr, HEADER_DISAGREEMENT_PENALTY);
        HeaderCrossCheck::Reject
    }

    /// Send a `getheaders` to a specific peer and return the first header
    /// hash from its response, or `None` on any failure (network, empty
    /// response, peer no longer in pool). This wraps the peer checkout/return
    /// dance so the cross-check helper stays readable.
    fn fetch_first_header_hash(
        &self,
        pool: &mut PeerPool,
        addr: &str,
        locator: &[BlockHash],
    ) -> Option<BlockHash> {
        let mut peer = pool.checkout_peer_by_addr(addr)?;
        let result = peer.get_headers(locator.to_vec(), BlockHash::all_zeros());
        match result {
            Ok(headers) => {
                pool.return_peer(peer);
                headers.first().map(|h| h.block_hash())
            }
            Err(e) => {
                warn!("cross-check: peer {} failed to respond: {}", addr, e);
                pool.remove_peer(addr);
                None
            }
        }
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
        // Reset shutdown flag so sync can be restarted after a stop
        self.shutdown_requested.store(false, Ordering::Relaxed);

        // Get our current height to report to peers
        let our_height = self
            .store
            .count()
            .map_err(|e| SyncError::Store(format!("{}", e)))?
            .saturating_sub(1);

        // Create the peer pool
        let mut pool = PeerPool::new(
            our_height,
            self.tor.clone(),
            self.peers_db_path.as_deref(),
        )
        .map_err(|e| {
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
            // Check for shutdown request
            if self.shutdown_requested.load(Ordering::Relaxed) {
                info!("Sync shutting down cleanly");
                return Ok(());
            }

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

            // Build block locator (tip + exponentially spaced hashes)
            let locator = self
                .store
                .get_locator_hashes()
                .map_err(|e| SyncError::Store(format!("{}", e)))?;

            // Request headers from best peer
            let headers = match peer.get_headers(locator, BlockHash::all_zeros()) {
                Ok(h) => {
                    pool.return_peer(peer);
                    // Reward peers that successfully serve us headers — even an
                    // empty response counts (it means we're caught up to them).
                    pool.reward(&active_addr, 1);
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
                // Peer height sanity: if a peer claims height far above our tip
                // but can't serve any headers beyond it, they're lying. Ban them.
                if let Some(claimed) = pool.get_peer_height(&active_addr) {
                    if claimed > tip_height + 2016 {
                        warn!(
                            "Peer {} claims height {} but has no headers above {}, banning",
                            active_addr, claimed, tip_height
                        );
                        pool.misbehaving(&active_addr, 100);
                        pool.maintain();
                        continue;
                    }
                }

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
                            // Successfully served a full block — bigger reward
                            // than headers since blocks are a meatier task.
                            pool.reward(&block_peer_addr, 2);
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

                    // Store block for NODE_NETWORK_LIMITED serving (last 288 blocks)
                    self.block_store
                        .store_block(&block, next_height)
                        .map_err(|e| SyncError::Store(format!("{}", e)))?;

                    // Remove confirmed transactions from mempool
                    self.mempool.lock().unwrap().remove_confirmed(&block);

                    self.store
                        .set_validated_height(next_height)
                        .map_err(|e| SyncError::Store(format!("{}", e)))?;

                    // Relay new tip block to peers (skip during IBD catchup)
                    if next_height == tip_height {
                        let inv = vec![Inventory::Block(block_hash)];
                        pool.for_each_peer(|_addr, _, peer| {
                            peer.send_inv(inv.clone())
                                .map_err(|e| format!("block relay: {}", e))
                        });
                    }

                    // Prune old data for deeply-buried blocks (keep 288 for reorgs)
                    if next_height % 1000 == 0 && next_height > 288 {
                        self.utxo
                            .prune_undo_below(next_height - 288)
                            .map_err(|e| SyncError::Store(format!("{}", e)))?;
                        self.block_store
                            .prune_below(next_height - 288)
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

                // Fully synced and validated — active monitor mode
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

                pool.update_our_height(tip_height);

                // Active message-processing loop (replaces passive 30s sleep).
                // Polls each peer for messages, handles serving requests,
                // and periodically checks for new blocks.
                let monitor_start = Instant::now();
                let mut last_maintain = Instant::now();
                let mut last_status = Instant::now();

                // Reset the flag before entering the loop
                self.new_block_announced.store(false, Ordering::Relaxed);

                while monitor_start.elapsed() < MONITOR_INTERVAL {
                    if self.shutdown_requested.load(Ordering::Relaxed) {
                        break;
                    }

                    // Process one message from each connected peer (round-robin)
                    self.service_peer_messages(&mut pool);

                    // Drain any addresses that the message handlers queued
                    // from `addr` / `addrv2` gossip into the PeerPool's
                    // AddrManager. This needs to happen outside the
                    // for_each_peer call because that path holds the slot
                    // mutex and can't take a `&mut PeerPool`.
                    let gossip = std::mem::take(
                        &mut *self.pending_gossip_addrs.lock().unwrap(),
                    );
                    if !gossip.is_empty() {
                        pool.ingest_gossip_addrs(gossip);
                    }

                    // Opportunistic refill: if the outbound pool has shrunk
                    // (peers dropped, banned, or removed by service_peer_messages
                    // for protocol errors), top it back up immediately rather
                    // than waiting for the next 30s `last_maintain` tick. This
                    // is the fix for "connected peers drop below 8 and don't
                    // recover" — by the time we noticed the drop on the
                    // periodic timer, anywhere from 0–30s of sync was wasted.
                    if pool.outbound_count() < pool.outbound_target() {
                        pool.maintain();
                    }

                    // Avoid busy-spinning when no peers are connected
                    if pool.count() == 0 {
                        std::thread::sleep(Duration::from_millis(100));
                    }

                    // If a peer announced a new block, break immediately to fetch it
                    if self.new_block_announced.swap(false, Ordering::Relaxed) {
                        info!("Breaking monitor loop early — new block announced");
                        break;
                    }

                    // Drain the relay queue (send pending tx inv messages)
                    self.drain_relay_queue(&pool);

                    // Accept pending inbound connections from Tor onion service
                    if let Some(ref tor) = self.tor {
                        while let Some(inbound_stream) = tor.accept_inbound() {
                            let peer_stream = crate::p2p::PeerStream::Tor(inbound_stream);
                            match crate::p2p::Peer::accept(peer_stream, tip_height as i32) {
                                Ok(peer) => {
                                    if !pool.add_inbound_peer(peer) {
                                        info!("Inbound peer rejected: at capacity");
                                    }
                                }
                                Err(e) => {
                                    warn!("Inbound handshake failed: {}", e);
                                }
                            }
                        }
                    }

                    // Periodic maintenance
                    if last_maintain.elapsed() >= Duration::from_secs(30) {
                        pool.maintain();
                        self.mempool.lock().unwrap().expire_old();
                        self.update_peer_counts(&pool);
                        // Clean up relay_state: remove entries for disconnected peers
                        // and cap per-peer known_txids to prevent unbounded growth
                        {
                            let connected: HashSet<String> = pool.peer_info()
                                .iter()
                                .map(|p| p.addr.clone())
                                .collect();
                            let mut state = self.relay_state.lock().unwrap();
                            state.retain(|addr, _| connected.contains(addr));
                            for rs in state.values_mut() {
                                if rs.known_txids.len() > 10_000 {
                                    rs.known_txids.clear();
                                }
                            }
                        }
                        last_maintain = Instant::now();
                    }

                    // Periodic status report
                    if last_status.elapsed() >= Duration::from_secs(10) {
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
                        last_status = Instant::now();
                    }
                }

                continue;
            }

            // We have new headers — validate and store them
            // Bitcoin P2P protocol allows max 2000 headers per message.
            // This check must come BEFORE fork detection to prevent
            // oversized batches from entering the reorg path.
            if headers.len() > 2000 {
                warn!(
                    "Peer sent {} headers (max 2000), disconnecting",
                    headers.len()
                );
                pool.misbehaving(&active_addr, 100);
                pool.maintain();
                continue;
            }

            // ── Eclipse-resistance: cross-check headers against an
            // independent peer before storing them. We re-fetch the locator
            // from the store rather than reusing the earlier `locator` since
            // borrow-checker constraints make threading it through cleaner.
            let cross_check_locator = self
                .store
                .get_locator_hashes()
                .map_err(|e| SyncError::Store(format!("{}", e)))?;
            let active_first_hash = headers[0].block_hash();
            match self.cross_check_headers(
                &mut pool,
                &cross_check_locator,
                &active_addr,
                active_first_hash,
            ) {
                HeaderCrossCheck::Accept => {}
                HeaderCrossCheck::Reject => {
                    // The cross-check helper has already applied the
                    // appropriate misbehavior penalty. Drop the batch and
                    // try again on the next iteration.
                    pool.maintain();
                    continue;
                }
            }

            // Epoch lookup for header validation (used in both fork and normal paths)
            let store = &self.store;
            let epoch_lookup = |height: u32| -> Result<u32, String> {
                store
                    .get_timestamp_at(height)
                    .map_err(|e| format!("{}", e))?
                    .ok_or_else(|| format!("no header at height {}", height))
            };

            // ── Fork detection ──────────────────────────────────────
            // If the first header's prev_hash doesn't match our tip,
            // the peer's chain diverges from ours.
            if headers[0].prev_blockhash != tip_hash {
                let first_prev = headers[0].prev_blockhash;

                let fork_base = self
                    .store
                    .find_height_of_hash(first_prev)
                    .map_err(|e| SyncError::Store(format!("{}", e)))?;

                match fork_base {
                    None => {
                        // Headers don't connect to any known block
                        warn!("Peer {} sent unconnectable headers", active_addr);
                        pool.misbehaving(&active_addr, 20);
                        continue;
                    }
                    Some(base_height) => {
                        // Walk forward to find the exact divergence point
                        let mut fork_at = base_height;
                        for i in 0..headers.len() {
                            let h = base_height + 1 + i as u32;
                            if h > tip_height {
                                break;
                            }
                            match self
                                .store
                                .get_hash_at_height(h)
                                .map_err(|e| SyncError::Store(format!("{}", e)))?
                            {
                                Some(our_hash)
                                    if our_hash == headers[i].block_hash() =>
                                {
                                    fork_at = h;
                                }
                                _ => break,
                            }
                        }

                        let reorg_depth = tip_height - fork_at;

                        if reorg_depth == 0 {
                            // Headers match our chain — peer responded from a lower
                            // locator point. This shouldn't happen normally; just retry.
                            warn!(
                                "Locator matched at {} but no fork (depth 0), skipping",
                                base_height
                            );
                            continue;
                        }

                        if reorg_depth > MAX_REORG_DEPTH {
                            warn!(
                                "Peer {} suggests reorg depth {} (max {}), ignoring",
                                active_addr, reorg_depth, MAX_REORG_DEPTH
                            );
                            pool.misbehaving(&active_addr, 20);
                            continue;
                        }

                        // Compare chainwork: our chain vs the fork
                        let our_headers = self
                            .store
                            .get_headers_in_range(fork_at + 1, tip_height)
                            .map_err(|e| SyncError::Store(format!("{}", e)))?;
                        let our_work = chainwork_for_headers(&our_headers);

                        let new_chain_offset = (fork_at - base_height) as usize;
                        let new_work =
                            chainwork_for_headers(&headers[new_chain_offset..]);

                        if !u256_gt(&new_work, &our_work) {
                            info!(
                                "Fork at height {} has equal or less work, ignoring",
                                fork_at
                            );
                            continue;
                        }

                        // ── Execute reorg ────────────────────────────
                        info!(
                            "Reorg detected: depth {}, rolling back from {} to {}",
                            reorg_depth, tip_height, fork_at
                        );

                        // Step 1: Gather fork-point context BEFORE any
                        // destructive operations (validate-before-destroy).
                        let (fork_hash, fork_header) = self
                            .store
                            .get_header_at_height(fork_at)
                            .map_err(|e| SyncError::Store(format!("{}", e)))?
                            .ok_or_else(|| {
                                SyncError::Store(format!(
                                    "no header at fork height {}",
                                    fork_at
                                ))
                            })?;
                        let fork_timestamps = self
                            .store
                            .timestamps_up_to(fork_at, 11)
                            .map_err(|e| SyncError::Store(format!("{}", e)))?;

                        // Step 2: Validate new chain headers against the
                        // fork point. If this fails, our existing chain is
                        // untouched — just penalize the peer.
                        let new_headers = &headers[new_chain_offset..];
                        if let Err(e) = validate_headers(
                            new_headers,
                            fork_hash,
                            fork_at,
                            &fork_timestamps,
                            fork_header.bits,
                            &epoch_lookup,
                        ) {
                            warn!(
                                "Reorg rejected: new chain failed validation: {}",
                                e
                            );
                            pool.misbehaving(&active_addr, 50);
                            continue;
                        }

                        // Step 3: Validation passed — now perform the
                        // destructive rollback.
                        let current_validated = self
                            .store
                            .validated_height()
                            .map_err(|e| SyncError::Store(format!("{}", e)))?;

                        // Roll back UTXO set for validated blocks above fork point
                        if current_validated > fork_at {
                            for h in (fork_at + 1..=current_validated).rev() {
                                self.utxo
                                    .rollback_block(h)
                                    .map_err(|e| SyncError::Store(format!("{}", e)))?;
                            }
                            info!(
                                "Rolled back UTXO set from {} to {}",
                                current_validated, fork_at
                            );
                        }

                        // Delete headers above fork point
                        self.store
                            .delete_headers_above(fork_at)
                            .map_err(|e| SyncError::Store(format!("{}", e)))?;

                        // Reset validated height
                        let new_validated =
                            std::cmp::min(current_validated, fork_at);
                        self.store
                            .set_validated_height(new_validated)
                            .map_err(|e| SyncError::Store(format!("{}", e)))?;

                        // Step 4: Store the validated new chain headers.
                        self.store
                            .store_headers(new_headers, fork_at + 1)
                            .map_err(|e| SyncError::Store(format!("{}", e)))?;

                        let new_tip = fork_at + new_headers.len() as u32;
                        peer_height = std::cmp::max(peer_height, new_tip);

                        // Clear the mempool — transactions may reference UTXOs
                        // that no longer exist on the new chain.
                        {
                            let mut mempool = self.mempool.lock().unwrap();
                            let count = mempool.count();
                            if count > 0 {
                                // Remove all transactions since UTXO state changed
                                let txids: Vec<_> = mempool.get_all_txids();
                                for txid in &txids {
                                    mempool.remove_tx(txid);
                                }
                                info!("Reorg: cleared {} transactions from mempool", count);
                            }
                        }

                        info!(
                            "Reorg complete: new tip at height {} ({} new headers)",
                            new_tip,
                            new_headers.len()
                        );

                        let best = pool.best_peer_addr().unwrap_or_default();
                        on_progress(self.make_status(
                            new_tip,
                            peer_height,
                            &pool,
                            &best,
                            true,
                            new_validated,
                            Some(format!(
                                "Reorg: rolled back {} blocks to height {}",
                                reorg_depth, fork_at
                            )),
                        ));

                        continue;
                    }
                }
            }

            // ── Normal extension: headers build on our tip ──────────
            let batch_size = headers.len() as u32;

            let timestamps = self
                .store
                .last_timestamps(11)
                .map_err(|e| SyncError::Store(format!("{}", e)))?;

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

    /// One-shot block validation for background push notifications.
    /// Connects to a single peer, checks for new headers, and optionally
    // ── Active message processing (Phase 5) ─────────────────────────

    /// Poll each connected peer for a message and handle it.
    /// Uses short timeouts to avoid blocking — one round-robin pass
    /// through all peers typically takes ~100ms * peer_count.
    fn service_peer_messages(&self, pool: &mut PeerPool) {
        let poll_timeout = Duration::from_millis(100);

        pool.for_each_peer(|addr, _is_inbound, peer| {
            match peer.poll_message(poll_timeout) {
                Ok(Some(msg)) => {
                    if let Err(e) = self.handle_peer_message(addr, msg, peer) {
                        warn!("Error handling message from {}: {}", addr, e);
                    }
                    Ok(())
                }
                Ok(None) => Ok(()), // timeout, no message
                Err(e) => Err(format!("{}", e)), // connection error — remove peer
            }
        });
    }

    /// Handle a single message received from a peer.
    fn handle_peer_message(
        &self,
        addr: &str,
        msg: NetworkMessage,
        peer: &mut crate::p2p::Peer,
    ) -> Result<(), String> {
        match msg {
            NetworkMessage::Ping(nonce) => {
                peer.send(NetworkMessage::Pong(nonce))
                    .map_err(|e| format!("pong: {}", e))?;
            }

            NetworkMessage::GetHeaders(get_hdrs) => {
                self.handle_getheaders(addr, &get_hdrs, peer)?;
            }

            NetworkMessage::GetData(inv_list) => {
                self.handle_getdata(addr, &inv_list, peer)?;
            }

            NetworkMessage::Inv(inv_list) => {
                self.handle_inv(addr, &inv_list, peer)?;
            }

            NetworkMessage::Tx(tx) => {
                self.handle_tx(addr, tx)?;
            }

            NetworkMessage::SendHeaders => {
                let mut state = self.relay_state.lock().unwrap();
                state
                    .entry(addr.to_string())
                    .or_insert_with(|| PeerRelayState {
                        wants_sendheaders: false,
                        feefilter_rate: 0,
                        known_txids: HashSet::new(),
                    })
                    .wants_sendheaders = true;
            }

            NetworkMessage::FeeFilter(rate) => {
                // BIP 133: rate is i64 sat/kvB. Clamp negative values to 0.
                let clamped = rate.max(0) as u64;
                let mut state = self.relay_state.lock().unwrap();
                state
                    .entry(addr.to_string())
                    .or_insert_with(|| PeerRelayState {
                        wants_sendheaders: false,
                        feefilter_rate: 0,
                        known_txids: HashSet::new(),
                    })
                    .feefilter_rate = clamped;
            }

            NetworkMessage::MemPool => {
                let txids = self.mempool.lock().unwrap().get_all_txids();
                if !txids.is_empty() {
                    let inv: Vec<Inventory> = txids
                        .into_iter()
                        .map(|txid| Inventory::Transaction(txid))
                        .collect();
                    peer.send_inv(inv).map_err(|e| format!("mempool inv: {}", e))?;
                }
            }

            NetworkMessage::GetAddr => {
                // We don't maintain an address book, so respond with an empty
                // addr message. Bitcoin Core only responds to inbound peers and
                // only once per connection to prevent address scraping — we
                // simplify by always sending empty. Proper addrman is future work.
                peer.send(NetworkMessage::Addr(Vec::new()))
                    .map_err(|e| format!("addr: {}", e))?;
            }

            NetworkMessage::Addr(entries) => {
                // Legacy v1 addr gossip. Each entry is `(timestamp, Address)`
                // where Address is the IPv4-mapped-in-IPv6 form. We collect
                // routable entries locally, then push them into
                // pending_gossip_addrs in a single locked extend for the
                // monitor loop to fold into the PeerPool's AddrManager.
                let batch: Vec<String> = entries
                    .iter()
                    .take(MAX_GOSSIP_ADDRS_PER_MSG)
                    .filter_map(|(_ts, a)| format_v1_address(a))
                    .collect();
                if !batch.is_empty() {
                    let queued = batch.len();
                    self.pending_gossip_addrs
                        .lock()
                        .unwrap()
                        .extend(batch);
                    debug!("Queued {} v1 gossip addresses from {}", queued, addr);
                }
            }

            NetworkMessage::AddrV2(entries) => {
                // BIP 155 addrv2 — supports Tor v3, I2P, etc. We only ingest
                // IPv4/IPv6 variants here; reconstructing a Tor v3 hostname
                // from its 32-byte pubkey would require SHA-3 (not in our dep
                // tree) and we already bootstrap Tor via bundled onion seeds.
                // I2P/Cjdns are not relevant on mobile.
                let batch: Vec<String> = entries
                    .iter()
                    .take(MAX_GOSSIP_ADDRS_PER_MSG)
                    .filter_map(format_v2_address)
                    .collect();
                if !batch.is_empty() {
                    let queued = batch.len();
                    self.pending_gossip_addrs
                        .lock()
                        .unwrap()
                        .extend(batch);
                    debug!("Queued {} v2 gossip addresses from {}", queued, addr);
                }
            }

            other => {
                // Log but don't error on unknown/unhandled messages
                debug!("Ignoring {} from {}", msg_name(&other), addr);
            }
        }
        Ok(())
    }

    /// Handle a getheaders request — respond with up to 2000 headers.
    fn handle_getheaders(
        &self,
        addr: &str,
        get_hdrs: &GetHeadersMessage,
        peer: &mut crate::p2p::Peer,
    ) -> Result<(), String> {
        // Find the best matching locator hash
        let mut start_height = None;
        for locator_hash in &get_hdrs.locator_hashes {
            if let Ok(Some(h)) = self.store.find_height_of_hash(*locator_hash) {
                start_height = Some(h + 1); // start from the block AFTER the locator
                break;
            }
        }

        let from = start_height.unwrap_or(0);
        let tip_height = self.store.count().unwrap_or(0).saturating_sub(1) as u32;
        let mut to = std::cmp::min(from + 1999, tip_height);

        // Respect stop_hash: stop sending headers once we hit it
        let stop_hash = get_hdrs.stop_hash;
        if stop_hash != BlockHash::all_zeros() {
            if let Ok(Some(stop_height)) = self.store.find_height_of_hash(stop_hash) {
                to = std::cmp::min(to, stop_height);
            }
        }

        if from > to {
            // Nothing to send
            peer.send_headers(Vec::new())
                .map_err(|e| format!("send empty headers: {}", e))?;
            return Ok(());
        }

        match self.store.get_headers_in_range(from, to) {
            Ok(headers) => {
                let count = headers.len();
                peer.send_headers(headers)
                    .map_err(|e| format!("send headers: {}", e))?;
                self.stats.lock().unwrap().headers_served += count as u64;
            }
            Err(e) => {
                warn!("Failed to get headers for {}: {}", addr, e);
            }
        }
        Ok(())
    }

    /// Handle a getdata request — serve blocks or transactions.
    fn handle_getdata(
        &self,
        _addr: &str,
        inv_list: &[Inventory],
        peer: &mut crate::p2p::Peer,
    ) -> Result<(), String> {
        // Bitcoin protocol limits getdata to 50,000 entries
        if inv_list.len() > 50_000 {
            return Err(format!("getdata too large: {} entries (max 50000)", inv_list.len()));
        }

        let mut not_found = Vec::new();

        for item in inv_list {
            match item {
                Inventory::Block(hash) | Inventory::WitnessBlock(hash) => {
                    match self.block_store.get_block_by_hash(hash) {
                        Ok(Some(block)) => {
                            peer.send_block(block)
                                .map_err(|e| format!("send block: {}", e))?;
                            self.stats.lock().unwrap().blocks_served += 1;
                        }
                        _ => {
                            not_found.push(*item);
                        }
                    }
                }
                Inventory::Transaction(txid) | Inventory::WitnessTransaction(txid) => {
                    let mempool = self.mempool.lock().unwrap();
                    if let Some(tx) = mempool.get(txid) {
                        let tx_clone = tx.clone();
                        drop(mempool);
                        peer.send_tx(tx_clone)
                            .map_err(|e| format!("send tx: {}", e))?;
                    } else {
                        not_found.push(*item);
                    }
                }
                _ => {
                    not_found.push(*item);
                }
            }
        }

        if !not_found.is_empty() {
            peer.send_not_found(not_found)
                .map_err(|e| format!("send notfound: {}", e))?;
        }
        Ok(())
    }

    /// Handle an inv announcement — request unknown blocks/txs.
    fn handle_inv(
        &self,
        addr: &str,
        inv_list: &[Inventory],
        peer: &mut crate::p2p::Peer,
    ) -> Result<(), String> {
        // Bitcoin protocol limits inv messages to 50,000 entries
        if inv_list.len() > 50_000 {
            return Err(format!("inv too large: {} entries (max 50000)", inv_list.len()));
        }

        let mut request = Vec::new();

        for item in inv_list {
            match item {
                Inventory::Block(hash) | Inventory::WitnessBlock(hash) => {
                    // Check if we already have this block header
                    if self.store.find_height_of_hash(*hash).ok().flatten().is_none() {
                        info!("New block announced by {}: {}", addr, hash);
                        // Signal the monitor loop to break early and fetch
                        self.new_block_announced.store(true, Ordering::Relaxed);
                    }
                }
                Inventory::Transaction(txid) | Inventory::WitnessTransaction(txid) => {
                    if !self.mempool.lock().unwrap().contains(txid) {
                        // Record that this peer knows about this tx
                        let mut state = self.relay_state.lock().unwrap();
                        state
                            .entry(addr.to_string())
                            .or_insert_with(|| PeerRelayState {
                                wants_sendheaders: false,
                                feefilter_rate: 0,
                                known_txids: HashSet::new(),
                            })
                            .known_txids
                            .insert(*txid);

                        // Request with witness data for segwit transactions
                        request.push(Inventory::WitnessTransaction(*txid));
                    }
                }
                _ => {}
            }
        }

        if !request.is_empty() {
            peer.send(NetworkMessage::GetData(request))
                .map_err(|e| format!("getdata for inv: {}", e))?;
        }
        Ok(())
    }

    /// Handle an incoming transaction — validate and add to mempool.
    fn handle_tx(&self, addr: &str, tx: bitcoin::Transaction) -> Result<(), String> {
        let validated_height = self.store.validated_height().unwrap_or(0);

        let result = {
            let mut mempool = self.mempool.lock().unwrap();
            mempool.accept_tx(tx, &self.utxo, validated_height)
        }; // mempool lock released before acquiring relay_queue lock

        match result {
            Ok(txid) => {
                // Schedule relay with Poisson delay
                let delay = poisson_delay_secs(2.0);
                self.relay_queue.lock().unwrap().push(RelayQueueEntry {
                    txid,
                    relay_at: Instant::now() + Duration::from_secs_f64(delay),
                    from_peer: addr.to_string(),
                });
            }
            Err(e) => {
                debug!("Rejected tx from {}: {}", addr, e);
            }
        }
        Ok(())
    }

    /// Send pending relay inv messages for transactions whose delay has elapsed.
    fn drain_relay_queue(&self, pool: &PeerPool) {
        let now = Instant::now();
        let mut queue = self.relay_queue.lock().unwrap();

        // Partition: ready vs not-yet
        let mut ready = Vec::new();
        queue.retain(|entry| {
            if entry.relay_at <= now {
                ready.push((entry.txid, entry.from_peer.clone()));
                false
            } else {
                true
            }
        });
        drop(queue);

        if ready.is_empty() {
            return;
        }

        // Snapshot the state we need, then release locks before I/O
        let relay_snapshot: HashMap<String, (HashSet<Txid>, u64)> = {
            let state = self.relay_state.lock().unwrap();
            state
                .iter()
                .map(|(addr, rs)| {
                    (addr.clone(), (rs.known_txids.clone(), rs.feefilter_rate))
                })
                .collect()
        };

        let fee_rates: Vec<(Txid, u64)> = {
            let mempool = self.mempool.lock().unwrap();
            ready
                .iter()
                .map(|(txid, _)| {
                    let rate = mempool.fee_rate(txid).unwrap_or(0.0);
                    (*txid, (rate * 1000.0) as u64) // convert sat/vB → sat/kvB
                })
                .collect()
        };
        // All locks released — safe to do network I/O now

        for ((txid, from_peer), (_, fee_rate_satkvb)) in ready.iter().zip(fee_rates.iter()) {
            let inv = vec![Inventory::Transaction(*txid)];

            pool.for_each_peer(|addr, _, peer| {
                // Don't relay back to sender
                if addr == from_peer {
                    return Ok(());
                }
                if let Some((known, feefilter)) = relay_snapshot.get(addr) {
                    // Skip if peer already knows about this tx
                    if known.contains(txid) {
                        return Ok(());
                    }
                    // BIP 133: skip if tx fee rate is below peer's feefilter
                    if *feefilter > 0 && *fee_rate_satkvb < *feefilter {
                        return Ok(());
                    }
                }
                peer.send_inv(inv.clone()).map_err(|e| format!("relay inv: {}", e))?;
                Ok(())
            });

            self.stats.lock().unwrap().txs_relayed += 1;
        }
    }

    /// downloads and validates the latest block — all within `timeout_secs`.
    ///
    /// Returns a `BlockNotification` with whatever validation was achieved
    /// before the deadline. This is designed for iOS's ~30-second background
    /// execution window (call with timeout_secs=25 to leave margin).
    pub fn validate_latest_block(
        &self,
        timeout_secs: u32,
    ) -> Result<BlockNotification, SyncError> {
        let deadline = Instant::now() + Duration::from_secs(timeout_secs as u64);

        // Get our current tip
        let (tip_height, tip_hash, tip_header) = self
            .store
            .tip()
            .map_err(|e| SyncError::Store(format!("{}", e)))?
            .ok_or_else(|| SyncError::Store("store has no headers".into()))?;

        let our_height = self
            .store
            .count()
            .map_err(|e| SyncError::Store(format!("{}", e)))?
            .saturating_sub(1);

        info!(
            "validate_latest_block: tip at {}, timeout {}s",
            tip_height, timeout_secs
        );

        // Connect to one peer
        if Instant::now() >= deadline {
            return Ok(BlockNotification::no_update(tip_height, &tip_header));
        }

        let pool = PeerPool::new(
            our_height,
            self.tor.clone(),
            self.peers_db_path.as_deref(),
        )
        .map_err(|e| {
            if format!("{}", e).contains("no peers discovered") {
                SyncError::NoPeers
            } else {
                SyncError::Peer(format!("{}", e))
            }
        })?;

        // Get headers from best peer
        if Instant::now() >= deadline {
            return Ok(BlockNotification::no_update(tip_height, &tip_header));
        }

        let peer = pool.best_peer();
        if peer.is_none() {
            return Err(SyncError::Peer("no peers available".into()));
        }
        let mut peer = peer.unwrap();
        let peer_addr = peer.addr().to_string();

        let headers = match peer.get_headers(vec![tip_hash], BlockHash::all_zeros()) {
            Ok(h) => {
                pool.return_peer(peer);
                h
            }
            Err(e) => {
                return Err(SyncError::Peer(format!("{}: {}", peer_addr, e)));
            }
        };

        if headers.is_empty() {
            info!("validate_latest_block: no new headers, chain is current");
            return Ok(BlockNotification::no_update(tip_height, &tip_header));
        }

        // Enforce 2000-header limit (same as main sync loop)
        if headers.len() > 2000 {
            return Err(SyncError::Validation(format!(
                "peer sent {} headers (max 2000)", headers.len()
            )));
        }

        // Validate and store new headers
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

        let new_tip = tip_height + headers.len() as u32;
        let new_header = &headers[headers.len() - 1];

        info!(
            "validate_latest_block: synced headers {}-{} (PoW validated)",
            new_start, new_tip
        );

        let mut notification = BlockNotification {
            height: new_tip,
            block_hash: new_header.block_hash().to_string(),
            prev_block_hash: new_header.prev_blockhash.to_string(),
            timestamp: new_header.time,
            timestamp_human: crate::chrono_format(new_header.time),
            validated: false,
            header_validated: true,
            validation_error: None,
        };

        // If time remains, try full block validation
        if Instant::now() >= deadline {
            info!("validate_latest_block: deadline reached after header sync");
            return Ok(notification);
        }

        let validated_height = self
            .store
            .validated_height()
            .map_err(|e| SyncError::Store(format!("{}", e)))?;

        // Only attempt full validation for the tip block if we're caught up
        if validated_height + 1 != new_tip {
            info!(
                "validate_latest_block: validated_height {} too far from tip {}, skipping block validation",
                validated_height, new_tip
            );
            return Ok(notification);
        }

        let block_hash = new_header.block_hash();
        let block_peer = pool.any_peer();
        if block_peer.is_none() {
            return Ok(notification);
        }
        let mut block_peer = block_peer.unwrap();

        match block_peer.get_block(block_hash) {
            Ok(block) => {
                pool.return_peer(block_peer);

                if Instant::now() >= deadline {
                    return Ok(notification);
                }

                // Structural validation
                if let Err(e) = validate_block(&block, new_tip) {
                    notification.validation_error =
                        Some(format!("structural: {}", e));
                    return Ok(notification);
                }

                // Script validation
                if let Err(e) = validate_block_scripts(&block, new_tip, &self.utxo) {
                    notification.validation_error =
                        Some(format!("scripts: {}", e));
                    return Ok(notification);
                }

                // Apply to UTXO set
                if let Err(e) = self.utxo.apply_block(&block, new_tip) {
                    notification.validation_error =
                        Some(format!("utxo: {}", e));
                    return Ok(notification);
                }

                // Store block for NODE_NETWORK_LIMITED serving
                let _ = self.block_store.store_block(&block, new_tip);

                // Remove confirmed transactions from mempool
                self.mempool.lock().unwrap().remove_confirmed(&block);

                self.store
                    .set_validated_height(new_tip)
                    .map_err(|e| SyncError::Store(format!("{}", e)))?;

                notification.validated = true;
                info!("validate_latest_block: block {} fully validated", new_tip);
            }
            Err(e) => {
                info!(
                    "validate_latest_block: block download failed: {}, returning header-only result",
                    e
                );
            }
        }

        Ok(notification)
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

/// Generate a Poisson-distributed delay in seconds (for transaction relay privacy).
/// Uses hash-based random number generation (no external rand dependency).
fn poisson_delay_secs(mean: f64) -> f64 {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    let u: f64 = (RandomState::new().build_hasher().finish() as f64) / (u64::MAX as f64);
    -mean * u.max(1e-15).ln()
}

/// Build a sibling path next to `db_path`. Used to put auxiliary stores
/// (UTXO LMDB env, block store, peer store) alongside the headers SQLite file
/// without coupling their names to the headers filename's substring layout.
///
/// Returns `<parent_of_db_path>/<name>`. If `db_path` has no parent (just a
/// bare filename), the result is `<name>` in the current directory.
pub(crate) fn derive_sibling_path(db_path: &str, name: &str) -> String {
    let path = std::path::Path::new(db_path);
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    parent.join(name).to_string_lossy().into_owned()
}
