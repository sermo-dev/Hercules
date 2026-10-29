use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
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

use crate::assumeutxo::{SnapshotAnchor, SNAPSHOT_MAP_REQUIRED_BYTES};
use crate::block_store::BlockStore;
use crate::block_validation::{
    check_block_mutation, validate_block, validate_block_scripts, BlockValidationError,
};
use crate::chain_params::ChainParams;
use crate::mempool::Mempool;
use crate::p2p::{msg_name, PeerError};
use crate::peer_pool::{PeerInfo, PeerPool, PeerSource};
use crate::store::HeaderStore;
use crate::tor::TorManager;
use crate::utxo::{SnapshotLoadError, SnapshotMeta, UtxoSet};
use crate::wake::{WakeBudget, WakePhase};
use crate::validation::{
    check_anchor, chainwork_for_headers, u256_add, u256_gt, validate_headers,
};

/// How often to poll for new blocks after initial sync (seconds).
const MONITOR_INTERVAL: Duration = Duration::from_secs(30);

/// How often we re-broadcast our own onion address to all addrv2-capable
/// peers. Bitcoin Core uses 24h here. Without periodic refresh, peers age
/// out our address from their addrman after a day or two and inbound
/// discovery quietly degrades.
const SELF_AD_REBROADCAST_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// Maximum reorg depth we'll accept (bounded by undo data retention window).
///
/// This number must stay in lock-step with the prune horizon below: every
/// 1000 blocks the sync loop calls `prune_undo_below(next_height - 288)`,
/// which keeps undo records for heights `>= next_height - 288`. A max-depth
/// reorg targets exactly `current_tip - 288`, so the boundary is *exact*,
/// not tight-with-bug — if you bump this constant you must also bump the
/// `next_height - 288` arithmetic in `sync.rs::prune_undo_below` and in
/// `block_store.prune_below`.
const MAX_REORG_DEPTH: u32 = 288;

/// Per-peer cap on the `known_txids` dedup set. A malicious peer that floods
/// us with INV messages full of unique txids can otherwise grow this set
/// unboundedly between maintenance ticks. 10k txids ≈ 320 KB per peer; with
/// MAX_OUTBOUND + MAX_INBOUND ≈ 28 peers that's a hard ceiling around 9 MB.
/// On overflow we clear the entire set rather than evicting individually —
/// the dedup is best-effort and a coarse reset is acceptable.
const MAX_KNOWN_TXIDS_PER_PEER: usize = 10_000;

/// Selection demerit for a peer outvoted 2-to-1 in the header cross-check.
/// Applied with `PeerPool::deprioritize`, which never touches the ban
/// score: two colluding witnesses can outvote an honest peer, and
/// divergence alone proves nothing.
const HEADER_DIVERGENCE_PENALTY: u32 = 50;

/// Lighter cost for a 2-peer disagreement we can't break with a third
/// opinion — both peers get this since we don't know who's lying. Also
/// `deprioritize`, never a ban.
const HEADER_DISAGREEMENT_PENALTY: u32 = 10;

/// Penalty for a peer that didn't deliver the block we requested (sent a
/// different block, or nothing, within the bound/timeout). Small because an
/// honest peer racing an announcement can trip it; the full ban weight is
/// reserved for a matching block that fails consensus (ticket 024).
const BLOCK_NOT_RECEIVED_PENALTY: u32 = 10;

/// Penalty for a peer whose headers conflict with the chain anchor (a
/// different block at the anchor height, or a reorg across it). No honest
/// peer can produce this, so it's an immediate ban.
const ANCHOR_CONFLICT_PENALTY: u32 = 100;

/// Penalty for a block whose transactions don't match what its header
/// commits to (stripped or altered witnesses, duplicated transactions): a
/// mutated delivery (ticket 024). The block itself may be fine, so it is
/// fetched from another peer and never marked invalid.
const MUTATED_BLOCK_PENALTY: u32 = 20;

/// Penalty for headers that fail validation (proof-of-work, timestamps,
/// difficulty, linkage), on a normal extension or a reorg.
const INVALID_HEADERS_PENALTY: u32 = 50;

/// Penalty for a peer that claimed a taller chain at handshake but answers
/// `getheaders` with nothing beyond our tip. Small: its claimed height is
/// also capped at our tip, which is what stops it being picked again.
const EMPTY_HEADERS_PENALTY: u32 = 10;

/// Pause before retrying a height at which every connected peer served a
/// mutated block, so the loop waits for the pool to refill instead of
/// spinning on the same peers.
const CORRUPT_DELIVERY_BACKOFF: Duration = Duration::from_secs(2);

/// Penalty for a peer that relays headers through a block we recorded as
/// invalid without having announced that chain to us. It is disconnected
/// and deprioritized, not banned (ticket 024): it may only be relaying,
/// and if our verdict was wrong we'd otherwise ban every honest peer.
const RELAYED_INVALID_CHAIN_PENALTY: u32 = 10;

/// Header rounds a below-minimum-work chain must go without any peer
/// extending it before a deep or lower-work fork may replace it (see
/// `HeaderSync::scratch_replacement`). Each such round waits a second, so
/// this is also roughly a minimum stall time in seconds.
const SCRATCH_STALL_ROUNDS: u32 = 10;

/// Best-block hash recorded when the UTXO set is rolled back to a block
/// whose header we no longer have (see `HeaderSync::rollback_utxo_to`). It
/// matches no real block, so that block is never taken as already applied.
const UNKNOWN_BLOCK_HASH: [u8; 32] = [0; 32];

/// Wall-clock budget for following one peer's header chain past a batch
/// (`HeaderSync::fork_reaches`, and skipping shared headers to find where a
/// fork begins). Long enough for a mainnet-length fork over Tor (~470
/// batches), short enough that a peer dribbling headers can't hold the sync
/// loop indefinitely.
const FORK_FOLLOW_BUDGET: Duration = Duration::from_secs(10 * 60);

/// Version of the block validation rules. Bump whenever a change to
/// validation could flip a verdict, so `failed_blocks` rows recorded under
/// the old rules are dropped at startup and those blocks reconsidered
/// (ticket 024). Combined with the crate version in `rules_tag`, which
/// changes only when `Cargo.toml`'s version does (not with the app's
/// marketing version), so a fix needs this bump. No test pins the number
/// (tests go through `rules_tag()`), so a bump is this one line.
///
/// History:
/// - 2: script verification moved from libbitcoinconsensus v26 to
///   libbitcoinkernel (ticket 047), and the verifier's errors are classified
///   through `ScriptVerifyError` instead of `bitcoinconsensus::Error`.
/// - 3: ticket 026 (contextual consensus rules; BIP 34 accepts heights 1..=16).
/// - 4: the retracted 943,500 snapshot stored uncompressed P2PK coins with
///   the wrong script, so valid blocks spending them failed CHECKSIG.
const VALIDATION_RULES_VERSION: u32 = 4;

/// Rules tag stored with each `failed_blocks` row. Includes the script
/// backend, so switching between libbitcoinkernel and the legacy library
/// (ticket 047) reconsiders blocks the other one failed.
fn rules_tag() -> String {
    format!(
        "{}+{}+{}",
        VALIDATION_RULES_VERSION,
        env!("CARGO_PKG_VERSION"),
        crate::script_verify::active_backend_name()
    )
}

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
    /// The wake budget ran out (deadline or cancellation) before any peer
    /// contradicted the active one: nothing was learned, nobody is
    /// penalized. Only with a budget (ticket 028).
    Inconclusive,
}

/// What `fetch_witness_headers` got from one peer.
enum FirstHeader {
    /// A batch that connects to our locator and passes header validation:
    /// its first hash, and every hash in it.
    Hash(BlockHash, Vec<BlockHash>),
    /// Network failure, empty or invalid response, or peer gone.
    Failed,
    /// Our wake budget ended the exchange: not the peer's fault.
    OutOfBudget,
}

/// Why `HeaderSync::check_witness_headers` didn't accept a cross-check
/// peer's answer as evidence.
enum WitnessHeaders {
    /// Doesn't connect to the locator we sent: says nothing either way and
    /// costs the peer nothing.
    NoOpinion(String),
    /// Invalid in itself (proof-of-work, linkage, timestamps, anchor):
    /// costs the peer `INVALID_HEADERS_PENALTY`.
    Invalid(String),
}

/// Why a downloaded block was rejected (ticket 024). Each class gets a
/// different response in `sync()`, `catch_up_blocks()` and
/// `validate_latest_block()`.
enum BlockFailure {
    /// This copy of the block is not what its header commits to (wrong
    /// hash, mutated transactions or witnesses). The peer is at fault and
    /// the real block may be fine: penalize, fetch it elsewhere.
    Delivery(String),
    /// The block matches its header and breaks a consensus rule, so every
    /// chain containing it is invalid: record it as failed, drop its header
    /// and everything above. The peer that announced that header chain (and
    /// any peer later sending headers through the failed block) is banned
    /// outright with `ban_peer`, not scored: `misbehaving(.., 100)` can
    /// leave a peer that earned rewards serving earlier blocks connected.
    /// Peers that merely served the block are not penalized: like Bitcoin
    /// Core, we don't punish relaying a block the peer didn't vouch for.
    Consensus(String),
    /// Our own storage failed. Nobody else's fault; stop as before.
    Local(SyncError),
}

impl From<BlockValidationError> for BlockFailure {
    fn from(e: BlockValidationError) -> Self {
        if e.is_mutation() {
            BlockFailure::Delivery(format!("{}", e))
        } else if e.is_consensus_failure() {
            BlockFailure::Consensus(format!("{}", e))
        } else {
            // UTXO store or script verifier failure: our fault.
            BlockFailure::Local(SyncError::Store(format!("{}", e)))
        }
    }
}

/// Delete persisted bans for `addrs` (a session's pool loads bans from
/// disk when it opens). Best effort: a failure only delays the unban until
/// the 24-hour ban expires.
fn lift_bans(peers_db_path: Option<&str>, addrs: &[String]) {
    let Some(path) = peers_db_path else { return };
    if addrs.is_empty() {
        return;
    }
    match crate::peer_store::PeerStore::open(path) {
        Ok(peers) => {
            for addr in addrs {
                if let Err(e) = peers.delete_ban(addr) {
                    warn!("failed to lift ban for {}: {}", addr, e);
                }
            }
        }
        Err(e) => warn!("failed to open peer store to lift bans: {}", e),
    }
}

/// Verdict on a fork that the normal reorg rules would refuse (too deep,
/// or not more work in the batch), while our chain is below minimum work.
enum ScratchReplacement {
    /// Not a candidate: apply the normal rules.
    No,
    /// A candidate, but our chain hasn't stalled long enough yet.
    Wait,
    /// Replace our headers with the fork.
    Replace,
}

/// Note that `addr` served a bad copy of the block at `height`, so the
/// next attempt at that height asks someone else.
fn record_bad_delivery(bad: &mut Option<(u32, Vec<String>)>, height: u32, addr: String) {
    match bad {
        Some((h, addrs)) if *h == height => addrs.push(addr),
        _ => *bad = Some((height, vec![addr])),
    }
}

/// The peer whose header batch put the current header at `height` into
/// our store this session, if any. `sources` holds `(first, last, addr)`
/// per stored batch, newest last.
fn header_source(sources: &[(u32, u32, String)], height: u32) -> Option<&str> {
    sources
        .iter()
        .rev()
        .find(|(first, last, _)| (*first..=*last).contains(&height))
        .map(|(_, _, addr)| addr.as_str())
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

/// Format a BIP 155 `AddrV2Message` into a `host:port` string. Handles
/// IPv4, IPv6, and Tor v3 — the latter is reconstructed from its 32-byte
/// ed25519 pubkey via `tor_v3::pubkey_to_hostname` so we can stash dialable
/// onion addresses in the AddrManager and feed them straight back to Arti's
/// `client.connect()`. I2P / Cjdns are still dropped — we don't reach those
/// networks from a mobile node.
fn format_v2_address(msg: &bitcoin::p2p::address::AddrV2Message) -> Option<String> {
    use bitcoin::p2p::address::AddrV2;
    if msg.port == 0 {
        return None;
    }
    match &msg.addr {
        AddrV2::Ipv4(_) | AddrV2::Ipv6(_) => {
            let sock = msg.socket_addr().ok()?;
            if !is_routable(&sock) {
                return None;
            }
            Some(sock.to_string())
        }
        AddrV2::TorV3(pubkey) => {
            let hostname = crate::tor_v3::pubkey_to_hostname(pubkey);
            Some(format!("{}:{}", hostname, msg.port))
        }
        // I2P, Cjdns, TorV2 (deprecated), Unknown — silently drop. Mobile
        // nodes don't have I2P or Cjdns transports configured, and TorV2
        // hasn't been supported by Arti or modern Tor in years.
        _ => None,
    }
}

/// Convert a `(timestamp, host:port)` entry sampled from the AddrManager into
/// the legacy v1 `(u32, Address)` shape used by `NetworkMessage::Addr`. Tor
/// entries can't be carried over v1 (the on-the-wire encoding has no room for
/// a 32-byte pubkey) so we drop them; peers that requested addrv2 take the
/// other branch in the GetAddr handler.
fn addr_entry_to_v1(ts: u32, host_port: &str) -> Option<(u32, bitcoin::p2p::Address)> {
    use std::str::FromStr;
    if host_port.contains(".onion") {
        return None;
    }
    let sock = std::net::SocketAddr::from_str(host_port).ok()?;
    Some((
        ts,
        bitcoin::p2p::Address::new(&sock, bitcoin::p2p::ServiceFlags::NETWORK),
    ))
}

/// Convert a `(timestamp, host:port)` entry into a v2 `AddrV2Message`. Handles
/// IPv4, IPv6, and Tor v3 .onion entries — the .onion path round-trips the
/// hostname back through `tor_v3::hostname_to_pubkey` so we re-emit the same
/// 32-byte pubkey we'd have ingested over the wire.
fn addr_entry_to_v2(ts: u32, host_port: &str) -> Option<bitcoin::p2p::address::AddrV2Message> {
    use bitcoin::p2p::address::{AddrV2, AddrV2Message};
    use bitcoin::p2p::ServiceFlags;
    use std::str::FromStr;

    if host_port.contains(".onion") {
        // Parse port from the trailing `:NNNN` — split from the right since
        // hostnames may contain colons (IPv6 doesn't appear here, but be safe).
        let port = host_port.rsplit(':').next()?.parse::<u16>().ok()?;
        let pubkey = crate::tor_v3::hostname_to_pubkey(host_port)?;
        return Some(AddrV2Message {
            time: ts,
            services: ServiceFlags::NETWORK,
            addr: AddrV2::TorV3(pubkey),
            port,
        });
    }

    let sock = std::net::SocketAddr::from_str(host_port).ok()?;
    let v2 = match sock.ip() {
        std::net::IpAddr::V4(v4) => AddrV2::Ipv4(v4),
        std::net::IpAddr::V6(v6) => AddrV2::Ipv6(v6),
    };
    Some(AddrV2Message {
        time: ts,
        services: ServiceFlags::NETWORK,
        addr: v2,
        port: sock.port(),
    })
}

/// Current Unix time clamped to a 32-bit `addrv2` timestamp. We saturate at
/// `u32::MAX` rather than wrap so a clock skew bug never produces a 1970
/// timestamp the receiving peer would aggressively age out.
fn unix_now_u32() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        .min(u32::MAX as u64) as u32
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

/// Mainnet genesis header, for the unit tests below.
#[cfg(test)]
fn genesis_header() -> Header {
    ChainParams::mainnet().genesis_header()
}

/// Stand-in anchor for chains without one (regtest): a height no header
/// chain reaches, so every anchor check passes trivially and no snapshot
/// file can match it.
const NO_ANCHOR: SnapshotAnchor = SnapshotAnchor {
    height: u32::MAX,
    block_hash: [0u8; 32],
    utxo_hash: [0u8; 32],
    utxo_count: 0,
};

/// How to construct a `HeaderSync`. Production goes through
/// `HeaderSync::new`: mainnet params and DNS/onion peer discovery. The sync
/// integration harness (ticket 027) uses regtest params and a static list
/// of loopback mock peers.
pub struct SyncConfig {
    pub db_path: String,
    pub tor: Option<Arc<TorManager>>,
    pub params: &'static ChainParams,
    pub peers: PeerSource,
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

/// Result of a budgeted multi-block catch-up attempt.
#[derive(Debug, Clone)]
pub struct CatchUpStatus {
    /// True if validated_height == header tip after this call.
    pub caught_up: bool,
    /// Number of blocks fully validated during this call.
    pub blocks_validated: u32,
    /// Current validated height after this call.
    pub current_height: u32,
    /// Header-chain tip height (the target).
    pub target_height: u32,
    /// Block hash at current_height (for notification records).
    pub tip_block_hash: String,
    /// Timestamp at current_height.
    pub tip_timestamp: u32,
    /// If non-None, the catch-up was aborted due to this error.
    /// Partial progress (blocks_validated > 0) may still have been made.
    pub error: Option<String>,
    /// True if the header cross-check detected disagreement among peers,
    /// signaling a possible eclipse attack. The wake still proceeds with
    /// the best-work tip, but the UI should surface this to the user.
    pub tip_disagreement: bool,
    /// True if a block failed consensus validation during this call: it
    /// was recorded as invalid and its headers dropped (ticket 024). The
    /// UI can say "rejected an invalid block" rather than show a generic
    /// error; `error` carries the details.
    pub invalid_chain_detected: bool,
}

/// Trust and verification info exposed to the UI.
#[derive(Debug, Clone)]
pub struct TrustInfo {
    /// Height at which the UTXO snapshot was loaded (0 if synced from genesis).
    pub snapshot_height: u32,
    /// Current validated block height.
    pub validated_height: u32,
    /// Number of blocks fully validated since the snapshot was loaded.
    pub forward_validated_blocks: u32,
    /// MuHash of the UTXO set at the snapshot height, compatible with
    /// `bitcoin-cli gettxoutsetinfo muhash`. None if synced from genesis.
    pub muhash: Option<String>,
}

/// Sync block headers and validate full blocks from the Bitcoin P2P network.
/// Per-peer relay state tracking.
#[derive(Default)]
struct PeerRelayState {
    wants_sendheaders: bool,
    feefilter_rate: u64, // sat/kvB from BIP 133
    known_txids: HashSet<Txid>,
    /// Own transactions (033) this peer is known to have: we announced
    /// them to it, or it announced them to us. Separate from the bounded,
    /// coarse-reset `known_txids` because it gates what we serve: a
    /// `getdata` for an own tx is answered only for peers in this set, and
    /// rebroadcasts skip them. Holds only tracked own txids, so it is as
    /// small as the own-tx tracker.
    own_txids: HashSet<Txid>,
    /// Bitcoin Core caps GetAddr responses to one per connection — repeated
    /// requests are scrapers we should ignore. We mirror that behavior.
    getaddr_responded: bool,
}

/// Insert `txid` into the per-peer dedup set, capped at
/// `MAX_KNOWN_TXIDS_PER_PEER`. On overflow the entire set is cleared rather
/// than evicting individually — the dedup is best-effort and a coarse reset
/// is acceptable.
fn record_known_txid(state: &mut PeerRelayState, txid: Txid) {
    if state.known_txids.len() >= MAX_KNOWN_TXIDS_PER_PEER {
        state.known_txids.clear();
    }
    state.known_txids.insert(txid);
}

/// Download `block_hash` for the push-wake path, trying at most two peers.
///
/// Returns `None` unless a block whose hash equals `block_hash` was
/// obtained — the caller must not advance `validated_height` in that case.
/// A peer that fails to deliver the requested block (`BlockNotReceived`, or
/// a mismatched block slipping past `get_block`) is penalized and, if the
/// deadline allows, the request is retried once with a different peer.
/// Transport errors keep the previous behavior: give up and report
/// header-only.
///
/// Peers in `exclude` are never asked (they already served a bad copy,
/// ticket 024), and a call with any excluded peer counts as a retry for
/// the deadline. Returns the block and the peer that served it.
fn fetch_requested_block(
    pool: &mut PeerPool,
    block_hash: BlockHash,
    deadline: Instant,
    exclude: &[String],
) -> Option<(bitcoin::block::Block, String)> {
    let mut tried: Vec<String> = exclude.to_vec();
    for _ in 0..2 {
        if !tried.is_empty() && Instant::now() >= deadline {
            info!("validate_latest_block: deadline reached, not retrying block download");
            return None;
        }
        let block_peer = if tried.is_empty() {
            pool.any_peer()
        } else {
            pool.peer_addr_excluding(&tried)
                .and_then(|addr| pool.checkout_peer_by_addr(&addr))
        };
        let mut block_peer = block_peer?;
        let block_peer_addr = block_peer.addr().to_string();
        tried.push(block_peer_addr.clone());

        let limit = deadline.saturating_duration_since(Instant::now());
        match block_peer.get_block_within(block_hash, Some(limit)) {
            // Defense in depth: get_block already binds to the requested
            // hash, but re-check here so a future p2p refactor can't
            // silently reopen the substitution hole.
            Ok(block) if block.block_hash() == block_hash => {
                pool.return_peer(block_peer);
                return Some((block, block_peer_addr));
            }
            Ok(block) => {
                warn!(
                    "validate_latest_block: {} sent block {}, expected {}",
                    block_peer_addr,
                    block.block_hash(),
                    block_hash
                );
                pool.misbehaving(&block_peer_addr, BLOCK_NOT_RECEIVED_PENALTY);
            }
            Err(e @ PeerError::BlockNotReceived { .. }) => {
                info!(
                    "validate_latest_block: {} from {}, trying another peer",
                    e, block_peer_addr
                );
                pool.misbehaving(&block_peer_addr, BLOCK_NOT_RECEIVED_PENALTY);
            }
            Err(e) => {
                info!(
                    "validate_latest_block: block download failed: {}, returning header-only result",
                    e
                );
                if matches!(e, PeerError::WrongMagic { .. }) {
                    pool.ban_peer(&block_peer_addr);
                }
                return None;
            }
        }
    }
    None
}

/// Pending transaction relay with Poisson delay.
struct RelayQueueEntry {
    txid: Txid,
    relay_at: Instant,
    /// Peer we got it from, so we don't relay it back. `None` for the
    /// user's own transactions (ticket 033), which are announced to every
    /// peer immediately and never attributed to a peer.
    from_peer: Option<String>,
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
    /// Stop flag for `sync()` / `stop_sync()` (tests). The app's sessions
    /// pass their own token to `run_sync` (ticket 028).
    #[cfg(test)]
    shutdown_requested: Arc<AtomicBool>,
    /// The Tor client, once it is up. Set at construction, or later by
    /// `attach_tor` when the node opened without waiting for bootstrap
    /// (ticket 028).
    tor: OnceLock<Arc<TorManager>>,
    /// Tor mode was configured: peer sessions must not start until `tor`
    /// is set, so a node still bootstrapping never falls back to clearnet.
    tor_required: bool,
    /// True when our regular peer connections go over Tor (`tor` is set).
    /// Without Tor they are clearnet, and an own tx announced on them
    /// first ties it to our IP, so it waits for the 029 private-broadcast
    /// transport instead. Its own field so tests can run "Tor mode"
    /// without a `TorManager`.
    regular_peers_over_tor: bool,
    /// Per-peer relay metadata (keyed by peer address).
    relay_state: Mutex<HashMap<String, PeerRelayState>>,
    /// Queue of transactions waiting to be relayed with Poisson delay.
    relay_queue: Mutex<Vec<RelayQueueEntry>>,
    /// The user's own transactions (ticket 033): persisted tracker that
    /// drives rebroadcast until confirmation.
    own_txs: crate::own_tx_store::OwnTxStore,
    /// Ticket 029 private-broadcast transport. When set, own transactions
    /// go through it instead of being announced on our regular peers.
    private_broadcast: Mutex<Option<Arc<dyn crate::own_tx_store::PrivateBroadcast>>>,
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
    /// Last time we re-broadcast our own onion address to all peers. Initial
    /// value is `Instant::now()` (set on construction), so the first periodic
    /// re-broadcast fires 24h after node start. The on-connect self-ad in
    /// `PeerPool::maintain` covers fresh connections in the meantime.
    last_self_ad: Mutex<Instant>,
    /// Chain anchor (ticket 023): the snapshot every loaded UTXO set must
    /// match, and the block every header chain must contain at
    /// `anchor.height`. Mainnet constants; tests (and the regtest harness,
    /// ticket 027) override these together with `min_chain_work`.
    anchor: SnapshotAnchor,
    /// Cumulative work the stored header chain must reach before we
    /// validate blocks, activate a snapshot, or report "synced".
    min_chain_work: [u8; 32],
    /// Running chainwork of the stored chain as (height, hash at that
    /// height, work of 0..=height), so `has_min_chain_work` only sums the
    /// headers added since its last call. Invalidated by any reorg below
    /// the cached height (the hash at that height no longer matches).
    chainwork_cache: Mutex<Option<(u32, BlockHash, [u8; 32])>>,
    /// Chain parameters (mainnet in production; regtest in the harness).
    params: &'static ChainParams,
    /// Where each session's `PeerPool` gets its addresses.
    peer_source: PeerSource,
    /// Peers left in an unresolved two-peer header disagreement (ticket
    /// 024). Their header batches need a fresh agreeing witness before we
    /// store them, even outside initial sync: otherwise banning the other
    /// side would leave the survivor's headers accepted unchecked. Cleared
    /// per peer once a witness agrees with it. Lives for the process, not
    /// one session, since the survivor is usually still connected next time.
    disputed_peers: Mutex<HashSet<String>>,
    /// Bans lifted by `reconsider_invalid_blocks` while a sync session may
    /// be running; that session's pool drains them (its in-memory ban list
    /// would otherwise keep them banned until it ends).
    pending_unbans: Mutex<Vec<String>>,
    /// Header rounds in a row in which a peer offered a fork that would
    /// replace our below-minimum-work headers, without any peer extending
    /// our tip. See `scratch_replacement`.
    scratch_stall_rounds: AtomicU32,
    /// How many such rounds must pass before the replacement is allowed.
    scratch_stall_threshold: u32,
}

impl HeaderSync {
    pub fn new(db_path: &str, tor: Option<Arc<TorManager>>) -> Result<HeaderSync, SyncError> {
        HeaderSync::with_config(SyncConfig {
            db_path: db_path.to_string(),
            tor,
            params: ChainParams::mainnet(),
            peers: PeerSource::Discover,
        })
    }

    /// Build a `HeaderSync` from an explicit config. Production code only
    /// ever passes mainnet + `PeerSource::Discover` (via `new`); regtest
    /// params and static peers exist only in test builds.
    pub fn with_config(config: SyncConfig) -> Result<HeaderSync, SyncError> {
        let SyncConfig {
            db_path,
            tor,
            params,
            peers: peer_source,
        } = config;
        let db_path = db_path.as_str();
        let store =
            HeaderStore::open(db_path).map_err(|e| SyncError::Store(format!("{}", e)))?;

        // Derive UTXO database path from header database path. The UTXO set
        // is now LMDB (a directory of mmapped files), not SQLite, so the path
        // is a directory name sitting next to the headers SQLite file.
        let utxo_path = derive_sibling_path(db_path, "utxo-lmdb");
        let utxo =
            UtxoSet::open(&utxo_path).map_err(|e| SyncError::Store(format!("{}", e)))?;

        // Derive block store path for NODE_NETWORK_LIMITED serving. Use the
        // sibling-path helper instead of `db_path.replace("headers", "blocks")`
        // — the substring approach silently misbehaves if a parent directory
        // happens to contain "headers" (e.g. `/var/headers-data/headers.sqlite3`
        // → `/var/blocks-data/blocks.sqlite3`) or if the operator picks a
        // headers filename like `mainnet.sqlite3`.
        let blocks_path = if db_path == ":memory:" {
            ":memory:".to_string()
        } else {
            derive_sibling_path(db_path, "blocks.sqlite3")
        };
        let block_store =
            BlockStore::open(&blocks_path).map_err(|e| SyncError::Store(format!("{}", e)))?;

        // Own-transaction tracker (ticket 033), next to the block store.
        let own_txs_path = if db_path == ":memory:" {
            ":memory:".to_string()
        } else {
            derive_sibling_path(db_path, "own_txs.sqlite3")
        };
        let own_txs = crate::own_tx_store::OwnTxStore::open(&own_txs_path)
            .map_err(|e| SyncError::Store(format!("{}", e)))?;

        // Derive peers DB path for persistent reputation scores and bans.
        // Skip persistence in :memory: mode (used by tests).
        let peers_db_path = if db_path == ":memory:" {
            None
        } else {
            Some(derive_sibling_path(db_path, "peers.sqlite3"))
        };

        // Ensure genesis header is stored
        if store.count().map_err(|e| SyncError::Store(format!("{}", e)))? == 0 {
            let genesis = params.genesis_header();
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
            // Every failed-block verdict was reached against the set that
            // is now gone, which may have been wrong (a retracted snapshot
            // condemns valid blocks spending its bad coins). Reconsider them
            // all, and lift the bans they caused.
            let unbanned = store
                .clear_failed_blocks()
                .map_err(|e| SyncError::Store(format!("{}", e)))?;
            if !unbanned.is_empty() {
                info!(
                    "UTXO set reset: reconsidering failed blocks, lifting {} ban(s)",
                    unbanned.len()
                );
            }
            lift_bans(peers_db_path.as_deref(), &unbanned);
        }

        // Ticket 024: a crash between a UTXO rollback and the matching
        // `set_validated_height` (inside `apply_reorg`) leaves the header
        // store claiming more than the UTXO set holds. The UTXO set records
        // the block it is at in the same LMDB txn as each write, so when
        // that block is on our header chain below `validated_height`, it is
        // the truth: step `validated_height` down to it. (A UTXO set ahead
        // of `validated_height` is left alone here: `utxo_has_block`
        // finishes that block if it is still ours when it is next
        // connected, and rolls it back otherwise.)
        if let Some((utxo_height, utxo_hash)) =
            utxo.best_block().map_err(|e| SyncError::Store(format!("{}", e)))?
        {
            let validated = store
                .validated_height()
                .map_err(|e| SyncError::Store(format!("{}", e)))?;
            let on_chain = store
                .get_hash_at_height(utxo_height)
                .map_err(|e| SyncError::Store(format!("{}", e)))?
                .map(|h| h.to_byte_array())
                == Some(utxo_hash);
            if utxo_height < validated && on_chain {
                warn!(
                    "UTXO set is at block {} but validated_height is {} (interrupted reorg); repairing",
                    utxo_height, validated
                );
                store
                    .set_validated_height(utxo_height)
                    .map_err(|e| SyncError::Store(format!("{}", e)))?;
            }
        }

        // Ticket 033: a crash between a block hook (or a reorg's rollback)
        // and the matching validated-height update can leave own txs
        // settled by blocks we no longer count as validated. Undo those;
        // re-applying the block settles them again (on_block is
        // idempotent, and the crash-recovery path re-runs it). Every path
        // runs the hook after the UTXO apply and before
        // `set_validated_height`, so once no block is mid-apply (true here,
        // before any sync starts, as long as no other HeaderSync in the
        // process has these files open: the app's `NodeHost` keeps it to
        // one node, ticket 028) a settled row with status_height above
        // validated_height can only be such a leftover. Not repeated at
        // session start: a push-wake `validate_latest_block` could be
        // mid-apply then. Skipped with no UTXO set (height 0): there is
        // nothing to re-validate against.
        let validated = store
            .validated_height()
            .map_err(|e| SyncError::Store(format!("{}", e)))?;
        if validated > 0 {
            own_txs
                .demote_confirmed_above(validated, unix_now_u32() as u64)
                .map_err(|e| SyncError::Store(format!("{}", e)))?;
        }

        // Ticket 024: failed blocks recorded under other validation rules
        // are reconsidered, and the bans they caused lifted.
        let unbanned = store
            .prune_failed_blocks(&rules_tag())
            .map_err(|e| SyncError::Store(format!("{}", e)))?;
        if !unbanned.is_empty() {
            info!(
                "Validation rules changed: reconsidering failed blocks, lifting {} ban(s)",
                unbanned.len()
            );
            lift_bans(peers_db_path.as_deref(), &unbanned);
        }

        if tor.is_some() {
            info!("HeaderSync: Tor enabled — all connections routed through Tor");
        }
        let tor_required = tor.is_some();
        let tor = match tor {
            Some(t) => OnceLock::from(t),
            None => OnceLock::new(),
        };

        Ok(HeaderSync {
            store,
            utxo,
            block_store,
            peers_db_path,
            mempool: Mutex::new(Mempool::with_params(params)),
            validation_paused: Arc::new(AtomicBool::new(false)),
            #[cfg(test)]
            shutdown_requested: Arc::new(AtomicBool::new(false)),
            regular_peers_over_tor: tor_required,
            tor,
            tor_required,
            relay_state: Mutex::new(HashMap::new()),
            relay_queue: Mutex::new(Vec::new()),
            own_txs,
            private_broadcast: Mutex::new(None),
            pending_gossip_addrs: Mutex::new(Vec::new()),
            stats: Mutex::new(NodeStats {
                blocks_served: 0,
                headers_served: 0,
                txs_relayed: 0,
            }),
            inbound_peer_count: AtomicU32::new(0),
            outbound_peer_count: AtomicU32::new(0),
            new_block_announced: AtomicBool::new(false),
            last_self_ad: Mutex::new(Instant::now()),
            anchor: params.anchor.unwrap_or(NO_ANCHOR),
            min_chain_work: params.min_chain_work,
            chainwork_cache: Mutex::new(None),
            params,
            peer_source,
            disputed_peers: Mutex::new(HashSet::new()),
            pending_unbans: Mutex::new(Vec::new()),
            scratch_stall_rounds: AtomicU32::new(0),
            scratch_stall_threshold: SCRATCH_STALL_ROUNDS,
        })
    }

    /// Load a UTXO snapshot from a file path. The file must match
    /// `self.anchor` (header height, header block hash, content hash).
    ///
    /// Accepts either a raw `.hutx` file or a `.hutx.gz` gzipped file.
    /// The `.gz` form is decompressed on the fly so we never need to write
    /// the (much larger) decompressed file to disk on mobile.
    ///
    /// Binding to the header chain: if our headers already reach the anchor
    /// height they must contain the anchor block there, or the load is
    /// refused before the file is opened. If they don't reach it yet (the
    /// app imports the snapshot before starting header sync), the UTXO set
    /// is loaded but `validated_height` is left alone; the snapshot stays
    /// *pending* until header sync stores the anchor block and
    /// `activate_pending_snapshot` advances `validated_height` to it.
    ///
    /// `on_progress` returning `false` cancels the load. Errors caused by
    /// the file itself come back as `SyncError::SnapshotInvalid`; anything
    /// else (map or disk full, cancelled, LMDB) leaves the file worth
    /// keeping for a retry.
    pub fn load_snapshot<F>(
        &self,
        snapshot_path: &str,
        on_progress: F,
    ) -> Result<SnapshotMeta, SyncError>
    where
        F: Fn(u64, u64) -> bool,
    {
        if let Some(hash) = self
            .store
            .get_hash_at_height(self.anchor.height)
            .map_err(|e| SyncError::Store(format!("{}", e)))?
        {
            if hash.to_byte_array() != self.anchor.block_hash {
                return Err(SyncError::Validation(format!(
                    "header chain has {} at snapshot height {}, expected anchor {}",
                    hash,
                    self.anchor.height,
                    BlockHash::from_byte_array(self.anchor.block_hash)
                )));
            }
        }

        let file = std::fs::File::open(snapshot_path)
            .map_err(|e| SyncError::Store(format!("open snapshot: {}", e)))?;

        let to_sync = |e: SnapshotLoadError| match e {
            SnapshotLoadError::Invalid(_) => SyncError::SnapshotInvalid(format!("{}", e)),
            SnapshotLoadError::Storage(_) => SyncError::Store(format!("{}", e)),
        };
        let meta = if snapshot_path.ends_with(".gz") {
            let decoder = flate2::read::GzDecoder::new(file);
            self.utxo
                .load_snapshot(decoder, Some(&self.anchor), on_progress)
                .map_err(to_sync)?
        } else {
            self.utxo
                .load_snapshot(file, Some(&self.anchor), on_progress)
                .map_err(to_sync)?
        };

        info!(
            "Loaded UTXO snapshot at height {}, {} utxos",
            meta.height, meta.utxo_count
        );

        if !self.activate_pending_snapshot()? {
            info!(
                "Snapshot activation deferred until headers reach height {}",
                meta.height
            );
        }

        Ok(meta)
    }

    /// Fail fast if the UTXO env can't be mapped large enough to hold the
    /// AssumeUTXO set (ticket 030): grows the map now if it can, otherwise
    /// errors so the app doesn't start a ~9 GB download it can't import.
    pub fn ensure_snapshot_map_capacity(&self) -> Result<(), SyncError> {
        self.utxo
            .ensure_map_capacity(SNAPSHOT_MAP_REQUIRED_BYTES)
            .map_err(|e| SyncError::Store(e.0))
    }

    /// If a loaded snapshot is still pending (`validated_height` below the
    /// assume-valid floor), activate it once the stored header chain has the
    /// snapshot's block at the floor height. Returns `true` when block
    /// validation may proceed (no snapshot, already active, or just
    /// activated) and `false` while headers haven't reached the snapshot.
    fn activate_pending_snapshot(&self) -> Result<bool, SyncError> {
        let floor = self
            .utxo
            .assume_valid_floor()
            .map_err(|e| SyncError::Store(format!("{}", e)))?;
        if floor == 0 {
            return Ok(true);
        }
        let validated = self
            .store
            .validated_height()
            .map_err(|e| SyncError::Store(format!("{}", e)))?;
        if validated >= floor {
            return Ok(true);
        }

        // The hash recorded at load time was checked against the anchor of
        // the build that loaded it. Snapshots loaded before that key existed
        // can only be bound if they sit at this build's anchor height.
        let expected = match self
            .utxo
            .snapshot_block_hash()
            .map_err(|e| SyncError::Store(format!("{}", e)))?
        {
            Some(h) => h,
            None if floor == self.anchor.height => self.anchor.block_hash,
            None => {
                return Err(SyncError::Validation(format!(
                    "snapshot at height {} has no recorded block hash",
                    floor
                )))
            }
        };

        match self
            .store
            .get_hash_at_height(floor)
            .map_err(|e| SyncError::Store(format!("{}", e)))?
        {
            Some(h) if h.to_byte_array() == expected => {
                self.store
                    .set_validated_height(floor)
                    .map_err(|e| SyncError::Store(format!("{}", e)))?;
                info!("Snapshot activated: header chain contains {} at {}", h, floor);
                Ok(true)
            }
            Some(h) => Err(SyncError::Validation(format!(
                "header chain has {} at snapshot height {}, expected {}",
                h,
                floor,
                BlockHash::from_byte_array(expected)
            ))),
            None => Ok(false),
        }
    }

    /// Whether the stored header chain has at least `min_chain_work`.
    ///
    /// Fast path: if the chain contains the anchor block, prev-hash linkage
    /// commits it to the anchor's exact ancestry, whose cumulative work is
    /// `MIN_CHAIN_WORK` by construction (see `assumeutxo.rs`). Otherwise sum
    /// the chain's work incrementally via `chainwork_cache`.
    fn has_min_chain_work(&self) -> Result<bool, SyncError> {
        if let Some(h) = self
            .store
            .get_hash_at_height(self.anchor.height)
            .map_err(|e| SyncError::Store(format!("{}", e)))?
        {
            if h.to_byte_array() == self.anchor.block_hash {
                return Ok(true);
            }
        }
        let work = self.stored_chainwork()?;
        Ok(!u256_gt(&self.min_chain_work, &work))
    }

    /// Cumulative work of the stored header chain (genesis through tip),
    /// reusing the cached prefix when it is still part of the chain.
    fn stored_chainwork(&self) -> Result<[u8; 32], SyncError> {
        let (tip_height, tip_hash, _) = self
            .store
            .tip()
            .map_err(|e| SyncError::Store(format!("{}", e)))?
            .ok_or_else(|| SyncError::Store("store has no headers".into()))?;

        let mut cache = self.chainwork_cache.lock().unwrap();
        let (mut next, mut work) = match *cache {
            Some((h, hash, w))
                if h <= tip_height
                    && self
                        .store
                        .get_hash_at_height(h)
                        .map_err(|e| SyncError::Store(format!("{}", e)))?
                        == Some(hash) =>
            {
                (h + 1, w)
            }
            _ => (0, [0u8; 32]),
        };
        while next <= tip_height {
            let end = std::cmp::min(next.saturating_add(1999), tip_height);
            let headers = self
                .store
                .get_headers_in_range(next, end)
                .map_err(|e| SyncError::Store(format!("{}", e)))?;
            work = u256_add(work, chainwork_for_headers(&headers));
            next = end + 1;
        }
        *cache = Some((tip_height, tip_hash, work));
        Ok(work)
    }

    /// Block validation may run only once the header chain has minimum
    /// work and any loaded snapshot is bound to it.
    fn ready_to_validate_blocks(&self) -> Result<bool, SyncError> {
        Ok(self.has_min_chain_work()? && self.activate_pending_snapshot()?)
    }

    /// A reorg from `fork_at` would disconnect (or replace the successors
    /// of) the anchor block in a chain that already contains it.
    fn reorg_crosses_anchor(&self, tip_height: u32, fork_at: u32) -> bool {
        tip_height >= self.anchor.height && fork_at <= self.anchor.height
    }

    /// Reject a header batch (first header at `start_height`) that puts a
    /// different block at the anchor height.
    fn check_batch_anchor(&self, headers: &[Header], start_height: u32) -> Result<(), String> {
        check_anchor(
            headers,
            start_height,
            self.anchor.height,
            &BlockHash::from_byte_array(self.anchor.block_hash),
        )
        .map_err(|e| format!("{}", e))
    }

    /// Trust information for the UI: snapshot height, forward-validated
    /// block count, and (future) MuHash for independent verification.
    pub fn get_trust_info(&self) -> Result<TrustInfo, SyncError> {
        let snapshot_height = self
            .utxo
            .assume_valid_floor()
            .map_err(|e| SyncError::Store(format!("{}", e)))?;

        let validated_height = self
            .store
            .validated_height()
            .map_err(|e| SyncError::Store(format!("{}", e)))?;

        let forward_validated = if snapshot_height > 0 && validated_height > snapshot_height {
            validated_height - snapshot_height
        } else {
            0
        };

        let muhash = self
            .utxo
            .muhash()
            .map_err(|e| SyncError::Store(format!("{}", e)))?
            .map(|mut h| {
                h.reverse(); // Match Core's uint256::GetHex() byte order
                hex::encode(h)
            });

        Ok(TrustInfo {
            snapshot_height,
            validated_height,
            forward_validated_blocks: forward_validated,
            muhash,
        })
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

    // ── Wallet RPC accessors (ticket 014) ────────────────────────────
    //
    // These methods provide read-only access to node state for the wallet
    // JSON-RPC server. All stores use internal Mutex or LMDB transactions,
    // so these are safe to call from the wallet RPC thread while the sync
    // loop runs on its own thread.

    /// Current chain tip: (height, hash, header).
    pub fn rpc_get_tip(&self) -> Result<Option<(u32, BlockHash, Header)>, SyncError> {
        self.store
            .tip()
            .map_err(|e| SyncError::Store(format!("{}", e)))
    }

    /// Block header at a given height: (hash, header).
    pub fn rpc_get_header_at_height(
        &self,
        height: u32,
    ) -> Result<Option<(BlockHash, Header)>, SyncError> {
        self.store
            .get_header_at_height(height)
            .map_err(|e| SyncError::Store(format!("{}", e)))
    }

    /// Block hash at a given height.
    pub fn rpc_get_block_hash(&self, height: u32) -> Result<Option<BlockHash>, SyncError> {
        self.store
            .get_hash_at_height(height)
            .map_err(|e| SyncError::Store(format!("{}", e)))
    }

    /// Find the height of a block hash.
    pub fn rpc_find_height(&self, hash: BlockHash) -> Result<Option<u32>, SyncError> {
        self.store
            .find_height_of_hash(hash)
            .map_err(|e| SyncError::Store(format!("{}", e)))
    }

    /// Full serialized block by hash (within prune window only).
    pub fn rpc_get_block(
        &self,
        hash: &BlockHash,
    ) -> Result<Option<bitcoin::Block>, SyncError> {
        self.block_store
            .get_block_by_hash(hash)
            .map_err(|e| SyncError::Store(format!("{}", e)))
    }

    /// UTXO lookup by outpoint.
    pub fn rpc_get_utxo(
        &self,
        txid: &bitcoin::Txid,
        vout: u32,
    ) -> Result<Option<crate::utxo::UtxoEntry>, SyncError> {
        self.utxo
            .get(txid, vout)
            .map_err(|e| SyncError::Store(format!("{}", e)))
    }

    /// Mempool entry info by txid.
    pub fn rpc_get_mempool_entry(
        &self,
        txid: &bitcoin::Txid,
    ) -> Option<crate::mempool::MempoolEntryInfo> {
        let pool = self.mempool.lock().unwrap();
        pool.get_entry_info(txid)
    }

    /// Fee rate estimates.
    pub fn rpc_get_fee_estimates(&self) -> crate::mempool::FeeEstimates {
        let pool = self.mempool.lock().unwrap();
        pool.estimate_fee_rates()
    }

    /// Submit one of the user's own transactions (ticket 033). Shared by
    /// the 014 wallet RPC `broadcast_transaction` and the FFI (in-app
    /// wallet, 020).
    ///
    /// - Validated against `validated_height` and the UTXO set (not the
    ///   header tip, which can be ahead of the UTXO set).
    /// - Consensus validity and network standardness are required; our
    ///   local Knots-style relay policy (018) is not applied — it is
    ///   reported as a warning on the receipt instead.
    /// - Persisted in the own-tx tracker, then announced immediately (no
    ///   Poisson trickle) to every connected peer, or handed to the 029
    ///   private-broadcast transport when one is installed. Rebroadcast
    ///   continues until it confirms, is replaced, conflicts, or expires.
    ///
    /// `SubmitError::AlreadyKnown` means it was already in the mempool: it
    /// is still tracked and re-announced, so a retry is harmless.
    pub fn submit_own_tx(
        &self,
        raw: &[u8],
    ) -> Result<crate::own_tx_store::OwnTxReceipt, crate::own_tx_store::SubmitError> {
        use crate::own_tx_store::{OwnTxReceipt, SubmitError};
        let tx: bitcoin::Transaction =
            deserialize(raw).map_err(|e| SubmitError::Decode(format!("{}", e)))?;
        let txid = tx.compute_txid();

        let validated_height = self
            .store
            .validated_height()
            .map_err(|e| SubmitError::Internal(format!("{}", e)))?;
        let tip_height = self
            .store
            .tip()
            .map_err(|e| SubmitError::Internal(format!("{}", e)))?
            .map(|(h, _, _)| h)
            .unwrap_or(0);
        if validated_height == 0 {
            // No UTXO set yet: nothing to validate inputs against.
            return Err(SubmitError::NotSynced {
                validated_height,
                tip_height,
            });
        }

        let mut warnings = Vec::new();
        if let Some(w) = Mempool::local_policy_violation(&tx) {
            warnings.push(format!(
                "{}; sent anyway, but nodes with similar filters may not relay it",
                w
            ));
        }

        let (accepted, conflicts) = {
            let mut pool = self.mempool.lock().unwrap();
            let conflicts = pool.conflicting_txids(&tx);
            (
                pool.accept_own_tx(tx.clone(), &self.utxo, validated_height, &self.store),
                conflicts,
            )
        };
        let already_known = match accepted {
            Ok(_) => false,
            Err(crate::mempool::MempoolError::AlreadyInMempool) => true,
            Err(e) => {
                return Err(SubmitError::from_mempool(
                    e,
                    validated_height < tip_height,
                    validated_height,
                    tip_height,
                    conflicts,
                ))
            }
        };

        let now = unix_now_u32() as u64;
        self.own_txs
            .track(txid, raw, now)
            .map_err(|e| SubmitError::Internal(format!("{}", e)))?;
        if !already_known {
            // Accepted with conflicts == it replaced them (RBF).
            for c in &conflicts {
                let _ = self.own_txs.mark_replaced(c, txid, now);
            }
        }
        info!(
            "Own tx {} submitted (validated_height {}{})",
            txid,
            validated_height,
            if already_known { ", already in mempool" } else { "" }
        );
        self.announce_own_tx(txid, &tx, now);

        if already_known {
            return Err(SubmitError::AlreadyKnown { txid });
        }
        Ok(OwnTxReceipt { txid, warnings })
    }

    /// Send an own transaction out now: via the 029 private-broadcast
    /// transport if installed, else an immediate `inv` to every peer on
    /// the next monitor-loop tick (`from_peer: None`, no Poisson delay).
    ///
    /// Without the transport and without Tor, our regular peers are
    /// clearnet: a pending tx is not announced on them (it would tie the
    /// tx to our IP) and waits for 029. A propagated one is: the network
    /// already has it from someone else, so we are not first.
    fn announce_own_tx(&self, txid: Txid, tx: &bitcoin::Transaction, now: u64) {
        let private = self.private_broadcast.lock().unwrap().clone();
        if let Some(pb) = private {
            match pb.broadcast(tx) {
                Ok(n) => info!("Own tx {} private-broadcast to {} peers", txid, n),
                // Stays pending; the rebroadcast schedule retries. Never
                // fall back to our regular connections silently (029).
                Err(e) => warn!("Own tx {} private broadcast failed: {}", txid, e),
            }
        } else if !self.regular_peers_over_tor && self.own_txs.is_pending(&txid) {
            // Stays pending; record_sent below pushes the retry back so
            // this doesn't repeat every tick.
            warn!(
                "Own tx {} not announced: peers are clearnet; waiting for the \
                 private-broadcast transport (ticket 029)",
                txid
            );
        } else {
            let mut queue = self.relay_queue.lock().unwrap();
            if !queue.iter().any(|e| e.txid == txid && e.from_peer.is_none()) {
                queue.push(RelayQueueEntry {
                    txid,
                    relay_at: Instant::now(),
                    from_peer: None,
                });
            }
        }
        let _ = self.own_txs.record_sent(&txid, now);
    }

    /// Install (or remove) the ticket 029 private-broadcast transport.
    #[allow(dead_code)] // wired up by ticket 029
    pub fn set_private_broadcast(
        &self,
        pb: Option<Arc<dyn crate::own_tx_store::PrivateBroadcast>>,
    ) {
        *self.private_broadcast.lock().unwrap() = pb;
    }

    /// Tracker record for an own transaction.
    pub fn own_tx_status(
        &self,
        txid: &Txid,
    ) -> Result<Option<crate::own_tx_store::OwnTxRecord>, SyncError> {
        self.own_txs
            .get(txid)
            .map_err(|e| SyncError::Store(format!("{}", e)))
    }

    /// All tracked own transactions, newest first.
    pub fn list_own_txs(&self) -> Result<Vec<crate::own_tx_store::OwnTxRecord>, SyncError> {
        self.own_txs
            .list()
            .map_err(|e| SyncError::Store(format!("{}", e)))
    }

    /// Start of a foreground sync session: put every active own
    /// transaction back in the (in-memory) mempool, and make the pending
    /// ones due for rebroadcast whatever their backoff. Propagated ones
    /// keep their 12–36h schedule (see `OwnTxStore::make_all_due`).
    fn begin_own_tx_session(&self) {
        let now = unix_now_u32() as u64;
        let _ = self.own_txs.make_all_due(now);
        if let Ok(active) = self.own_txs.active_records() {
            let validated_height = self.store.validated_height().unwrap_or(0);
            for rec in active {
                self.readd_own_tx(&rec, validated_height, now);
            }
        }
        self.rebroadcast_due_own_txs(now);
    }

    /// Ensure an own tx is in the mempool, re-adding it if needed (app
    /// restart, eviction, reorg). An accepted re-add that evicts other own
    /// txs settles them as replaced, as `submit_own_tx` would: after a
    /// reorg demotes both an RBF original and its replacement, the second
    /// re-add wins the RBF race again. Returns whether it is in the pool.
    fn readd_own_tx(
        &self,
        rec: &crate::own_tx_store::OwnTxRecord,
        validated_height: u32,
        now: u64,
    ) -> bool {
        let Some(tx) = rec.tx() else { return false };
        let replaced = {
            let mut pool = self.mempool.lock().unwrap();
            if pool.contains(&rec.txid) {
                return true;
            }
            let conflicts = pool.conflicting_txids(&tx);
            match pool.accept_own_tx(tx, &self.utxo, validated_height, &self.store) {
                Ok(_) => conflicts,
                Err(e) => {
                    // Inputs not validated yet, or a conflict that a block
                    // will settle: retry on schedule.
                    debug!("own tx {} not re-added to mempool: {}", rec.txid, e);
                    return false;
                }
            }
        };
        for c in &replaced {
            let _ = self.own_txs.mark_replaced(c, rec.txid, now);
        }
        true
    }

    /// Re-announce own transactions whose rebroadcast is due, re-adding
    /// them to the mempool first if needed. Called at session start and
    /// from the monitor loop's maintenance tick.
    fn rebroadcast_due_own_txs(&self, now: u64) {
        let validated_height = self.store.validated_height().unwrap_or(0);
        // Expire only when caught up: while the UTXO set lags the headers,
        // an "unconfirmed" own tx may sit in a block we haven't validated.
        let tip_height = self.store.tip().ok().flatten().map(|(h, _, _)| h).unwrap_or(0);
        if validated_height >= tip_height {
            let _ = self.own_txs.expire(now);
        }
        let due = match self.own_txs.due(now) {
            Ok(d) => d,
            Err(e) => {
                warn!("own tx rebroadcast: {}", e);
                return;
            }
        };
        for rec in due {
            // An earlier re-add in this loop may have replaced it.
            if !self.own_txs.is_active(&rec.txid) {
                continue;
            }
            let Some(tx) = rec.tx() else { continue };
            if self.readd_own_tx(&rec, validated_height, now) {
                self.announce_own_tx(rec.txid, &tx, now);
            } else {
                // Push the schedule back so we don't retry every tick.
                let _ = self.own_txs.record_sent(&rec.txid, now);
            }
        }
    }

    /// Destructive half of a reorg, run once the new chain's headers are
    /// validated against the fork point: roll the UTXO set back to
    /// `fork_at`, replace the headers above it with `new_headers`, clear
    /// the mempool, and unsettle own txs confirmed or conflicted above the
    /// fork. Returns `(new_tip, new_validated)`.
    fn apply_reorg(&self, fork_at: u32, new_headers: &[Header]) -> Result<(u32, u32), SyncError> {
        let current_validated = self
            .store
            .validated_height()
            .map_err(|e| SyncError::Store(format!("{}", e)))?;

        // Roll the UTXO set back to the fork point from the block it is
        // actually at, not from `validated_height`: a block applied above
        // it (crash, or a failed block-store write, before
        // `set_validated_height`) must go too, or the new chain's block at
        // that height would later be taken for it. Runs before the old
        // headers are deleted, so their hashes name the rolled-back-to
        // blocks.
        if let Some(from) = self.rollback_utxo_to(fork_at, current_validated)? {
            info!("Rolled back UTXO set from {} to {}", from, fork_at);
        }

        // Delete headers above fork point
        self.store
            .delete_headers_above(fork_at)
            .map_err(|e| SyncError::Store(format!("{}", e)))?;

        // Reset validated height
        let new_validated = std::cmp::min(current_validated, fork_at);
        self.store
            .set_validated_height(new_validated)
            .map_err(|e| SyncError::Store(format!("{}", e)))?;

        // Step 4: Store the validated new chain headers.
        self.store
            .store_headers(new_headers, fork_at + 1)
            .map_err(|e| SyncError::Store(format!("{}", e)))?;

        let new_tip = fork_at + new_headers.len() as u32;

        // Clear the mempool — transactions may reference UTXOs that no
        // longer exist on the new chain.
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
        // Own txs confirmed or conflicted above the fork are unsettled
        // again; rebroadcast re-adds them.
        let _ = self
            .own_txs
            .demote_confirmed_above(fork_at, unix_now_u32() as u64);

        Ok((new_tip, new_validated))
    }

    /// Height of the block the UTXO set is at. From the best-block marker
    /// when there is one; on a legacy database written before the marker
    /// (ticket 024) it is inferred: `validated_height`, or one above it if
    /// that block's outputs are already indexed (a crash between the UTXO
    /// write and `set_validated_height`). The marker is written by the
    /// first apply or rollback, so the inference only ever covers that
    /// first step after an upgrade.
    fn utxo_tip_height(&self, validated: u32) -> Result<u32, SyncError> {
        match self
            .utxo
            .best_block()
            .map_err(|e| SyncError::Store(format!("{}", e)))?
        {
            Some((height, _)) => Ok(height),
            None => {
                let ahead = self
                    .utxo
                    .has_utxos_at_height(validated + 1)
                    .map_err(|e| SyncError::Store(format!("{}", e)))?;
                Ok(validated + ahead as u32)
            }
        }
    }

    /// Roll the UTXO set back, block by block from wherever it is, until it
    /// is at `target`. Each step records the new best block's hash: our
    /// header at that height when it is at or below `validated` (those
    /// blocks are the ones the UTXO set was built from), otherwise
    /// `UNKNOWN_BLOCK_HASH`, which never matches a real block, so the next
    /// connect at that height rolls it back rather than trusting it.
    /// Returns the height rolled back from, or `None` if the set was
    /// already at or below `target`.
    ///
    /// Never steps at or below a loaded snapshot's floor (its rows can't be
    /// rolled back, see `UtxoSet::assume_valid_floor`), and rolls nothing
    /// back while that snapshot is still pending (`validated` below the
    /// floor: not yet bound to our header chain, so no header reorg can
    /// have disconnected anything in it). Otherwise any reorg of cheap
    /// headers below the anchor would fail every sync with a store error.
    fn rollback_utxo_to(&self, target: u32, validated: u32) -> Result<Option<u32>, SyncError> {
        let floor = self
            .utxo
            .assume_valid_floor()
            .map_err(|e| SyncError::Store(format!("{}", e)))?;
        if validated < floor {
            return Ok(None);
        }
        let target = target.max(floor);
        let top = self.utxo_tip_height(validated)?;
        if top <= target {
            return Ok(None);
        }
        for h in (target + 1..=top).rev() {
            let parent = if h - 1 <= validated {
                self.store
                    .get_hash_at_height(h - 1)
                    .map_err(|e| SyncError::Store(format!("{}", e)))?
                    .map(|hash| hash.to_byte_array())
            } else {
                None
            };
            self.utxo
                .rollback_block_to(h, parent.unwrap_or(UNKNOWN_BLOCK_HASH))
                .map_err(|e| SyncError::Store(format!("{}", e)))?;
        }
        Ok(Some(top))
    }

    /// Crash recovery before connecting block `hash` at `height` (always
    /// `validated_height + 1`). True iff the UTXO set already holds exactly
    /// this block (applied, then a kill or failed block-store write before
    /// `set_validated_height`): the caller then only finishes connecting it
    /// (`finish_recovered_block`). If the set holds a different block at
    /// this height (or is above it), e.g. one a reorg replaced, that is
    /// rolled back first and this returns false, so the block is validated
    /// in full.
    ///
    /// Legacy databases with no best-block marker fall back to asking
    /// whether any output is indexed at `height`. That can't tell two
    /// blocks at one height apart, nor see a block whose outputs are all
    /// OP_RETURN or spent in-block, so it is only used until the first
    /// apply or rollback writes the marker.
    fn utxo_has_block(&self, height: u32, hash: BlockHash) -> Result<bool, SyncError> {
        match self
            .utxo
            .best_block()
            .map_err(|e| SyncError::Store(format!("{}", e)))?
        {
            Some((h, bh)) if h == height && bh == hash.to_byte_array() => Ok(true),
            Some((h, bh)) if h >= height => {
                warn!(
                    "UTXO set is at block {} (height {}), not below {} at {}; rolling it back",
                    BlockHash::from_byte_array(bh),
                    h,
                    hash,
                    height
                );
                self.rollback_utxo_to(height - 1, height - 1)?;
                Ok(false)
            }
            Some((h, _)) if h + 1 == height => Ok(false),
            // Behind `validated_height`: validating against it would be
            // wrong, and only a restart's repair (HeaderSync::new) can fix
            // it safely. A local fault, never a verdict on the block.
            Some((h, bh)) => Err(SyncError::Store(format!(
                "UTXO set at height {} block {} doesn't match the header chain at {}; \
                 not validating block {} (restart to repair)",
                h,
                BlockHash::from_byte_array(bh),
                height - 1,
                height
            ))),
            None => self
                .utxo
                .has_utxos_at_height(height)
                .map_err(|e| SyncError::Store(format!("{}", e))),
        }
    }

    /// The rest of connecting a block `utxo_has_block` found already
    /// applied: store it for serving if that write never happened, run the
    /// block hook (it may not have run, or was undone at open, see
    /// `HeaderSync::new`; it is idempotent), and advance `validated_height`.
    fn finish_recovered_block(&self, block: &bitcoin::Block, height: u32) -> Result<(), SyncError> {
        info!(
            "Block {} at {} already applied (crash recovery), advancing validated height",
            block.block_hash(),
            height
        );
        let stored = self
            .block_store
            .has_block(&block.block_hash())
            .map_err(|e| SyncError::Store(format!("{}", e)))?;
        if !stored {
            self.block_store
                .store_block(block, height)
                .map_err(|e| SyncError::Store(format!("{}", e)))?;
        }
        self.on_block_connected(block, height);
        self.store
            .set_validated_height(height)
            .map_err(|e| SyncError::Store(format!("{}", e)))
    }

    /// Full validation of a downloaded block at `height`, classified for
    /// the ticket 024 response matrix. The mutation check runs first so a
    /// stripped or altered copy is blamed on the peer that sent it rather
    /// than surfacing later (say, as a script failure) and condemning a
    /// block that may be valid.
    ///
    /// A consensus verdict is only as good as the UTXO set it was checked
    /// against, so before one is returned the UTXO set's best block is
    /// compared with our header at `height - 1`. On a mismatch the failure
    /// is `Local`: nothing is marked invalid and nobody is banned.
    fn check_block(&self, block: &bitcoin::Block, height: u32) -> Result<(), BlockFailure> {
        let result = (|| -> Result<(), BlockValidationError> {
            check_block_mutation(block, height, self.params)?;
            validate_block(block, height, self.params)?;
            validate_block_scripts(block, height, &self.utxo, self.params, &self.store)
        })();
        match result.map_err(BlockFailure::from) {
            Err(BlockFailure::Consensus(reason)) => match self.utxo_out_of_step(height - 1) {
                Ok(None) => Err(BlockFailure::Consensus(reason)),
                Ok(Some(mismatch)) => Err(BlockFailure::Local(SyncError::Store(format!(
                    "block {} failed validation ({}), but the UTXO set doesn't match the \
                     header chain ({}); not marking it invalid",
                    height, reason, mismatch
                )))),
                Err(e) => Err(BlockFailure::Local(e)),
            },
            other => other,
        }
    }

    /// Why the UTXO set is not exactly at our header at `height`, or `None`
    /// if it is (or if the set predates the best-block marker: unknown,
    /// so the old behavior applies until the next block populates it).
    fn utxo_out_of_step(&self, height: u32) -> Result<Option<String>, SyncError> {
        let Some((utxo_height, utxo_hash)) = self
            .utxo
            .best_block()
            .map_err(|e| SyncError::Store(format!("{}", e)))?
        else {
            return Ok(None);
        };
        let header = self
            .store
            .get_hash_at_height(height)
            .map_err(|e| SyncError::Store(format!("{}", e)))?;
        if utxo_height == height && header.map(|h| h.to_byte_array()) == Some(utxo_hash) {
            return Ok(None);
        }
        Ok(Some(format!(
            "UTXO set at height {} block {}, header chain at height {} block {}",
            utxo_height,
            BlockHash::from_byte_array(utxo_hash),
            height,
            header.map_or("<none>".to_string(), |h| h.to_string())
        )))
    }

    /// Ban the peer that announced the header chain containing failed
    /// block `hash`, remembering why so `reconsider_invalid_blocks` (or a
    /// rules change) can lift it.
    fn ban_announcer(&self, pool: &mut PeerPool, addr: &str, hash: BlockHash) {
        pool.ban_peer(addr);
        if let Err(e) = self.store.record_failed_block_ban(addr, hash) {
            warn!("failed to record ban of {} for {}: {}", addr, hash, e);
        }
    }

    /// Ticket 024 (023 follow-up, option 2): may a fork that the normal
    /// reorg rules refuse replace our headers? Headers stored below minimum
    /// work were never used to validate anything, and a fresh node eclipsed
    /// by peers feeding a cheap chain that stops short of the anchor is
    /// otherwise stuck for good: the honest chain forks near genesis, far
    /// deeper than `MAX_REORG_DEPTH`, and one 2,000-header batch can't show
    /// its real work. But skipping the work comparison also lets colluding
    /// peers wipe honest progress, so it is allowed only when all hold:
    ///
    /// - our chain is below minimum work and its tip below the anchor;
    /// - no validated block would be disconnected;
    /// - the fork reaches at least our tip height. A full batch
    ///   (`fork_continues`) that stops short may go on in later batches: it
    ///   stays a candidate, and the caller proves its reach with
    ///   `fork_reaches` before replacing anything;
    /// - our chain has stalled: `scratch_stall_threshold` rounds of such
    ///   forks with no peer extending our tip in between (any extension
    ///   resets the count), so an honest, progressing chain is never
    ///   replaced. The batch was already cross-checked (strict, since we
    ///   are below minimum work).
    fn scratch_replacement(
        &self,
        tip_height: u32,
        fork_at: u32,
        validated: u32,
        fork_tip: u32,
        fork_continues: bool,
    ) -> Result<ScratchReplacement, SyncError> {
        if self.has_min_chain_work()?
            || tip_height >= self.anchor.height
            || fork_at < validated
            || (fork_tip < tip_height && !fork_continues)
        {
            return Ok(ScratchReplacement::No);
        }
        let rounds = self.scratch_stall_rounds.fetch_add(1, Ordering::Relaxed) + 1;
        if rounds < self.scratch_stall_threshold {
            Ok(ScratchReplacement::Wait)
        } else {
            Ok(ScratchReplacement::Replace)
        }
    }

    /// Follow a fork from `addr` beyond its first batch (`first`, building
    /// on our header at `fork_at`) until it reaches height `target`,
    /// validating every batch as it comes (linkage, proof-of-work at the
    /// contextual difficulty, timestamps, the anchor, recorded-invalid
    /// blocks). Only constant state is kept (the last header, the last 11
    /// timestamps, and the fork's retarget-epoch start times), never the
    /// headers themselves, so a fork hundreds of thousands of headers long
    /// costs bandwidth and time but not memory. True iff the fork reaches
    /// `target`; invalid headers cost the peer as on the normal path.
    ///
    /// For `scratch_replacement`: below minimum work, a fork whose first
    /// batch is full may reach our tip only several batches later (the
    /// eclipse case: a cheap chain ending just short of the anchor, far
    /// past one batch from the fork).
    ///
    /// `first` is the fork's part of the peer's batch (non-empty), and
    /// `first_full` whether the peer's whole batch was full: shared headers
    /// may lead it, so the fork part can be short although the peer has
    /// more. The follow is bounded by `FORK_FOLLOW_BUDGET` and `stop`.
    fn fork_reaches(
        &self,
        pool: &mut PeerPool,
        addr: &str,
        fork_at: u32,
        first: &[Header],
        first_full: bool,
        target: u32,
        stop: &AtomicBool,
        progress: &dyn Fn(&PeerPool, u32),
    ) -> Result<bool, SyncError> {
        debug_assert!(!first.is_empty(), "fork_reaches needs the fork's first headers");
        if first.is_empty() {
            return Ok(false);
        }
        let deadline = Instant::now() + FORK_FOLLOW_BUDGET;
        let mut full = first_full;
        let (mut prev_hash, fork_header) = self
            .store
            .get_header_at_height(fork_at)
            .map_err(|e| SyncError::Store(format!("{}", e)))?
            .ok_or_else(|| SyncError::Store(format!("no header at fork height {}", fork_at)))?;
        let mut prev_bits = fork_header.bits;
        let mut prev_height = fork_at;
        let mut timestamps = self
            .store
            .timestamps_up_to(fork_at, 11)
            .map_err(|e| SyncError::Store(format!("{}", e)))?;
        // Timestamps of the fork's retarget-epoch first blocks.
        let mut epoch_starts: HashMap<u32, u32> = HashMap::new();
        let mut batch: Vec<Header> = first.to_vec();
        loop {
            if self.first_failed_header(&batch)?.is_some() {
                pool.disconnect_and_deprioritize(addr, RELAYED_INVALID_CHAIN_PENALTY);
                return Ok(false);
            }
            if let Err(e) = self.check_batch_anchor(&batch, prev_height + 1) {
                warn!("Fork from {} conflicts with anchor: {}", addr, e);
                pool.misbehaving(addr, ANCHOR_CONFLICT_PENALTY);
                return Ok(false);
            }
            let validated = {
                let store = &self.store;
                let starts = &epoch_starts;
                let lookup = |h: u32| -> Result<u32, String> {
                    if h <= fork_at {
                        store
                            .get_timestamp_at(h)
                            .map_err(|e| format!("{}", e))?
                            .ok_or_else(|| format!("no header at height {}", h))
                    } else {
                        starts
                            .get(&h)
                            .copied()
                            .ok_or_else(|| format!("no fork header at height {}", h))
                    }
                };
                validate_headers(
                    self.params,
                    &batch,
                    prev_hash,
                    prev_height,
                    &timestamps,
                    prev_bits,
                    &lookup,
                )
            };
            if let Err(e) = validated {
                warn!("Fork from {} has invalid headers: {}", addr, e);
                pool.misbehaving(addr, INVALID_HEADERS_PENALTY);
                return Ok(false);
            }
            for (i, h) in batch.iter().enumerate() {
                let height = prev_height + 1 + i as u32;
                if height % 2016 == 0 {
                    epoch_starts.insert(height, h.time);
                }
                timestamps.push(h.time);
            }
            let excess = timestamps.len().saturating_sub(11);
            timestamps.drain(..excess);
            let last = batch[batch.len() - 1];
            prev_hash = last.block_hash();
            prev_bits = last.bits;
            prev_height += batch.len() as u32;

            if prev_height >= target {
                info!("Fork from {} at {} reaches {} (our tip {})", addr, fork_at, prev_height, target);
                return Ok(true);
            }
            progress(pool, prev_height);
            if !full {
                return Ok(false);
            }
            match self.headers_after(pool, addr, prev_hash, deadline, stop) {
                Some(next) => {
                    full = next.len() == 2000;
                    batch = next;
                }
                None => return Ok(false),
            }
        }
    }

    /// The next batch of `addr`'s headers after `after` (a one-hash
    /// locator), for following a chain past one batch. `None` when there is
    /// nothing usable: `stop` set or `deadline` passed, the peer is gone or
    /// failed (removed; banned on wrong magic), or it answered with nothing,
    /// too much, or headers not building on `after`.
    fn headers_after(
        &self,
        pool: &mut PeerPool,
        addr: &str,
        after: BlockHash,
        deadline: Instant,
        stop: &AtomicBool,
    ) -> Option<Vec<Header>> {
        if stop.load(Ordering::Relaxed) {
            return None;
        }
        let limit = deadline.saturating_duration_since(Instant::now());
        let mut peer = pool.checkout_peer_by_addr(addr)?;
        match peer.get_headers_within(vec![after], BlockHash::all_zeros(), Some(limit)) {
            Ok(h) => {
                pool.return_peer(peer);
                if h.is_empty() || h.len() > 2000 || h[0].prev_blockhash != after {
                    return None;
                }
                Some(h)
            }
            Err(PeerError::DeadlineReached) => {
                pool.return_peer(peer);
                warn!("Peer {}: header follow budget spent", addr);
                None
            }
            Err(e) => {
                warn!("Peer {} failed while following its chain: {}", addr, e);
                if matches!(e, PeerError::WrongMagic { .. }) {
                    pool.ban_peer(addr);
                }
                pool.remove_peer(addr);
                None
            }
        }
    }

    /// Height of the last header of `headers` (building on our header at
    /// `base_height`) that matches our chain, walking no further than
    /// `tip_height`: the fork point if the batch diverges.
    fn common_prefix_end(
        &self,
        headers: &[Header],
        base_height: u32,
        tip_height: u32,
    ) -> Result<u32, SyncError> {
        let mut fork_at = base_height;
        for (i, header) in headers.iter().enumerate() {
            let h = base_height + 1 + i as u32;
            if h > tip_height {
                break;
            }
            match self
                .store
                .get_hash_at_height(h)
                .map_err(|e| SyncError::Store(format!("{}", e)))?
            {
                Some(our_hash) if our_hash == header.block_hash() => fork_at = h,
                _ => break,
            }
        }
        Ok(fork_at)
    }

    /// If the block at `height` in our header chain was recorded as invalid
    /// (e.g. headers stored before the verdict, or restored by a peer we
    /// didn't catch), drop it and everything above instead of requesting it.
    fn drop_failed_from_chain(&self, height: u32, hash: BlockHash) -> Result<bool, SyncError> {
        let failed = self
            .store
            .failed_hashes()
            .map_err(|e| SyncError::Store(format!("{}", e)))?;
        if !failed.contains(&hash) {
            return Ok(false);
        }
        warn!("Block {} at height {} is recorded invalid; dropping it instead of fetching", hash, height);
        self.store
            .delete_headers_above(height - 1)
            .map_err(|e| SyncError::Store(format!("{}", e)))?;
        Ok(true)
    }

    /// Cut our header chain below the lowest recorded failed block it
    /// contains (ticket 024). `reject_invalid_block` already does this when
    /// the verdict is reached; this catches headers stored around it (an
    /// earlier crash, a restored database). Without it a stored chain
    /// through a failed block could outweigh every honest fork batch and
    /// never be validated far enough to be dropped.
    fn truncate_at_failed_blocks(&self) -> Result<(), SyncError> {
        let failed = self
            .store
            .failed_hashes()
            .map_err(|e| SyncError::Store(format!("{}", e)))?;
        let validated = self
            .store
            .validated_height()
            .map_err(|e| SyncError::Store(format!("{}", e)))?;
        let mut lowest: Option<u32> = None;
        for hash in failed {
            if let Some(h) = self
                .store
                .find_height_of_hash(hash)
                .map_err(|e| SyncError::Store(format!("{}", e)))?
            {
                if h > validated {
                    lowest = Some(lowest.map_or(h, |l| l.min(h)));
                } else {
                    warn!("Recorded-invalid block {} is at validated height {}", hash, h);
                }
            }
        }
        if let Some(h) = lowest {
            warn!("Header chain contains recorded-invalid block at {}; truncating", h);
            self.store
                .delete_headers_above(h - 1)
                .map_err(|e| SyncError::Store(format!("{}", e)))?;
        }
        Ok(())
    }

    /// Lift bans queued by `reconsider_invalid_blocks` in this session's pool.
    fn drain_pending_unbans(&self, pool: &mut PeerPool) {
        for addr in std::mem::take(&mut *self.pending_unbans.lock().unwrap()) {
            pool.unban_peer(&addr);
        }
    }

    /// Forget every block recorded as consensus-invalid and lift the bans
    /// recorded because of them (ticket 024). For when our verdict may have
    /// been wrong (a validation bug, a corrupted UTXO set): those blocks
    /// are fetched and validated again. Returns how many bans were lifted.
    pub fn reconsider_invalid_blocks(&self) -> Result<u32, SyncError> {
        let unbanned = self
            .store
            .clear_failed_blocks()
            .map_err(|e| SyncError::Store(format!("{}", e)))?;
        info!("Reconsidering invalid blocks; lifting {} ban(s)", unbanned.len());
        lift_bans(self.peers_db_path.as_deref(), &unbanned);
        self.pending_unbans.lock().unwrap().extend(unbanned.iter().cloned());
        Ok(unbanned.len() as u32)
    }

    /// Response to a consensus-invalid block at `height` (ticket 024):
    /// record it in `failed_blocks` and drop its header and everything
    /// above, so header sync resumes at `height - 1` and follows whichever
    /// peers have a valid chain. Callers only validate the block at
    /// `validated_height + 1`, so the UTXO set needs no rollback.
    fn reject_invalid_block(
        &self,
        height: u32,
        hash: BlockHash,
        reason: &str,
    ) -> Result<(), SyncError> {
        warn!(
            "Block {} at height {} is invalid ({}); marking it failed and dropping its headers",
            hash, height, reason
        );
        self.store
            .mark_failed(hash, height, reason, &rules_tag())
            .map_err(|e| SyncError::Store(format!("{}", e)))?;
        self.store
            .delete_headers_above(height - 1)
            .map_err(|e| SyncError::Store(format!("{}", e)))
    }

    /// The first block in `headers` that is, or builds directly on, a
    /// block recorded as consensus-invalid. A chain through a failed block
    /// is invalid however much work it has, so such a batch is refused
    /// before it is cross-checked or stored.
    fn first_failed_header(&self, headers: &[Header]) -> Result<Option<BlockHash>, SyncError> {
        let failed = self
            .store
            .failed_hashes()
            .map_err(|e| SyncError::Store(format!("{}", e)))?;
        if failed.is_empty() {
            return Ok(None);
        }
        Ok(headers.iter().find_map(|h| {
            let hash = h.block_hash();
            if failed.contains(&h.prev_blockhash) {
                Some(h.prev_blockhash)
            } else if failed.contains(&hash) {
                Some(hash)
            } else {
                None
            }
        }))
    }

    /// Block-connect hook shared by every path that applies a block:
    /// drop its transactions (and their conflicts) from the mempool and
    /// settle any own transactions it confirms or conflicts.
    fn on_block_connected(&self, block: &bitcoin::Block, height: u32) {
        self.mempool.lock().unwrap().remove_confirmed(block);
        if let Err(e) = self.own_txs.on_block(block, height, unix_now_u32() as u64) {
            warn!("own tx tracker block hook at {}: {}", height, e);
        }
    }

    /// Height of the last block whose scripts were fully validated.
    pub fn rpc_validated_height(&self) -> Result<u32, SyncError> {
        self.store
            .validated_height()
            .map_err(|e| SyncError::Store(format!("{}", e)))
    }

    /// Open a fresh `PeerPool` for one sync session, using this node's chain
    /// params and peer source.
    fn open_pool(&self, our_height: u32) -> Result<PeerPool, SyncError> {
        self.open_pool_until(our_height, None)
    }

    /// `open_pool` that stops dialing new peers at `connect_deadline`
    /// (wake paths, ticket 028).
    fn open_pool_until(
        &self,
        our_height: u32,
        connect_deadline: Option<Instant>,
    ) -> Result<PeerPool, SyncError> {
        if self.tor_required && self.tor().is_none() {
            return Err(SyncError::Peer("Tor transport not ready".into()));
        }
        PeerPool::new_until(
            our_height,
            self.tor().cloned(),
            self.peers_db_path.as_deref(),
            self.params,
            self.peer_source.clone(),
            connect_deadline,
        )
        .map_err(|e| {
            if format!("{}", e).contains("no peers discovered") {
                SyncError::NoPeers
            } else {
                SyncError::Peer(format!("{}", e))
            }
        })
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
    #[cfg(test)]
    pub fn stop_sync(&self) {
        self.shutdown_requested.store(true, Ordering::Relaxed);
        info!("Sync stop requested");
    }

    /// Tor mode with the client still bootstrapping: peer sessions are
    /// refused until `attach_tor` (ticket 028).
    pub fn require_tor(&mut self) {
        self.tor_required = true;
        self.regular_peers_over_tor = true;
    }

    /// Hand over the Tor client once it has bootstrapped. Later calls are
    /// ignored: a node keeps one Tor client for its lifetime.
    pub fn attach_tor(&self, tor: Arc<TorManager>) {
        if self.tor.set(tor).is_ok() {
            info!("HeaderSync: Tor attached — all connections routed through Tor");
        }
    }

    fn tor(&self) -> Option<&Arc<TorManager>> {
        self.tor.get()
    }

    /// Cross-check a freshly fetched header batch against one or two
    /// independent peers before storing it. This is the core eclipse-attack
    /// defense: even if our active peer is fully attacker-controlled, an
    /// honest second peer responding to the same locator will return a
    /// different first header hash, and we can detect the lie.
    ///
    /// Witness and tiebreaker are outbound peers in netgroups distinct from
    /// each other and from the active peer (`PeerPool::cross_check_peer`):
    /// inbound connections, or several addresses in one netgroup, are cheap
    /// for one attacker to multiply. A witness's answer only counts if it
    /// connects to our locator and passes header validation
    /// (`fetch_witness_headers`); an invalid one costs the witness and is
    /// no opinion.
    ///
    /// Strategy:
    /// 1. Pick a witness. Send the same `getheaders` locator. It agrees if
    ///    its batch contains the active peer's first header.
    /// 2. If they agree → accept. Both peers earn a small reward.
    /// 3. If they disagree → query a tiebreaker.
    ///    - If 2-of-3 agree, the divergent peer is deprioritized by
    ///      `HEADER_DIVERGENCE_PENALTY`. Accept iff active peer is in the
    ///      majority; reject otherwise.
    ///    - If we have no third peer, we can't tell who is lying. Apply a
    ///      lighter `HEADER_DISAGREEMENT_PENALTY` to both and reject the
    ///      batch — refusing to commit dubious headers is the safer default.
    ///    Divergence never bans (`PeerPool::deprioritize`): outvoting proves
    ///    nothing on its own, and colluding witnesses must not be able to
    ///    get honest peers banned. Invalid headers, once validated, do.
    /// 4. If no witness is available → best-effort accept (we logged a
    ///    warning at sync start; this is a degraded mode).
    ///
    /// `strict` (initial sync, chain below minimum work): a missing or
    /// unresponsive witness rejects the batch instead of accepting it, so a
    /// fresh node only stores headers that two distinct peers agree on. The
    /// caller retries on the next iteration. Steady-state behavior is
    /// unchanged.
    ///
    /// The same fail-closed rule applies to a peer in `disputed_peers`
    /// (step 3's two-peer case, ticket 024): once it has disagreed with a
    /// witness we couldn't overrule, its batches need a fresh witness that
    /// agrees with it, however the dispute ended.
    ///
    /// `budget` (wake paths): if it runs out before any divergence is seen
    /// the result is `Inconclusive`. A divergence already seen stays a
    /// `Reject` even when the tiebreaker then runs out of time.
    fn cross_check_headers(
        &self,
        pool: &mut PeerPool,
        locator: &[BlockHash],
        active_addr: &str,
        active_first_hash: BlockHash,
        strict: bool,
        budget: Option<&WakeBudget>,
    ) -> HeaderCrossCheck {
        let disputed = self.disputed_peers.lock().unwrap().contains(active_addr);
        let strict = strict || disputed;

        // Step 1: pick an independent witness peer.
        let witness_addr = match pool.cross_check_peer(&[active_addr.to_string()]) {
            Some(a) => a,
            None if strict => {
                debug!(
                    "cross-check: no witness for {} (initial sync or disputed); rejecting batch",
                    active_addr
                );
                return HeaderCrossCheck::Reject;
            }
            None => {
                debug!(
                    "cross-check skipped: no independent witness for active peer {}",
                    active_addr
                );
                return HeaderCrossCheck::Accept;
            }
        };

        let (witness_first, witness_hashes) =
            match self.fetch_witness_headers(pool, &witness_addr, locator, budget) {
                FirstHeader::Hash(h, all) => (h, all),
                FirstHeader::OutOfBudget => {
                    debug!("cross-check: budget spent before witness {} answered", witness_addr);
                    return HeaderCrossCheck::Inconclusive;
                }
                FirstHeader::Failed if strict => {
                    // Same "can't conclude" case, but during initial sync we
                    // fail closed. No penalty for the active peer.
                    debug!(
                        "cross-check witness {} failed (initial sync or disputed); rejecting batch",
                        witness_addr
                    );
                    return HeaderCrossCheck::Reject;
                }
                FirstHeader::Failed => {
                    // No usable answer — we can't conclude anything. Don't
                    // penalize the active peer over the witness's failure.
                    debug!(
                        "cross-check witness {} failed; accepting active peer's headers",
                        witness_addr
                    );
                    return HeaderCrossCheck::Accept;
                }
            };

        if witness_hashes.contains(&active_first_hash) {
            // Two independent peers agree on the first header — accept.
            pool.reward(active_addr, 1);
            pool.reward(&witness_addr, 1);
            let mut disputed = self.disputed_peers.lock().unwrap();
            disputed.remove(active_addr);
            disputed.remove(&witness_addr);
            return HeaderCrossCheck::Accept;
        }

        warn!(
            "Header divergence: active {} returned {}, witness {} returned {} — escalating",
            active_addr, active_first_hash, witness_addr, witness_first
        );

        // Step 3: try to break the tie with a third peer.
        let others = [active_addr.to_string(), witness_addr.clone()];
        let tiebreaker_addr = pool.cross_check_peer(&others);

        if let Some(tb_addr) = tiebreaker_addr {
            // A tiebreaker that runs out of budget (or answers with nothing
            // valid) falls through to the 2-peer case: the divergence stands.
            if let FirstHeader::Hash(tb_first, tb_hashes) =
                self.fetch_witness_headers(pool, &tb_addr, locator, budget)
            {
                if tb_hashes.contains(&active_first_hash) {
                    // Active + tiebreaker agree → witness is outvoted.
                    warn!(
                        "Header cross-check: deprioritizing divergent witness {}",
                        witness_addr
                    );
                    pool.deprioritize(&witness_addr, HEADER_DIVERGENCE_PENALTY);
                    self.disputed_peers.lock().unwrap().remove(active_addr);
                    return HeaderCrossCheck::Accept;
                } else if tb_first == witness_first {
                    // Witness + tiebreaker agree → active is outvoted.
                    warn!(
                        "Header cross-check: deprioritizing divergent active peer {}",
                        active_addr
                    );
                    pool.deprioritize(active_addr, HEADER_DIVERGENCE_PENALTY);
                    self.disputed_peers.lock().unwrap().remove(&witness_addr);
                    return HeaderCrossCheck::Reject;
                } else {
                    // All three peers disagree — pathological case.
                    // Deprioritize active (it's our default trust target)
                    // and reject.
                    warn!(
                        "Header cross-check: 3-way disagreement, rejecting batch from {}",
                        active_addr
                    );
                    pool.deprioritize(active_addr, HEADER_DISAGREEMENT_PENALTY);
                    return HeaderCrossCheck::Reject;
                }
            }
        }

        // Step 4: no usable tiebreaker and the two disagree.
        warn!(
            "Header cross-check: 2-peer disagreement with no tiebreaker available; rejecting batch"
        );
        pool.deprioritize(active_addr, HEADER_DISAGREEMENT_PENALTY);
        pool.deprioritize(&witness_addr, HEADER_DISAGREEMENT_PENALTY);
        let mut disputed = self.disputed_peers.lock().unwrap();
        disputed.insert(active_addr.to_string());
        disputed.insert(witness_addr);
        HeaderCrossCheck::Reject
    }

    /// Send a `getheaders` to a specific cross-check peer and return its
    /// answer if it is usable as evidence. This wraps the peer
    /// checkout/return dance so the cross-check helper stays readable.
    /// `budget` bounds the whole exchange (wake budgets, ticket 028);
    /// running out of it is `OutOfBudget` and never counts against the
    /// peer.
    ///
    /// An answer that doesn't build on our locator, or fails header
    /// validation, is proof against the peer that sent it (it costs
    /// `INVALID_HEADERS_PENALTY`) and is no opinion about anyone else:
    /// `Failed`.
    fn fetch_witness_headers(
        &self,
        pool: &mut PeerPool,
        addr: &str,
        locator: &[BlockHash],
        budget: Option<&WakeBudget>,
    ) -> FirstHeader {
        if budget.is_some_and(|b| b.should_stop()) {
            return FirstHeader::OutOfBudget;
        }
        let Some(mut peer) = pool.checkout_peer_by_addr(addr) else {
            return FirstHeader::Failed;
        };
        let limit = budget.map(|b| b.remaining());
        let result = peer.get_headers_within(locator.to_vec(), BlockHash::all_zeros(), limit);
        match result {
            Ok(headers) => {
                pool.return_peer(peer);
                // A witness answering with a chain we know is invalid
                // (ticket 024) is no opinion at all: drop it rather than let
                // it dispute an honest active peer.
                match self.first_failed_header(&headers) {
                    Ok(Some(failed)) => {
                        warn!(
                            "cross-check: peer {} sent headers through invalid block {}",
                            addr, failed
                        );
                        pool.disconnect_and_deprioritize(addr, RELAYED_INVALID_CHAIN_PENALTY);
                        return FirstHeader::Failed;
                    }
                    Ok(None) => {}
                    Err(e) => warn!("cross-check: failed-block lookup: {}", e),
                }
                let Some(first) = headers.first() else {
                    return FirstHeader::Failed;
                };
                match self.check_witness_headers(&headers, locator) {
                    Ok(()) => FirstHeader::Hash(
                        first.block_hash(),
                        headers.iter().map(|h| h.block_hash()).collect(),
                    ),
                    Err(WitnessHeaders::NoOpinion(e)) => {
                        // A peer that lacks our locator's blocks answers
                        // from elsewhere (genesis): not misbehavior.
                        debug!("cross-check: peer {}'s headers are no opinion: {}", addr, e);
                        FirstHeader::Failed
                    }
                    Err(WitnessHeaders::Invalid(e)) => {
                        warn!("cross-check: peer {} sent invalid headers: {}", addr, e);
                        pool.misbehaving(addr, INVALID_HEADERS_PENALTY);
                        FirstHeader::Failed
                    }
                }
            }
            Err(PeerError::DeadlineReached) => {
                // Our deadline, not the peer's fault: keep it in the pool.
                // A late reply may still be in flight, but the wake is over
                // and drops the pool with it.
                pool.return_peer(peer);
                FirstHeader::OutOfBudget
            }
            Err(e) => {
                warn!("cross-check: peer {} failed to respond: {}", addr, e);
                if matches!(e, PeerError::WrongMagic { .. }) {
                    pool.ban_peer(addr);
                }
                pool.remove_peer(addr);
                FirstHeader::Failed
            }
        }
    }

    /// Whether a cross-check peer's `headers` are evidence at all: they must
    /// build on a block in the `locator` we sent that is on our header
    /// chain, respect the chain anchor, and pass the same header validation
    /// as a batch we would store (proof-of-work at the contextually
    /// required difficulty, timestamps, linkage).
    ///
    /// Not connecting to our locator is `NoOpinion`, never proof: an honest
    /// peer that has none of the hashes we sent answers from genesis (and
    /// in an eclipse recovery our stored chain may well be fake). Only
    /// headers that are invalid in themselves are `Invalid`.
    fn check_witness_headers(
        &self,
        headers: &[Header],
        locator: &[BlockHash],
    ) -> Result<(), WitnessHeaders> {
        let local = |e: String| WitnessHeaders::NoOpinion(e);
        let prev = headers[0].prev_blockhash;
        if !locator.contains(&prev) {
            return Err(local(format!("first header builds on {}, not on our locator", prev)));
        }
        let height = self
            .store
            .find_height_of_hash(prev)
            .map_err(|e| local(format!("{}", e)))?
            .ok_or_else(|| local(format!("{} is not on our header chain", prev)))?;
        let (_, prev_header) = self
            .store
            .get_header_at_height(height)
            .map_err(|e| local(format!("{}", e)))?
            .ok_or_else(|| local(format!("no header at height {}", height)))?;
        let timestamps = self
            .store
            .timestamps_up_to(height, 11)
            .map_err(|e| local(format!("{}", e)))?;
        self.check_batch_anchor(headers, height + 1)
            .map_err(WitnessHeaders::Invalid)?;
        let store = &self.store;
        let epoch_lookup = |h: u32| -> Result<u32, String> {
            store
                .get_timestamp_at(h)
                .map_err(|e| format!("{}", e))?
                .ok_or_else(|| format!("no header at height {}", h))
        };
        validate_headers(
            self.params,
            headers,
            prev,
            height,
            &timestamps,
            prev_header.bits,
            &epoch_lookup,
        )
        .map_err(|e| WitnessHeaders::Invalid(format!("{}", e)))
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
    /// The app goes through `run_sync` (via `HerculesNode::start_header_sync`).
    #[cfg(test)]
    pub fn sync<F>(&self, on_progress: F) -> Result<(), SyncError>
    where
        F: Fn(SyncStatus),
    {
        // Reset shutdown flag so sync can be restarted after a stop
        self.shutdown_requested.store(false, Ordering::Relaxed);
        self.run_sync(&self.shutdown_requested, on_progress)
    }

    /// `sync`, stopped by `stop` instead of the shared `stop_sync` flag.
    /// The FFI gives every foreground session its own token (ticket 028):
    /// a stop aimed at one session can't leak into the next, and a stop
    /// issued while the session waits for transport or the node's session
    /// lock still counts.
    pub fn run_sync<F>(&self, stop: &AtomicBool, on_progress: F) -> Result<(), SyncError>
    where
        F: Fn(SyncStatus),
    {
        self.truncate_at_failed_blocks()?;

        // Get our current height to report to peers
        let our_height = self
            .store
            .count()
            .map_err(|e| SyncError::Store(format!("{}", e)))?
            .saturating_sub(1);

        // Create the peer pool
        let mut pool = self.open_pool(our_height)?;

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

        // Ticket 033: restore and re-announce pending own transactions.
        self.begin_own_tx_session();

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

        // Ticket 024 bookkeeping for this session: which peer supplied each
        // stored header batch (so the announcer of an invalid block can be
        // banned), and which peers served a mutated copy of the block at
        // the height we're stuck on (so it is fetched from someone else).
        let mut header_sources: Vec<(u32, u32, String)> = Vec::new();
        let mut bad_deliveries: Option<(u32, Vec<String>)> = None;

        loop {
            // Check for shutdown request
            if stop.load(Ordering::Relaxed) {
                info!("Sync shutting down cleanly");
                return Ok(());
            }
            self.drain_pending_unbans(&mut pool);

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
            let mut headers = match peer.get_headers(locator, BlockHash::all_zeros()) {
                Ok(h) => {
                    pool.return_peer(peer);
                    // Reward peers that successfully serve us headers — even an
                    // empty response counts (it means we're caught up to them).
                    pool.reward(&active_addr, 1);
                    h
                }
                Err(e) => {
                    warn!("Peer {} error during get_headers: {}", active_addr, e);
                    if matches!(e, PeerError::WrongMagic { .. }) {
                        // Wrong network after a good handshake: never honest,
                        // and a plain disconnect would just reconnect it.
                        pool.ban_peer(&active_addr);
                    }
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
                    // A smaller gap is no proof of lying (it may have
                    // reorged), but this peer has nothing for us: stop
                    // preferring it for its claimed height and ask the
                    // next-best peer, rather than concluding we're synced
                    // from the one peer that won't serve headers.
                    if claimed > tip_height {
                        info!(
                            "Peer {} claims height {} but has no headers above {}; asking others",
                            active_addr, claimed, tip_height
                        );
                        pool.lower_peer_height(&active_addr, tip_height);
                        pool.misbehaving(&active_addr, EMPTY_HEADERS_PENALTY);
                        continue;
                    }
                }

                // Headers caught up — download and validate blocks
                peer_height = std::cmp::max(peer_height, tip_height);

                // Minimum-work floor: a peer that has nothing beyond a chain
                // below `min_chain_work` is either behind or feeding us a
                // cheap fake chain. Never validate blocks against it or
                // report synced; drop the peer and keep syncing headers from
                // others. Not a misbehavior penalty — an honest peer that is
                // itself still syncing looks the same.
                if !self.has_min_chain_work()? {
                    warn!(
                        "Peer {} has no headers above {}, but our chain is below minimum work; dropping peer",
                        active_addr, tip_height
                    );
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
                        Some("Verifying chain work: header chain below minimum work".into()),
                    ));
                    std::thread::sleep(Duration::from_secs(1));
                    continue;
                }

                // Headers now include the anchor, so a snapshot imported
                // before header sync reached it can be bound and activated.
                let snapshot_ready = self.activate_pending_snapshot()?;

                let mut validated = self
                    .store
                    .validated_height()
                    .map_err(|e| SyncError::Store(format!("{}", e)))?;

                // Guard: if validated_height exceeds tip (e.g. after reorg), reset.
                // Can't drop below the snapshot floor: we only get here with
                // the anchor in the chain (min work), so tip >= anchor height
                // >= floor, and reorgs across the anchor are refused.
                if validated > tip_height {
                    warn!(
                        "validated_height {} exceeds tip {}, resetting",
                        validated, tip_height
                    );
                    // The UTXO set goes back with it (ticket 024), or the
                    // blocks above the tip would stay applied.
                    self.rollback_utxo_to(tip_height, validated)?;
                    self.store
                        .set_validated_height(tip_height)
                        .map_err(|e| SyncError::Store(format!("{}", e)))?;
                    validated = tip_height;
                }

                if validated < tip_height
                    && snapshot_ready
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
                    if self.drop_failed_from_chain(next_height, block_hash)? {
                        continue;
                    }

                    // Use any available peer for block download, except
                    // those that already served a bad copy of this block.
                    let excluded: Vec<String> = match &bad_deliveries {
                        Some((h, addrs)) if *h == next_height => addrs.clone(),
                        _ => Vec::new(),
                    };
                    let block_peer = if excluded.is_empty() {
                        pool.any_peer()
                    } else {
                        pool.peer_addr_excluding(&excluded)
                            .and_then(|addr| pool.checkout_peer_by_addr(&addr))
                    };
                    if block_peer.is_none() && !excluded.is_empty() {
                        // Every connected peer served a corrupted copy. Say
                        // so, refill the pool and start over: each bad copy
                        // cost its sender MUTATED_BLOCK_PENALTY, so peers
                        // that keep doing it are eventually banned.
                        warn!(
                            "All {} tried peers served corrupted blocks at height {}",
                            excluded.len(),
                            next_height
                        );
                        bad_deliveries = None;
                        pool.maintain();
                        let best = pool.best_peer_addr().unwrap_or_default();
                        on_progress(self.make_status(
                            tip_height,
                            peer_height,
                            &pool,
                            &best,
                            false,
                            validated,
                            Some(format!(
                                "Peers are serving corrupted blocks at height {}",
                                next_height
                            )),
                        ));
                        std::thread::sleep(CORRUPT_DELIVERY_BACKOFF);
                        continue;
                    }
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
                            if matches!(e, PeerError::WrongMagic { .. }) {
                                pool.ban_peer(&block_peer_addr);
                            }
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

                    // Verify block hash matches our header chain.
                    // `get_block` already binds it (ticket 022); this is
                    // defense in depth, handled as a bad delivery.
                    if block.block_hash() != block_hash {
                        warn!(
                            "Block {} from {}: expected {}, got {}",
                            next_height,
                            block_peer_addr,
                            block_hash,
                            block.block_hash()
                        );
                        pool.misbehaving(&block_peer_addr, BLOCK_NOT_RECEIVED_PENALTY);
                        record_bad_delivery(&mut bad_deliveries, next_height, block_peer_addr);
                        continue;
                    }

                    // Crash recovery: the UTXO set already holds this very
                    // block (applied, then validated_height not updated).
                    // A different block there is rolled back first.
                    if self.utxo_has_block(next_height, block_hash)? {
                        self.finish_recovered_block(&block, next_height)?;
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

                    // Mutation check, structure, scripts + UTXO spends.
                    // Ticket 024: a bad copy costs the sender and is fetched
                    // elsewhere; an invalid block costs the chain.
                    match self.check_block(&block, next_height) {
                        Ok(()) => {}
                        Err(BlockFailure::Delivery(reason)) => {
                            warn!(
                                "Mutated block {} from {}: {}; fetching it elsewhere",
                                next_height, block_peer_addr, reason
                            );
                            pool.misbehaving(&block_peer_addr, MUTATED_BLOCK_PENALTY);
                            record_bad_delivery(&mut bad_deliveries, next_height, block_peer_addr);
                            continue;
                        }
                        Err(BlockFailure::Consensus(reason)) => {
                            self.reject_invalid_block(next_height, block_hash, &reason)?;
                            if let Some(announcer) = header_source(&header_sources, next_height) {
                                let announcer = announcer.to_string();
                                self.ban_announcer(&mut pool, &announcer, block_hash);
                            }
                            let best = pool.best_peer_addr().unwrap_or_default();
                            on_progress(self.make_status(
                                next_height - 1,
                                peer_height,
                                &pool,
                                &best,
                                true,
                                validated,
                                Some(format!(
                                    "Rejected an invalid block from the network at height {}: {}",
                                    next_height, reason
                                )),
                            ));
                            continue;
                        }
                        Err(BlockFailure::Local(e)) => return Err(e),
                    }

                    // Update UTXO set with this block's changes
                    self.utxo
                        .apply_block(&block, next_height)
                        .map_err(|e| SyncError::Store(format!("{}", e)))?;

                    // Store block for NODE_NETWORK_LIMITED serving (last 288 blocks)
                    self.block_store
                        .store_block(&block, next_height)
                        .map_err(|e| SyncError::Store(format!("{}", e)))?;

                    // Remove confirmed transactions from mempool
                    self.on_block_connected(&block, next_height);

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
                    if stop.load(Ordering::Relaxed) {
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

                    // Accept pending inbound connections from Tor onion
                    // service. Cap per-iteration so a sudden burst of
                    // inbound circuits can't starve the header-sync work
                    // below — each accept runs a full handshake, which
                    // is expensive enough that >10 in a single tick would
                    // visibly stall progress. Anything beyond the cap
                    // waits for the next monitor-loop pass.
                    const MAX_INBOUND_ACCEPTS_PER_TICK: usize = 10;
                    if let Some(tor) = self.tor() {
                        let mut accepted_this_tick = 0;
                        while accepted_this_tick < MAX_INBOUND_ACCEPTS_PER_TICK {
                            let Some(inbound_stream) = tor.accept_inbound() else {
                                break;
                            };
                            accepted_this_tick += 1;
                            let peer_stream = crate::p2p::PeerStream::Tor(inbound_stream);
                            match crate::p2p::Peer::accept(peer_stream, tip_height as i32, self.params.magic) {
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

                    // Periodic 24h re-broadcast of our own onion address.
                    // Cheap when nothing is due — just a Mutex check + elapsed
                    // comparison — so safe to evaluate every loop iteration.
                    {
                        let mut last = self.last_self_ad.lock().unwrap();
                        if last.elapsed() >= SELF_AD_REBROADCAST_INTERVAL {
                            *last = Instant::now();
                            drop(last);
                            self.rebroadcast_self_ad(&pool);
                        }
                    }

                    // Periodic maintenance
                    if last_maintain.elapsed() >= Duration::from_secs(30) {
                        pool.maintain();
                        self.mempool.lock().unwrap().expire_old();
                        self.rebroadcast_due_own_txs(unix_now_u32() as u64);
                        self.update_peer_counts(&pool);
                        // Clean up relay_state: remove entries for disconnected
                        // peers. The per-peer known_txids cap is enforced at
                        // the INV insertion site (MAX_KNOWN_TXIDS_PER_PEER), so
                        // there's nothing to cap here.
                        {
                            let connected: HashSet<String> = pool.peer_info()
                                .iter()
                                .map(|p| p.addr.clone())
                                .collect();
                            let mut state = self.relay_state.lock().unwrap();
                            state.retain(|addr, _| connected.contains(addr));
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

            // A batch through a block we recorded as invalid (ticket 024)
            // pushes a chain we already know is invalid. Only its original
            // announcer is banned; this peer may just be relaying it.
            if let Some(failed) = self.first_failed_header(&headers)? {
                warn!(
                    "Peer {} sent headers through invalid block {}",
                    active_addr, failed
                );
                pool.disconnect_and_deprioritize(&active_addr, RELAYED_INVALID_CHAIN_PENALTY);
                pool.maintain();
                // If it was the only candidate, `maintain` may reconnect it
                // at once; don't spin on that.
                std::thread::sleep(Duration::from_secs(1));
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
            let strict = !self.has_min_chain_work()?;
            match self.cross_check_headers(
                &mut pool,
                &cross_check_locator,
                &active_addr,
                active_first_hash,
                strict,
                None,
            ) {
                HeaderCrossCheck::Accept => {}
                // Inconclusive needs a budget; the main loop has none.
                HeaderCrossCheck::Reject | HeaderCrossCheck::Inconclusive => {
                    // The cross-check helper has already applied the
                    // appropriate misbehavior penalty. Drop the batch and
                    // try again on the next iteration.
                    pool.maintain();
                    if pool.cross_check_peer(&[active_addr.clone()]).is_none() {
                        // Waiting for an independent witness (initial sync
                        // or a disputed peer) — don't spin. Inbound peers
                        // and same-netgroup peers don't count as one.
                        std::thread::sleep(Duration::from_secs(1));
                    }
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
                    Some(mut base_height) => {
                        // Walk forward to find the exact divergence point
                        let mut fork_at =
                            self.common_prefix_end(&headers, base_height, tip_height)?;

                        // A full batch of headers we already have: the peer
                        // answered from a locator entry below the fork point
                        // (entries are far apart low in the chain). Ask for
                        // what follows until its chain diverges from ours,
                        // within FORK_FOLLOW_BUDGET.
                        let mut skipped = false;
                        let skip_deadline = Instant::now() + FORK_FOLLOW_BUDGET;
                        while fork_at == base_height + headers.len() as u32
                            && headers.len() == 2000
                            && fork_at < tip_height
                        {
                            let after = self
                                .store
                                .get_hash_at_height(fork_at)
                                .map_err(|e| SyncError::Store(format!("{}", e)))?
                                .ok_or_else(|| {
                                    SyncError::Store(format!("no hash at height {}", fork_at))
                                })?;
                            let Some(next) = self.headers_after(
                                &mut pool,
                                &active_addr,
                                after,
                                skip_deadline,
                                stop,
                            ) else {
                                break;
                            };
                            headers = next;
                            base_height = fork_at;
                            fork_at = self.common_prefix_end(&headers, base_height, tip_height)?;
                            skipped = true;
                            on_progress(self.make_status(
                                tip_height,
                                peer_height,
                                &pool,
                                &active_addr,
                                true,
                                current_validated,
                                Some(format!(
                                    "Checking a peer's headers: shared with ours up to {}",
                                    fork_at
                                )),
                            ));
                        }
                        if fork_at == base_height + headers.len() as u32 && fork_at < tip_height {
                            // Still nothing but our own headers: the peer's
                            // chain is a prefix of ours (it is behind us), or
                            // it stopped answering. Not a fork.
                            info!(
                                "Peer {}'s headers match ours up to {}, below our tip {}",
                                active_addr, fork_at, tip_height
                            );
                            pool.lower_peer_height(&active_addr, fork_at);
                            continue;
                        }
                        if skipped && fork_at < tip_height {
                            // The diverging batch wasn't the one cross-checked
                            // above: check it too. The locator leads with the
                            // hash it builds on, then our usual locator, so a
                            // witness without that block (our stored chain
                            // may be fake) still lands on a real entry.
                            let after = self
                                .store
                                .get_hash_at_height(base_height)
                                .map_err(|e| SyncError::Store(format!("{}", e)))?
                                .ok_or_else(|| {
                                    SyncError::Store(format!("no hash at height {}", base_height))
                                })?;
                            let mut recheck_locator = vec![after];
                            recheck_locator.extend(
                                self.store
                                    .get_locator_hashes()
                                    .map_err(|e| SyncError::Store(format!("{}", e)))?,
                            );
                            match self.cross_check_headers(
                                &mut pool,
                                &recheck_locator,
                                &active_addr,
                                headers[0].block_hash(),
                                strict,
                                None,
                            ) {
                                HeaderCrossCheck::Accept => {}
                                HeaderCrossCheck::Reject | HeaderCrossCheck::Inconclusive => {
                                    std::thread::sleep(Duration::from_secs(1));
                                    continue;
                                }
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

                        let new_chain_offset = (fork_at - base_height) as usize;
                        let fork_tip = fork_at + (headers.len() - new_chain_offset) as u32;
                        let deep = reorg_depth > MAX_REORG_DEPTH;

                        // Compare chainwork: our chain vs the fork. Skipped
                        // for a deep fork, which is refused (or replaces us
                        // as scratch) regardless, and whose span of our
                        // chain could be huge.
                        let more_work = !deep && {
                            let our_headers = self
                                .store
                                .get_headers_in_range(fork_at + 1, tip_height)
                                .map_err(|e| SyncError::Store(format!("{}", e)))?;
                            let our_work = chainwork_for_headers(&our_headers);
                            let new_work =
                                chainwork_for_headers(&headers[new_chain_offset..]);
                            u256_gt(&new_work, &our_work)
                        };

                        // Below minimum work, a stalled chain may be
                        // replaced anyway (see `scratch_replacement`).
                        let scratch = if deep || !more_work {
                            match self.scratch_replacement(
                                tip_height,
                                fork_at,
                                current_validated,
                                fork_tip,
                                headers.len() == 2000,
                            )? {
                                ScratchReplacement::No => false,
                                ScratchReplacement::Replace if fork_tip >= tip_height => true,
                                ScratchReplacement::Replace => {
                                    // Only the first batch is stored; the
                                    // rest of the fork follows as normal
                                    // extensions once it has replaced us.
                                    let reaches = self.fork_reaches(
                                        &mut pool,
                                        &active_addr,
                                        fork_at,
                                        &headers[new_chain_offset..],
                                        headers.len() == 2000,
                                        tip_height,
                                        stop,
                                        &|pool: &PeerPool, reached: u32| {
                                            on_progress(self.make_status(
                                                tip_height,
                                                peer_height,
                                                pool,
                                                &active_addr,
                                                true,
                                                current_validated,
                                                Some(format!(
                                                    "Checking a competing header chain: at {} of {}",
                                                    reached, tip_height
                                                )),
                                            ))
                                        },
                                    )?;
                                    if !reaches {
                                        // Our tip is below the anchor, so a
                                        // fork that can't get past it isn't
                                        // the chain we need: ask others first
                                        // (no ban: it may just be slow), and
                                        // start the stall count over rather
                                        // than following it every round.
                                        pool.lower_peer_height(&active_addr, 0);
                                        pool.deprioritize(&active_addr, HEADER_DIVERGENCE_PENALTY);
                                        self.scratch_stall_rounds.store(0, Ordering::Relaxed);
                                        continue;
                                    }
                                    true
                                }
                                ScratchReplacement::Wait => {
                                    // Not a penalty (an honest peer looks
                                    // the same), but ask someone else next.
                                    info!(
                                        "Peer {} offers fork at {} replacing our low-work headers; waiting for a stall",
                                        active_addr, fork_at
                                    );
                                    pool.lower_peer_height(&active_addr, 0);
                                    std::thread::sleep(Duration::from_secs(1));
                                    continue;
                                }
                            }
                        } else {
                            false
                        };

                        if deep && !scratch {
                            warn!(
                                "Peer {} suggests reorg depth {} (max {}), ignoring",
                                active_addr, reorg_depth, MAX_REORG_DEPTH
                            );
                            // Below minimum work our own headers prove
                            // nothing, and a deep fork may be the honest
                            // chain: never a penalty then, just ask someone
                            // else next.
                            if strict {
                                pool.lower_peer_height(&active_addr, 0);
                            } else {
                                pool.misbehaving(&active_addr, 20);
                            }
                            continue;
                        }

                        // Never reorg across the chain anchor: once our chain
                        // contains it, a fork at or below it is refused.
                        if self.reorg_crosses_anchor(tip_height, fork_at) {
                            warn!(
                                "Peer {} suggests reorg from fork point {} at or below anchor {}, refusing",
                                active_addr, fork_at, self.anchor.height
                            );
                            pool.misbehaving(&active_addr, ANCHOR_CONFLICT_PENALTY);
                            continue;
                        }

                        if !scratch && !more_work {
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
                        if let Err(e) = self.check_batch_anchor(new_headers, fork_at + 1) {
                            warn!("Reorg rejected: {}", e);
                            pool.misbehaving(&active_addr, ANCHOR_CONFLICT_PENALTY);
                            continue;
                        }
                        if let Err(e) = validate_headers(
                            self.params,
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
                            pool.misbehaving(&active_addr, INVALID_HEADERS_PENALTY);
                            continue;
                        }

                        // Steps 3-4: Validation passed — now perform the
                        // destructive rollback and store the new headers.
                        let (new_tip, new_validated) = self.apply_reorg(fork_at, new_headers)?;
                        header_sources.push((fork_at + 1, new_tip, active_addr.clone()));
                        self.scratch_stall_rounds.store(0, Ordering::Relaxed);
                        peer_height = std::cmp::max(peer_height, new_tip);

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

            // A chain that puts a different block at the anchor height is
            // fake no matter how valid its PoW looks — ban the peer.
            if let Err(e) = self.check_batch_anchor(&headers, tip_height + 1) {
                warn!("Peer {} sent headers conflicting with anchor: {}", active_addr, e);
                pool.misbehaving(&active_addr, ANCHOR_CONFLICT_PENALTY);
                pool.maintain();
                continue;
            }

            // Invalid headers cost the peer that sent them (ticket 024);
            // the batch is dropped and the next iteration asks again, by
            // then most likely of a different, better-scored peer.
            if let Err(e) = validate_headers(
                self.params,
                &headers,
                tip_hash,
                tip_height,
                &timestamps,
                tip_header.bits,
                &epoch_lookup,
            ) {
                warn!("Peer {} sent invalid headers: {}", active_addr, e);
                pool.misbehaving(&active_addr, INVALID_HEADERS_PENALTY);
                pool.maintain();
                continue;
            }

            let new_start = tip_height + 1;
            self.store
                .store_headers(&headers, new_start)
                .map_err(|e| SyncError::Store(format!("{}", e)))?;

            let new_height = tip_height + batch_size;
            header_sources.push((new_start, new_height, active_addr.clone()));
            self.scratch_stall_rounds.store(0, Ordering::Relaxed);
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
        // Reborrow `pool` as a shared reference so the closure can capture it
        // and call the message handler with `&PeerPool` access (e.g. for the
        // `GetAddr` handler, which samples our address book). `for_each_peer`
        // is itself `&self` and only briefly locks the slots Mutex when
        // checking peers in/out, so re-entry is safe — the closure runs
        // *outside* that lock and only touches the orthogonal addrs HashMap.
        let pool_shared: &PeerPool = pool;

        pool_shared.for_each_peer(|addr, _is_inbound, peer| {
            match peer.poll_message(poll_timeout) {
                Ok(Some(msg)) => {
                    if let Err(e) = self.handle_peer_message(addr, msg, peer, pool_shared) {
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
        pool: &PeerPool,
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
                        own_txids: HashSet::new(),
                        getaddr_responded: false,
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
                        own_txids: HashSet::new(),
                        getaddr_responded: false,
                    })
                    .feefilter_rate = clamped;
            }

            NetworkMessage::MemPool => {
                let txids = self.mempool.lock().unwrap().get_all_txids();
                // Own txs no peer has announced back yet stay out: listing
                // them would reveal us as their source (and, in clearnet
                // mode, leak them before 029 sends them).
                let txids: Vec<Txid> = txids
                    .into_iter()
                    .filter(|txid| !self.own_txs.is_pending(txid))
                    .collect();
                if !txids.is_empty() {
                    // Listed own (propagated) txs count as announced to
                    // this peer, so it may fetch them.
                    let own: Vec<Txid> =
                        txids.iter().copied().filter(|t| self.own_txs.is_active(t)).collect();
                    if !own.is_empty() {
                        let mut state = self.relay_state.lock().unwrap();
                        state.entry(addr.to_string()).or_default().own_txids.extend(own);
                    }
                    let inv: Vec<Inventory> = txids.into_iter().map(Inventory::Transaction).collect();
                    peer.send_inv(inv).map_err(|e| format!("mempool inv: {}", e))?;
                }
            }

            NetworkMessage::GetAddr => {
                // Bitcoin Core caps `getaddr` at one response per connection
                // to make address scraping unattractive. Mirror that — silently
                // ignore repeats so we don't drip our address book to a peer
                // running a long-lived survey job.
                {
                    let mut state = self.relay_state.lock().unwrap();
                    let entry = state
                        .entry(addr.to_string())
                        .or_insert_with(|| PeerRelayState {
                            wants_sendheaders: false,
                            feefilter_rate: 0,
                            known_txids: HashSet::new(),
                            own_txids: HashSet::new(),
                            getaddr_responded: false,
                        });
                    if entry.getaddr_responded {
                        return Ok(());
                    }
                    entry.getaddr_responded = true;
                }

                // Sample up to 999 addresses from the AddrManager, leaving one
                // slot in the 1000-entry budget for our own self-advertisement.
                let sample = pool.sample_addresses(999);
                let our_pubkey = self.tor().and_then(|t| t.our_onion_pubkey());

                if peer.wants_addrv2() {
                    let mut entries: Vec<bitcoin::p2p::address::AddrV2Message> = sample
                        .iter()
                        .filter_map(|(ts, host_port)| addr_entry_to_v2(*ts, host_port))
                        .collect();
                    // Self-advertise: append a TorV3 entry for our own onion
                    // service so this peer can dial us back. This is the whole
                    // point of the addrman → gossip → inbound loop and is what
                    // closes the `inbound_peers = 0` gap.
                    if let Some(pubkey) = our_pubkey {
                        entries.push(bitcoin::p2p::address::AddrV2Message {
                            time: unix_now_u32(),
                            services: bitcoin::p2p::ServiceFlags::NETWORK_LIMITED
                                | bitcoin::p2p::ServiceFlags::WITNESS,
                            addr: bitcoin::p2p::address::AddrV2::TorV3(pubkey),
                            port: 8333,
                        });
                    }
                    let count = entries.len();
                    peer.send(NetworkMessage::AddrV2(entries))
                        .map_err(|e| format!("addrv2: {}", e))?;
                    debug!("Sent addrv2 with {} entries to {}", count, addr);
                } else {
                    // Peer didn't negotiate addrv2 — fall back to v1. Tor
                    // entries are silently dropped (v1 has no encoding for
                    // them) and we cannot self-advertise our onion either.
                    let entries: Vec<(u32, bitcoin::p2p::Address)> = sample
                        .iter()
                        .filter_map(|(ts, host_port)| addr_entry_to_v1(*ts, host_port))
                        .collect();
                    let count = entries.len();
                    peer.send(NetworkMessage::Addr(entries))
                        .map_err(|e| format!("addr: {}", e))?;
                    debug!("Sent addr with {} entries to {}", count, addr);
                }
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
        addr: &str,
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
                    // An own tx is served only to a peer we announced it
                    // to or that announced it to us; anyone else asking
                    // is probing whether we have it (i.e. are its source).
                    if self.own_txs.is_active(txid) && !self.peer_knows_own_tx(addr, txid) {
                        not_found.push(*item);
                        continue;
                    }
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
                    let own = self.own_txs.is_active(txid);
                    if own {
                        // A peer announcing our own tx back: it propagated.
                        // Deduped per (peer, txid) in the store.
                        let _ = self.own_txs.record_seen(txid, addr, unix_now_u32() as u64);
                    }
                    {
                        // Record that this peer knows about this tx, even
                        // if we already have it, so we never announce it
                        // back (an own-tx rebroadcast to a peer that told
                        // us about it would mark us as the source). The
                        // helper enforces MAX_KNOWN_TXIDS_PER_PEER on every
                        // insert so a malicious INV burst can't grow this
                        // set arbitrarily between maintenance ticks.
                        let mut state = self.relay_state.lock().unwrap();
                        let entry = state.entry(addr.to_string()).or_default();
                        record_known_txid(entry, *txid);
                        if own {
                            entry.own_txids.insert(*txid);
                        }
                    }
                    if !self.mempool.lock().unwrap().contains(txid) {
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
    //
    // Known race: `validated_height` is read here without holding the
    // mempool lock, so a block could be applied between the read and
    // `accept_tx`'s coinbase-maturity / nLockTime checks. The window is
    // at most one block, and the worst case is a spurious `NonFinal` or
    // `ImmatureCoinbase` rejection of a tx the peer can re-submit.
    // Closing the window properly requires either an `Arc<AtomicU32>`
    // shared with block validation or atomic acquisition of both the
    // header-store and mempool locks. Deferred until the inbound peer
    // path lands and we have a clearer picture of locking ordering.
    fn handle_tx(&self, addr: &str, tx: bitcoin::Transaction) -> Result<(), String> {
        let validated_height = self.store.validated_height().unwrap_or(0);

        let result = {
            let mut mempool = self.mempool.lock().unwrap();
            mempool.accept_tx(tx, &self.utxo, validated_height, &self.store)
        }; // mempool lock released before acquiring relay_queue lock

        match result {
            Ok(txid) => {
                // Schedule relay with Poisson delay
                let delay = poisson_delay_secs(2.0);
                self.relay_queue.lock().unwrap().push(RelayQueueEntry {
                    txid,
                    relay_at: Instant::now() + Duration::from_secs_f64(delay),
                    from_peer: Some(addr.to_string()),
                });
            }
            Err(e) => {
                debug!("Rejected tx from {}: {}", addr, e);
            }
        }
        Ok(())
    }

    /// Re-broadcast our own onion address to every addrv2-capable peer.
    /// Called from the monitor loop on a 24h cadence — Bitcoin Core does the
    /// same so other nodes refresh our entry in their addrman before it ages
    /// out. No-op if we have no onion service yet (still bootstrapping Tor)
    /// or no peers connected.
    fn rebroadcast_self_ad(&self, pool: &PeerPool) {
        let Some(pubkey) = self.tor().and_then(|t| t.our_onion_pubkey()) else {
            return;
        };
        let mut sent = 0usize;
        pool.for_each_peer(|_addr, _is_inbound, peer| {
            // send_self_advertisement silently no-ops on peers that didn't
            // negotiate addrv2, so we don't need to filter here. Errors are
            // surfaced as Err to let `for_each_peer` drop dead connections.
            match peer.send_self_advertisement(pubkey, 8333) {
                Ok(()) => {
                    if peer.wants_addrv2() {
                        sent += 1;
                    }
                    Ok(())
                }
                Err(e) => Err(format!("self-ad: {}", e)),
            }
        });
        if sent > 0 {
            info!("Re-broadcast self-ad to {} peers", sent);
        }
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
        let relay_snapshot: HashMap<String, (HashSet<Txid>, HashSet<Txid>, u64)> = {
            let state = self.relay_state.lock().unwrap();
            state
                .iter()
                .map(|(addr, rs)| {
                    (
                        addr.clone(),
                        (rs.known_txids.clone(), rs.own_txids.clone(), rs.feefilter_rate),
                    )
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
        let own: HashSet<Txid> = ready
            .iter()
            .map(|(txid, _)| *txid)
            .filter(|txid| self.own_txs.is_active(txid))
            .collect();
        // All locks released — safe to do network I/O now

        let mut sent: Vec<(String, Txid)> = Vec::new();
        for ((txid, from_peer), (_, fee_rate_satkvb)) in ready.iter().zip(fee_rates.iter()) {
            let inv = vec![Inventory::Transaction(*txid)];

            pool.for_each_peer(|addr, _, peer| {
                // Don't relay back to sender
                if from_peer.as_deref() == Some(addr) {
                    return Ok(());
                }
                if let Some((known, own_known, feefilter)) = relay_snapshot.get(addr) {
                    // Skip if peer already knows about this tx (so an own
                    // tx rebroadcast only reaches peers that lack it)
                    if known.contains(txid) || own_known.contains(txid) {
                        return Ok(());
                    }
                    // BIP 133: skip if tx fee rate is below peer's feefilter
                    if *feefilter > 0 && *fee_rate_satkvb < *feefilter {
                        return Ok(());
                    }
                }
                peer.send_inv(inv.clone()).map_err(|e| format!("relay inv: {}", e))?;
                sent.push((addr.to_string(), *txid));
                Ok(())
            });

            self.stats.lock().unwrap().txs_relayed += 1;
        }

        // The peers we just told now know these txs: don't tell them again
        // (rebroadcasts), and allow them to fetch our own ones.
        if !sent.is_empty() {
            let mut state = self.relay_state.lock().unwrap();
            for (addr, txid) in sent {
                let entry = state.entry(addr).or_default();
                record_known_txid(entry, txid);
                if own.contains(&txid) {
                    entry.own_txids.insert(txid);
                }
            }
        }
    }

    /// True if `addr` is known to have own tx `txid` (we announced it to
    /// the peer, or it announced it to us).
    fn peer_knows_own_tx(&self, addr: &str, txid: &Txid) -> bool {
        self.relay_state
            .lock()
            .unwrap()
            .get(addr)
            .is_some_and(|s| s.own_txids.contains(txid))
    }

    /// downloads and validates the latest block — all within `timeout_secs`.
    ///
    /// Returns a `BlockNotification` with whatever validation was achieved
    /// before the deadline. This is designed for iOS's ~30-second background
    /// execution window (call with timeout_secs=25 to leave margin).
    #[cfg(test)]
    pub fn validate_latest_block(
        &self,
        timeout_secs: u32,
    ) -> Result<BlockNotification, SyncError> {
        self.validate_latest_block_in(&WakeBudget::new(timeout_secs.saturating_mul(1000)))
    }

    /// `validate_latest_block` against a wake budget (ticket 028): stops
    /// between steps once the budget is spent or cancelled, and records
    /// phase timings on it.
    pub fn validate_latest_block_in(
        &self,
        budget: &WakeBudget,
    ) -> Result<BlockNotification, SyncError> {
        let deadline = budget.deadline();

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
            "validate_latest_block: tip at {}, {} ms left",
            tip_height,
            budget.remaining_ms()
        );

        // Connect to one peer
        if budget.should_stop() {
            return Ok(BlockNotification::no_update(tip_height, &tip_header));
        }

        let mut pool = self.open_pool_until(our_height, Some(budget.deadline()))?;
        budget.mark(WakePhase::PeersReady);

        // Get headers from best peer
        if budget.should_stop() {
            return Ok(BlockNotification::no_update(tip_height, &tip_header));
        }

        let peer = pool.best_peer();
        if peer.is_none() {
            return Err(SyncError::Peer("no peers available".into()));
        }
        let mut peer = peer.unwrap();
        let peer_addr = peer.addr().to_string();

        let headers = match peer.get_headers_within(
            vec![tip_hash],
            BlockHash::all_zeros(),
            Some(budget.remaining()),
        ) {
            Ok(h) => {
                pool.return_peer(peer);
                h
            }
            // Out of budget waiting for headers: nothing learned.
            Err(_) if budget.should_stop() => {
                return Ok(BlockNotification::no_update(tip_height, &tip_header));
            }
            Err(e) => {
                if matches!(e, PeerError::WrongMagic { .. }) {
                    pool.ban_peer(&peer_addr);
                }
                return Err(SyncError::Peer(format!("{}: {}", peer_addr, e)));
            }
        };

        if headers.is_empty() {
            budget.mark(WakePhase::HeadersChecked);
            info!("validate_latest_block: no new headers, chain is current");
            return Ok(BlockNotification::no_update(tip_height, &tip_header));
        }

        // Enforce 2000-header limit (same as main sync loop)
        if headers.len() > 2000 {
            pool.misbehaving(&peer_addr, 100);
            return Err(SyncError::Validation(format!(
                "peer sent {} headers (max 2000)", headers.len()
            )));
        }

        // With a one-hash locator, an honest peer whose chain no longer
        // contains our tip answers from an earlier point (a reorg, ticket
        // 025): an error, but not misbehavior, so nothing below may
        // penalize it for that.
        if headers[0].prev_blockhash != tip_hash {
            return Err(SyncError::Validation(format!(
                "headers from {} don't extend our tip {} (reorg?)",
                peer_addr, tip_hash
            )));
        }

        // Bad headers cost the peer (ticket 024); the wake still ends here.
        if let Some(failed) = self.first_failed_header(&headers)? {
            pool.disconnect_and_deprioritize(&peer_addr, RELAYED_INVALID_CHAIN_PENALTY);
            return Err(SyncError::Validation(format!(
                "{} sent headers through invalid block {}",
                peer_addr, failed
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

        if let Err(e) = self.check_batch_anchor(&headers, tip_height + 1) {
            pool.misbehaving(&peer_addr, ANCHOR_CONFLICT_PENALTY);
            return Err(SyncError::Validation(e));
        }

        if let Err(e) = validate_headers(
            self.params,
            &headers,
            tip_hash,
            tip_height,
            &timestamps,
            tip_header.bits,
            &epoch_lookup,
        ) {
            pool.misbehaving(&peer_addr, INVALID_HEADERS_PENALTY);
            return Err(SyncError::Validation(format!("{}", e)));
        }

        let new_start = tip_height + 1;
        self.store
            .store_headers(&headers, new_start)
            .map_err(|e| SyncError::Store(format!("{}", e)))?;

        let new_tip = tip_height + headers.len() as u32;
        let new_header = &headers[headers.len() - 1];

        budget.mark(WakePhase::HeadersChecked);
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
        if budget.should_stop() {
            info!("validate_latest_block: deadline reached or cancelled after header sync");
            return Ok(notification);
        }

        if !self.ready_to_validate_blocks()? {
            info!("validate_latest_block: chain below minimum work or snapshot pending, skipping block validation");
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
        if self.drop_failed_from_chain(new_tip, block_hash)? {
            notification.validation_error = Some("block is recorded as invalid".into());
            return Ok(notification);
        }
        // Peers that served a mutated copy (ticket 024); one retry elsewhere.
        let mut bad_peers: Vec<String> = Vec::new();
        while bad_peers.len() < 2 {
            // A retry is new work: not once the wake is cancelled.
            if !bad_peers.is_empty() && budget.should_stop() {
                return Ok(notification);
            }
            let Some((block, from)) =
                fetch_requested_block(&mut pool, block_hash, deadline, &bad_peers)
            else {
                // Never got the requested block: validated_height stays put
                // and the caller gets the header-only notification.
                break;
            };
            budget.mark(WakePhase::BlockDownloaded);
            if budget.should_stop() {
                return Ok(notification);
            }

            // Crash recovery, as in `sync()` and `catch_up_blocks`: the UTXO
            // set may already hold this block, or a different one at this
            // height that must be rolled back before validating.
            match self.utxo_has_block(new_tip, block_hash) {
                Ok(false) => {}
                Ok(true) => {
                    if let Err(e) = self.finish_recovered_block(&block, new_tip) {
                        notification.validation_error = Some(format!("{}", e));
                        return Ok(notification);
                    }
                    notification.validation_error = None;
                    notification.validated = true;
                    budget.mark(WakePhase::Validated);
                    break;
                }
                Err(e) => {
                    notification.validation_error = Some(format!("{}", e));
                    return Ok(notification);
                }
            }

            // Mutation check, structure, scripts (ticket 024 classes).
            match self.check_block(&block, new_tip) {
                Ok(()) => {}
                Err(BlockFailure::Delivery(reason)) => {
                    warn!("validate_latest_block: mutated block from {}: {}", from, reason);
                    pool.misbehaving(&from, MUTATED_BLOCK_PENALTY);
                    notification.validation_error =
                        Some(format!("peer served a corrupted block: {}", reason));
                    bad_peers.push(from);
                    continue;
                }
                Err(BlockFailure::Consensus(reason)) => {
                    // The header came from `peer_addr` in this call.
                    self.reject_invalid_block(new_tip, block_hash, &reason)?;
                    self.ban_announcer(&mut pool, &peer_addr, block_hash);
                    notification.validation_error =
                        Some(format!("rejected invalid block: {}", reason));
                    return Ok(notification);
                }
                Err(BlockFailure::Local(e)) => {
                    notification.validation_error = Some(format!("{}", e));
                    return Ok(notification);
                }
            }
            notification.validation_error = None;

            // Apply to UTXO set
            if let Err(e) = self.utxo.apply_block(&block, new_tip) {
                notification.validation_error =
                    Some(format!("utxo: {}", e));
                return Ok(notification);
            }

            // Store block for NODE_NETWORK_LIMITED serving. A failure here
            // means the chain has advanced past `new_tip` in the UTXO set
            // but `block_store` doesn't have the bytes — we'd be unable to
            // serve this height to peers asking for it. Surface the error
            // so the Swift caller can retry, matching the propagation
            // pattern used in the main sync loop above.
            if let Err(e) = self.block_store.store_block(&block, new_tip) {
                notification.validation_error =
                    Some(format!("block store: {}", e));
                return Ok(notification);
            }

            // Remove confirmed transactions from mempool
            self.on_block_connected(&block, new_tip);

            self.store
                .set_validated_height(new_tip)
                .map_err(|e| SyncError::Store(format!("{}", e)))?;

            notification.validated = true;
            budget.mark(WakePhase::Validated);
            info!("validate_latest_block: block {} fully validated", new_tip);
            break;
        }

        Ok(notification)
    }

    /// Validate multiple blocks within a time budget. Preferred over
    /// `validate_latest_block` for push wakes when the node may be
    /// multiple blocks behind.
    #[cfg(test)]
    pub fn catch_up_blocks(
        &self,
        max_blocks: u32,
        budget_secs: u32,
    ) -> Result<CatchUpStatus, SyncError> {
        self.catch_up_blocks_in(max_blocks, &WakeBudget::new(budget_secs.saturating_mul(1000)))
    }

    /// `catch_up_blocks` against a wake budget (ticket 028). The budget's
    /// deadline was set at wake receipt, so time spent before this call
    /// (node open, transport) is already counted. Checks for cancellation
    /// between steps and returns partial progress, records phase timings,
    /// and clamps block downloads to the time left.
    pub fn catch_up_blocks_in(
        &self,
        max_blocks: u32,
        budget: &WakeBudget,
    ) -> Result<CatchUpStatus, SyncError> {

        // Read current state
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

        let mut validated_height = self
            .store
            .validated_height()
            .map_err(|e| SyncError::Store(format!("{}", e)))?;

        info!(
            "catch_up_blocks: tip {}, validated {}, max_blocks {}, {} ms left",
            tip_height,
            validated_height,
            max_blocks,
            budget.remaining_ms()
        );

        // Connect to peers. Until headers have been checked against peers
        // the local tip says nothing about the network's, so the early
        // returns below never report caught_up.
        if budget.should_stop() {
            return Ok(self.make_catchup_status(false, 0, validated_height, tip_height));
        }

        // Stop dialing new peers at the deadline (ticket 028).
        let mut pool = self.open_pool_until(our_height, Some(budget.deadline()))?;
        budget.mark(WakePhase::PeersReady);

        // Sync headers to tip
        if budget.should_stop() {
            return Ok(self.make_catchup_status(false, 0, validated_height, tip_height));
        }

        let mut peer = pool
            .best_peer()
            .ok_or_else(|| SyncError::Peer("no peers available".into()))?;
        let peer_addr = peer.addr().to_string();

        let headers = match peer.get_headers_within(
            vec![tip_hash],
            BlockHash::all_zeros(),
            Some(budget.remaining()),
        ) {
            Ok(h) => {
                pool.return_peer(peer);
                h
            }
            // Out of budget waiting for headers: headers stay unchecked.
            Err(_) if budget.should_stop() => {
                return Ok(self.make_catchup_status(false, 0, validated_height, tip_height));
            }
            Err(e) => {
                if matches!(e, PeerError::WrongMagic { .. }) {
                    pool.ban_peer(&peer_addr);
                }
                return Err(SyncError::Peer(format!("{}: {}", peer_addr, e)));
            }
        };

        let mut new_tip = tip_height;
        // Bad headers cost the peer and are dropped, but the backlog we
        // already have headers for is still validated (ticket 024).
        let mut header_error: Option<String> = None;

        'batch: {
            if headers.is_empty() {
                break 'batch;
            }
            if headers.len() > 2000 {
                pool.misbehaving(&peer_addr, 100);
                header_error = Some(format!("peer sent {} headers (max 2000)", headers.len()));
                break 'batch;
            }
            // As in `validate_latest_block`: a batch that doesn't extend our
            // tip is a reorg (ticket 025), not misbehavior.
            if headers[0].prev_blockhash != tip_hash {
                header_error = Some(format!(
                    "headers from {} don't extend our tip {} (reorg?)",
                    peer_addr, tip_hash
                ));
                break 'batch;
            }
            if let Some(failed) = self.first_failed_header(&headers)? {
                pool.disconnect_and_deprioritize(&peer_addr, RELAYED_INVALID_CHAIN_PENALTY);
                header_error = Some(format!("peer sent headers through invalid block {}", failed));
                break 'batch;
            }

            // Eclipse-resistance: cross-check the new headers against an
            // independent peer BEFORE validating or storing. If the cross-check
            // rejects, we drop the batch without touching the header store —
            // same ordering as the main sync loop. Called once per wake, not
            // per block — the per-block cost would be prohibitive during catch-up.
            let cross_check_locator = self
                .store
                .get_locator_hashes()
                .map_err(|e| SyncError::Store(format!("{}", e)))?;
            let active_first_hash = headers[0].block_hash();
            let strict = !self.has_min_chain_work()?;
            match self.cross_check_headers(
                &mut pool,
                &cross_check_locator,
                &peer_addr,
                active_first_hash,
                strict,
                Some(budget),
            ) {
                HeaderCrossCheck::Accept => {}
                // The budget ran out before any peer disagreed: not an
                // eclipse signal. Headers stay unchecked.
                HeaderCrossCheck::Inconclusive => {
                    info!("catch_up_blocks: budget spent during header cross-check");
                    return Ok(self.make_catchup_status(false, 0, validated_height, tip_height));
                }
                HeaderCrossCheck::Reject => {
                    // Headers were checked: peers disagree (possible eclipse),
                    // even if the budget ran out after the divergence.
                    budget.mark(WakePhase::HeadersChecked);
                    warn!("catch_up_blocks: header cross-check rejected batch from {}", peer_addr);
                    let mut status = self.make_catchup_status(
                        false,
                        0,
                        validated_height,
                        tip_height,
                    );
                    status.tip_disagreement = true;
                    status.error = Some("header tip cross-check failed: peer disagreement".into());
                    return Ok(status);
                }
            }

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

            if let Err(e) = self.check_batch_anchor(&headers, tip_height + 1) {
                pool.misbehaving(&peer_addr, ANCHOR_CONFLICT_PENALTY);
                header_error = Some(e);
                break 'batch;
            }

            if let Err(e) = validate_headers(
                self.params,
                &headers,
                tip_hash,
                tip_height,
                &timestamps,
                tip_header.bits,
                &epoch_lookup,
            ) {
                warn!("catch_up_blocks: invalid headers from {}: {}", peer_addr, e);
                pool.misbehaving(&peer_addr, INVALID_HEADERS_PENALTY);
                header_error = Some(format!("invalid headers from peer: {}", e));
                break 'batch;
            }

            let new_start = tip_height + 1;
            self.store
                .store_headers(&headers, new_start)
                .map_err(|e| SyncError::Store(format!("{}", e)))?;

            new_tip = tip_height + headers.len() as u32;
            info!(
                "catch_up_blocks: synced headers {}-{} (PoW validated, cross-checked)",
                new_start, new_tip
            );
        }
        budget.mark(WakePhase::HeadersChecked);

        // No block validation until the chain has minimum work and any
        // pending snapshot is bound to it (may advance validated_height).
        if !self.ready_to_validate_blocks()? {
            info!("catch_up_blocks: chain below minimum work or snapshot pending, skipping block validation");
            return Ok(CatchUpStatus {
                error: header_error,
                ..self.make_catchup_status(false, 0, validated_height, new_tip)
            });
        }
        validated_height = self
            .store
            .validated_height()
            .map_err(|e| SyncError::Store(format!("{}", e)))?;

        // Block validation loop — oldest-first
        let mut blocks_validated: u32 = 0;
        // Peers that served a bad copy of the block at `validated_height
        // + 1` (ticket 024); cleared whenever a block is connected.
        let mut bad_peers: Vec<String> = Vec::new();

        while validated_height < new_tip
            && blocks_validated < max_blocks
            && !budget.should_stop()
        {
            let next_height = validated_height + 1;

            let block_hash = self
                .store
                .get_hash_at_height(next_height)
                .map_err(|e| SyncError::Store(format!("{}", e)))?
                .ok_or_else(|| {
                    SyncError::Store(format!("no hash at height {}", next_height))
                })?;
            if self.drop_failed_from_chain(next_height, block_hash)? {
                new_tip = next_height - 1;
                break;
            }

            let block_peer = if bad_peers.is_empty() {
                pool.any_peer()
            } else {
                pool.peer_addr_excluding(&bad_peers)
                    .and_then(|addr| pool.checkout_peer_by_addr(&addr))
            };
            let mut block_peer = match block_peer {
                Some(p) => p,
                None => {
                    let error = if bad_peers.is_empty() {
                        "no peers available for block download".to_string()
                    } else {
                        format!("Peers are serving corrupted blocks at height {}", next_height)
                    };
                    return Ok(CatchUpStatus {
                        error: Some(error),
                        ..self.make_catchup_status(false, blocks_validated, validated_height, new_tip)
                    });
                }
            };
            let block_peer_addr = block_peer.addr().to_string();

            let block = match block_peer.get_block_within(block_hash, Some(budget.remaining())) {
                Ok(b) => {
                    pool.return_peer(block_peer);
                    budget.mark(WakePhase::BlockDownloaded);
                    b
                }
                // The read timeout was clamped to the budget: running out
                // of it is partial progress, not a peer error.
                Err(e) if budget.should_stop() => {
                    info!("catch_up_blocks: budget spent downloading {}: {}", next_height, e);
                    break;
                }
                Err(e) => {
                    if matches!(e, PeerError::WrongMagic { .. }) {
                        pool.ban_peer(&block_peer_addr);
                    }
                    return Ok(CatchUpStatus {
                        error: Some(format!("block download at {}: {}", next_height, e)),
                        ..self.make_catchup_status(false, blocks_validated, validated_height, new_tip)
                    });
                }
            };

            // Defense in depth behind get_block's hash binding (022): a
            // bad delivery, like a mutated block.
            if block.block_hash() != block_hash {
                warn!(
                    "catch_up_blocks: {} sent {} for height {}, expected {}",
                    block_peer_addr,
                    block.block_hash(),
                    next_height,
                    block_hash
                );
                pool.misbehaving(&block_peer_addr, BLOCK_NOT_RECEIVED_PENALTY);
                bad_peers.push(block_peer_addr);
                continue;
            }

            // Crash recovery: the UTXO set already holds this very block
            // (a different block there is rolled back first).
            if self.utxo_has_block(next_height, block_hash)? {
                if let Err(e) = self.finish_recovered_block(&block, next_height) {
                    return Ok(CatchUpStatus {
                        error: Some(format!("block {}: {}", next_height, e)),
                        ..self.make_catchup_status(false, blocks_validated, validated_height, new_tip)
                    });
                }
                validated_height = next_height;
                blocks_validated += 1;
                bad_peers.clear();
                continue;
            }

            // Mutation check, structure, scripts (ticket 024 classes).
            match self.check_block(&block, next_height) {
                Ok(()) => {}
                Err(BlockFailure::Delivery(reason)) => {
                    warn!(
                        "catch_up_blocks: mutated block {} from {}: {}",
                        next_height, block_peer_addr, reason
                    );
                    pool.misbehaving(&block_peer_addr, MUTATED_BLOCK_PENALTY);
                    bad_peers.push(block_peer_addr);
                    continue;
                }
                Err(BlockFailure::Consensus(reason)) => {
                    self.reject_invalid_block(next_height, block_hash, &reason)?;
                    // Only the peer whose headers (this call) put the block
                    // in our chain vouched for it.
                    if (tip_height + 1..=new_tip).contains(&next_height) {
                        self.ban_announcer(&mut pool, &peer_addr, block_hash);
                    }
                    return Ok(CatchUpStatus {
                        error: Some(format!(
                            "Rejected an invalid block from the network at height {}: {}",
                            next_height, reason
                        )),
                        invalid_chain_detected: true,
                        ..self.make_catchup_status(
                            false,
                            blocks_validated,
                            validated_height,
                            next_height - 1,
                        )
                    });
                }
                Err(BlockFailure::Local(e)) => return Err(e),
            }

            // Update UTXO set
            self.utxo
                .apply_block(&block, next_height)
                .map_err(|e| SyncError::Store(format!("{}", e)))?;

            // Store block for NODE_NETWORK_LIMITED serving
            if let Err(e) = self.block_store.store_block(&block, next_height) {
                return Ok(CatchUpStatus {
                    error: Some(format!("block store at {}: {}", next_height, e)),
                    ..self.make_catchup_status(false, blocks_validated, validated_height, new_tip)
                });
            }

            // Remove confirmed transactions from mempool
            self.on_block_connected(&block, next_height);

            self.store
                .set_validated_height(next_height)
                .map_err(|e| SyncError::Store(format!("{}", e)))?;

            validated_height = next_height;
            blocks_validated += 1;
            bad_peers.clear();
            budget.mark(WakePhase::Validated);

            info!(
                "catch_up_blocks: validated block {} ({}/{})",
                next_height, blocks_validated, max_blocks
            );
        }

        let caught_up = validated_height >= new_tip;
        info!(
            "catch_up_blocks: done — validated {} blocks, height {}/{}, caught_up={}",
            blocks_validated, validated_height, new_tip, caught_up
        );

        // `caught_up` with an error set would read as plain success to the
        // app (NotificationManager.makeRecord), so an error always wins.
        let caught_up = caught_up && header_error.is_none();
        Ok(CatchUpStatus {
            error: header_error,
            ..self.make_catchup_status(caught_up, blocks_validated, validated_height, new_tip)
        })
    }

    /// Build a CatchUpStatus, reading block hash/timestamp from the store.
    fn make_catchup_status(
        &self,
        caught_up: bool,
        blocks_validated: u32,
        current_height: u32,
        target_height: u32,
    ) -> CatchUpStatus {
        let (tip_block_hash, tip_timestamp) = self
            .store
            .get_header_at_height(current_height)
            .ok()
            .flatten()
            .map(|(hash, header)| (hash.to_string(), header.time))
            .unwrap_or_else(|| ("".into(), 0));

        CatchUpStatus {
            caught_up,
            blocks_validated,
            current_height,
            target_height,
            tip_block_hash,
            tip_timestamp,
            error: None,
            tip_disagreement: false,
            invalid_chain_detected: false,
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
    /// The snapshot file itself is corrupt or doesn't match the anchor.
    SnapshotInvalid(String),
}

impl std::fmt::Display for SyncError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SyncError::NoPeers => write!(f, "no peers found via DNS seeds"),
            SyncError::Peer(s) => write!(f, "peer error: {}", s),
            SyncError::Validation(s) => write!(f, "validation error: {}", s),
            SyncError::Store(s) => write!(f, "store error: {}", s),
            SyncError::SnapshotInvalid(s) => write!(f, "snapshot rejected: {}", s),
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

// Own-transaction broadcast tests (ticket 033) live in their own file to
// keep this module's diff small.
#[cfg(test)]
#[path = "sync_own_tx_tests.rs"]
mod own_tx_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::p2p::address::{AddrV2, AddrV2Message};
    use bitcoin::p2p::ServiceFlags;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
    use crate::p2p::tests::{loopback_peer_pair, synthetic_block, write_message};

    // ── fetch_requested_block (ticket 022 wake path) ───────────────────

    /// Pool of outbound loopback peers (regtest: no netgroup diversity,
    /// so each counts as independent); returns the server halves in pool
    /// order.
    fn loopback_pool(n: usize) -> (PeerPool, Vec<(String, std::net::TcpStream)>) {
        let pool = PeerPool::new_for_test_with(ChainParams::regtest());
        let mut servers = Vec::new();
        for _ in 0..n {
            let (peer, server) = loopback_peer_pair();
            let addr = peer.addr().to_string();
            pool.add_outbound_peer_for_test(peer);
            servers.push((addr, server));
        }
        (pool, servers)
    }

    /// Stream blocks other than the one being requested, so `get_block`
    /// ends in `BlockNotReceived` (unrequested-block cap or message bound).
    fn serve_wrong_block(server: &mut std::net::TcpStream) {
        for _ in 0..20 {
            write_message(server, NetworkMessage::Block(synthetic_block(2)));
        }
    }

    #[test]
    fn fetch_requested_block_returns_none_when_peers_serve_wrong_block() {
        // Unit-level regression for the push-wake path: when no peer
        // delivers the requested block, the fetch yields None, so
        // validate_latest_block never reaches apply_block or
        // set_validated_height. (End-to-end coverage lands with ticket 027.)
        let (mut pool, mut servers) = loopback_pool(2);
        for (_, server) in servers.iter_mut() {
            serve_wrong_block(server);
        }
        let wanted_hash = synthetic_block(1).block_hash();
        let deadline = Instant::now() + Duration::from_secs(30);

        assert!(fetch_requested_block(&mut pool, wanted_hash, deadline, &[]).is_none());
        for (addr, _) in &servers {
            assert_eq!(
                pool.get_score(addr),
                Some(100 - BLOCK_NOT_RECEIVED_PENALTY as i32),
                "peer {} should be penalized",
                addr
            );
        }
    }

    #[test]
    fn fetch_requested_block_retries_with_another_peer() {
        let (mut pool, mut servers) = loopback_pool(2);
        let wanted = synthetic_block(1);
        let wanted_hash = wanted.block_hash();
        serve_wrong_block(&mut servers[0].1);
        write_message(&mut servers[1].1, NetworkMessage::Block(wanted));
        let deadline = Instant::now() + Duration::from_secs(30);

        let (got, from) =
            fetch_requested_block(&mut pool, wanted_hash, deadline, &[]).expect("block");
        assert_eq!(got.block_hash(), wanted_hash);
        assert_eq!(from, servers[1].0);
        assert_eq!(
            pool.get_score(&servers[0].0),
            Some(100 - BLOCK_NOT_RECEIVED_PENALTY as i32)
        );
        assert_eq!(pool.get_score(&servers[1].0), Some(100));
    }

    #[test]
    fn fetch_requested_block_does_not_penalize_a_peer_our_deadline_cut_off() {
        // A silent peer and a 200 ms budget: our deadline ends the request,
        // which says nothing about the peer (ticket 028).
        let (mut pool, servers) = loopback_pool(1);
        let wanted_hash = synthetic_block(1).block_hash();
        let start = Instant::now();
        let deadline = start + Duration::from_millis(200);
        assert!(fetch_requested_block(&mut pool, wanted_hash, deadline, &[]).is_none());
        assert!(start.elapsed() < Duration::from_secs(1), "{:?}", start.elapsed());
        assert_eq!(pool.get_score(&servers[0].0), Some(100));
    }

    #[test]
    fn fetch_requested_block_does_not_retry_past_deadline() {
        let (mut pool, mut servers) = loopback_pool(2);
        serve_wrong_block(&mut servers[0].1);
        write_message(&mut servers[1].1, NetworkMessage::Block(synthetic_block(1)));
        let wanted_hash = synthetic_block(1).block_hash();

        // Deadline already passed: the first attempt still runs (the
        // caller checked the deadline before calling), but no retry.
        assert!(fetch_requested_block(&mut pool, wanted_hash, Instant::now(), &[]).is_none());
        assert_eq!(pool.get_score(&servers[1].0), Some(100));
    }

    // ── cross_check_headers under a wake budget (ticket 028) ─────────────

    /// Three loopback peers: active, tiebreaker, witness. The witness gets
    /// a reward so it is picked first. The syncer is a regtest node at
    /// genesis, so cross-check answers can carry valid headers.
    fn cross_check_pool() -> (PeerPool, Vec<(String, std::net::TcpStream)>, tempfile::TempDir, HeaderSync) {
        let (pool, servers) = loopback_pool(3);
        pool.reward(&servers[2].0, 5);
        let dir = tempfile::TempDir::new().unwrap();
        let syncer = regtest_syncer(&dir);
        (pool, servers, dir, syncer)
    }

    fn regtest_syncer(dir: &tempfile::TempDir) -> HeaderSync {
        HeaderSync::with_config(SyncConfig {
            db_path: dir.path().join("headers.sqlite3").to_str().unwrap().to_string(),
            tor: None,
            params: ChainParams::regtest(),
            peers: PeerSource::Static(vec![]),
        })
        .unwrap()
    }

    /// The locator a regtest node at genesis sends.
    fn genesis_locator() -> Vec<BlockHash> {
        vec![crate::testkit::FixtureChain::new().hash_at(0)]
    }

    /// A valid regtest header on genesis; different `salt`s give
    /// different (competing) headers.
    fn valid_header(salt: u32) -> Header {
        let mut chain = crate::testkit::FixtureChain::new().fork_at(0);
        for _ in 0..salt {
            chain = chain.fork_at(0);
        }
        chain.mine(1);
        chain.block(1).header
    }

    /// PR #24 review: two colluding witnesses answering with the same junk
    /// used to outvote the active peer until it was banned. Junk is now no
    /// opinion and costs the active peer nothing. Junk that doesn't connect
    /// to our locator costs its sender nothing either (honest peers without
    /// our blocks answer like that); junk that is invalid in itself (here,
    /// the wrong difficulty) costs its sender until it is banned.
    #[test]
    fn colluding_junk_witnesses_cannot_get_the_active_peer_banned() {
        let mut bad_bits = valid_header(0);
        bad_bits.bits = bitcoin::CompactTarget::from_consensus(0x1d00ffff);
        for (junk, provably_invalid) in [(synthetic_block(2).header, false), (bad_bits, true)] {
            let (mut pool, mut servers, _dir, syncer) = cross_check_pool();
            let active = servers[0].0.clone();
            for round in 0..4 {
                for (addr, server) in servers.iter_mut().skip(1) {
                    // Only the current witness (highest score) is asked.
                    if pool.cross_check_peer(&[active.clone()]).as_deref() == Some(addr.as_str()) {
                        write_message(server, NetworkMessage::Headers(vec![junk]));
                    }
                }
                let r = syncer.cross_check_headers(
                    &mut pool,
                    &genesis_locator(),
                    &active,
                    valid_header(0).block_hash(),
                    false,
                    None,
                );
                assert!(matches!(r, HeaderCrossCheck::Accept), "round {}", round);
            }
            assert_eq!(pool.get_score(&active), Some(100), "active peer paid for junk");
            assert_eq!(pool.get_demerit(&active), Some(0));
            assert!(!pool.is_banned(&active));
            for (addr, _) in &servers[1..] {
                assert_eq!(
                    pool.is_banned(addr),
                    provably_invalid,
                    "junk sender {} (provably invalid: {})",
                    addr,
                    provably_invalid
                );
            }
        }
    }

    /// Re-review of 1cbfcd8: in an eclipse recovery our stored chain may be
    /// fake, and honest witnesses don't have its blocks. Asked with a
    /// locator of only such a block, they answer from genesis: that is no
    /// opinion, never a penalty. Asked with that block plus our full
    /// locator (as the diverging-batch re-check now does), they land on a
    /// real entry and simply disagree: a demerit for the active peer, still
    /// nothing against them.
    #[test]
    fn honest_witnesses_without_our_fake_blocks_are_never_penalized() {
        let (mut pool, mut servers, _dir, syncer) = cross_check_pool();
        let mut fake = crate::testkit::FixtureChain::new().fork_at(0).fork_at(0);
        fake.mine(10);
        let fake_headers: Vec<Header> = (1..=10).map(|h| fake.block(h).header).collect();
        syncer.store.store_headers(&fake_headers, 1).unwrap();
        let mut honest = crate::testkit::FixtureChain::new();
        honest.mine(3);
        let honest_batch: Vec<Header> = (1..=3).map(|h| honest.block(h).header).collect();
        let (active, tiebreaker, witness) =
            (servers[0].0.clone(), servers[1].0.clone(), servers[2].0.clone());
        // The attacker's diverging batch: builds on fake block 5.
        let after = fake.hash_at(5);
        let active_first = valid_header(7).block_hash();

        // One-hash locator: the witness answers from genesis. No opinion.
        for round in 0..4 {
            write_message(&mut servers[2].1, NetworkMessage::Headers(honest_batch.clone()));
            let r = syncer.cross_check_headers(&mut pool, &[after], &active, active_first, true, None);
            assert!(matches!(r, HeaderCrossCheck::Reject), "round {}", round);
        }
        // Full locator: ordinary disagreement.
        let mut locator = vec![after];
        locator.extend(syncer.store.get_locator_hashes().unwrap());
        for round in 0..4 {
            for (_, server) in servers.iter_mut().skip(1) {
                write_message(server, NetworkMessage::Headers(honest_batch.clone()));
            }
            let r = syncer.cross_check_headers(&mut pool, &locator, &active, active_first, true, None);
            assert!(matches!(r, HeaderCrossCheck::Reject), "round {}", round);
        }
        for (addr, fresh) in [(&witness, 105), (&tiebreaker, 100)] {
            assert!(!pool.is_banned(addr), "honest witness {} banned", addr);
            assert_eq!(pool.get_score(addr), Some(fresh), "honest witness {} penalized", addr);
            assert_eq!(pool.get_demerit(addr), Some(0));
        }
        assert!(pool.get_demerit(&active).unwrap() > 0, "outvoted active peer not deprioritized");
        assert_eq!(pool.count(), 3);
    }

    /// Even valid headers from colluding witnesses (a real competing
    /// chain) only deprioritize the outvoted active peer: divergence is
    /// never proof, so it can't get an honest peer banned.
    #[test]
    fn outvoted_active_peer_is_deprioritized_never_banned() {
        let (mut pool, mut servers, _dir, syncer) = cross_check_pool();
        let active = servers[0].0.clone();
        for round in 0..6 {
            for (_, server) in servers.iter_mut().skip(1) {
                write_message(server, NetworkMessage::Headers(vec![valid_header(0)]));
            }
            let r = syncer.cross_check_headers(
                &mut pool,
                &genesis_locator(),
                &active,
                valid_header(1).block_hash(),
                false,
                None,
            );
            assert!(matches!(r, HeaderCrossCheck::Reject), "round {}", round);
        }
        assert!(!pool.is_banned(&active), "divergence alone banned the active peer");
        assert_eq!(pool.count(), 3);
        assert_eq!(pool.get_score(&active), Some(100), "divergence touched the ban score");
        assert!(pool.get_demerit(&active).unwrap() > 0, "outvoted peer not deprioritized");
        // A later routine penalty can't combine with it into a ban.
        pool.misbehaving(&active, BLOCK_NOT_RECEIVED_PENALTY);
        assert!(!pool.is_banned(&active));
    }

    /// Inbound peers are never witnesses or tiebreakers, whatever they'd
    /// answer: with only inbound peers besides the active one there is no
    /// cross-check (best-effort accept), and nobody is penalized.
    #[test]
    fn inbound_peers_are_never_cross_check_witnesses() {
        let dir = tempfile::TempDir::new().unwrap();
        let syncer = regtest_syncer(&dir);
        let (mut pool, servers) = loopback_pool(1);
        let active = servers[0].0.clone();
        let mut inbound_servers = Vec::new();
        for i in 0..2 {
            let (mut peer, mut server) = loopback_peer_pair();
            peer.set_addr_for_test(&format!("inbound#{}", i), true);
            write_message(&mut server, NetworkMessage::Headers(vec![valid_header(0)]));
            assert!(pool.add_inbound_peer(peer));
            inbound_servers.push(server);
        }
        let r = syncer.cross_check_headers(
            &mut pool,
            &genesis_locator(),
            &active,
            valid_header(1).block_hash(),
            false,
            None,
        );
        assert!(matches!(r, HeaderCrossCheck::Accept));
        assert_eq!(pool.get_score(&active), Some(100));
        // Strict mode fails closed instead: still no inbound witness.
        let r = syncer.cross_check_headers(
            &mut pool,
            &genesis_locator(),
            &active,
            valid_header(1).block_hash(),
            true,
            None,
        );
        assert!(matches!(r, HeaderCrossCheck::Reject));
        assert_eq!(pool.get_score(&active), Some(100));
        assert_eq!(pool.count(), 3);
    }

    #[test]
    fn cross_check_divergence_survives_a_tiebreaker_deadline() {
        // The witness contradicts the active peer, then the tiebreaker
        // runs into our deadline. The divergence was seen: Reject (the
        // wake reports tip_disagreement), and the tiebreaker isn't blamed.
        let (mut pool, mut servers, _dir, syncer) = cross_check_pool();
        let (active, tiebreaker, witness) = (servers[0].0.clone(), servers[1].0.clone(), servers[2].0.clone());
        write_message(&mut servers[2].1, NetworkMessage::Headers(vec![valid_header(0)]));
        let budget = WakeBudget::new(300);

        let start = Instant::now();
        let r = syncer.cross_check_headers(&mut pool, &genesis_locator(), &active, synthetic_block(1).block_hash(), false, Some(&budget));
        assert!(matches!(r, HeaderCrossCheck::Reject));
        assert!(start.elapsed() < Duration::from_secs(1), "{:?}", start.elapsed());
        assert_eq!(pool.get_score(&tiebreaker), Some(100), "deadline counted against tiebreaker");
        assert_eq!(pool.count(), 3, "tiebreaker removed over our deadline");
        assert_eq!(pool.get_score(&active), Some(100));
        assert_eq!(pool.get_demerit(&active), Some(HEADER_DISAGREEMENT_PENALTY as i32));
        assert_eq!(pool.get_demerit(&witness), Some(HEADER_DISAGREEMENT_PENALTY as i32));
    }

    #[test]
    fn cross_check_deadline_before_any_answer_is_inconclusive() {
        // Silent witness: the budget ends before anyone disagrees. Not an
        // eclipse signal, and no peer pays for our deadline.
        for strict in [false, true] {
            let (mut pool, servers, _dir, syncer) = cross_check_pool();
            let budget = WakeBudget::new(200);
            let r = syncer.cross_check_headers(&mut pool, &genesis_locator(), &servers[0].0, synthetic_block(1).block_hash(), strict, Some(&budget));
            assert!(matches!(r, HeaderCrossCheck::Inconclusive), "strict {}", strict);
            assert_eq!(pool.count(), 3, "witness removed over our deadline");
            assert_eq!(pool.get_score(&servers[0].0), Some(100));
            assert_eq!(pool.get_score(&servers[1].0), Some(100));
            assert_eq!(pool.get_score(&servers[2].0), Some(105));
        }
    }

    #[test]
    fn cross_check_cancelled_before_the_witness_is_inconclusive() {
        let (mut pool, mut servers, _dir, syncer) = cross_check_pool();
        // The witness would contradict, but we never ask it.
        write_message(&mut servers[2].1, NetworkMessage::Headers(vec![valid_header(0)]));
        let budget = WakeBudget::new(10_000);
        budget.cancel();
        let r = syncer.cross_check_headers(&mut pool, &genesis_locator(), &servers[0].0, synthetic_block(1).block_hash(), false, Some(&budget));
        assert!(matches!(r, HeaderCrossCheck::Inconclusive));
        assert_eq!(pool.get_score(&servers[0].0), Some(100));
    }

    // ── is_routable ────────────────────────────────────────────────────

    #[test]
    fn is_routable_rejects_loopback() {
        let v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8333);
        assert!(!is_routable(&v4));
        let v6 = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 8333);
        assert!(!is_routable(&v6));
    }

    #[test]
    fn is_routable_rejects_unspecified_and_multicast() {
        let v4 = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8333);
        assert!(!is_routable(&v4));
        let mcast = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)), 8333);
        assert!(!is_routable(&mcast));
    }

    #[test]
    fn is_routable_rejects_link_local_and_broadcast() {
        let link = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1)), 8333);
        assert!(!is_routable(&link));
        let bcast = SocketAddr::new(IpAddr::V4(Ipv4Addr::BROADCAST), 8333);
        assert!(!is_routable(&bcast));
    }

    #[test]
    fn is_routable_accepts_normal_v4() {
        // 1.2.3.4 — public-ish, not in any reject list.
        let sock = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 8333);
        assert!(is_routable(&sock));
    }

    #[test]
    fn is_routable_accepts_rfc1918() {
        // We deliberately allow RFC1918 so node operators can talk to a
        // self-hosted peer on the LAN. This pins down that decision.
        let sock = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 8333);
        assert!(is_routable(&sock));
    }

    // ── unix_now_u32 ───────────────────────────────────────────────────

    #[test]
    fn unix_now_u32_is_after_2024() {
        // Sanity: the timestamp should be well past 2024-01-01 = 1704067200.
        // If this trips, the host clock is broken or we wrapped to 0.
        let ts = unix_now_u32();
        assert!(ts > 1_700_000_000, "ts={} suspiciously small", ts);
    }

    // ── format_v2_address ──────────────────────────────────────────────

    #[test]
    fn format_v2_address_ipv4() {
        let msg = AddrV2Message {
            time: 0,
            services: ServiceFlags::NETWORK,
            addr: AddrV2::Ipv4(Ipv4Addr::new(8, 8, 8, 8)),
            port: 8333,
        };
        assert_eq!(format_v2_address(&msg), Some("8.8.8.8:8333".to_string()));
    }

    #[test]
    fn format_v2_address_ipv6() {
        let msg = AddrV2Message {
            time: 0,
            services: ServiceFlags::NETWORK,
            addr: AddrV2::Ipv6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
            port: 8333,
        };
        let formatted = format_v2_address(&msg).unwrap();
        // SocketAddr's IPv6 Display wraps the address in brackets.
        assert!(formatted.contains("2001:db8"));
        assert!(formatted.ends_with(":8333"));
    }

    #[test]
    fn format_v2_address_torv3_round_trip() {
        // Encode a known pubkey, format the AddrV2 message, parse the
        // hostname back through tor_v3, and confirm we recover the pubkey.
        let pubkey = [0x42u8; 32];
        let msg = AddrV2Message {
            time: 0,
            services: ServiceFlags::NETWORK,
            addr: AddrV2::TorV3(pubkey),
            port: 8333,
        };
        let formatted = format_v2_address(&msg).expect("torv3 should format");
        assert!(formatted.ends_with(":8333"));
        assert!(formatted.contains(".onion"));
        let recovered = crate::tor_v3::hostname_to_pubkey(&formatted).unwrap();
        assert_eq!(recovered, pubkey);
    }

    #[test]
    fn format_v2_address_rejects_zero_port() {
        let msg = AddrV2Message {
            time: 0,
            services: ServiceFlags::NETWORK,
            addr: AddrV2::Ipv4(Ipv4Addr::new(8, 8, 8, 8)),
            port: 0,
        };
        assert_eq!(format_v2_address(&msg), None);
    }

    #[test]
    fn format_v2_address_rejects_loopback() {
        let msg = AddrV2Message {
            time: 0,
            services: ServiceFlags::NETWORK,
            addr: AddrV2::Ipv4(Ipv4Addr::LOCALHOST),
            port: 8333,
        };
        assert_eq!(format_v2_address(&msg), None);
    }

    // ── addr_entry_to_v1 ───────────────────────────────────────────────

    #[test]
    fn addr_entry_to_v1_ipv4() {
        let result = addr_entry_to_v1(123456, "1.2.3.4:8333");
        let (ts, addr) = result.expect("ipv4 should parse");
        assert_eq!(ts, 123456);
        // The Address has services + ip + port. Re-serialize to inspect.
        let sock = addr.socket_addr().unwrap();
        assert_eq!(sock, SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 8333)));
    }

    #[test]
    fn addr_entry_to_v1_drops_onion() {
        // V1 wire format can't carry a 32-byte pubkey, so onion entries
        // must be silently dropped here. Peers that handle addrv2 take
        // the other branch.
        let result = addr_entry_to_v1(0, "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrstuvwx.onion:8333");
        assert!(result.is_none());
    }

    #[test]
    fn addr_entry_to_v1_rejects_garbage() {
        assert!(addr_entry_to_v1(0, "not a socket addr").is_none());
        assert!(addr_entry_to_v1(0, "1.2.3.4").is_none()); // missing port
    }

    // ── addr_entry_to_v2 ───────────────────────────────────────────────

    #[test]
    fn addr_entry_to_v2_ipv4() {
        let msg = addr_entry_to_v2(99, "1.2.3.4:8333").expect("ipv4 should parse");
        assert_eq!(msg.time, 99);
        assert_eq!(msg.port, 8333);
        match msg.addr {
            AddrV2::Ipv4(v4) => assert_eq!(v4, Ipv4Addr::new(1, 2, 3, 4)),
            _ => panic!("expected v4"),
        }
    }

    #[test]
    fn addr_entry_to_v2_ipv6() {
        let msg = addr_entry_to_v2(0, "[2001:db8::1]:8333").expect("ipv6 should parse");
        assert_eq!(msg.port, 8333);
        match msg.addr {
            AddrV2::Ipv6(v6) => {
                assert_eq!(v6, Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
            }
            _ => panic!("expected v6"),
        }
    }

    #[test]
    fn addr_entry_to_v2_torv3_round_trip() {
        // Round-trip through tor_v3 to make sure the host:port → pubkey
        // path inside addr_entry_to_v2 is wired correctly.
        let pubkey = [0x99u8; 32];
        let host = crate::tor_v3::pubkey_to_hostname(&pubkey);
        let entry = format!("{}:8333", host);
        let msg = addr_entry_to_v2(42, &entry).expect("torv3 should parse");
        assert_eq!(msg.time, 42);
        assert_eq!(msg.port, 8333);
        match msg.addr {
            AddrV2::TorV3(pk) => assert_eq!(pk, pubkey),
            _ => panic!("expected torv3"),
        }
    }

    #[test]
    fn addr_entry_to_v2_rejects_garbage() {
        assert!(addr_entry_to_v2(0, "garbage").is_none());
        // .onion suffix but not a valid v3 hostname (wrong length).
        assert!(addr_entry_to_v2(0, "shortbutfake.onion:8333").is_none());
    }

    // ── derive_sibling_path ────────────────────────────────────────────

    #[test]
    fn derive_sibling_path_with_parent() {
        let result = derive_sibling_path("/var/data/headers.sqlite3", "utxo-lmdb");
        assert_eq!(result, "/var/data/utxo-lmdb");
    }

    #[test]
    fn derive_sibling_path_bare_filename() {
        // No usable parent → fall back to "./<name>". The "./" prefix is
        // important: a bare relative name would be ambiguous if cwd ever
        // changes, while "./" pins it to the current directory.
        let result = derive_sibling_path("headers.sqlite3", "utxo-lmdb");
        assert_eq!(result, "./utxo-lmdb");
    }

    // ── poisson_delay_secs ─────────────────────────────────────────────

    #[test]
    fn poisson_delay_is_positive_and_bounded() {
        // Each call uses a fresh RandomState; we just verify the value
        // is in a sane range. -ln(u) for u in (0, 1] is in [0, ~34) when
        // u >= 1e-15 (we clamp at the bottom).
        let mean = 2.0;
        for _ in 0..100 {
            let d = poisson_delay_secs(mean);
            assert!(d >= 0.0, "delay should be non-negative: {}", d);
            // 1e-15 floor → max -ln = ~34.5, times mean=2 → ~69.
            assert!(d < 100.0, "delay should be bounded: {}", d);
        }
    }

    // ── record_known_txid (per-peer dedup cap) ────────────────────────

    /// Build a `PeerRelayState` with an empty txid set for the cap tests.
    fn empty_relay_state() -> PeerRelayState {
        PeerRelayState {
            wants_sendheaders: false,
            feefilter_rate: 0,
            known_txids: HashSet::new(),
            own_txids: HashSet::new(),
            getaddr_responded: false,
        }
    }

    /// Synthesize `n` distinct txids for use as test inputs. Each is the
    /// little-endian counter padded to 32 bytes.
    fn synthetic_txid(i: usize) -> Txid {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&(i as u64).to_le_bytes());
        Txid::from_byte_array(bytes)
    }

    #[test]
    fn record_known_txid_inserts_below_cap() {
        let mut s = empty_relay_state();
        for i in 0..50 {
            record_known_txid(&mut s, synthetic_txid(i));
        }
        assert_eq!(s.known_txids.len(), 50);
    }

    #[test]
    fn record_known_txid_resets_on_overflow() {
        // Drive the helper past MAX_KNOWN_TXIDS_PER_PEER and assert the
        // set never grows above the cap. The reset is coarse — we clear the
        // entire set rather than evict individually — so after the (cap+1)th
        // insert the size drops back to 1 and starts climbing again.
        let mut s = empty_relay_state();
        for i in 0..(MAX_KNOWN_TXIDS_PER_PEER + 5) {
            record_known_txid(&mut s, synthetic_txid(i));
            assert!(
                s.known_txids.len() <= MAX_KNOWN_TXIDS_PER_PEER,
                "known_txids grew past cap at i={}: len={}",
                i,
                s.known_txids.len()
            );
        }
        // After the overflow, the set has been cleared and the last 5
        // insertions accumulated on a fresh set.
        assert_eq!(s.known_txids.len(), 5);
    }

    #[test]
    fn record_known_txid_burst_stays_bounded() {
        // Worst case: an attacker bursts 50k unique txids in a single INV
        // (the Bitcoin protocol max). The cap must hold throughout.
        let mut s = empty_relay_state();
        for i in 0..50_000 {
            record_known_txid(&mut s, synthetic_txid(i));
        }
        assert!(
            s.known_txids.len() <= MAX_KNOWN_TXIDS_PER_PEER,
            "burst grew set past cap: {}",
            s.known_txids.len()
        );
    }

    // ── Chain anchoring (ticket 023) ───────────────────────────────────

    use crate::assumeutxo::MIN_CHAIN_WORK;
    use crate::utxo::UtxoEntry;
    use bitcoin::pow::CompactTarget;
    use tempfile::TempDir;

    /// Anchor height used by these tests (the mainnet one is 943,500).
    const TEST_ANCHOR_HEIGHT: u32 = 5;

    fn fresh_sync(dir: &TempDir) -> HeaderSync {
        let db = dir.path().join("headers.sqlite3");
        HeaderSync::new(db.to_str().unwrap(), None).unwrap()
    }

    /// `n` headers linked onto mainnet genesis at minimum (regtest)
    /// difficulty. `HeaderStore` doesn't validate PoW, so these are cheap.
    /// `salt` makes distinct chains.
    fn cheap_chain(n: u32, salt: u32) -> Vec<Header> {
        let mut prev = genesis_header().block_hash();
        (1..=n)
            .map(|i| {
                let h = Header {
                    version: bitcoin::block::Version::ONE,
                    prev_blockhash: prev,
                    merkle_root: bitcoin::TxMerkleNode::all_zeros(),
                    time: 1_231_006_505 + i * 600,
                    bits: CompactTarget::from_consensus(0x207fffff),
                    nonce: i ^ (salt << 16),
                };
                prev = h.block_hash();
                h
            })
            .collect()
    }

    /// Write a one-entry HUTX snapshot whose header claims `height` /
    /// `block_hash`; returns its path and the anchor it satisfies.
    fn write_test_snapshot(dir: &TempDir, height: u32, block_hash: [u8; 32]) -> (String, SnapshotAnchor) {
        let src = UtxoSet::open(dir.path().join("src-utxo").to_str().unwrap()).unwrap();
        src.test_insert_utxo(
            [7u8; 32],
            0,
            UtxoEntry {
                amount: 5000,
                script_pubkey: vec![0x51],
                height: 1,
                is_coinbase: false,
            },
        )
        .unwrap();
        let mut buf = Vec::new();
        let meta = src.write_snapshot(&mut buf, height, &block_hash).unwrap();
        let path = dir.path().join("snap.hutx");
        std::fs::write(&path, &buf).unwrap();
        (
            path.to_str().unwrap().to_string(),
            SnapshotAnchor {
                height,
                block_hash,
                utxo_hash: meta.utxo_hash,
                utxo_count: meta.utxo_count,
            },
        )
    }

    /// HeaderSync anchored at `TEST_ANCHOR_HEIGHT` of `chain`, with a
    /// snapshot file for that anchor. Headers are NOT stored yet.
    fn anchored_fixture(chain: &[Header]) -> (TempDir, HeaderSync, String) {
        let dir = TempDir::new().unwrap();
        let anchor_hash = chain[TEST_ANCHOR_HEIGHT as usize - 1]
            .block_hash()
            .to_byte_array();
        let (path, anchor) = write_test_snapshot(&dir, TEST_ANCHOR_HEIGHT, anchor_hash);
        let mut hs = fresh_sync(&dir);
        hs.anchor = anchor;
        (dir, hs, path)
    }

    #[test]
    fn load_snapshot_activates_when_headers_include_anchor() {
        let chain = cheap_chain(10, 0);
        let (_dir, hs, path) = anchored_fixture(&chain);
        hs.store.store_headers(&chain, 1).unwrap();

        let meta = hs.load_snapshot(&path, |_, _| true).unwrap();
        assert_eq!(meta.height, TEST_ANCHOR_HEIGHT);
        assert_eq!(hs.store.validated_height().unwrap(), TEST_ANCHOR_HEIGHT);
        assert_eq!(hs.utxo.count().unwrap(), 1);
        assert!(hs.ready_to_validate_blocks().unwrap());
    }

    #[test]
    fn reopen_discards_set_from_retracted_snapshot() {
        // A device that imported the retracted 943,500 file (no recorded
        // content hash) must be sent back to the snapshot download.
        let chain = cheap_chain(10, 0);
        let (dir, hs, path) = anchored_fixture(&chain);
        hs.store.store_headers(&chain, 1).unwrap();
        hs.load_snapshot(&path, |_, _| true).unwrap();
        assert_eq!(hs.store.validated_height().unwrap(), TEST_ANCHOR_HEIGHT);
        assert!(!hs.needs_snapshot().unwrap());
        hs.utxo.test_set_snapshot_utxo_hash(None);
        // A verdict reached against the bad set, under the current rules
        // (so version pruning alone would keep it), and the ban it caused.
        let condemned = chain[9].block_hash();
        hs.store.mark_failed(condemned, 10, "script failure", &rules_tag()).unwrap();
        hs.store.record_failed_block_ban("203.0.113.7:8333", condemned).unwrap();
        let peers_path = dir.path().join("peers.sqlite3");
        crate::peer_store::PeerStore::open(peers_path.to_str().unwrap())
            .unwrap()
            .save_ban("203.0.113.7:8333", Instant::now() + Duration::from_secs(3600))
            .unwrap();
        drop(hs);

        let hs = fresh_sync(&dir);
        assert_eq!(hs.utxo.count().unwrap(), 0);
        assert_eq!(hs.utxo.assume_valid_floor().unwrap(), 0);
        assert_eq!(hs.store.validated_height().unwrap(), 0);
        assert!(hs.needs_snapshot().unwrap());
        // Headers are kept; only validation state is reset.
        assert_eq!(hs.store.get_hash_at_height(10).unwrap(), Some(chain[9].block_hash()));
        // The verdict and its ban went with the set.
        assert!(hs.store.failed_hashes().unwrap().is_empty());
        let bans = crate::peer_store::PeerStore::open(peers_path.to_str().unwrap())
            .unwrap()
            .load_active_bans()
            .unwrap();
        assert!(!bans.contains_key("203.0.113.7:8333"), "{:?}", bans);
    }

    #[test]
    fn reopen_keeps_set_from_current_snapshot() {
        let chain = cheap_chain(10, 0);
        let (dir, hs, path) = anchored_fixture(&chain);
        hs.store.store_headers(&chain, 1).unwrap();
        hs.load_snapshot(&path, |_, _| true).unwrap();
        drop(hs);

        let hs = fresh_sync(&dir);
        assert_eq!(hs.utxo.count().unwrap(), 1);
        assert_eq!(hs.store.validated_height().unwrap(), TEST_ANCHOR_HEIGHT);
        assert!(!hs.needs_snapshot().unwrap());
    }

    #[test]
    fn load_snapshot_defers_activation_until_headers_reach_anchor() {
        // The app imports the snapshot before header sync starts.
        let chain = cheap_chain(10, 0);
        let (_dir, hs, path) = anchored_fixture(&chain);
        hs.store.store_headers(&chain[..3], 1).unwrap();

        hs.load_snapshot(&path, |_, _| true).unwrap();
        assert_eq!(hs.utxo.count().unwrap(), 1);
        assert_eq!(hs.store.validated_height().unwrap(), 0, "must stay pending");
        assert!(!hs.ready_to_validate_blocks().unwrap());
        assert!(!hs.needs_snapshot().unwrap(), "don't re-download a pending snapshot");

        // Header sync reaches the anchor → activation.
        hs.store.store_headers(&chain[3..], 4).unwrap();
        assert!(hs.ready_to_validate_blocks().unwrap());
        assert_eq!(hs.store.validated_height().unwrap(), TEST_ANCHOR_HEIGHT);
    }

    /// PR #24 second review: with a snapshot loaded but not yet bound to
    /// our headers (validated_height 0, best block at the floor), a reorg
    /// of cheap headers below the anchor used to try rolling the snapshot
    /// back and fail every sync with a store error.
    #[test]
    fn reorg_below_pending_snapshot_leaves_the_utxo_set_alone() {
        let chain = cheap_chain(10, 0);
        let (_dir, hs, path) = anchored_fixture(&chain);
        hs.store.store_headers(&chain[..3], 1).unwrap();
        hs.load_snapshot(&path, |_, _| true).unwrap();
        assert_eq!(hs.store.validated_height().unwrap(), 0);
        let best = hs.utxo.best_block().unwrap();

        let (new_tip, new_validated) = hs.apply_reorg(1, &cheap_chain(10, 1)[1..4]).unwrap();
        assert_eq!((new_tip, new_validated), (4, 0));
        assert_eq!(hs.utxo.best_block().unwrap(), best, "snapshot touched");
        assert_eq!(hs.utxo.count().unwrap(), 1);

        // Once bound, a rollback target below the floor stops at it.
        assert_eq!(hs.rollback_utxo_to(0, TEST_ANCHOR_HEIGHT).unwrap(), None);
        assert_eq!(hs.utxo.best_block().unwrap(), best);
    }

    #[test]
    fn load_snapshot_refuses_header_chain_missing_anchor() {
        // Our stored chain has a different block at the anchor height.
        let chain = cheap_chain(10, 0);
        let (_dir, hs, path) = anchored_fixture(&chain);
        hs.store.store_headers(&cheap_chain(10, 1), 1).unwrap();

        let err = hs.load_snapshot(&path, |_, _| true).unwrap_err();
        assert!(format!("{}", err).contains("expected anchor"), "got: {}", err);
        assert_eq!(hs.utxo.count().unwrap(), 0, "UTXO db must be untouched");
        assert_eq!(hs.utxo.assume_valid_floor().unwrap(), 0);
        assert_eq!(hs.store.validated_height().unwrap(), 0);
    }

    #[test]
    fn load_snapshot_rejects_wrong_height_or_hash() {
        let chain = cheap_chain(10, 0);
        for (height, block_hash) in [
            (TEST_ANCHOR_HEIGHT + 1, chain[4].block_hash().to_byte_array()),
            (TEST_ANCHOR_HEIGHT, chain[5].block_hash().to_byte_array()),
        ] {
            let dir = TempDir::new().unwrap();
            let (path, file_anchor) = write_test_snapshot(&dir, height, block_hash);
            let mut hs = fresh_sync(&dir);
            hs.anchor = SnapshotAnchor {
                height: TEST_ANCHOR_HEIGHT,
                block_hash: chain[4].block_hash().to_byte_array(),
                utxo_hash: file_anchor.utxo_hash,
                utxo_count: file_anchor.utxo_count,
            };
            hs.store.store_headers(&chain, 1).unwrap();

            let err = hs.load_snapshot(&path, |_, _| true).unwrap_err();
            assert!(format!("{}", err).contains("mismatch"), "got: {}", err);
            assert_eq!(hs.utxo.count().unwrap(), 0);
            assert_eq!(hs.store.validated_height().unwrap(), 0);
        }
    }

    #[test]
    fn low_work_chain_is_below_min_chain_work() {
        // A cheap chain that never reaches the anchor height can't satisfy
        // the mainnet floor.
        let dir = TempDir::new().unwrap();
        let hs = fresh_sync(&dir);
        hs.store.store_headers(&cheap_chain(50, 0), 1).unwrap();
        assert_eq!(hs.min_chain_work, MIN_CHAIN_WORK);
        assert!(!hs.has_min_chain_work().unwrap());
        assert!(!hs.ready_to_validate_blocks().unwrap());
    }

    #[test]
    fn chain_meeting_min_chain_work_is_accepted() {
        let dir = TempDir::new().unwrap();
        let mut hs = fresh_sync(&dir);
        let chain = cheap_chain(50, 0);
        hs.store.store_headers(&chain, 1).unwrap();
        let mut all = vec![genesis_header()];
        all.extend_from_slice(&chain);
        let work = chainwork_for_headers(&all);

        hs.min_chain_work = work;
        assert!(hs.has_min_chain_work().unwrap(), "work == floor passes");

        let mut one = [0u8; 32];
        one[0] = 1;
        hs.min_chain_work = u256_add(work, one);
        assert!(!hs.has_min_chain_work().unwrap(), "work < floor fails");
    }

    #[test]
    fn anchor_in_chain_satisfies_min_chain_work() {
        let chain = cheap_chain(10, 0);
        let (_dir, hs, _path) = anchored_fixture(&chain);
        hs.store.store_headers(&chain, 1).unwrap();
        // min_chain_work is still the mainnet value; the anchor proves it.
        assert!(hs.has_min_chain_work().unwrap());
    }

    #[test]
    fn stored_chainwork_is_incremental_and_reorg_safe() {
        let dir = TempDir::new().unwrap();
        let hs = fresh_sync(&dir);
        let chain = cheap_chain(30, 0);
        hs.store.store_headers(&chain[..10], 1).unwrap();
        hs.stored_chainwork().unwrap();
        hs.store.store_headers(&chain[10..], 11).unwrap();

        let mut all = vec![genesis_header()];
        all.extend_from_slice(&chain);
        assert_eq!(hs.stored_chainwork().unwrap(), chainwork_for_headers(&all));

        // Replace the top of the chain: the cached prefix must be dropped.
        hs.store.delete_headers_above(5).unwrap();
        let fork = cheap_chain(40, 2);
        let mut fork_tail: Vec<Header> = Vec::new();
        let mut prev = chain[4].block_hash();
        for h in &fork[5..40] {
            let mut h = *h;
            h.prev_blockhash = prev;
            prev = h.block_hash();
            fork_tail.push(h);
        }
        hs.store.store_headers(&fork_tail, 6).unwrap();
        let mut all = vec![genesis_header()];
        all.extend_from_slice(&chain[..5]);
        all.extend_from_slice(&fork_tail);
        assert_eq!(hs.stored_chainwork().unwrap(), chainwork_for_headers(&all));
    }

    #[test]
    fn header_batch_conflicting_with_anchor_is_rejected() {
        let chain = cheap_chain(10, 0);
        let (_dir, hs, _path) = anchored_fixture(&chain);
        assert!(hs.check_batch_anchor(&chain, 1).is_ok());
        let fake = cheap_chain(10, 1);
        let err = hs.check_batch_anchor(&fake, 1).unwrap_err();
        assert!(err.contains("conflicts with the chain anchor"), "got: {}", err);
        // A batch that stops short of the anchor can't conflict yet.
        assert!(hs.check_batch_anchor(&fake[..3], 1).is_ok());
    }

    #[test]
    fn reorg_across_anchor_is_refused() {
        let chain = cheap_chain(10, 0);
        let (_dir, hs, _path) = anchored_fixture(&chain);
        let a = TEST_ANCHOR_HEIGHT;
        assert!(hs.reorg_crosses_anchor(a + 3, a - 1));
        assert!(hs.reorg_crosses_anchor(a + 3, a));
        assert!(!hs.reorg_crosses_anchor(a + 3, a + 1));
        // Below the anchor height nothing is anchored yet.
        assert!(!hs.reorg_crosses_anchor(a - 1, a - 3));
    }
}

#[cfg(test)]
#[path = "testkit/sync_integration.rs"]
mod integration_tests;
