use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use log::{info, warn};

use crate::p2p::{Peer, PeerError};
use crate::peer_store::PeerStore;
use crate::tor::TorManager;

/// Maximum number of outbound connections (matches Bitcoin Core default).
const MAX_OUTBOUND: usize = 8;

/// Maximum number of inbound connections (conservative for mobile).
const MAX_INBOUND: usize = 16;

/// Short idle wait per peer when servicing pings.
const PEER_PING_TIMEOUT: Duration = Duration::from_millis(500);

/// Information about a connected peer, exported to the UI.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub addr: String,
    pub user_agent: String,
    pub height: u32,
}

/// A slot holding a live peer connection.
struct PeerSlot {
    peer: Option<Peer>,
    addr: String,
    user_agent: String,
    height: u32,
    /// Reputation score, range [SCORE_MIN, SCORE_MAX], starts at SCORE_DEFAULT.
    /// Misbehavior subtracts; good behavior (header batches, blocks served,
    /// pings) adds. Drops to BAN_LOW_THRESHOLD or below trigger an automatic
    /// 24-hour ban.
    score: i32,
    /// True if this peer connected to us (inbound).
    inbound: bool,
    /// When the peer was last checked out (taken from the slot). Used to
    /// detect leaked slots where the caller dropped the Peer without
    /// calling return_peer().
    checked_out_at: Option<Instant>,
}

/// Minimum interval between DNS re-discovery attempts.
const DNS_REDISCOVERY_INTERVAL: Duration = Duration::from_secs(60);

/// Maximum number of known addresses to retain in memory. The real Bitcoin
/// Core addrman keeps tens of thousands; we cap small for an iPhone budget.
/// When the manager fills up, eviction prefers the address with the most
/// connection failures (oldest as tiebreaker) and never evicts an address
/// that has succeeded at least once. See `AddrManager::evict_if_full`.
const MAX_KNOWN_ADDRS: usize = 10_000;

/// Wall-clock budget for a single `maintain()` connection-refill pass. We
/// blow through addresses in priority order until either we hit the slot
/// target or this budget is exhausted, whichever comes first. The cap exists
/// because `maintain()` runs on the synchronous monitor loop — we can't let
/// it stall the loop for tens of seconds chasing a long tail of dead peers.
const REFILL_BUDGET: Duration = Duration::from_secs(2);

/// Minimum number of viable candidates before we'll re-query DNS seeds. The
/// AddrManager is the primary source of peer addresses; DNS is only consulted
/// as a fallback when the manager has been depleted (initial bootstrap or
/// after a long offline period).
const DNS_FALLBACK_THRESHOLD: usize = 50;

/// Base delay between connection retries for an address that has failed.
/// Failures double this up to ADDR_RETRY_MAX, so a flapping peer naturally
/// drops to the back of the candidate queue without us needing an explicit
/// blacklist.
const ADDR_RETRY_BASE: Duration = Duration::from_secs(60);

/// Cap on the exponential backoff for failed addresses. After ~6 failures
/// the backoff plateaus here so an address eventually becomes eligible again
/// rather than being shadow-banned forever.
const ADDR_RETRY_MAX: Duration = Duration::from_secs(3600);

/// Per-address bookkeeping for the in-memory address manager. Tracks when
/// we first heard about an address, when we last tried it, the last time
/// we successfully connected to it, and how many failures we've seen. This
/// is the minimum state needed to schedule retries with backoff and to rank
/// candidates by reliability without dragging in a full Bitcoin Core
/// new/tried addrman implementation.
#[derive(Debug, Clone)]
struct AddrMeta {
    first_seen: Instant,
    last_tried: Option<Instant>,
    last_success: Option<Instant>,
    failure_count: u32,
}

impl AddrMeta {
    fn new() -> AddrMeta {
        AddrMeta {
            first_seen: Instant::now(),
            last_tried: None,
            last_success: None,
            failure_count: 0,
        }
    }

    /// Compute the per-address backoff based on consecutive failures.
    /// Doubles per failure, capped at ADDR_RETRY_MAX. A never-tried address
    /// has zero backoff.
    fn current_backoff(&self) -> Duration {
        if self.failure_count == 0 {
            return Duration::ZERO;
        }
        let exp = self.failure_count.saturating_sub(1).min(20);
        let multiplier = 1u64.checked_shl(exp).unwrap_or(u64::MAX);
        let secs = ADDR_RETRY_BASE
            .as_secs()
            .saturating_mul(multiplier)
            .min(ADDR_RETRY_MAX.as_secs());
        Duration::from_secs(secs)
    }

    /// Is this address eligible for a connection attempt right now? An
    /// address is eligible if we've never tried it, or enough time has
    /// elapsed since the last attempt to satisfy its current backoff.
    fn is_eligible(&self, now: Instant) -> bool {
        match self.last_tried {
            None => true,
            Some(t) => now.duration_since(t) >= self.current_backoff(),
        }
    }

    /// Ranking tier for candidate selection — lower is better.
    /// 0: known-good (last_success set, currently eligible)
    /// 1: never-tried (no attempts yet)
    /// 2: previously-tried, currently eligible
    /// 3: in backoff (only used if all higher tiers are empty)
    fn tier(&self, now: Instant) -> u8 {
        if !self.is_eligible(now) {
            return 3;
        }
        if self.last_success.is_some() {
            return 0;
        }
        if self.last_tried.is_none() {
            return 1;
        }
        2
    }
}

/// In-memory address manager. Replaces the old forward-only `known_addrs`
/// vector with a HashMap that tracks per-address state, supports gossip
/// ingestion (so peers feed us new candidates), and ranks candidates by
/// reliability when refilling the outbound pool.
///
/// This is intentionally much simpler than Bitcoin Core's `CAddrMan`: no
/// new/tried tables, no bucket-based eclipse hardening, no peers.dat
/// persistence. The goal is to fix the immediate symptom (outbound pool
/// shrinks below MAX_OUTBOUND when DNS-discovered peers fall over) without
/// committing to the full addrman complexity. Persistence can be added
/// later if iPhone restart-churn proves it necessary.
struct AddrManager {
    addrs: HashMap<String, AddrMeta>,
    max_size: usize,
}

impl AddrManager {
    fn new(max_size: usize) -> AddrManager {
        AddrManager {
            addrs: HashMap::new(),
            max_size,
        }
    }

    fn len(&self) -> usize {
        self.addrs.len()
    }

    /// Insert a single address. New addresses get a fresh AddrMeta; existing
    /// addresses are left alone (we don't want gossip to wipe out a peer's
    /// established success/failure history). Returns true if a new entry
    /// was actually added.
    fn insert(&mut self, addr: String) -> bool {
        if self.addrs.contains_key(&addr) {
            return false;
        }
        self.evict_if_full();
        self.addrs.insert(addr, AddrMeta::new());
        true
    }

    /// Bulk insert. Returns the number of brand-new entries added.
    fn insert_many<I: IntoIterator<Item = String>>(&mut self, addrs: I) -> usize {
        let mut added = 0;
        for addr in addrs {
            if self.insert(addr) {
                added += 1;
            }
        }
        added
    }

    /// Evict one entry to make room when at capacity.
    ///
    /// Policy, in priority order:
    /// 1. Among entries that have never successfully connected, drop the one
    ///    with the highest `failure_count` (oldest `first_seen` as tiebreaker).
    ///    This pushes addresses we have evidence are bad off the list before
    ///    addresses we've never tried.
    /// 2. If every entry has succeeded at least once, drop the oldest one.
    ///    Should be exceedingly rare at MAX_KNOWN_ADDRS=10_000.
    ///
    /// Known-good entries are *never* evicted by step 1 — they're the most
    /// valuable thing the addrman holds and they survive churn.
    fn evict_if_full(&mut self) {
        if self.addrs.len() < self.max_size {
            return;
        }

        // Capture `now` once so the comparator inside max_by_key doesn't
        // re-read the clock for every entry.
        let now = Instant::now();

        let victim: Option<String> = self
            .addrs
            .iter()
            .filter(|(_, m)| m.last_success.is_none())
            .max_by_key(|(_, m)| {
                (m.failure_count, now.duration_since(m.first_seen).as_secs())
            })
            .map(|(addr, _)| addr.clone());

        if let Some(addr) = victim {
            self.addrs.remove(&addr);
            return;
        }

        // Fallback: every entry has at least one success. Drop the oldest.
        if let Some(addr) = self
            .addrs
            .iter()
            .max_by_key(|(_, m)| now.duration_since(m.first_seen).as_secs())
            .map(|(addr, _)| addr.clone())
        {
            self.addrs.remove(&addr);
        }
    }

    /// Mark an address as successfully connected. Resets failure count and
    /// stamps last_success/last_tried so the entry is treated as known-good.
    fn record_success(&mut self, addr: &str) {
        let now = Instant::now();
        let entry = self
            .addrs
            .entry(addr.to_string())
            .or_insert_with(AddrMeta::new);
        entry.last_tried = Some(now);
        entry.last_success = Some(now);
        entry.failure_count = 0;
    }

    /// Mark an address as having failed to connect. Increments failure_count
    /// (driving the exponential backoff) and stamps last_tried.
    fn record_failure(&mut self, addr: &str) {
        let now = Instant::now();
        let entry = self
            .addrs
            .entry(addr.to_string())
            .or_insert_with(AddrMeta::new);
        entry.last_tried = Some(now);
        entry.failure_count = entry.failure_count.saturating_add(1);
    }

    /// Number of addresses currently eligible for a connection attempt
    /// (i.e., not still in backoff). Used to decide whether DNS fallback
    /// should kick in.
    fn candidate_count(&self) -> usize {
        let now = Instant::now();
        self.addrs.values().filter(|m| m.is_eligible(now)).count()
    }

    /// Pick up to `limit` candidate addresses, ranked best first. Excludes
    /// addresses for which `exclude` returns true (used to skip already-
    /// connected or banned peers, or to enforce subnet diversity).
    ///
    /// Ranking: known-good first, then never-tried, then retry tier. Within
    /// a tier, oldest first_seen wins so we don't starve older entries when
    /// new gossip floods in.
    fn pick_candidates(&self, limit: usize, exclude: &dyn Fn(&str) -> bool) -> Vec<String> {
        let now = Instant::now();
        let mut entries: Vec<(&String, &AddrMeta)> = self
            .addrs
            .iter()
            .filter(|(addr, _)| !exclude(addr.as_str()))
            .collect();

        entries.sort_by(|(_, a), (_, b)| {
            let ta = a.tier(now);
            let tb = b.tier(now);
            ta.cmp(&tb)
                .then(a.failure_count.cmp(&b.failure_count))
                .then(a.first_seen.cmp(&b.first_seen))
        });

        entries
            .into_iter()
            .take(limit)
            .map(|(addr, _)| addr.clone())
            .collect()
    }
}

/// Duration of a peer ban (24 hours, matches Bitcoin Core default).
const BAN_DURATION: Duration = Duration::from_secs(24 * 3600);

/// Default starting score for a freshly connected peer (neutral).
const SCORE_DEFAULT: i32 = 100;

/// Maximum allowed score (cap on rewards so a long-lived peer can still be
/// penalised meaningfully if it later starts misbehaving).
const SCORE_MAX: i32 = 200;

/// Minimum allowed score (clamp so we don't underflow on adversarial input).
const SCORE_MIN: i32 = 0;

/// Score at or below this triggers an automatic ban. With SCORE_DEFAULT=100,
/// this means a peer must lose 80 points to get banned — matching the spirit
/// of Bitcoin Core's 100-point misbehavior threshold but in the new direction.
const BAN_LOW_THRESHOLD: i32 = 20;

/// Maximum ban entries to prevent unbounded memory growth from address rotation.
const MAX_BANS: usize = 1024;

/// How often we flush peer scores to disk. Bans go through immediately because
/// they're rare and load-bearing for safety; scores are flushed in bulk so a
/// chatty header-sync session doesn't hammer SQLite.
const SCORE_FLUSH_INTERVAL: Duration = Duration::from_secs(60);

/// Timeout for checked-out peer slots before they are reclaimed (prevents slot leaks).
const CHECKOUT_TIMEOUT: Duration = Duration::from_secs(120);

/// Compute a coarse "subnet bucket" for an address used to enforce outbound
/// peer diversity. The goal is to prevent an attacker who controls a single
/// /16 (IPv4) or /32 (IPv6) from dominating our outbound pool.
///
/// - IPv4 → first two octets ("v4:1.2")
/// - IPv6 → first 32 bits / four hex groups ("v6:2001:db8")
/// - .onion → returns None: Tor circuits provide their own diversity, and
///   onion addresses have no meaningful network locality.
/// - Unparseable → returns None: skip the check rather than mis-bucket.
fn subnet_bucket(addr: &str) -> Option<String> {
    // .onion addresses look like "abc...xyz.onion:8333"
    if addr.contains(".onion") {
        return None;
    }

    // IPv6 form: "[2001:db8::1]:8333"
    if let Some(rest) = addr.strip_prefix('[') {
        if let Some(end) = rest.find(']') {
            let ip = &rest[..end];
            let groups: Vec<&str> = ip.split(':').take(2).collect();
            if groups.len() == 2 && !groups[0].is_empty() && !groups[1].is_empty() {
                return Some(format!("v6:{}:{}", groups[0], groups[1]));
            }
            return None;
        }
        return None;
    }

    // IPv4 form: "1.2.3.4:8333"
    let host = addr.split(':').next()?;
    let octets: Vec<&str> = host.split('.').collect();
    if octets.len() == 4 && octets.iter().all(|o| o.parse::<u8>().is_ok()) {
        return Some(format!("v4:{}.{}", octets[0], octets[1]));
    }

    None
}

/// Thread-safe pool of Bitcoin peer connections.
pub struct PeerPool {
    slots: Arc<Mutex<Vec<PeerSlot>>>,
    /// In-memory address manager. Sources include DNS seeds (bootstrap),
    /// `addr` / `addrv2` gossip from connected peers, and inbound peers'
    /// self-reported addresses.
    addrs: AddrManager,
    our_height: u32,
    /// Last time DNS seeds were queried (for backoff).
    last_dns_query: Instant,
    /// Peers banned for misbehavior, with ban expiry time.
    bans: HashMap<String, Instant>,
    tor: Option<Arc<TorManager>>,
    /// Optional disk persistence for scores and bans across restarts.
    /// `None` for ephemeral pools (tests, in-memory builds).
    store: Option<Arc<PeerStore>>,
    /// Last time we flushed scores to the store (rate-limit bulk writes).
    last_score_flush: Instant,
}

impl PeerPool {
    /// Create a new peer pool. Discovers peers via DNS (or Tor if available)
    /// and connects to an initial batch of up to `MAX_OUTBOUND` peers.
    ///
    /// If `peers_db_path` is provided, scores and bans are loaded from that
    /// SQLite file at startup and persisted across changes. Pass `None` for
    /// ephemeral test pools.
    pub fn new(
        our_height: u32,
        tor: Option<Arc<TorManager>>,
        peers_db_path: Option<&str>,
    ) -> Result<PeerPool, PeerError> {
        let seeds = if let Some(ref tor) = tor {
            Peer::discover_peers_tor(tor)
        } else {
            Peer::discover_peers()
        };

        if seeds.is_empty() {
            return Err(PeerError::Connection("no peers discovered via DNS".into()));
        }

        info!(
            "PeerPool: bootstrap from DNS produced {} addresses, connecting up to {}",
            seeds.len(),
            MAX_OUTBOUND
        );

        // Open the persistence store and hydrate any existing bans. Failures
        // are logged but non-fatal — the pool still works without persistence.
        let (store, bans) = match peers_db_path {
            Some(path) => match PeerStore::open(path) {
                Ok(s) => {
                    let bans = s.load_active_bans().unwrap_or_else(|e| {
                        warn!("PeerPool: failed to load bans from disk: {}", e);
                        HashMap::new()
                    });
                    if !bans.is_empty() {
                        info!("PeerPool: restored {} ban(s) from disk", bans.len());
                    }
                    (Some(Arc::new(s)), bans)
                }
                Err(e) => {
                    warn!("PeerPool: peer store unavailable, running without persistence: {}", e);
                    (None, HashMap::new())
                }
            },
            None => (None, HashMap::new()),
        };

        let mut addrs = AddrManager::new(MAX_KNOWN_ADDRS);
        addrs.insert_many(seeds);

        let mut pool = PeerPool {
            slots: Arc::new(Mutex::new(Vec::new())),
            addrs,
            our_height,
            last_dns_query: Instant::now(),
            bans,
            tor,
            store,
            last_score_flush: Instant::now(),
        };

        pool.maintain();

        let count = pool.slots.lock().unwrap().len();
        if count == 0 {
            return Err(PeerError::Connection("could not connect to any peer".into()));
        }

        info!("PeerPool: initial connections: {}/{}", count, MAX_OUTBOUND);
        Ok(pool)
    }

    /// Try to fill the pool up to `MAX_OUTBOUND` connections.
    pub fn maintain(&mut self) {
        // Expire old bans and enforce max size
        let now = Instant::now();
        let expired: Vec<String> = self
            .bans
            .iter()
            .filter(|(_, expiry)| **expiry <= now)
            .map(|(addr, _)| addr.clone())
            .collect();
        for addr in &expired {
            self.bans.remove(addr);
            if let Some(ref store) = self.store {
                if let Err(e) = store.delete_ban(addr) {
                    warn!("PeerPool: failed to drop expired ban for {}: {}", addr, e);
                }
            }
        }
        if self.bans.len() > MAX_BANS {
            // Evict oldest bans (earliest expiry) to stay bounded
            let mut entries: Vec<_> = self.bans.drain().collect();
            entries.sort_by_key(|(_, expiry)| *expiry);
            let skip = entries.len() - MAX_BANS;
            // Drop the on-disk record for any bans we're evicting from memory
            // so the disk view stays consistent with the in-memory cap.
            if let Some(ref store) = self.store {
                for (addr, _) in entries.iter().take(skip) {
                    let _ = store.delete_ban(addr);
                }
            }
            self.bans = entries.into_iter().skip(skip).collect();
        }

        // Periodically flush in-memory scores to disk so reputation survives
        // a crash. We only do this if the interval has elapsed to avoid
        // hammering SQLite during chatty header sync.
        if self.last_score_flush.elapsed() >= SCORE_FLUSH_INTERVAL {
            self.flush_scores();
        }

        // Reclaim slots where a peer was checked out but never returned
        // (prevents permanent slot loss from dropped Peer handles)
        {
            let mut slots = self.slots.lock().unwrap();
            let before = slots.len();
            slots.retain(|s| {
                if s.peer.is_some() {
                    return true; // peer present, slot is fine
                }
                match s.checked_out_at {
                    Some(t) => t.elapsed() < CHECKOUT_TIMEOUT,
                    None => true, // shouldn't happen, keep it
                }
            });
            let removed = before - slots.len();
            if removed > 0 {
                warn!("PeerPool: reclaimed {} orphaned peer slots", removed);
            }
        }

        let current = self.outbound_count();
        if current >= MAX_OUTBOUND {
            return;
        }

        // DNS is now a fallback, not the primary source. We only re-query
        // when the AddrManager is depleted enough that we'd otherwise stall
        // — the steady-state expectation is that gossip from connected peers
        // keeps the manager well above DNS_FALLBACK_THRESHOLD.
        if self.addrs.candidate_count() < DNS_FALLBACK_THRESHOLD
            && self.last_dns_query.elapsed() >= DNS_REDISCOVERY_INTERVAL
        {
            self.last_dns_query = Instant::now();
            let fresh = if let Some(ref tor) = self.tor {
                Peer::discover_peers_tor(tor)
            } else {
                Peer::discover_peers()
            };
            if !fresh.is_empty() {
                let added = self.addrs.insert_many(fresh);
                info!(
                    "PeerPool: DNS fallback added {} new addresses (total known: {})",
                    added,
                    self.addrs.len()
                );
            }
        }

        let needed = MAX_OUTBOUND - current;
        let refill_started = Instant::now();

        // Snapshot the current outbound buckets and connected addresses so
        // we can filter candidates without holding the slots lock for the
        // duration of the connection attempt.
        let (already_connected, used_buckets): (HashSet<String>, HashSet<String>) = {
            let slots = self.slots.lock().unwrap();
            let connected = slots.iter().map(|s| s.addr.clone()).collect();
            let buckets = slots
                .iter()
                .filter(|s| !s.inbound)
                .filter_map(|s| subnet_bucket(&s.addr))
                .collect();
            (connected, buckets)
        };

        let bans = &self.bans;
        let exclude = |addr: &str| -> bool {
            if bans.contains_key(addr) {
                return true;
            }
            if already_connected.contains(addr) {
                return true;
            }
            if let Some(bucket) = subnet_bucket(addr) {
                if used_buckets.contains(&bucket) {
                    return true;
                }
            }
            false
        };

        // Pick a healthy multiple of `needed` candidates so we have a buffer
        // when several attempts in a row fail. The wall-clock budget is the
        // real cap; this just keeps us from sorting the entire address book
        // for every refill pass.
        let candidates = self.addrs.pick_candidates(needed.saturating_mul(4), &exclude);

        if candidates.is_empty() {
            warn!(
                "PeerPool: no eligible candidates to refill outbound (have {}, need {})",
                current, MAX_OUTBOUND
            );
            return;
        }

        let mut connected = 0;
        // Track buckets we've claimed during this pass so we don't let two
        // back-to-back successful connects both come from the same /16.
        let mut claimed_buckets: HashSet<String> = HashSet::new();

        for addr in candidates {
            if connected >= needed {
                break;
            }
            if refill_started.elapsed() >= REFILL_BUDGET {
                info!(
                    "PeerPool: refill budget ({}s) exhausted after {} new connections",
                    REFILL_BUDGET.as_secs(),
                    connected
                );
                break;
            }

            // Re-check the bucket against this pass's claims (the snapshot
            // above only reflects buckets occupied at the start of refill).
            if let Some(bucket) = subnet_bucket(&addr) {
                if claimed_buckets.contains(&bucket) {
                    continue;
                }
            }

            let result = if let Some(ref tor) = self.tor {
                Peer::connect_tor(tor, &addr, self.our_height as i32)
            } else {
                Peer::connect(&addr, self.our_height as i32)
            };

            match result {
                Ok(peer) => {
                    let user_agent = peer.peer_user_agent().unwrap_or_default();
                    let height = peer.peer_height().unwrap_or(0).max(0) as u32;
                    info!(
                        "PeerPool: connected to {} ({}) at height {}",
                        addr, user_agent, height
                    );
                    self.addrs.record_success(&addr);

                    // Restore any persisted score so a known-good peer comes
                    // back at its earned reputation, not as a stranger.
                    let score = self
                        .store
                        .as_ref()
                        .and_then(|s| s.load_score(&addr).ok().flatten())
                        .unwrap_or(SCORE_DEFAULT);

                    if let Some(bucket) = subnet_bucket(&addr) {
                        claimed_buckets.insert(bucket);
                    }

                    let slot = PeerSlot {
                        peer: Some(peer),
                        addr,
                        user_agent,
                        height,
                        score,
                        inbound: false,
                        checked_out_at: None,
                    };

                    self.slots.lock().unwrap().push(slot);
                    connected += 1;
                }
                Err(e) => {
                    warn!("PeerPool: failed to connect to {}: {}", addr, e);
                    self.addrs.record_failure(&addr);
                }
            }
        }

        if connected > 0 {
            let total = self.slots.lock().unwrap().len();
            info!(
                "PeerPool: added {} peers, total now {}/{} (known addrs: {})",
                connected,
                total,
                MAX_OUTBOUND,
                self.addrs.len()
            );
        }
    }

    /// Public entry point for ingesting addresses learned via `addr` /
    /// `addrv2` gossip from connected peers. Called by the sync loop after
    /// it drains queued gossip from message handlers. Returns the number of
    /// brand-new addresses added (existing entries are left untouched so
    /// gossip can't reset earned reputation).
    pub fn ingest_gossip_addrs(&mut self, addrs: Vec<String>) -> usize {
        let added = self.addrs.insert_many(addrs);
        if added > 0 {
            info!(
                "PeerPool: ingested {} new gossip addresses (total known: {})",
                added,
                self.addrs.len()
            );
        }
        added
    }

    /// Number of addresses currently held in the address manager. Exposed
    /// for diagnostics and tests; the sync loop can also use it to decide
    /// whether to issue a fresh `getaddr` to top up.
    pub fn known_addr_count(&self) -> usize {
        self.addrs.len()
    }

    /// Return the "best" peer for header sync, temporarily taking it out of
    /// the pool. The caller MUST return it via `return_peer`.
    ///
    /// Selection is reputation-weighted: a peer's score scales their effective
    /// height via `height * (score / SCORE_DEFAULT)`. A reliable peer at score
    /// 180 sitting one block behind the absolute tip is preferred over a
    /// sketchy peer (score 30) at the literal tip — the whole point of the
    /// graduated reputation system. New peers default to `SCORE_DEFAULT` so
    /// they get fair selection until they prove themselves either way.
    pub fn best_peer(&self) -> Option<Peer> {
        let mut slots = self.slots.lock().unwrap();
        if slots.is_empty() {
            return None;
        }

        // f64 is fine here — we're picking a max, not persisting the value,
        // and SCORE_MAX * MAX_HEIGHT is far below precision concerns.
        let best_idx = slots
            .iter()
            .enumerate()
            .filter(|(_, s)| s.peer.is_some())
            .max_by(|(_, a), (_, b)| {
                let wa = a.height as f64 * (a.score as f64 / SCORE_DEFAULT as f64);
                let wb = b.height as f64 * (b.score as f64 / SCORE_DEFAULT as f64);
                wa.partial_cmp(&wb).unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|(i, _)| i)?;

        slots[best_idx].checked_out_at = Some(Instant::now());
        slots[best_idx].peer.take()
    }

    /// Return any available connected peer, temporarily taking it out of the
    /// pool. The caller MUST return it via `return_peer`.
    pub fn any_peer(&self) -> Option<Peer> {
        let mut slots = self.slots.lock().unwrap();
        for slot in slots.iter_mut() {
            if slot.peer.is_some() {
                slot.checked_out_at = Some(Instant::now());
                return slot.peer.take();
            }
        }
        None
    }

    /// Return a peer back to the pool after use.
    pub fn return_peer(&self, peer: Peer) {
        let addr = peer.addr().to_string();
        let mut slots = self.slots.lock().unwrap();
        for slot in slots.iter_mut() {
            if slot.addr == addr && slot.peer.is_none() {
                slot.peer = Some(peer);
                slot.checked_out_at = None;
                return;
            }
        }
        // Slot was removed while peer was checked out — just drop it
        warn!("PeerPool: returning peer {} but slot was removed", addr);
    }

    /// Remove a peer by address (e.g., after a communication error).
    pub fn remove_peer(&self, addr: &str) {
        let mut slots = self.slots.lock().unwrap();
        let before = slots.len();
        slots.retain(|s| s.addr != addr);
        let after = slots.len();
        if after < before {
            info!("PeerPool: removed peer {}, {} remaining", addr, after);
        }
    }

    /// Get a snapshot of all connected peers for the UI.
    pub fn peer_info(&self) -> Vec<PeerInfo> {
        let slots = self.slots.lock().unwrap();
        slots
            .iter()
            .map(|s| PeerInfo {
                addr: s.addr.clone(),
                user_agent: s.user_agent.clone(),
                height: s.height,
            })
            .collect()
    }

    /// Ban a peer address. Removes it from the pool and prevents reconnection.
    /// Persists the ban to disk if a store is configured so the peer stays
    /// banned across app restarts.
    pub fn ban_peer(&mut self, addr: &str) {
        let expiry = Instant::now() + BAN_DURATION;
        self.bans.insert(addr.to_string(), expiry);
        self.remove_peer(addr);
        if let Some(ref store) = self.store {
            if let Err(e) = store.save_ban(addr, expiry) {
                warn!("PeerPool: failed to persist ban for {}: {}", addr, e);
            }
        }
        info!("PeerPool: banned peer {} for 24h", addr);
    }

    /// Flush all in-memory peer scores to disk in a single transaction.
    /// Called periodically from `maintain()` and on `Drop` so we don't
    /// write on every reward (which would be many writes per second during
    /// header sync).
    pub fn flush_scores(&mut self) {
        let store = match self.store.clone() {
            Some(s) => s,
            None => return,
        };
        let entries: Vec<(String, i32)> = {
            let slots = self.slots.lock().unwrap();
            slots.iter().map(|s| (s.addr.clone(), s.score)).collect()
        };
        if let Err(e) = store.save_scores_bulk(&entries) {
            warn!("PeerPool: failed to flush scores: {}", e);
        }
        self.last_score_flush = Instant::now();
    }

    /// Record misbehavior for a peer. Subtracts `howmuch` from the peer's
    /// reputation score; if the result drops to `BAN_LOW_THRESHOLD` or below,
    /// the peer is automatically banned. Mirrors Bitcoin Core's Misbehaving()
    /// pattern but uses a graduated 0–200 scale rather than a unidirectional
    /// counter.
    ///
    /// Callers pass a positive penalty (10, 20, 50, 100, …) — this method
    /// handles the sign internally so existing call sites need no changes.
    pub fn misbehaving(&mut self, addr: &str, howmuch: u32) {
        let mut should_ban = false;
        {
            let mut slots = self.slots.lock().unwrap();
            if let Some(slot) = slots.iter_mut().find(|s| s.addr == addr) {
                // Subtract via i64 so adversarial input (u32::MAX) doesn't
                // wrap when cast to i32 — that would silently turn a huge
                // penalty into a small reward.
                let new_score = (slot.score as i64 - howmuch as i64).max(SCORE_MIN as i64);
                slot.score = new_score as i32;
                warn!(
                    "PeerPool: peer {} misbehaving (-{}), score now {}",
                    addr, howmuch, slot.score
                );
                if slot.score <= BAN_LOW_THRESHOLD {
                    should_ban = true;
                }
            }
        }
        if should_ban {
            self.ban_peer(addr);
        }
    }

    /// Reward a peer for good behavior. Adds `howmuch` to the peer's score,
    /// capped at SCORE_MAX. Used to reflect successful header batches, block
    /// downloads, and ping replies — so reliable peers accumulate headroom
    /// against future misbehavior penalties and earn preferential selection
    /// from `best_peer()`.
    pub fn reward(&self, addr: &str, howmuch: u32) {
        let mut slots = self.slots.lock().unwrap();
        if let Some(slot) = slots.iter_mut().find(|s| s.addr == addr) {
            // i64 add for the same reason as `misbehaving`: a huge `howmuch`
            // would otherwise wrap into a negative i32 and silently lower
            // the score.
            let new_score = (slot.score as i64 + howmuch as i64).min(SCORE_MAX as i64);
            slot.score = new_score as i32;
        }
    }

    /// Get a peer's current reputation score, if it's connected.
    pub fn get_score(&self, addr: &str) -> Option<i32> {
        let slots = self.slots.lock().unwrap();
        slots.iter().find(|s| s.addr == addr).map(|s| s.score)
    }

    /// Get the claimed height of a connected peer by address string.
    pub fn get_peer_height(&self, addr: &str) -> Option<u32> {
        let slots = self.slots.lock().unwrap();
        slots
            .iter()
            .find(|s| s.addr == addr)
            .map(|s| s.height)
    }

    /// Update our reported height (used when connecting to new peers).
    pub fn update_our_height(&mut self, height: u32) {
        self.our_height = height;
    }

    /// Number of connected peers (includes peers currently checked out).
    pub fn count(&self) -> usize {
        self.slots.lock().unwrap().len()
    }

    /// Pick the address of any connected peer that is not `excluded`. Used by
    /// header cross-validation to find an independent witness peer. Returns
    /// `None` if no such peer exists. Prefers peers with higher reputation
    /// scores so the witness is also a "good citizen" rather than the most
    /// suspect peer in the pool.
    pub fn peer_addr_other_than(&self, excluded: &str) -> Option<String> {
        let slots = self.slots.lock().unwrap();
        slots
            .iter()
            .filter(|s| s.addr != excluded && s.peer.is_some())
            .max_by_key(|s| s.score)
            .map(|s| s.addr.clone())
    }

    /// Pick a peer address that's not in `excluded`. Used to find a third
    /// "tiebreaker" peer when the first two cross-check peers disagree.
    pub fn peer_addr_excluding(&self, excluded: &[String]) -> Option<String> {
        let slots = self.slots.lock().unwrap();
        slots
            .iter()
            .filter(|s| !excluded.iter().any(|e| e == &s.addr) && s.peer.is_some())
            .max_by_key(|s| s.score)
            .map(|s| s.addr.clone())
    }

    /// Take a specific peer out of the pool by address. Returns `None` if the
    /// peer isn't in the pool, is checked out, or doesn't match. Caller MUST
    /// `return_peer` afterwards.
    pub fn checkout_peer_by_addr(&self, addr: &str) -> Option<Peer> {
        let mut slots = self.slots.lock().unwrap();
        for slot in slots.iter_mut() {
            if slot.addr == addr && slot.peer.is_some() {
                slot.checked_out_at = Some(Instant::now());
                return slot.peer.take();
            }
        }
        None
    }

    /// Get the address of the best peer without taking it. Uses the same
    /// reputation-weighted ranking as `best_peer()` so the UI's "active peer"
    /// label and the actual sync target stay in sync.
    pub fn best_peer_addr(&self) -> Option<String> {
        let slots = self.slots.lock().unwrap();
        slots
            .iter()
            .max_by(|a, b| {
                let wa = a.height as f64 * (a.score as f64 / SCORE_DEFAULT as f64);
                let wb = b.height as f64 * (b.score as f64 / SCORE_DEFAULT as f64);
                wa.partial_cmp(&wb).unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|s| s.addr.clone())
    }

    /// Add an inbound peer to the pool. Returns false if at inbound capacity,
    /// if the address is a duplicate, or other rejection criteria.
    /// Uses a single lock acquisition for check+insert to avoid TOCTOU races.
    pub fn add_inbound_peer(&self, peer: Peer) -> bool {
        let addr = peer.addr().to_string();
        let user_agent = peer.peer_user_agent().unwrap_or_default();
        let height = peer.peer_height().unwrap_or(0).max(0) as u32;

        let mut slots = self.slots.lock().unwrap();

        // Reject duplicate connections (same address already in pool)
        if slots.iter().any(|s| s.addr == addr) {
            info!("PeerPool: rejecting duplicate inbound peer {}", addr);
            return false;
        }

        let inbound = slots.iter().filter(|s| s.inbound).count();
        if inbound >= MAX_INBOUND {
            info!("PeerPool: rejecting inbound peer (at capacity {}/{})", inbound, MAX_INBOUND);
            return false;
        }

        info!("PeerPool: accepted inbound peer {} ({}) at height {}", addr, user_agent, height);

        // Restore any persisted score for this peer (e.g. a long-lived
        // inbound peer that briefly disconnected and reconnected).
        let score = self
            .store
            .as_ref()
            .and_then(|s| s.load_score(&addr).ok().flatten())
            .unwrap_or(SCORE_DEFAULT);

        slots.push(PeerSlot {
            peer: Some(peer),
            addr,
            user_agent,
            height,
            score,
            inbound: true,
            checked_out_at: None,
        });
        true
    }

    /// Number of inbound peers.
    pub fn inbound_count(&self) -> usize {
        self.slots.lock().unwrap().iter().filter(|s| s.inbound).count()
    }

    /// Number of outbound peers.
    pub fn outbound_count(&self) -> usize {
        self.slots.lock().unwrap().iter().filter(|s| !s.inbound).count()
    }

    /// Target number of outbound peers. The monitor loop checks
    /// `outbound_count() < outbound_target()` after every message-processing
    /// pass and triggers an opportunistic refill if peers have been lost.
    pub fn outbound_target(&self) -> usize {
        MAX_OUTBOUND
    }

    /// Process each connected peer with a callback. Takes each peer out of its
    /// slot for the duration of the callback, then returns it. If the callback
    /// returns an error, the peer is removed from the pool.
    ///
    /// The callback receives `(addr, is_inbound, &mut Peer)` and returns
    /// `Ok(())` to keep the peer or `Err(reason)` to remove it.
    pub fn for_each_peer<F>(&self, mut f: F)
    where
        F: FnMut(&str, bool, &mut Peer) -> Result<(), String>,
    {
        // Collect addresses and inbound flags of peers that have a connection
        let peer_info: Vec<(String, bool)> = {
            let slots = self.slots.lock().unwrap();
            slots
                .iter()
                .filter(|s| s.peer.is_some())
                .map(|s| (s.addr.clone(), s.inbound))
                .collect()
        };

        let mut dead_addrs = Vec::new();

        for (addr, is_inbound) in peer_info {
            // Take peer out of slot
            let peer_opt = {
                let mut slots = self.slots.lock().unwrap();
                slots
                    .iter_mut()
                    .find(|s| s.addr == addr && s.peer.is_some())
                    .and_then(|s| {
                        s.checked_out_at = Some(Instant::now());
                        s.peer.take()
                    })
            };

            let Some(mut peer) = peer_opt else { continue };

            match f(&addr, is_inbound, &mut peer) {
                Ok(()) => {
                    // Return peer to slot
                    let mut slots = self.slots.lock().unwrap();
                    if let Some(slot) = slots.iter_mut().find(|s| s.addr == addr && s.peer.is_none()) {
                        slot.peer = Some(peer);
                        slot.checked_out_at = None;
                    }
                }
                Err(reason) => {
                    warn!("PeerPool: removing peer {}: {}", addr, reason);
                    dead_addrs.push(addr);
                }
            }
        }

        if !dead_addrs.is_empty() {
            let mut slots = self.slots.lock().unwrap();
            slots.retain(|s| !dead_addrs.contains(&s.addr));
        }
    }

    /// Check whether an address is currently banned.
    pub fn is_banned(&self, addr: &str) -> bool {
        self.bans.get(addr).map_or(false, |expiry| Instant::now() < *expiry)
    }

    /// Service pings on all peers that are currently in the pool (not checked out).
    /// This keeps connections alive during idle periods.
    /// Peers are taken out of slots before I/O so the mutex is not held during network operations.
    pub fn service_pings(&self) {
        // Take all idle peers out of their slots (releases lock for I/O)
        let peers_with_addrs: Vec<(String, Peer)> = {
            let mut slots = self.slots.lock().unwrap();
            slots
                .iter_mut()
                .filter_map(|slot| slot.peer.take().map(|p| (slot.addr.clone(), p)))
                .collect()
        };

        let mut live = Vec::new();
        let mut dead_addrs = Vec::new();

        for (addr, mut peer) in peers_with_addrs {
            match peer.idle_wait(PEER_PING_TIMEOUT) {
                Ok(()) => live.push((addr, peer)),
                Err(e) => {
                    warn!(
                        "PeerPool: peer {} failed during ping service: {}",
                        addr, e
                    );
                    dead_addrs.push(addr);
                }
            }
        }

        // Return live peers and remove dead slots
        let mut slots = self.slots.lock().unwrap();
        for (addr, peer) in live {
            for slot in slots.iter_mut() {
                if slot.addr == addr && slot.peer.is_none() {
                    slot.peer = Some(peer);
                    break;
                }
            }
        }

        if !dead_addrs.is_empty() {
            slots.retain(|s| !dead_addrs.contains(&s.addr));
            let remaining = slots.len();
            info!(
                "PeerPool: removed {} dead peers, {} remaining",
                dead_addrs.len(),
                remaining
            );
        }
    }
}

impl Drop for PeerPool {
    /// Last-chance flush of in-memory scores so a clean shutdown after a
    /// shorter session than `SCORE_FLUSH_INTERVAL` doesn't lose the work.
    fn drop(&mut self) {
        if self.store.is_some() {
            self.flush_scores();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Create a PeerPool without DNS discovery for testing.
    fn test_pool() -> PeerPool {
        PeerPool {
            slots: Arc::new(Mutex::new(Vec::new())),
            addrs: AddrManager::new(MAX_KNOWN_ADDRS),
            our_height: 0,
            last_dns_query: Instant::now(),
            bans: HashMap::new(),
            tor: None,
            store: None,
            last_score_flush: Instant::now(),
        }
    }

    /// Create a PeerPool backed by an in-memory peer store, for tests that
    /// exercise the persistence code paths without touching disk.
    fn test_pool_with_store() -> PeerPool {
        PeerPool {
            slots: Arc::new(Mutex::new(Vec::new())),
            addrs: AddrManager::new(MAX_KNOWN_ADDRS),
            our_height: 0,
            last_dns_query: Instant::now(),
            bans: HashMap::new(),
            tor: None,
            store: Some(Arc::new(PeerStore::open(":memory:").unwrap())),
            last_score_flush: Instant::now(),
        }
    }

    /// Insert a test slot (peer=None, simulating a checked-out peer).
    fn add_slot(pool: &PeerPool, addr: &str, height: u32) {
        add_slot_with_inbound(pool, addr, height, false);
    }

    fn add_slot_with_inbound(pool: &PeerPool, addr: &str, height: u32, inbound: bool) {
        pool.slots.lock().unwrap().push(PeerSlot {
            peer: None,
            addr: addr.to_string(),
            user_agent: "/test/".to_string(),
            height,
            score: SCORE_DEFAULT,
            inbound,
            checked_out_at: None,
        });
    }

    #[test]
    fn count_reflects_slots() {
        let pool = test_pool();
        assert_eq!(pool.count(), 0);
        add_slot(&pool, "1.2.3.4:8333", 100);
        assert_eq!(pool.count(), 1);
        add_slot(&pool, "5.6.7.8:8333", 200);
        assert_eq!(pool.count(), 2);
    }

    #[test]
    fn peer_info_returns_all_slots() {
        let pool = test_pool();
        add_slot(&pool, "1.2.3.4:8333", 100);
        add_slot(&pool, "5.6.7.8:8333", 200);
        let info = pool.peer_info();
        assert_eq!(info.len(), 2);
        assert_eq!(info[0].addr, "1.2.3.4:8333");
        assert_eq!(info[0].height, 100);
        assert_eq!(info[1].addr, "5.6.7.8:8333");
        assert_eq!(info[1].height, 200);
    }

    #[test]
    fn get_peer_height_found_and_missing() {
        let pool = test_pool();
        add_slot(&pool, "1.2.3.4:8333", 850_000);
        assert_eq!(pool.get_peer_height("1.2.3.4:8333"), Some(850_000));
        assert_eq!(pool.get_peer_height("9.9.9.9:8333"), None);
    }

    #[test]
    fn best_peer_addr_selects_highest_height() {
        let pool = test_pool();
        add_slot(&pool, "low.peer:8333", 100);
        add_slot(&pool, "high.peer:8333", 900_000);
        add_slot(&pool, "mid.peer:8333", 500_000);
        assert_eq!(pool.best_peer_addr(), Some("high.peer:8333".to_string()));
    }

    #[test]
    fn best_peer_addr_empty_pool() {
        let pool = test_pool();
        assert_eq!(pool.best_peer_addr(), None);
    }

    #[test]
    fn best_peer_addr_prefers_high_reputation_over_marginally_higher_tip() {
        // Reliable peer one block behind beats sketchy peer at the absolute tip.
        // sketchy: 900_000 * (30/100)  = 270_000
        // reliable: 899_999 * (180/100) = 1_619_998 → reliable wins
        let mut pool = test_pool();
        add_slot(&pool, "sketchy.peer:8333", 900_000);
        add_slot(&pool, "reliable.peer:8333", 899_999);
        // 70-point penalty leaves sketchy at 30, above BAN_LOW_THRESHOLD so
        // it stays in the pool but its weighted score makes reliable win.
        pool.misbehaving("sketchy.peer:8333", 70);
        assert!(!pool.is_banned("sketchy.peer:8333"));
        pool.reward("reliable.peer:8333", 80);
        assert_eq!(
            pool.best_peer_addr(),
            Some("reliable.peer:8333".to_string())
        );
    }

    #[test]
    fn best_peer_addr_height_dominates_when_scores_equal() {
        // Sanity: with default scores, the higher-height peer wins, matching
        // the legacy behavior so the rest of the sync flow is unchanged.
        let pool = test_pool();
        add_slot(&pool, "low.peer:8333", 800_000);
        add_slot(&pool, "high.peer:8333", 900_000);
        assert_eq!(pool.best_peer_addr(), Some("high.peer:8333".to_string()));
    }

    #[test]
    fn remove_peer_drops_slot() {
        let pool = test_pool();
        add_slot(&pool, "1.2.3.4:8333", 100);
        add_slot(&pool, "5.6.7.8:8333", 200);
        assert_eq!(pool.count(), 2);
        pool.remove_peer("1.2.3.4:8333");
        assert_eq!(pool.count(), 1);
        assert_eq!(pool.get_peer_height("1.2.3.4:8333"), None);
        assert_eq!(pool.get_peer_height("5.6.7.8:8333"), Some(200));
    }

    #[test]
    fn remove_peer_nonexistent_is_noop() {
        let pool = test_pool();
        add_slot(&pool, "1.2.3.4:8333", 100);
        pool.remove_peer("9.9.9.9:8333");
        assert_eq!(pool.count(), 1);
    }

    #[test]
    fn ban_peer_removes_and_records() {
        let mut pool = test_pool();
        add_slot(&pool, "bad.peer:8333", 100);
        pool.ban_peer("bad.peer:8333");
        assert_eq!(pool.count(), 0);
        assert!(pool.is_banned("bad.peer:8333"));
    }

    #[test]
    fn misbehaving_decrements_score() {
        let mut pool = test_pool();
        add_slot(&pool, "peer:8333", 100);
        assert_eq!(pool.get_score("peer:8333"), Some(SCORE_DEFAULT));

        pool.misbehaving("peer:8333", 10);
        assert_eq!(pool.get_score("peer:8333"), Some(SCORE_DEFAULT - 10));

        pool.misbehaving("peer:8333", 20);
        assert_eq!(pool.get_score("peer:8333"), Some(SCORE_DEFAULT - 30));
    }

    #[test]
    fn misbehaving_auto_bans_at_low_threshold() {
        let mut pool = test_pool();
        add_slot(&pool, "peer:8333", 100);

        // Drop to just above ban threshold — not banned
        // 100 - 79 = 21, > BAN_LOW_THRESHOLD (20)
        pool.misbehaving("peer:8333", 79);
        assert!(!pool.is_banned("peer:8333"));
        assert_eq!(pool.count(), 1);

        // One more point — score = 20, == BAN_LOW_THRESHOLD → banned
        pool.misbehaving("peer:8333", 1);
        assert!(pool.is_banned("peer:8333"));
        assert_eq!(pool.count(), 0);
    }

    #[test]
    fn misbehaving_score_clamps_at_min() {
        let mut pool = test_pool();
        add_slot(&pool, "peer:8333", 100);

        pool.misbehaving("peer:8333", u32::MAX);
        // Score should be clamped at SCORE_MIN, not panic, and peer should be banned
        assert!(pool.is_banned("peer:8333"));
    }

    #[test]
    fn reward_increments_score() {
        let pool = test_pool();
        add_slot(&pool, "peer:8333", 100);

        pool.reward("peer:8333", 5);
        assert_eq!(pool.get_score("peer:8333"), Some(SCORE_DEFAULT + 5));

        pool.reward("peer:8333", 10);
        assert_eq!(pool.get_score("peer:8333"), Some(SCORE_DEFAULT + 15));
    }

    #[test]
    fn reward_clamps_at_max() {
        let pool = test_pool();
        add_slot(&pool, "peer:8333", 100);

        // Push way past SCORE_MAX
        pool.reward("peer:8333", 9999);
        assert_eq!(pool.get_score("peer:8333"), Some(SCORE_MAX));
    }

    #[test]
    fn reward_then_misbehave_combines_correctly() {
        // Verifies a long-lived reliable peer can absorb a penalty without
        // immediately being banned (which is the whole point of bidirectional
        // scoring).
        let mut pool = test_pool();
        add_slot(&pool, "peer:8333", 100);

        // Build up reputation
        pool.reward("peer:8333", 50); // score = 150
        assert_eq!(pool.get_score("peer:8333"), Some(150));

        // Take a 100-point hit (e.g., serving an oversized header batch)
        pool.misbehaving("peer:8333", 100); // score = 50
        assert!(!pool.is_banned("peer:8333"), "earned reputation absorbs the hit");
        assert_eq!(pool.get_score("peer:8333"), Some(50));
    }

    #[test]
    fn ban_persists_to_store() {
        // Banning a peer should write through to the SQLite store so a
        // restart still treats them as banned.
        let mut pool = test_pool_with_store();
        add_slot(&pool, "bad.peer:8333", 100);
        pool.ban_peer("bad.peer:8333");

        let store = pool.store.as_ref().unwrap().clone();
        let bans = store.load_active_bans().unwrap();
        assert!(bans.contains_key("bad.peer:8333"));
    }

    #[test]
    fn flush_scores_writes_through_to_store() {
        let mut pool = test_pool_with_store();
        add_slot(&pool, "peer.a:8333", 100);
        add_slot(&pool, "peer.b:8333", 200);
        pool.reward("peer.a:8333", 25);   // 125
        pool.misbehaving("peer.b:8333", 10); // 90

        pool.flush_scores();

        let store = pool.store.as_ref().unwrap().clone();
        assert_eq!(store.load_score("peer.a:8333").unwrap(), Some(125));
        assert_eq!(store.load_score("peer.b:8333").unwrap(), Some(90));
    }

    #[test]
    fn maintain_drops_expired_bans_from_store() {
        // Insert a ban with an already-expired Instant; maintain() should
        // drop it from both memory and disk.
        let mut pool = test_pool_with_store();
        let already_expired = Instant::now() - Duration::from_secs(1);
        pool.bans
            .insert("ghost.peer:8333".to_string(), already_expired);
        // We didn't go through ban_peer, so write the corresponding store row
        // ourselves to simulate a real persisted ban that just expired.
        let store = pool.store.as_ref().unwrap().clone();
        store
            .save_ban("ghost.peer:8333", Instant::now() + Duration::from_secs(1))
            .unwrap();

        pool.maintain();

        assert!(pool.bans.is_empty());
        // load_active_bans also prunes expired rows, so use load_score's
        // sister query: the row should be gone after maintain.
        let bans = store.load_active_bans().unwrap();
        assert!(!bans.contains_key("ghost.peer:8333"));
    }

    #[test]
    fn bans_overflow_eviction_keeps_newest() {
        let mut pool = test_pool();

        // Fill bans beyond MAX_BANS
        for i in 0..MAX_BANS + 50 {
            let addr = format!("peer{}:8333", i);
            // Stagger expiry times so oldest can be identified
            pool.bans.insert(addr, Instant::now() + Duration::from_secs(i as u64 + 1));
        }
        assert!(pool.bans.len() > MAX_BANS);

        pool.maintain();

        assert!(pool.bans.len() <= MAX_BANS);
    }

    #[test]
    fn slot_checkout_timeout_reclaim() {
        let mut pool = test_pool();

        // Add a slot with checkout time far in the past (simulating a leaked peer)
        {
            let mut slots = pool.slots.lock().unwrap();
            slots.push(PeerSlot {
                peer: None,
                addr: "leaked:8333".to_string(),
                user_agent: "/test/".to_string(),
                height: 100,
                score: SCORE_DEFAULT,
                inbound: false,
                checked_out_at: Some(Instant::now() - Duration::from_secs(300)),
            });
            // Also add a healthy slot with no checkout
            slots.push(PeerSlot {
                peer: None,
                addr: "healthy:8333".to_string(),
                user_agent: "/test/".to_string(),
                height: 200,
                score: SCORE_DEFAULT,
                inbound: false,
                checked_out_at: None,
            });
        }
        assert_eq!(pool.count(), 2);

        pool.maintain();

        // Leaked slot should be reclaimed, healthy one kept
        assert_eq!(pool.count(), 1);
        assert_eq!(pool.get_peer_height("leaked:8333"), None);
        assert_eq!(pool.get_peer_height("healthy:8333"), Some(200));
    }

    #[test]
    fn recent_checkout_not_reclaimed() {
        let mut pool = test_pool();

        {
            let mut slots = pool.slots.lock().unwrap();
            slots.push(PeerSlot {
                peer: None,
                addr: "recent:8333".to_string(),
                user_agent: "/test/".to_string(),
                height: 100,
                score: SCORE_DEFAULT,
                inbound: false,
                checked_out_at: Some(Instant::now()), // just now
            });
        }

        pool.maintain();

        // Recently checked out slot should NOT be reclaimed
        assert_eq!(pool.count(), 1);
    }

    #[test]
    fn update_our_height() {
        let mut pool = test_pool();
        assert_eq!(pool.our_height, 0);
        pool.update_our_height(850_000);
        assert_eq!(pool.our_height, 850_000);
    }

    #[test]
    fn best_peer_returns_none_when_all_checked_out() {
        let pool = test_pool();
        // Slots with peer=None (all checked out)
        add_slot(&pool, "peer:8333", 100);
        assert!(pool.best_peer().is_none());
    }

    #[test]
    fn any_peer_returns_none_when_all_checked_out() {
        let pool = test_pool();
        add_slot(&pool, "peer:8333", 100);
        assert!(pool.any_peer().is_none());
    }

    #[test]
    fn best_peer_skips_checked_out_slots() {
        let pool = test_pool();
        // Slots with peer=None are treated as checked-out; best_peer should skip them
        add_slot(&pool, "peer:8333", 100);
        assert!(pool.best_peer().is_none());

        // Verify the slot was not modified (no checkout timestamp set)
        let slots = pool.slots.lock().unwrap();
        assert!(slots[0].checked_out_at.is_none());
    }

    #[test]
    fn is_banned_false_for_unknown() {
        let pool = test_pool();
        assert!(!pool.is_banned("unknown:8333"));
    }

    // ── Inbound peer slot tests ──────────────────────────────────────

    #[test]
    fn inbound_outbound_counts() {
        let pool = test_pool();
        add_slot_with_inbound(&pool, "out1:8333", 100, false);
        add_slot_with_inbound(&pool, "out2:8333", 200, false);
        add_slot_with_inbound(&pool, "in1:8333", 300, true);

        assert_eq!(pool.outbound_count(), 2);
        assert_eq!(pool.inbound_count(), 1);
        assert_eq!(pool.count(), 3);
    }

    #[test]
    fn maintain_only_fills_outbound() {
        let mut pool = test_pool();
        // Fill with MAX_OUTBOUND outbound + some inbound slots
        for i in 0..MAX_OUTBOUND {
            add_slot_with_inbound(&pool, &format!("out{}:8333", i), 100, false);
        }
        add_slot_with_inbound(&pool, "in1:8333", 100, true);

        // maintain() should not try to add more outbound (already at MAX_OUTBOUND)
        pool.maintain();
        assert_eq!(pool.outbound_count(), MAX_OUTBOUND);
    }

    // ── Subnet diversity tests ───────────────────────────────────────

    #[test]
    fn subnet_bucket_ipv4() {
        assert_eq!(subnet_bucket("1.2.3.4:8333"), Some("v4:1.2".to_string()));
        assert_eq!(subnet_bucket("1.2.99.99:8333"), Some("v4:1.2".to_string()));
        assert_eq!(subnet_bucket("10.0.0.1:8333"), Some("v4:10.0".to_string()));
    }

    #[test]
    fn subnet_bucket_ipv6() {
        assert_eq!(
            subnet_bucket("[2001:db8::1]:8333"),
            Some("v6:2001:db8".to_string())
        );
        assert_eq!(
            subnet_bucket("[2001:db8:1234:5678::1]:8333"),
            Some("v6:2001:db8".to_string())
        );
    }

    #[test]
    fn subnet_bucket_onion_returns_none() {
        // .onion addresses skip the diversity check entirely
        assert_eq!(
            subnet_bucket("abcdef1234567890abcdef1234567890abcdef1234567890abcdef.onion:8333"),
            None
        );
    }

    #[test]
    fn subnet_bucket_unparseable_returns_none() {
        assert_eq!(subnet_bucket("garbage"), None);
        assert_eq!(subnet_bucket("not.an.ip.really:8333"), None);
    }

    #[test]
    fn subnet_diversity_via_bucket_helper() {
        // Direct test of the helper used by maintain() — verifies that two
        // addresses in the same /16 hash to the same bucket and would be
        // rejected by the diversity check.
        let a = subnet_bucket("1.2.3.4:8333");
        let b = subnet_bucket("1.2.5.6:8333");
        let c = subnet_bucket("1.3.0.1:8333");
        assert_eq!(a, b, "same /16 should bucket together");
        assert_ne!(a, c, "different /16 should bucket apart");
    }

    #[test]
    fn for_each_peer_skips_checked_out() {
        let pool = test_pool();
        // All slots have peer=None (simulating checked out), so callback should never fire
        add_slot(&pool, "peer1:8333", 100);
        add_slot(&pool, "peer2:8333", 200);

        let mut visited = Vec::new();
        pool.for_each_peer(|addr, _, _| {
            visited.push(addr.to_string());
            Ok(())
        });
        assert!(visited.is_empty());
    }

    // ── AddrManager tests ────────────────────────────────────────────

    #[test]
    fn addrman_insert_dedupes() {
        let mut m = AddrManager::new(100);
        assert!(m.insert("1.2.3.4:8333".to_string()));
        assert!(!m.insert("1.2.3.4:8333".to_string()));
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn addrman_insert_many_counts_only_new() {
        let mut m = AddrManager::new(100);
        let added = m.insert_many(vec![
            "1.2.3.4:8333".to_string(),
            "5.6.7.8:8333".to_string(),
            "1.2.3.4:8333".to_string(), // duplicate
        ]);
        assert_eq!(added, 2);
        assert_eq!(m.len(), 2);
    }

    #[test]
    fn addrman_record_success_marks_known_good() {
        let mut m = AddrManager::new(100);
        m.insert("1.2.3.4:8333".to_string());
        m.record_success("1.2.3.4:8333");
        let meta = m.addrs.get("1.2.3.4:8333").unwrap();
        assert!(meta.last_success.is_some());
        assert_eq!(meta.failure_count, 0);
        assert_eq!(meta.tier(Instant::now()), 0); // tier 0 = known-good
    }

    #[test]
    fn addrman_record_failure_increments_count() {
        let mut m = AddrManager::new(100);
        m.insert("1.2.3.4:8333".to_string());
        m.record_failure("1.2.3.4:8333");
        m.record_failure("1.2.3.4:8333");
        let meta = m.addrs.get("1.2.3.4:8333").unwrap();
        assert_eq!(meta.failure_count, 2);
        assert!(meta.last_success.is_none());
    }

    #[test]
    fn addrman_record_success_after_failures_resets() {
        let mut m = AddrManager::new(100);
        m.insert("1.2.3.4:8333".to_string());
        m.record_failure("1.2.3.4:8333");
        m.record_failure("1.2.3.4:8333");
        m.record_success("1.2.3.4:8333");
        let meta = m.addrs.get("1.2.3.4:8333").unwrap();
        assert_eq!(meta.failure_count, 0);
        assert_eq!(meta.tier(Instant::now()), 0);
    }

    #[test]
    fn addrman_backoff_grows_with_failures() {
        // Backoff doubles per failure, starting from ADDR_RETRY_BASE.
        let mut meta = AddrMeta::new();
        meta.last_tried = Some(Instant::now());

        meta.failure_count = 1;
        assert_eq!(meta.current_backoff(), ADDR_RETRY_BASE);

        meta.failure_count = 2;
        assert_eq!(meta.current_backoff(), ADDR_RETRY_BASE * 2);

        meta.failure_count = 3;
        assert_eq!(meta.current_backoff(), ADDR_RETRY_BASE * 4);
    }

    #[test]
    fn addrman_backoff_caps_at_max() {
        // After enough failures the backoff plateaus at ADDR_RETRY_MAX
        // instead of growing without bound.
        let mut meta = AddrMeta::new();
        meta.last_tried = Some(Instant::now());
        meta.failure_count = 50;
        assert_eq!(meta.current_backoff(), ADDR_RETRY_MAX);
    }

    #[test]
    fn addrman_eligible_for_never_tried() {
        let meta = AddrMeta::new();
        assert!(meta.is_eligible(Instant::now()));
    }

    #[test]
    fn addrman_eligible_after_backoff_elapsed() {
        // Synthesise an entry whose last_tried was long ago, so even with
        // failures the backoff has elapsed.
        let mut meta = AddrMeta::new();
        meta.failure_count = 1;
        meta.last_tried = Some(Instant::now() - (ADDR_RETRY_BASE * 2));
        assert!(meta.is_eligible(Instant::now()));
    }

    #[test]
    fn addrman_pick_candidates_orders_known_good_first() {
        let mut m = AddrManager::new(100);
        m.insert("never:8333".to_string());
        m.insert("good:8333".to_string());
        m.record_success("good:8333");

        let picked = m.pick_candidates(10, &|_| false);
        assert_eq!(picked[0], "good:8333");
        assert_eq!(picked[1], "never:8333");
    }

    #[test]
    fn addrman_pick_candidates_respects_exclude() {
        let mut m = AddrManager::new(100);
        m.insert("a:8333".to_string());
        m.insert("b:8333".to_string());
        m.insert("c:8333".to_string());

        let picked = m.pick_candidates(10, &|addr| addr == "b:8333");
        assert_eq!(picked.len(), 2);
        assert!(!picked.contains(&"b:8333".to_string()));
    }

    #[test]
    fn addrman_pick_candidates_respects_limit() {
        let mut m = AddrManager::new(100);
        for i in 0..10 {
            m.insert(format!("peer{}:8333", i));
        }
        let picked = m.pick_candidates(3, &|_| false);
        assert_eq!(picked.len(), 3);
    }

    #[test]
    fn addrman_eviction_protects_known_good_entry() {
        // With a tiny capacity, inserting a new address should evict the
        // never-tried entry, never the known-good one. (`record_success`
        // marks the entry as the highest tier, so eviction picks the
        // remaining lower-tier entry.)
        let mut m = AddrManager::new(2);
        m.insert("good:8333".to_string());
        m.record_success("good:8333");
        m.insert("never:8333".to_string());
        assert_eq!(m.len(), 2);

        // Inserting a third should evict "never", not "good".
        m.insert("new:8333".to_string());
        assert_eq!(m.len(), 2);
        assert!(m.addrs.contains_key("good:8333"));
        assert!(m.addrs.contains_key("new:8333"));
        assert!(!m.addrs.contains_key("never:8333"));
    }

    #[test]
    fn addrman_eviction_drops_most_failed_entry() {
        // When the AddrManager is full and no known-good entry exists, the
        // entry with the highest failure_count should be evicted first
        // (this is the actual policy implemented by `evict_if_full`).
        let mut m = AddrManager::new(2);
        m.insert("flaky:8333".to_string());
        m.record_failure("flaky:8333");
        m.record_failure("flaky:8333");
        m.record_failure("flaky:8333");
        m.insert("fresh:8333".to_string());
        assert_eq!(m.len(), 2);

        // A new insertion should evict "flaky" (3 failures) over "fresh"
        // (0 failures).
        m.insert("newcomer:8333".to_string());
        assert_eq!(m.len(), 2);
        assert!(!m.addrs.contains_key("flaky:8333"));
        assert!(m.addrs.contains_key("fresh:8333"));
        assert!(m.addrs.contains_key("newcomer:8333"));
    }

    #[test]
    fn addrman_candidate_count_excludes_in_backoff() {
        let mut m = AddrManager::new(100);
        m.insert("eligible:8333".to_string());
        m.insert("backoff:8333".to_string());
        m.record_failure("backoff:8333");
        // backoff:8333 just failed → not eligible until ADDR_RETRY_BASE elapses
        assert_eq!(m.candidate_count(), 1);
    }

    #[test]
    fn addrman_record_on_unknown_address_creates_entry() {
        // Defensive: record_success / record_failure on a never-seen address
        // should still work (e.g., a peer we connect to that we never put
        // through `insert` ourselves).
        let mut m = AddrManager::new(100);
        m.record_success("surprise:8333");
        assert!(m.addrs.contains_key("surprise:8333"));
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn ingest_gossip_addrs_returns_count_added() {
        let mut pool = test_pool();
        let added = pool.ingest_gossip_addrs(vec![
            "1.2.3.4:8333".to_string(),
            "5.6.7.8:8333".to_string(),
        ]);
        assert_eq!(added, 2);
        assert_eq!(pool.known_addr_count(), 2);

        // Re-ingesting the same addresses adds zero new entries.
        let added2 = pool.ingest_gossip_addrs(vec!["1.2.3.4:8333".to_string()]);
        assert_eq!(added2, 0);
        assert_eq!(pool.known_addr_count(), 2);
    }
}
