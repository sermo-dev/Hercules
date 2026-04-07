use std::collections::HashMap;
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
    known_addrs: Vec<String>,
    /// Index into known_addrs for round-robin connection attempts.
    next_addr: usize,
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
        let addrs = if let Some(ref tor) = tor {
            Peer::discover_peers_tor(tor)
        } else {
            Peer::discover_peers()
        };

        if addrs.is_empty() {
            return Err(PeerError::Connection("no peers discovered via DNS".into()));
        }

        info!("PeerPool: discovered {} addresses, connecting up to {}", addrs.len(), MAX_OUTBOUND);

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

        let mut pool = PeerPool {
            slots: Arc::new(Mutex::new(Vec::new())),
            known_addrs: addrs,
            next_addr: 0,
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

        // Re-discover peers from DNS if we've exhausted the address list
        // (with backoff to avoid spamming DNS seeds)
        if self.next_addr >= self.known_addrs.len()
            && self.last_dns_query.elapsed() >= DNS_REDISCOVERY_INTERVAL
        {
            self.last_dns_query = Instant::now();
            let fresh = if let Some(ref tor) = self.tor {
                Peer::discover_peers_tor(tor)
            } else {
                Peer::discover_peers()
            };
            if !fresh.is_empty() {
                info!(
                    "PeerPool: refreshed DNS, got {} addresses",
                    fresh.len()
                );
                self.known_addrs = fresh;
                self.next_addr = 0;
            }
        }

        let needed = MAX_OUTBOUND - current;
        let mut connected = 0;
        let mut attempts = 0;
        let max_attempts = needed * 3; // try up to 3x the slots we need

        while connected < needed && attempts < max_attempts {
            if self.next_addr >= self.known_addrs.len() {
                break; // exhausted address list
            }

            let addr = self.known_addrs[self.next_addr].clone();
            self.next_addr += 1;
            attempts += 1;

            // Skip if already connected or banned
            if self.bans.contains_key(&addr) {
                continue;
            }
            {
                let slots = self.slots.lock().unwrap();
                if slots.iter().any(|s| s.addr == addr) {
                    continue;
                }
                // Subnet diversity: don't fill outbound slots with multiple
                // peers from the same /16. .onion addresses skip this check
                // (they return None from subnet_bucket).
                if let Some(ref bucket) = subnet_bucket(&addr) {
                    let already_present = slots.iter().any(|s| {
                        !s.inbound
                            && subnet_bucket(&s.addr).as_ref() == Some(bucket)
                    });
                    if already_present {
                        continue;
                    }
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
                    info!("PeerPool: connected to {} ({}) at height {}", addr, user_agent, height);

                    // Restore any persisted score so a known-good peer comes
                    // back at its earned reputation, not as a stranger.
                    let score = self
                        .store
                        .as_ref()
                        .and_then(|s| s.load_score(&addr).ok().flatten())
                        .unwrap_or(SCORE_DEFAULT);

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
                }
            }
        }

        if connected > 0 {
            let total = self.slots.lock().unwrap().len();
            info!("PeerPool: added {} peers, total now {}/{}", connected, total, MAX_OUTBOUND);
        }
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
            known_addrs: Vec::new(),
            next_addr: 0,
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
            known_addrs: Vec::new(),
            next_addr: 0,
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
}
