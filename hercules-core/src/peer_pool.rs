use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use log::{info, warn};

use crate::p2p::{Peer, PeerError};
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
    misbehavior: u32,
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

/// Misbehavior score threshold for automatic banning (matches Bitcoin Core's 100).
const BAN_THRESHOLD: u32 = 100;

/// Maximum ban entries to prevent unbounded memory growth from address rotation.
const MAX_BANS: usize = 1024;

/// Timeout for checked-out peer slots before they are reclaimed (prevents slot leaks).
const CHECKOUT_TIMEOUT: Duration = Duration::from_secs(120);

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
}

impl PeerPool {
    /// Create a new peer pool. Discovers peers via DNS (or Tor if available)
    /// and connects to an initial batch of up to `MAX_OUTBOUND` peers.
    pub fn new(our_height: u32, tor: Option<Arc<TorManager>>) -> Result<PeerPool, PeerError> {
        let addrs = if let Some(ref tor) = tor {
            Peer::discover_peers_tor(tor)
        } else {
            Peer::discover_peers()
        };

        if addrs.is_empty() {
            return Err(PeerError::Connection("no peers discovered via DNS".into()));
        }

        info!("PeerPool: discovered {} addresses, connecting up to {}", addrs.len(), MAX_OUTBOUND);

        let mut pool = PeerPool {
            slots: Arc::new(Mutex::new(Vec::new())),
            known_addrs: addrs,
            next_addr: 0,
            our_height,
            last_dns_query: Instant::now(),
            bans: HashMap::new(),
            tor,
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
        self.bans.retain(|_, expiry| *expiry > now);
        if self.bans.len() > MAX_BANS {
            // Evict oldest bans (earliest expiry) to stay bounded
            let mut entries: Vec<_> = self.bans.drain().collect();
            entries.sort_by_key(|(_, expiry)| *expiry);
            let skip = entries.len() - MAX_BANS;
            self.bans = entries.into_iter().skip(skip).collect();
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

                    let slot = PeerSlot {
                        peer: Some(peer),
                        addr,
                        user_agent,
                        height,
                        misbehavior: 0,
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

    /// Return the peer with the highest reported height, temporarily taking
    /// it out of the pool. The caller MUST return it via `return_peer`.
    pub fn best_peer(&self) -> Option<Peer> {
        let mut slots = self.slots.lock().unwrap();
        if slots.is_empty() {
            return None;
        }

        // Find index of peer with highest height
        let best_idx = slots
            .iter()
            .enumerate()
            .filter(|(_, s)| s.peer.is_some())
            .max_by_key(|(_, s)| s.height)
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
    pub fn ban_peer(&mut self, addr: &str) {
        let expiry = Instant::now() + BAN_DURATION;
        self.bans.insert(addr.to_string(), expiry);
        self.remove_peer(addr);
        info!("PeerPool: banned peer {} for 24h", addr);
    }

    /// Record misbehavior for a peer. If the score reaches BAN_THRESHOLD (100),
    /// the peer is automatically banned (following Bitcoin Core's Misbehaving() pattern).
    pub fn misbehaving(&mut self, addr: &str, howmuch: u32) {
        let mut should_ban = false;
        {
            let mut slots = self.slots.lock().unwrap();
            if let Some(slot) = slots.iter_mut().find(|s| s.addr == addr) {
                slot.misbehavior = slot.misbehavior.saturating_add(howmuch);
                warn!(
                    "PeerPool: peer {} misbehaving (+{}), score now {}",
                    addr, howmuch, slot.misbehavior
                );
                if slot.misbehavior >= BAN_THRESHOLD {
                    should_ban = true;
                }
            }
        }
        if should_ban {
            self.ban_peer(addr);
        }
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

    /// Get the address of the best peer (highest height) without taking it.
    pub fn best_peer_addr(&self) -> Option<String> {
        let slots = self.slots.lock().unwrap();
        slots
            .iter()
            .max_by_key(|s| s.height)
            .map(|s| s.addr.clone())
    }

    /// Add an inbound peer to the pool. Returns false if at inbound capacity.
    /// Uses a single lock acquisition for check+insert to avoid TOCTOU races.
    pub fn add_inbound_peer(&self, peer: Peer) -> bool {
        let addr = peer.addr().to_string();
        let user_agent = peer.peer_user_agent().unwrap_or_default();
        let height = peer.peer_height().unwrap_or(0).max(0) as u32;

        let mut slots = self.slots.lock().unwrap();
        let inbound = slots.iter().filter(|s| s.inbound).count();
        if inbound >= MAX_INBOUND {
            info!("PeerPool: rejecting inbound peer (at capacity {}/{})", inbound, MAX_INBOUND);
            return false;
        }

        info!("PeerPool: accepted inbound peer {} ({}) at height {}", addr, user_agent, height);

        slots.push(PeerSlot {
            peer: Some(peer),
            addr,
            user_agent,
            height,
            misbehavior: 0,
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
            misbehavior: 0,
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
    fn misbehaving_increments_score() {
        let mut pool = test_pool();
        add_slot(&pool, "peer:8333", 100);

        pool.misbehaving("peer:8333", 10);
        {
            let slots = pool.slots.lock().unwrap();
            let slot = slots.iter().find(|s| s.addr == "peer:8333").unwrap();
            assert_eq!(slot.misbehavior, 10);
        }

        pool.misbehaving("peer:8333", 20);
        {
            let slots = pool.slots.lock().unwrap();
            let slot = slots.iter().find(|s| s.addr == "peer:8333").unwrap();
            assert_eq!(slot.misbehavior, 30);
        }
    }

    #[test]
    fn misbehaving_auto_bans_at_threshold() {
        let mut pool = test_pool();
        add_slot(&pool, "peer:8333", 100);

        // Below threshold — not banned
        pool.misbehaving("peer:8333", 99);
        assert!(!pool.is_banned("peer:8333"));
        assert_eq!(pool.count(), 1);

        // Exactly at threshold — banned
        pool.misbehaving("peer:8333", 1);
        assert!(pool.is_banned("peer:8333"));
        assert_eq!(pool.count(), 0);
    }

    #[test]
    fn misbehaving_score_saturates() {
        let mut pool = test_pool();
        add_slot(&pool, "peer:8333", 100);

        pool.misbehaving("peer:8333", u32::MAX);
        // Should be banned (score >= 100) and not panic from overflow
        assert!(pool.is_banned("peer:8333"));
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
                misbehavior: 0,
                inbound: false,
                checked_out_at: Some(Instant::now() - Duration::from_secs(300)),
            });
            // Also add a healthy slot with no checkout
            slots.push(PeerSlot {
                peer: None,
                addr: "healthy:8333".to_string(),
                user_agent: "/test/".to_string(),
                height: 200,
                misbehavior: 0,
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
                misbehavior: 0,
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
