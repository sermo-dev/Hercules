use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use log::{info, warn};

use crate::p2p::{Peer, PeerError};

/// Maximum number of outbound connections (matches Bitcoin Core default).
const MAX_OUTBOUND: usize = 8;

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
    addr: SocketAddr,
    user_agent: String,
    height: u32,
    connected_at: Instant,
}

/// Minimum interval between DNS re-discovery attempts.
const DNS_REDISCOVERY_INTERVAL: Duration = Duration::from_secs(60);

/// Thread-safe pool of Bitcoin peer connections.
/// Maximum number of banned addresses to track (bounded to prevent growth).
const MAX_BANNED: usize = 256;

pub struct PeerPool {
    slots: Arc<Mutex<Vec<PeerSlot>>>,
    known_addrs: Vec<SocketAddr>,
    /// Index into known_addrs for round-robin connection attempts.
    next_addr: usize,
    our_height: u32,
    /// Last time DNS seeds were queried (for backoff).
    last_dns_query: Instant,
    /// Peers banned for misbehavior (height lying, invalid data).
    banned_addrs: HashSet<SocketAddr>,
}

impl PeerPool {
    /// Create a new peer pool. Discovers peers via DNS and connects to an
    /// initial batch of up to `MAX_OUTBOUND` peers.
    pub fn new(our_height: u32) -> Result<PeerPool, PeerError> {
        let addrs = Peer::discover_peers();
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
            banned_addrs: HashSet::new(),
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
        let current = self.slots.lock().unwrap().len();
        if current >= MAX_OUTBOUND {
            return;
        }

        // Re-discover peers from DNS if we've exhausted the address list
        // (with backoff to avoid spamming DNS seeds)
        if self.next_addr >= self.known_addrs.len()
            && self.last_dns_query.elapsed() >= DNS_REDISCOVERY_INTERVAL
        {
            self.last_dns_query = Instant::now();
            let fresh = Peer::discover_peers();
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

            let addr = self.known_addrs[self.next_addr];
            self.next_addr += 1;
            attempts += 1;

            // Skip if already connected or banned
            if self.banned_addrs.contains(&addr) {
                continue;
            }
            {
                let slots = self.slots.lock().unwrap();
                if slots.iter().any(|s| s.addr == addr) {
                    continue;
                }
            }

            match Peer::connect(addr, self.our_height as i32) {
                Ok(peer) => {
                    let user_agent = peer.peer_user_agent().unwrap_or_default();
                    let height = peer.peer_height().unwrap_or(0) as u32;
                    info!("PeerPool: connected to {} ({}) at height {}", addr, user_agent, height);

                    let slot = PeerSlot {
                        peer: Some(peer),
                        addr,
                        user_agent,
                        height,
                        connected_at: Instant::now(),
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

        slots[best_idx].peer.take()
    }

    /// Return any available connected peer, temporarily taking it out of the
    /// pool. The caller MUST return it via `return_peer`.
    pub fn any_peer(&self) -> Option<Peer> {
        let mut slots = self.slots.lock().unwrap();
        for slot in slots.iter_mut() {
            if slot.peer.is_some() {
                return slot.peer.take();
            }
        }
        None
    }

    /// Return a peer back to the pool after use.
    pub fn return_peer(&self, peer: Peer) {
        let addr = peer.addr();
        let mut slots = self.slots.lock().unwrap();
        for slot in slots.iter_mut() {
            if slot.addr == addr && slot.peer.is_none() {
                slot.peer = Some(peer);
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
        slots.retain(|s| s.addr.to_string() != addr);
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
                addr: s.addr.to_string(),
                user_agent: s.user_agent.clone(),
                height: s.height,
            })
            .collect()
    }

    /// Ban a peer address. Removes it from the pool and prevents reconnection.
    pub fn ban_peer(&mut self, addr: SocketAddr) {
        // Keep ban list bounded
        if self.banned_addrs.len() >= MAX_BANNED {
            self.banned_addrs.clear();
        }
        self.banned_addrs.insert(addr);
        self.remove_peer(&addr.to_string());
        info!("PeerPool: banned peer {}", addr);
    }

    /// Get the claimed height of a connected peer by address string.
    pub fn get_peer_height(&self, addr: &str) -> Option<u32> {
        let slots = self.slots.lock().unwrap();
        slots
            .iter()
            .find(|s| s.addr.to_string() == addr)
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
            .map(|s| s.addr.to_string())
    }

    /// Service pings on all peers that are currently in the pool (not checked out).
    /// This keeps connections alive during idle periods.
    /// Peers are taken out of slots before I/O so the mutex is not held during network operations.
    pub fn service_pings(&self) {
        // Take all idle peers out of their slots (releases lock for I/O)
        let peers_with_addrs: Vec<(SocketAddr, Peer)> = {
            let mut slots = self.slots.lock().unwrap();
            slots
                .iter_mut()
                .filter_map(|slot| slot.peer.take().map(|p| (slot.addr, p)))
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
