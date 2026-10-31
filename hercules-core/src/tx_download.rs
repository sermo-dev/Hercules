//! Transaction download bookkeeping (ticket 052): a recently-rejected
//! filter, so a transaction our policy refused isn't fetched again from
//! every peer that announces it, and a map of in-flight requests, so one
//! announced by several peers at once is fetched from one of them, and from
//! another only once that request has timed out.
//!
//! Both follow Bitcoin Core: the filter is `m_lazy_recent_rejects` (reset
//! whenever the chain tip changes, keyed by wtxid, and by txid only when the
//! witness can't have been the reason), the timeout is
//! `GETDATA_TX_INTERVAL`. Core's `TxRequestTracker` is far richer
//! (per-peer limits, preferred peers, delays for inbound announcers); this
//! keeps the part that stops the repeated downloads.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use bitcoin::hashes::Hash;
use bitcoin::{Txid, Wtxid};

/// Core's `GETDATA_TX_INTERVAL`: how long a peer has to deliver a tx we
/// asked it for before another announcer is asked.
pub const TX_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// Entries per generation of the rolling reject filter: it holds between
/// one and two generations (Core's `CRollingBloomFilter` holds 120,000
/// with a false-positive rate; this exact set is smaller for a phone, and
/// is reset at every block anyway).
const REJECTS_PER_GENERATION: usize = 25_000;

/// Most txs in flight at once: announcements beyond it aren't requested
/// (a peer re-announcing later gets them asked for).
const MAX_IN_FLIGHT: usize = 10_000;

/// Other announcers remembered per in-flight tx, to ask in turn.
const MAX_ALTERNATES: usize = 8;

/// A rolling set: inserts go into `current`; when it fills, it becomes
/// `previous` and the old `previous` is dropped.
#[derive(Default)]
struct RollingSet {
    current: HashSet<[u8; 32]>,
    previous: HashSet<[u8; 32]>,
}

impl RollingSet {
    fn insert(&mut self, key: [u8; 32]) {
        if self.current.len() >= REJECTS_PER_GENERATION {
            self.previous = std::mem::take(&mut self.current);
        }
        self.current.insert(key);
    }

    fn contains(&self, key: &[u8; 32]) -> bool {
        self.current.contains(key) || self.previous.contains(key)
    }

    fn clear(&mut self) {
        self.current.clear();
        self.previous.clear();
    }
}

struct InFlight {
    peer: String,
    expires_at: Instant,
    alternates: VecDeque<String>,
}

#[derive(Default)]
pub struct TxDownload {
    rejects: RollingSet,
    /// The validated height the filter's verdicts were reached at.
    rejects_tip: Option<u32>,
    in_flight: HashMap<Txid, InFlight>,
}

impl TxDownload {
    pub fn new() -> TxDownload {
        TxDownload::default()
    }

    /// Our validated tip is at `height`: if it moved since the filter's
    /// verdicts, they are stale (a block may have made a premature spend
    /// final, or confirmed a parent) and the filter starts over, as Core's
    /// does when `hashRecentRejectsChainTip` changes. Keyed on the height,
    /// which every block connected or disconnected moves.
    pub fn on_tip(&mut self, height: u32) {
        if self.rejects_tip != Some(height) {
            self.rejects.clear();
            self.rejects_tip = Some(height);
        }
    }

    /// Remember a rejected transaction until the next block. Always by
    /// wtxid; by txid as well only if `by_txid` (the rejection didn't
    /// depend on the witness). Core never filters a witness transaction by
    /// txid for a witness-dependent failure: a peer could send a copy with a
    /// mangled witness and so hide the valid transaction (bitcoin#8279).
    /// For a transaction without a witness the two are equal.
    pub fn reject(&mut self, txid: Txid, wtxid: Wtxid, by_txid: bool) {
        self.rejects.insert(wtxid.to_byte_array());
        if by_txid {
            self.rejects.insert(txid.to_byte_array());
        }
    }

    /// True if an announcement of `txid` is for a transaction we rejected
    /// since the last block.
    pub fn recently_rejected(&self, txid: &Txid) -> bool {
        self.rejects.contains(&txid.to_byte_array())
    }

    /// `peer` announced `txid` (which we lack and haven't rejected): true if
    /// we should ask it now. Not while another peer's request is in flight
    /// and not timed out; this peer is then remembered as a fallback.
    pub fn should_request(&mut self, txid: Txid, peer: &str, now: Instant) -> bool {
        if let Some(entry) = self.in_flight.get_mut(&txid) {
            if now < entry.expires_at {
                if entry.peer != peer
                    && entry.alternates.len() < MAX_ALTERNATES
                    && !entry.alternates.iter().any(|p| p == peer)
                {
                    entry.alternates.push_back(peer.to_string());
                }
                return false;
            }
            entry.peer = peer.to_string();
            entry.expires_at = now + TX_REQUEST_TIMEOUT;
            entry.alternates.retain(|p| p != peer);
            return true;
        }
        if self.in_flight.len() >= MAX_IN_FLIGHT {
            return false;
        }
        self.in_flight.insert(
            txid,
            InFlight { peer: peer.to_string(), expires_at: now + TX_REQUEST_TIMEOUT, alternates: VecDeque::new() },
        );
        true
    }

    /// The transaction arrived (accepted or not): nothing is in flight.
    pub fn received(&mut self, txid: &Txid) {
        self.in_flight.remove(txid);
    }

    /// `peer` said `notfound` for `txid`: if it was the one asked, its
    /// request is over now rather than at the timeout, as in Core.
    pub fn not_found(&mut self, txid: &Txid, peer: &str, now: Instant) {
        if let Some(entry) = self.in_flight.get_mut(txid) {
            if entry.peer == peer {
                entry.expires_at = now;
            }
        }
    }

    /// `peer` is gone: its requests are over, and it is no fallback.
    pub fn forget_peer(&mut self, peer: &str, now: Instant) {
        for entry in self.in_flight.values_mut() {
            entry.alternates.retain(|p| p != peer);
            if entry.peer == peer {
                entry.expires_at = now;
            }
        }
    }

    /// Every peer with a request in flight or waiting as a fallback.
    pub fn peers(&self) -> impl Iterator<Item = &str> {
        self.in_flight
            .values()
            .flat_map(|e| std::iter::once(e.peer.as_str()).chain(e.alternates.iter().map(|p| p.as_str())))
    }

    /// Requests that have run out: each with a fallback announcer is
    /// handed to the next one (returned as `(peer, txid)` to ask), the rest
    /// are dropped.
    pub fn retries(&mut self, now: Instant) -> Vec<(String, Txid)> {
        let mut out = Vec::new();
        self.in_flight.retain(|txid, entry| {
            if now < entry.expires_at {
                return true;
            }
            match entry.alternates.pop_front() {
                Some(next) => {
                    entry.peer = next.clone();
                    entry.expires_at = now + TX_REQUEST_TIMEOUT;
                    out.push((next, *txid));
                    true
                }
                None => false,
            }
        });
        out
    }

    #[cfg(test)]
    pub fn in_flight_from(&self, txid: &Txid) -> Option<&str> {
        self.in_flight.get(txid).map(|e| e.peer.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn txid(i: u8) -> Txid {
        Txid::from_byte_array([i; 32])
    }

    fn wtxid(i: u8) -> Wtxid {
        Wtxid::from_byte_array([i; 32])
    }

    #[test]
    fn rejects_are_forgotten_when_the_tip_moves() {
        let mut d = TxDownload::new();
        d.on_tip(100);
        d.reject(txid(1), wtxid(1), true);
        assert!(d.recently_rejected(&txid(1)));
        d.on_tip(100);
        assert!(d.recently_rejected(&txid(1)), "same tip keeps the verdict");
        d.on_tip(101);
        assert!(!d.recently_rejected(&txid(1)));
    }

    #[test]
    fn a_witness_dependent_rejection_is_filtered_by_wtxid_only() {
        let mut d = TxDownload::new();
        d.on_tip(1);
        d.reject(txid(2), wtxid(3), false);
        assert!(!d.recently_rejected(&txid(2)), "valid copy with another witness hidden");
        assert!(d.rejects.contains(&wtxid(3).to_byte_array()));
        d.reject(txid(4), wtxid(5), true);
        assert!(d.recently_rejected(&txid(4)));
    }

    #[test]
    fn the_filter_rolls_over_instead_of_growing() {
        let mut d = TxDownload::new();
        d.on_tip(1);
        for i in 0..(3 * REJECTS_PER_GENERATION) as u32 {
            let mut b = [0u8; 32];
            b[..4].copy_from_slice(&i.to_le_bytes());
            d.reject(Txid::from_byte_array(b), Wtxid::from_byte_array(b), true);
        }
        assert!(d.rejects.current.len() + d.rejects.previous.len() <= 2 * REJECTS_PER_GENERATION);
    }

    #[test]
    fn one_request_per_tx_until_it_times_out() {
        let mut d = TxDownload::new();
        let t0 = Instant::now();
        assert!(d.should_request(txid(1), "a", t0));
        assert!(!d.should_request(txid(1), "b", t0 + Duration::from_secs(1)));
        assert!(!d.should_request(txid(1), "c", t0 + Duration::from_secs(2)));
        assert!(!d.should_request(txid(1), "a", t0 + Duration::from_secs(3)), "asked again of the same peer");
        // Timed out: the fallbacks are asked in announcement order.
        let later = t0 + TX_REQUEST_TIMEOUT;
        assert_eq!(d.retries(later), vec![("b".to_string(), txid(1))]);
        assert_eq!(d.in_flight_from(&txid(1)), Some("b"));
        assert!(d.retries(later).is_empty(), "b has its own timeout");
        d.received(&txid(1));
        assert!(d.retries(later + TX_REQUEST_TIMEOUT).is_empty());
        assert!(d.should_request(txid(1), "c", later), "fresh after delivery");
    }

    #[test]
    fn notfound_or_a_disconnect_hands_the_request_on_at_once() {
        let mut d = TxDownload::new();
        let t0 = Instant::now();
        assert!(d.should_request(txid(1), "a", t0));
        assert!(!d.should_request(txid(1), "b", t0));
        d.not_found(&txid(1), "b", t0); // not the one asked: ignored
        assert!(d.retries(t0).is_empty());
        d.not_found(&txid(1), "a", t0);
        assert_eq!(d.retries(t0), vec![("b".to_string(), txid(1))]);
        d.forget_peer("b", t0);
        assert!(d.retries(t0).is_empty(), "no fallback left: dropped");
        assert_eq!(d.in_flight_from(&txid(1)), None);
    }

    #[test]
    fn a_late_announcer_takes_over_an_expired_request() {
        let mut d = TxDownload::new();
        let t0 = Instant::now();
        assert!(d.should_request(txid(1), "a", t0));
        assert!(d.should_request(txid(1), "b", t0 + TX_REQUEST_TIMEOUT));
        assert_eq!(d.in_flight_from(&txid(1)), Some("b"));
    }
}
