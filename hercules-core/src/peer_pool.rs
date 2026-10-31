use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use log::{info, warn};

use crate::chain_params::ChainParams;
use crate::p2p::{Peer, PeerError};
use crate::peer_store::{AddrRecord, PeerStore};
use crate::tor::TorManager;

/// Maximum number of outbound connections. Higher than Core's default of 8
/// because Hercules's bursty wake model re-rolls peers each wake — more
/// outbound connections improve eclipse resistance per wake and increase
/// addr gossip fanout for inbound discovery.
const MAX_OUTBOUND: usize = 12;

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
    /// Selection-only demerit from header cross-check divergence
    /// (`PeerPool::deprioritize`): subtracted from `score` when choosing a
    /// peer, but never counted toward a ban and never persisted, so
    /// divergence evidence can't combine with an unrelated small penalty
    /// into a ban.
    demerit: i32,
    /// When the peer was last checked out (taken from the slot). Used to
    /// detect leaked slots where the caller dropped the Peer without
    /// calling return_peer().
    checked_out_at: Option<Instant>,
    /// The address had connected successfully before this connection, so
    /// an onion counts as its own netgroup (ticket 052; see `netgroup`).
    /// Decided at connect time: the connection itself doesn't prove it.
    proven: bool,
    /// We told this peer our .onion address on this connection (the
    /// on-connect self-ad, a `getaddr` reply or the 24 h re-broadcast). Own
    /// transactions never go to such a peer, nor to any inbound one (which
    /// dialed the onion): either could tie them to that long-lived identity
    /// (ticket 052's stopgap until 029's private broadcast). Never set for
    /// the `OWN_TX_OUTBOUND` connections kept clean for own transactions.
    self_advertised: bool,
    /// Where the address came from, for the per-source outbound cap: the
    /// gossip source group of an address that was neither known-good nor
    /// from DNS when we dialed it, else `None` (protected).
    gossip_source: Option<String>,
    /// Core's per-peer `addr` token bucket (`m_addr_token_bucket`): one
    /// token per address processed, refilled at `ADDR_RATE_PER_SEC`.
    addr_tokens: f64,
    addr_tokens_at: Instant,
}

impl PeerSlot {
    /// A slot with every ticket 052 field at its default (unproven, never
    /// self-advertised to, protected source, Core's initial single addr
    /// token), for struct-update syntax at the construction sites.
    fn base(peer: Option<Peer>, addr: String, inbound: bool) -> PeerSlot {
        PeerSlot {
            peer,
            addr,
            user_agent: String::new(),
            height: 0,
            score: SCORE_DEFAULT,
            inbound,
            demerit: 0,
            checked_out_at: None,
            proven: false,
            self_advertised: false,
            gossip_source: None,
            addr_tokens: 1.0,
            addr_tokens_at: Instant::now(),
        }
    }

    /// What peer selection ranks by: reputation minus divergence demerits.
    fn weight(&self) -> i32 {
        (self.score - self.demerit).max(SCORE_MIN)
    }
}

/// Floor for `PeerPool::disconnect_and_deprioritize`'s persisted penalty:
/// a relayer of a bad chain is made less attractive, but stays far enough
/// from the ban threshold that a later routine penalty (a download timeout)
/// can't ban it.
const SOFT_PENALTY_FLOOR: i32 = SCORE_DEFAULT / 2;

/// Minimum interval between DNS re-discovery attempts.
const DNS_REDISCOVERY_INTERVAL: Duration = Duration::from_secs(60);

/// Core's addr rate limit (net_processing `MAX_ADDR_RATE_PER_SECOND`):
/// each peer's token bucket refills at this many addresses a second...
const ADDR_RATE_PER_SEC: f64 = 0.1;

/// ...up to `MAX_ADDR_PROCESSING_TOKEN_BUCKET` (= `MAX_ADDR_TO_SEND`).
/// Sending `getaddr` (every outbound connect does) adds this many on top,
/// as Core does, so the reply is taken whole. An inbound peer, which we
/// never ask, starts with Core's single token: its unsolicited gossip is
/// a trickle (ticket 052).
const ADDR_TOKEN_BURST: f64 = 1000.0;

/// One gossip source (an outbound peer's netgroup, or all inbound peers
/// together: their gossip is the unverified bucket) may hold at most this
/// fraction of the address book (1 / `ADDR_SOURCE_SHARE`), like Core's
/// source-keyed new-table buckets (a source group maps to 64 of 1024).
/// Further addresses from a full source are dropped (ticket 052).
const ADDR_SOURCE_SHARE: usize = 16;

/// Outbound slots that only protected addresses (DNS seeds, bundled
/// onion seeds, addresses we have connected to before) may fill, so a
/// gossip flood can't own every connection (ticket 052).
const RESERVED_PROTECTED_OUTBOUND: usize = 4;

/// Most outbound slots filled from one gossip source's addresses.
const MAX_OUTBOUND_PER_SOURCE: usize = 2;

/// Below this many eligible protected candidates, DNS fallback runs even
/// when gossip keeps the total above `DNS_FALLBACK_THRESHOLD`: a flood
/// must not starve the seeds (ticket 052).
const PROTECTED_FALLBACK_THRESHOLD: usize = 2 * RESERVED_PROTECTED_OUTBOUND;

/// Outbound connections kept free of our onion self-ad, the only ones own
/// transactions are announced on (ticket 052): every other outbound peer
/// is told our onion on connect, as before, for inbound discovery.
const OWN_TX_OUTBOUND: usize = 4;

/// An inbound peer must have been silent this long to be evicted for a
/// newcomer when inbound slots are full (ticket 052). Live peers answer
/// our pings (`p2p::PING_INTERVAL`) well within it.
const INBOUND_EVICTION_IDLE: Duration = Duration::from_secs(5 * 60);

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

/// A wake's connect pass (ticket 054, 028's fanout): connections dialed
/// at once, the fewest it settles for while time allows (two peers can
/// confirm a tip between them), and how long it keeps dialing to get
/// them. The pass also stops at the wake's own connect deadline.
const WAKE_CONNECT_PARALLEL: usize = 3;
const WAKE_MIN_PEERS: usize = 2;
const WAKE_CONNECT_BUDGET: Duration = Duration::from_secs(8);

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

/// How we first learned about an address. `Dns` and `Manual` entries are
/// protected (ticket 052): eviction never picks them over gossip, and a
/// share of outbound slots is reserved for them (see `AddrMeta::protected`).
/// New variants must also be reflected in `AddrSource::as_str` / `from_str`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AddrSource {
    Dns,
    Gossip,
    Inbound,
    Manual,
}

impl AddrSource {
    fn as_str(&self) -> &'static str {
        match self {
            AddrSource::Dns => "dns",
            AddrSource::Gossip => "gossip",
            AddrSource::Inbound => "inbound",
            AddrSource::Manual => "manual",
        }
    }

    fn from_str(s: &str) -> AddrSource {
        match s {
            "dns" => AddrSource::Dns,
            "inbound" => AddrSource::Inbound,
            "manual" => AddrSource::Manual,
            // Default to gossip for unknown / legacy values — gossip is the
            // most common source and the safest bucket for an unknown tag.
            _ => AddrSource::Gossip,
        }
    }
}

/// Per-address bookkeeping for the in-memory address manager. Tracks when
/// we first heard about an address, when we last tried it, the last time
/// we successfully connected to it, and how many failures we've seen. This
/// is the minimum state needed to schedule retries with backoff and to rank
/// candidates by reliability without dragging in a full Bitcoin Core
/// new/tried addrman implementation.
///
/// `dirty` is set whenever any other field changes between flushes; the
/// periodic `flush_addrs` only writes back rows whose `dirty` flag is on,
/// so a steady-state idle pool produces zero SQLite writes.
#[derive(Debug, Clone)]
struct AddrMeta {
    first_seen: Instant,
    last_tried: Option<Instant>,
    last_success: Option<Instant>,
    failure_count: u32,
    source: AddrSource,
    /// Who told us (ticket 052): the netgroup of the outbound peer that
    /// gossiped it, `INBOUND_SOURCE` for every inbound peer, or the source
    /// tag itself ("dns", "manual"). Caps one source's share of the book.
    source_group: String,
    dirty: bool,
}

/// The one gossip source group shared by every inbound peer: whoever
/// connects to us picks itself, and its per-connection id says nothing
/// about who it is, so all of them together are one "unverified" source.
const INBOUND_SOURCE: &str = "inbound";

impl AddrMeta {
    fn new(source: AddrSource, source_group: &str) -> AddrMeta {
        AddrMeta {
            first_seen: Instant::now(),
            last_tried: None,
            last_success: None,
            failure_count: 0,
            source,
            source_group: source_group.to_string(),
            dirty: true,
        }
    }

    /// Never evicted ahead of gossip, and eligible for the reserved
    /// outbound slots: DNS / bundled seeds, manual entries, and anything we
    /// have connected to before (ticket 052's protected set).
    fn protected(&self) -> bool {
        self.last_success.is_some() || matches!(self.source, AddrSource::Dns | AddrSource::Manual)
    }

    /// Reconstruct an in-memory entry from a persisted record. Restored
    /// entries are *not* dirty: they reflect what's already on disk and
    /// shouldn't be re-written until something actually changes.
    fn from_record(record: &AddrRecord) -> AddrMeta {
        let now_unix = unix_now();
        let now = Instant::now();
        // We can't recover the original `Instant` for first_seen across a
        // process restart — `Instant` is monotonic. Walk the offset from
        // "now" so the relative ordering between addresses is preserved
        // (older first_seen → earlier Instant) and the candidate ranker's
        // tiebreaker stays meaningful.
        let first_seen = unix_to_instant_offset(record.first_seen, now_unix, now);
        let last_tried = record
            .last_tried
            .map(|t| unix_to_instant_offset(t, now_unix, now));
        let last_success = record
            .last_success
            .map(|t| unix_to_instant_offset(t, now_unix, now));
        AddrMeta {
            first_seen,
            last_tried,
            last_success,
            failure_count: record.failure_count,
            source: AddrSource::from_str(&record.source),
            // Rows from before ticket 052 have no group: their tag stands
            // in, so they share one bucket per kind rather than none.
            source_group: if record.source_group.is_empty() {
                record.source.clone()
            } else {
                record.source_group.clone()
            },
            dirty: false,
        }
    }

    /// Convert this entry to its on-disk form for `save_addrs_bulk`.
    fn to_record(&self, addr: &str) -> AddrRecord {
        let now_unix = unix_now();
        let now = Instant::now();
        AddrRecord {
            addr: addr.to_string(),
            first_seen: instant_to_unix_offset(self.first_seen, now, now_unix),
            last_tried: self
                .last_tried
                .map(|t| instant_to_unix_offset(t, now, now_unix)),
            last_success: self
                .last_success
                .map(|t| instant_to_unix_offset(t, now, now_unix)),
            failure_count: self.failure_count,
            source: self.source.as_str().to_string(),
            source_group: self.source_group.clone(),
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
/// new/tried tables. Ticket 052 adds the parts of its eclipse hardening a
/// flood defeats without them: each gossip source may fill only
/// 1 / `ADDR_SOURCE_SHARE` of the book (Core's source-keyed buckets), and
/// protected entries (`AddrMeta::protected`) are never evicted to make
/// room for gossip.
struct AddrManager {
    addrs: HashMap<String, AddrMeta>,
    max_size: usize,
    /// Entries per `source_group`, for the per-source cap.
    per_source: HashMap<String, usize>,
    /// Addresses evicted (or otherwise removed) since the last flush, queued
    /// for `delete_addrs_bulk` so the on-disk view stays consistent with the
    /// in-memory cap. Cleared by `take_pending_deletes` after flush.
    pending_deletes: Vec<String>,
}

impl AddrManager {
    fn new(max_size: usize) -> AddrManager {
        AddrManager {
            addrs: HashMap::new(),
            max_size,
            per_source: HashMap::new(),
            pending_deletes: Vec::new(),
        }
    }

    fn len(&self) -> usize {
        self.addrs.len()
    }

    /// Most entries one gossip source may hold.
    fn source_cap(&self) -> usize {
        (self.max_size / ADDR_SOURCE_SHARE).max(1)
    }

    /// Add `meta` under `addr` (not present), keeping `per_source` in step.
    fn put(&mut self, addr: String, meta: AddrMeta) {
        *self.per_source.entry(meta.source_group.clone()).or_default() += 1;
        self.addrs.insert(addr, meta);
    }

    /// Remove `addr` and queue its on-disk delete.
    fn remove(&mut self, addr: &str) {
        if let Some(meta) = self.addrs.remove(addr) {
            if let Some(n) = self.per_source.get_mut(&meta.source_group) {
                *n -= 1;
                if *n == 0 {
                    self.per_source.remove(&meta.source_group);
                }
            }
            self.pending_deletes.push(addr.to_string());
        }
    }

    /// Insert a single address with a `source` tag, learned from
    /// `source_group` (see `AddrMeta::source_group`). New addresses get a
    /// fresh AddrMeta; existing addresses are left alone (we don't want
    /// gossip to wipe out a peer's established success/failure history).
    /// Gossip from a source that already holds its share is dropped.
    /// Returns true if a new entry was actually added.
    fn insert(&mut self, addr: String, source: AddrSource, source_group: &str) -> bool {
        if self.addrs.contains_key(&addr) {
            return false;
        }
        let meta = AddrMeta::new(source, source_group);
        if !meta.protected() && self.per_source.get(source_group).copied().unwrap_or(0) >= self.source_cap() {
            return false;
        }
        if !self.evict_if_full(meta.protected()) {
            return false;
        }
        self.put(addr, meta);
        true
    }

    /// Restore an entry from the persistence layer. Unlike `insert`, this
    /// preserves the original `first_seen` / `failure_count` so a known-good
    /// peer comes back at the same tier it had before the restart, and
    /// leaves `dirty=false` so we don't immediately rewrite it.
    fn insert_from_record(&mut self, record: &AddrRecord) -> bool {
        if self.addrs.contains_key(&record.addr) {
            return false;
        }
        let meta = AddrMeta::from_record(record);
        if !self.evict_if_full(meta.protected()) {
            return false;
        }
        self.put(record.addr.clone(), meta);
        true
    }

    /// Bulk insert. Returns the number of brand-new entries added.
    fn insert_many<I: IntoIterator<Item = String>>(
        &mut self,
        addrs: I,
        source: AddrSource,
        source_group: &str,
    ) -> usize {
        let mut added = 0;
        for addr in addrs {
            if self.insert(addr, source, source_group) {
                added += 1;
            }
        }
        added
    }

    /// Drain the queued delete list for the next flush.
    fn take_pending_deletes(&mut self) -> Vec<String> {
        std::mem::take(&mut self.pending_deletes)
    }

    /// Drain dirty entries as on-disk records, clearing their dirty flag.
    /// Used by `flush_addrs` so the next flush is a no-op until something
    /// else changes.
    fn take_dirty_records(&mut self) -> Vec<AddrRecord> {
        let mut out = Vec::new();
        for (addr, meta) in self.addrs.iter_mut() {
            if meta.dirty {
                out.push(meta.to_record(addr));
                meta.dirty = false;
            }
        }
        out
    }

    /// Make room for one entry when at capacity. Returns false if there is
    /// none to be had for it: a gossip entry never displaces a protected
    /// one (ticket 052).
    ///
    /// Policy, in priority order:
    /// 1. Among unprotected entries (gossip we never connected to), drop
    ///    the one with the highest `failure_count`, oldest `first_seen` as
    ///    tiebreaker. Evidence of badness goes first; per-source caps keep
    ///    any one source from owning this pool.
    /// 2. For a protected newcomer only: among protected entries that never
    ///    connected (untried seeds), the same order.
    /// 3. For a protected newcomer only, if every entry has succeeded at
    ///    least once: the oldest. Exceedingly rare at MAX_KNOWN_ADDRS=10_000.
    ///
    /// Known-good entries are the most valuable thing the addrman holds:
    /// only step 3 ever evicts one.
    fn evict_if_full(&mut self, newcomer_protected: bool) -> bool {
        if self.addrs.len() < self.max_size {
            return true;
        }

        // Capture `now` once so the comparator inside max_by_key doesn't
        // re-read the clock for every entry.
        let now = Instant::now();
        let worst = |filter: &dyn Fn(&AddrMeta) -> bool| -> Option<String> {
            self.addrs
                .iter()
                .filter(|(_, m)| filter(m))
                .max_by_key(|(_, m)| (m.failure_count, now.duration_since(m.first_seen).as_secs()))
                .map(|(addr, _)| addr.clone())
        };

        let mut victim = worst(&|m| !m.protected());
        if victim.is_none() && newcomer_protected {
            victim = worst(&|m| m.last_success.is_none());
        }
        if victim.is_none() && newcomer_protected {
            victim = self
                .addrs
                .iter()
                .max_by_key(|(_, m)| now.duration_since(m.first_seen).as_secs())
                .map(|(addr, _)| addr.clone());
        }
        match victim {
            Some(addr) => {
                self.remove(&addr);
                true
            }
            None => false,
        }
    }

    /// Mark an address as successfully connected. Resets failure count and
    /// stamps last_success/last_tried so the entry is treated as known-good.
    /// New entries created by this path are tagged as `Dns` since the only
    /// caller that creates a *new* entry here is the bootstrap connect path.
    fn record_success(&mut self, addr: &str) {
        let now = Instant::now();
        if !self.addrs.contains_key(addr) {
            self.evict_if_full(true);
            self.put(addr.to_string(), AddrMeta::new(AddrSource::Dns, AddrSource::Dns.as_str()));
        }
        let entry = self.addrs.get_mut(addr).expect("just inserted");
        entry.last_tried = Some(now);
        entry.last_success = Some(now);
        entry.failure_count = 0;
        entry.dirty = true;
    }

    /// Mark an address as having failed to connect. Increments failure_count
    /// (driving the exponential backoff) and stamps last_tried.
    fn record_failure(&mut self, addr: &str) {
        let now = Instant::now();
        if !self.addrs.contains_key(addr) {
            self.evict_if_full(true);
            self.put(addr.to_string(), AddrMeta::new(AddrSource::Dns, AddrSource::Dns.as_str()));
        }
        let entry = self.addrs.get_mut(addr).expect("just inserted");
        entry.last_tried = Some(now);
        entry.failure_count = entry.failure_count.saturating_add(1);
        entry.dirty = true;
    }

    /// True if `addr` has connected successfully before (an onion then
    /// counts as its own netgroup).
    fn is_proven(&self, addr: &str) -> bool {
        self.addrs.get(addr).is_some_and(|m| m.last_success.is_some())
    }

    /// The gossip source group an address was learned from, or `None` if
    /// it is protected (see `PeerSlot::gossip_source`).
    fn gossip_source(&self, addr: &str) -> Option<String> {
        self.addrs
            .get(addr)
            .filter(|m| !m.protected())
            .map(|m| m.source_group.clone())
    }

    /// Number of addresses currently eligible for a connection attempt
    /// (i.e., not still in backoff). Used to decide whether DNS fallback
    /// should kick in.
    fn candidate_count(&self) -> usize {
        let now = Instant::now();
        self.addrs.values().filter(|m| m.is_eligible(now)).count()
    }

    /// `candidate_count` over protected entries only: a gossip flood can
    /// keep the total high while every seed is gone or in backoff.
    fn protected_candidate_count(&self) -> usize {
        let now = Instant::now();
        self.addrs.values().filter(|m| m.protected() && m.is_eligible(now)).count()
    }

    /// Pick up to `limit` candidate addresses, ranked best first. Excludes
    /// addresses for which `exclude` returns true (used to skip already-
    /// connected or banned peers, or to enforce subnet diversity).
    ///
    /// Ranking: known-good first, then never-tried, then retry tier. Within
    /// a tier protected entries (seeds) come before gossip (ticket 052),
    /// then fewer failures, then oldest first_seen, so we don't starve
    /// older entries when new gossip floods in.
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
                .then(b.protected().cmp(&a.protected()))
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
pub(crate) const SCORE_DEFAULT: i32 = 100;

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

/// How often we flush dirty AddrManager entries to disk. Same rationale as
/// `SCORE_FLUSH_INTERVAL`: a chatty gossip stream can produce hundreds of
/// updates per minute and we don't want a SQLite write per update. The
/// final state is also flushed on `Drop`, so a clean shutdown after a
/// shorter session won't lose the work.
const ADDR_FLUSH_INTERVAL: Duration = Duration::from_secs(60);

/// Timeout for checked-out peer slots before they are reclaimed (prevents slot leaks).
const CHECKOUT_TIMEOUT: Duration = Duration::from_secs(120);

/// Current Unix timestamp in seconds. Used at the boundary between in-memory
/// `Instant`s (monotonic, opaque) and on-disk `u64` wall-clock seconds.
fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Convert a Unix timestamp into an `Instant` relative to `now_instant` /
/// `now_unix`. Past timestamps land in the past, future ones in the future.
/// Both directions saturate so a corrupted-far-future row from disk can't
/// trigger an `Instant` overflow.
fn unix_to_instant_offset(unix: u64, now_unix: u64, now_instant: Instant) -> Instant {
    if unix >= now_unix {
        let delta = unix - now_unix;
        // Clamp to one year to defend against junk DB rows claiming year 2099.
        let one_year_secs: u64 = 365 * 24 * 3600;
        let delta = delta.min(one_year_secs);
        now_instant + Duration::from_secs(delta)
    } else {
        let delta = now_unix - unix;
        // Clamp the past offset too — `Instant - huge_duration` would saturate
        // anyway, but doing it explicitly makes the intent obvious.
        let one_year_secs: u64 = 10 * 365 * 24 * 3600;
        let delta = delta.min(one_year_secs);
        now_instant
            .checked_sub(Duration::from_secs(delta))
            .unwrap_or(now_instant)
    }
}

/// Reverse of `unix_to_instant_offset`: convert an `Instant` back into Unix
/// seconds by walking the offset from `now_instant` / `now_unix`.
fn instant_to_unix_offset(instant: Instant, now_instant: Instant, now_unix: u64) -> u64 {
    if instant >= now_instant {
        now_unix.saturating_add(instant.duration_since(now_instant).as_secs())
    } else {
        now_unix.saturating_sub(now_instant.duration_since(instant).as_secs())
    }
}

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

/// The single netgroup of every onion we haven't connected to before
/// (ticket 052): anyone can mint onions by the thousand, so unproven ones
/// count as one operator for outbound diversity and the cross-check.
const UNPROVEN_ONION_GROUP: &str = "onion";

fn is_onion(addr: &str) -> bool {
    addr.contains(".onion")
}

/// `subnet_bucket`, or `None` (no bucket, so no diversity limit) when the
/// chain doesn't enforce netgroup diversity. Only regtest turns it off:
/// every mock peer in the test harness lives on 127.0.0.1. An onion is in
/// `UNPROVEN_ONION_GROUP` unless `proven` (it connected before), and then
/// in no bucket, as before: Tor gives it no network locality.
fn netgroup(addr: &str, enforce_diversity: bool, proven: bool) -> Option<String> {
    if !enforce_diversity {
        return None;
    }
    if is_onion(addr) && !proven {
        return Some(UNPROVEN_ONION_GROUP.to_string());
    }
    subnet_bucket(addr)
}

/// Group used to keep header cross-check peers independent of each other
/// (and of the peer being checked): the outbound diversity bucket (/16
/// IPv4, /32 IPv6), `UNPROVEN_ONION_GROUP` for onions we hadn't connected
/// to before, and otherwise the host itself, so each proven onion address
/// (or unparseable host) is its own group. With diversity off (regtest,
/// where every mock peer is on 127.0.0.1) each address is its own group.
fn cross_check_group(addr: &str, enforce_diversity: bool, proven: bool) -> String {
    if !enforce_diversity {
        return addr.to_string();
    }
    if is_onion(addr) && !proven {
        return UNPROVEN_ONION_GROUP.to_string();
    }
    subnet_bucket(addr).unwrap_or_else(|| {
        let host = match addr.rsplit_once(':') {
            Some((host, port)) if port.chars().all(|c| c.is_ascii_digit()) => host,
            _ => addr,
        };
        format!("host:{}", host)
    })
}

/// `cross_check_group` for a wake's agreement count (ticket 054): an
/// onion's group follows its slot's `proven`. A peer that has left the
/// pool counts as unproven (one group with every other unproven onion):
/// its address book entry is proven by the connect itself, and taking
/// that would count it as an independent opinion.
fn wake_group(slots: &[PeerSlot], addr: &str, enforce_diversity: bool) -> String {
    let proven = slots.iter().find(|s| s.addr == addr).is_some_and(|s| s.proven);
    cross_check_group(addr, enforce_diversity, proven)
}

/// Why a peer is penalized: the two of ticket 024's three failure
/// classes that are the peer's fault (ticket 052's audit). The third,
/// a local fault (our store, our clock, our deadline), has no variant on
/// purpose: it never costs a peer anything, so it can't be passed to
/// `misbehaving`. Logged with every penalty.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Offense {
    /// Bad delivery or protocol abuse: a wrong or mutated copy of a
    /// block, a block or headers it never sent, unconnectable or oversized
    /// batches, height claims it can't back. The data on the network may
    /// be fine; this peer's handling of it isn't.
    Delivery,
    /// Data that breaks a consensus rule (or the compiled-in anchor) by
    /// itself, whatever our clock or store says.
    Consensus,
}

impl std::fmt::Display for Offense {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Offense::Delivery => "bad delivery",
            Offense::Consensus => "consensus-invalid",
        })
    }
}

/// Where a pool gets addresses when its address book runs low.
#[derive(Debug, Clone)]
pub enum PeerSource {
    /// DNS seeds (clearnet) or onion seeds (Tor). The only production source.
    Discover,
    /// A fixed address list: the sync integration harness's loopback mock
    /// peers (ticket 027). Never touches DNS or Tor.
    #[cfg(test)]
    Static(Vec<String>),
}

/// Bootstrap / fallback addresses for `source`.
fn seed_addrs(source: &PeerSource, tor: Option<&Arc<TorManager>>) -> Vec<String> {
    match source {
        PeerSource::Discover => match tor {
            Some(tor) => Peer::discover_peers_tor(tor),
            None => Peer::discover_peers(),
        },
        #[cfg(test)]
        PeerSource::Static(addrs) => addrs.clone(),
    }
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
    /// Last time we flushed dirty AddrManager entries to the store. Same
    /// rate-limiting purpose as `last_score_flush` — gossip can be chatty.
    last_addr_flush: Instant,
    /// Chain parameters: handshake magic and netgroup-diversity policy.
    params: &'static ChainParams,
    /// Where bootstrap / fallback addresses come from.
    source: PeerSource,
    /// Why a configured peer store could not be opened (after one retry),
    /// if it couldn't: this session then remembers no bans, scores or
    /// addresses, and says so in its status (ticket 052).
    store_error: Option<String>,
}

/// Pause before the one retry of a peer store that failed to open.
const STORE_OPEN_RETRY_DELAY: Duration = Duration::from_millis(250);

impl PeerPool {
    /// Create a new peer pool. Discovers peers via DNS (or Tor if available)
    /// and connects to an initial batch of up to `MAX_OUTBOUND` peers.
    ///
    /// If `peers_db_path` is provided, scores and bans are loaded from that
    /// SQLite file at startup and persisted across changes. Pass `None` for
    /// ephemeral test pools.
    ///
    /// `params` selects the network magic and netgroup policy; `source`
    /// says where bootstrap addresses come from (production: DNS/onion seeds).
    pub fn new(
        our_height: u32,
        tor: Option<Arc<TorManager>>,
        peers_db_path: Option<&str>,
        params: &'static ChainParams,
        source: PeerSource,
    ) -> Result<PeerPool, PeerError> {
        PeerPool::new_until(our_height, tor, peers_db_path, params, source, None)
    }

    /// `new`, but the initial connect pass starts no new connection after
    /// `connect_deadline` (ticket 028: a wake's budget). An attempt already
    /// in flight runs to its own connect timeout.
    pub fn new_until(
        our_height: u32,
        tor: Option<Arc<TorManager>>,
        peers_db_path: Option<&str>,
        params: &'static ChainParams,
        source: PeerSource,
        connect_deadline: Option<Instant>,
    ) -> Result<PeerPool, PeerError> {
        // Open the persistence store and hydrate any existing bans + known
        // addresses. A store that won't open is retried once (ticket 052:
        // the WAL-switch race is fixed, but any other open error used to
        // drop ban persistence for the whole session without a word); if it
        // still fails the pool runs without persistence and its status says
        // so (`persistence_warning`).
        let mut store_error = None;
        let (store, bans, restored_addrs) = match peers_db_path {
            Some(path) => match PeerStore::open(path).or_else(|e| {
                warn!("PeerPool: peer store failed to open ({}), retrying once", e);
                std::thread::sleep(STORE_OPEN_RETRY_DELAY);
                PeerStore::open(path)
            }) {
                Ok(s) => {
                    let bans = s.load_active_bans().unwrap_or_else(|e| {
                        warn!("PeerPool: failed to load bans from disk: {}", e);
                        HashMap::new()
                    });
                    if !bans.is_empty() {
                        info!("PeerPool: restored {} ban(s) from disk", bans.len());
                    }
                    let restored_addrs = s.load_all_addrs().unwrap_or_else(|e| {
                        warn!("PeerPool: failed to load known addresses: {}", e);
                        Vec::new()
                    });
                    if !restored_addrs.is_empty() {
                        info!(
                            "PeerPool: restored {} known address(es) from disk",
                            restored_addrs.len()
                        );
                    }
                    (Some(Arc::new(s)), bans, restored_addrs)
                }
                Err(e) => {
                    warn!("PeerPool: peer store unavailable, running without persistence: {}", e);
                    store_error = Some(e.to_string());
                    (None, HashMap::new(), Vec::new())
                }
            },
            None => (None, HashMap::new(), Vec::new()),
        };

        let mut addrs = AddrManager::new(MAX_KNOWN_ADDRS);
        for record in &restored_addrs {
            addrs.insert_from_record(record);
        }

        // DNS is now a fallback: only consult seeds when the persisted set
        // can't sustain a healthy outbound pool. The first launch always hits
        // this branch (empty disk → 0 < threshold); subsequent launches with
        // a populated peers.sqlite skip DNS entirely and start cold-syncing
        // against known-good peers. A book full of gossip but short of
        // protected entries also asks (ticket 052).
        if addrs.candidate_count() < DNS_FALLBACK_THRESHOLD
            || addrs.protected_candidate_count() < PROTECTED_FALLBACK_THRESHOLD
        {
            let seeds = seed_addrs(&source, tor.as_ref());
            if seeds.is_empty() && addrs.len() == 0 {
                return Err(PeerError::Connection(
                    "no peers discovered via DNS and no addresses on disk".into(),
                ));
            }
            let added = addrs.insert_many(seeds, AddrSource::Dns, AddrSource::Dns.as_str());
            info!(
                "PeerPool: bootstrap added {} new addresses from DNS (total known: {})",
                added,
                addrs.len()
            );
        } else {
            info!(
                "PeerPool: skipping DNS — disk has {} addresses ({} eligible)",
                addrs.len(),
                addrs.candidate_count()
            );
        }

        let mut pool = PeerPool {
            slots: Arc::new(Mutex::new(Vec::new())),
            addrs,
            our_height,
            last_dns_query: Instant::now(),
            bans,
            tor,
            store,
            last_score_flush: Instant::now(),
            last_addr_flush: Instant::now(),
            params,
            source,
            store_error,
        };

        pool.maintain_until(connect_deadline);

        let count = pool.slots.lock().unwrap().len();
        if count == 0 {
            return Err(PeerError::Connection("could not connect to any peer".into()));
        }

        info!("PeerPool: initial connections: {}/{}", count, MAX_OUTBOUND);
        Ok(pool)
    }

    /// Try to fill the pool up to `MAX_OUTBOUND` connections.
    pub fn maintain(&mut self) {
        self.maintain_until(None)
    }

    /// `maintain`, starting no new connection after `connect_deadline`.
    fn maintain_until(&mut self, connect_deadline: Option<Instant>) {
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
        // Same rate-limit pattern for the addr book — gossip can produce
        // hundreds of dirty entries per minute and we don't want a SQLite
        // write per gossip message.
        if self.last_addr_flush.elapsed() >= ADDR_FLUSH_INTERVAL {
            self.flush_addrs();
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
        // keeps the manager well above DNS_FALLBACK_THRESHOLD — or when
        // protected entries run short: a gossip flood keeps the total up
        // while every seed has gone (ticket 052).
        if (self.addrs.candidate_count() < DNS_FALLBACK_THRESHOLD
            || self.addrs.protected_candidate_count() < PROTECTED_FALLBACK_THRESHOLD)
            && self.last_dns_query.elapsed() >= DNS_REDISCOVERY_INTERVAL
        {
            self.last_dns_query = Instant::now();
            let fresh = seed_addrs(&self.source, self.tor.as_ref());
            if !fresh.is_empty() {
                let added = self.addrs.insert_many(fresh, AddrSource::Dns, AddrSource::Dns.as_str());
                info!(
                    "PeerPool: DNS fallback added {} new addresses (total known: {})",
                    added,
                    self.addrs.len()
                );
            }
        }

        let needed = MAX_OUTBOUND - current;
        let refill_started = Instant::now();

        let diversity = self.params.enforce_netgroup_diversity;

        // Snapshot the current outbound buckets, connected addresses and
        // per-source counts so we can filter candidates without holding the
        // slots lock for the duration of the connection attempt.
        let mut already_connected: HashSet<String> = HashSet::new();
        let mut used_buckets: HashSet<String> = HashSet::new();
        let mut per_source: HashMap<String, usize> = HashMap::new();
        let mut unprotected_slots = 0;
        let mut clean_slots = 0;
        {
            let slots = self.slots.lock().unwrap();
            for s in slots.iter() {
                already_connected.insert(s.addr.clone());
                if s.inbound {
                    continue;
                }
                if let Some(bucket) = netgroup(&s.addr, diversity, s.proven) {
                    used_buckets.insert(bucket);
                }
                if let Some(src) = &s.gossip_source {
                    *per_source.entry(src.clone()).or_default() += 1;
                    unprotected_slots += 1;
                }
                if !s.self_advertised {
                    clean_slots += 1;
                }
            }
        }

        let bans = &self.bans;
        let addrs = &self.addrs;
        let exclude = |addr: &str| -> bool {
            if bans.contains_key(addr) {
                return true;
            }
            if already_connected.contains(addr) {
                return true;
            }
            if let Some(bucket) = netgroup(addr, diversity, addrs.is_proven(addr)) {
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

        // Snapshot our own onion pubkey once per maintain pass — it's the
        // same for every successful connect, and there's no point asking
        // TorManager twice. `None` means either Tor isn't enabled or the
        // onion service hasn't been started yet, in which case we just
        // skip the self-ad until the next maintain cycle.
        let our_onion_pubkey: Option<[u8; 32]> =
            self.tor.as_ref().and_then(|t| t.our_onion_pubkey());

        // A wake (it has a connect deadline) dials in parallel, and keeps
        // dialing past `REFILL_BUDGET` until it has `WAKE_MIN_PEERS` (ticket
        // 054): one sequential attempt per round trip, checked against the
        // budget only between attempts, left a Tor wake with one peer, and
        // one peer's word for the tip.
        let wake = connect_deadline.is_some();
        let parallel = if wake { WAKE_CONNECT_PARALLEL } else { 1 };
        let mut pending: std::collections::VecDeque<String> = candidates.into();

        loop {
            if connected >= needed || pending.is_empty() {
                break;
            }
            if connect_deadline.is_some_and(|d| Instant::now() >= d) {
                info!("PeerPool: connect deadline reached after {} new connections", connected);
                break;
            }
            let short_of_wake_minimum = wake
                && current + connected < WAKE_MIN_PEERS
                && refill_started.elapsed() < WAKE_CONNECT_BUDGET;
            if refill_started.elapsed() >= REFILL_BUDGET && !short_of_wake_minimum {
                info!(
                    "PeerPool: refill budget ({}s) exhausted after {} new connections",
                    REFILL_BUDGET.as_secs(),
                    connected
                );
                break;
            }

            // The next batch: candidates from distinct buckets that this
            // pass hasn't claimed (the snapshot above only reflects buckets
            // occupied at the start of refill), within ticket 052's gossip
            // limits counting the batch as if every dial succeeds. One that
            // shares a bucket or source with another in the batch waits for
            // a later one. Proven and the gossip source are decided before
            // connecting: the connect itself would make the address
            // "proven" and "protected".
            let want = parallel.min(needed - connected);
            let mut batch: Vec<(String, bool, Option<String>, Option<String>)> = Vec::with_capacity(want);
            let mut batch_buckets: HashSet<String> = HashSet::new();
            let mut batch_sources: HashMap<String, usize> = HashMap::new();
            let mut batch_unprotected = 0;
            let mut i = 0;
            while batch.len() < want && i < pending.len() {
                let addr = &pending[i];
                let proven = self.addrs.is_proven(addr);
                let gossip_source = self.addrs.gossip_source(addr);
                let bucket = netgroup(addr, diversity, proven);
                if bucket.as_ref().is_some_and(|b| claimed_buckets.contains(b)) {
                    pending.remove(i);
                    continue;
                }
                // Ticket 052: gossip addresses fill at most
                // MAX_OUTBOUND - RESERVED_PROTECTED_OUTBOUND slots, and at
                // most MAX_OUTBOUND_PER_SOURCE of them from any one source.
                if let Some(src) = &gossip_source {
                    let from_src = per_source.get(src).copied().unwrap_or(0);
                    if unprotected_slots >= MAX_OUTBOUND - RESERVED_PROTECTED_OUTBOUND
                        || from_src >= MAX_OUTBOUND_PER_SOURCE
                    {
                        pending.remove(i);
                        continue;
                    }
                    if unprotected_slots + batch_unprotected >= MAX_OUTBOUND - RESERVED_PROTECTED_OUTBOUND
                        || from_src + batch_sources.get(src).copied().unwrap_or(0) >= MAX_OUTBOUND_PER_SOURCE
                    {
                        i += 1;
                        continue;
                    }
                }
                if bucket.as_ref().is_some_and(|b| batch_buckets.contains(b)) {
                    i += 1;
                    continue;
                }
                batch_buckets.extend(bucket.clone());
                if let Some(src) = &gossip_source {
                    *batch_sources.entry(src.clone()).or_default() += 1;
                    batch_unprotected += 1;
                }
                if let Some(addr) = pending.remove(i) {
                    batch.push((addr, proven, gossip_source, bucket));
                }
            }
            if batch.is_empty() {
                break;
            }

            let magic = self.params.magic;
            let our_height = self.our_height as i32;
            let tor = self.tor.clone();
            let dial = |addr: &str| match tor {
                Some(ref tor) => Peer::connect_tor(tor, addr, our_height, magic),
                None => Peer::connect(addr, our_height, magic),
            };
            type Dialed = (String, bool, Option<String>, Option<String>, Result<Peer, PeerError>);
            let results: Vec<Dialed> = if batch.len() == 1 {
                batch.into_iter().map(|(addr, proven, src, bucket)| {
                    let r = dial(&addr);
                    (addr, proven, src, bucket, r)
                }).collect()
            } else {
                std::thread::scope(|s| {
                    let dials: Vec<_> = batch
                        .into_iter()
                        .map(|(addr, proven, src, bucket)| {
                            let dial = &dial;
                            s.spawn(move || {
                                let r = dial(&addr);
                                (addr, proven, src, bucket, r)
                            })
                        })
                        .collect();
                    dials
                        .into_iter()
                        .filter_map(|h| h.join().ok())
                        .collect()
                })
            };

            for (addr, proven, gossip_source, bucket, result) in results {
                match result {
                    Ok(mut peer) => {
                        let user_agent = peer.peer_user_agent().unwrap_or_default();
                        let height = peer.peer_height().unwrap_or(0).max(0) as u32;
                        info!(
                            "PeerPool: connected to {} ({}) at height {}",
                            addr, user_agent, height
                        );
                        self.addrs.record_success(&addr);

                        // Self-advertise unsolicited so this peer learns our
                        // onion address immediately and can start gossiping
                        // it onward — except on the first `OWN_TX_OUTBOUND`
                        // connections, kept clean so own transactions have
                        // peers that can't tie them to the onion (ticket
                        // 052). `send_self_advertisement` no-ops if the peer
                        // didn't negotiate addrv2 (it then never learns the
                        // onion). A failure on the self-ad is non-fatal — the
                        // peer is still usable for header sync, we just won't
                        // get inbound discovery via this particular path.
                        let mut self_advertised = false;
                        if let Some(pubkey) = our_onion_pubkey.filter(|_| clean_slots >= OWN_TX_OUTBOUND) {
                            self_advertised = peer.wants_addrv2();
                            if let Err(e) = peer.send_self_advertisement(pubkey, 8333) {
                                warn!("PeerPool: self-ad to {} failed: {}", addr, e);
                            }
                        }
                        if !self_advertised {
                            clean_slots += 1;
                        }

                        // Restore any persisted score so a known-good peer comes
                        // back at its earned reputation, not as a stranger.
                        let score = self
                            .store
                            .as_ref()
                            .and_then(|s| s.load_score(&addr).ok().flatten())
                            .unwrap_or(SCORE_DEFAULT);

                        if let Some(bucket) = bucket {
                            claimed_buckets.insert(bucket);
                        }
                        if let Some(src) = &gossip_source {
                            *per_source.entry(src.clone()).or_default() += 1;
                            unprotected_slots += 1;
                        }

                        let slot = PeerSlot {
                            user_agent,
                            height,
                            score,
                            proven,
                            self_advertised,
                            gossip_source,
                            // `connect` asked for its address book: take the
                            // reply whole, as Core does after a `getaddr`.
                            addr_tokens: 1.0 + ADDR_TOKEN_BURST,
                            ..PeerSlot::base(Some(peer), addr, false)
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
    ///
    /// `from` is the peer that sent them (ticket 052): its source group
    /// bounds how much of the book its gossip may fill. Every inbound peer
    /// shares the one `INBOUND_SOURCE` group (the unverified bucket); an
    /// outbound peer's group is its netgroup (`cross_check_group`, each
    /// onion its own: we chose to dial it).
    ///
    /// They are rate-limited first by `from`'s token bucket
    /// (`take_addr_tokens`): addresses beyond its tokens are dropped, and a
    /// peer no longer in the pool gets none in.
    pub fn ingest_gossip_addrs(&mut self, from: &str, mut addrs: Vec<String>) -> usize {
        addrs.truncate(self.take_addr_tokens(from, addrs.len()));
        let (source, group) = if self.is_inbound(from) {
            (AddrSource::Inbound, INBOUND_SOURCE.to_string())
        } else {
            let group = cross_check_group(from, self.params.enforce_netgroup_diversity, true);
            (AddrSource::Gossip, format!("gossip:{}", group))
        };
        let added = self.addrs.insert_many(addrs, source, &group);
        if added > 0 {
            info!(
                "PeerPool: ingested {} new gossip addresses from {} (total known: {})",
                added,
                from,
                self.addrs.len()
            );
        }
        added
    }

    /// Core's addr rate limit (ProcessAddrs, ticket 052): refill `addr`'s
    /// token bucket for the time since its last message (at
    /// `ADDR_RATE_PER_SEC`, not past `ADDR_TOKEN_BURST`) and spend one
    /// token per address, up to `wanted`. Returns how many of the message's
    /// addresses may be processed; the rest are dropped. 0 for a peer not
    /// in the pool.
    pub fn take_addr_tokens(&self, addr: &str, wanted: usize) -> usize {
        let now = Instant::now();
        let mut slots = self.slots.lock().unwrap();
        let Some(slot) = slots.iter_mut().find(|s| s.addr == addr) else {
            return 0;
        };
        if slot.addr_tokens < ADDR_TOKEN_BURST {
            let elapsed = now.saturating_duration_since(slot.addr_tokens_at).as_secs_f64();
            slot.addr_tokens = (slot.addr_tokens + elapsed * ADDR_RATE_PER_SEC).min(ADDR_TOKEN_BURST);
        }
        slot.addr_tokens_at = now;
        let allowed = (slot.addr_tokens.floor().max(0.0) as usize).min(wanted);
        slot.addr_tokens -= allowed as f64;
        if allowed < wanted {
            info!("PeerPool: rate-limited {} of {} addresses from {}", wanted - allowed, wanted, addr);
        }
        allowed
    }

    /// Whether `addr` may be told our onion address: inbound peers (they
    /// dialed it) and outbound peers already told on connect. The
    /// `OWN_TX_OUTBOUND` clean connections never are (ticket 052).
    pub fn may_self_advertise(&self, addr: &str) -> bool {
        let slots = self.slots.lock().unwrap();
        slots.iter().any(|s| s.addr == addr && (s.inbound || s.self_advertised))
    }

    /// Whether own transactions may be announced or served to `addr`: an
    /// outbound peer we never told our onion (ticket 052's stopgap until
    /// 029's private broadcast). Inbound peers reached us at the onion, so
    /// anything they learn first from us is tied to it.
    pub fn may_carry_own_txs(&self, addr: &str) -> bool {
        let slots = self.slots.lock().unwrap();
        slots.iter().any(|s| s.addr == addr && !s.inbound && !s.self_advertised)
    }

    /// Why this session isn't persisting bans and scores, if it isn't: the
    /// configured peer store failed to open, twice (ticket 052).
    pub fn persistence_warning(&self) -> Option<String> {
        self.store_error.as_ref().map(|e| {
            format!("Peer store unavailable: bans and peer scores are not remembered this session ({})", e)
        })
    }

    /// Number of addresses currently held in the address manager. Exposed
    /// for diagnostics and tests; the sync loop can also use it to decide
    /// whether to issue a fresh `getaddr` to top up.
    pub fn known_addr_count(&self) -> usize {
        self.addrs.len()
    }

    /// Pseudo-random sample of up to `limit` known addresses for serving
    /// inbound `getaddr` requests. Each entry is `(timestamp, host:port)`,
    /// where `timestamp` is the Unix-seconds equivalent of `last_success`
    /// (or `first_seen` for never-tried entries) — Bitcoin Core peers use
    /// this to age out stale gossip.
    ///
    /// The sampler walks the HashMap in iteration order and pulls every
    /// Nth entry; this is biased but cheap, and the bias doesn't matter
    /// for `getaddr` (which Bitcoin Core itself caps at 1000 random
    /// addresses). For an honest replacement we'd want a Fisher-Yates
    /// reservoir sampler, but that's overkill until we see evidence
    /// peers care about sample uniformity here.
    pub fn sample_addresses(&self, limit: usize) -> Vec<(u32, String)> {
        if limit == 0 || self.addrs.len() == 0 {
            return Vec::new();
        }
        let now_unix = unix_now();
        let now_instant = Instant::now();
        let stride = (self.addrs.len() / limit).max(1);
        let mut out = Vec::with_capacity(limit.min(self.addrs.len()));
        for (i, (addr, meta)) in self.addrs.addrs.iter().enumerate() {
            if i % stride != 0 {
                continue;
            }
            if out.len() >= limit {
                break;
            }
            let when = meta.last_success.unwrap_or(meta.first_seen);
            let ts = instant_to_unix_offset(when, now_instant, now_unix);
            // Clamp to u32 — addrv2 timestamps are 32-bit Unix seconds.
            let ts32 = ts.min(u32::MAX as u64) as u32;
            out.push((ts32, addr.clone()));
        }
        out
    }

    /// Empty pool with no DNS discovery or persistence, for tests in other
    /// modules that populate it via `add_inbound_peer`.
    #[cfg(test)]
    pub(crate) fn new_for_test() -> PeerPool {
        PeerPool::new_for_test_with(ChainParams::mainnet())
    }

    /// `new_for_test` with the given chain parameters (regtest: no
    /// netgroup diversity, so loopback peers count as independent).
    #[cfg(test)]
    pub(crate) fn new_for_test_with(params: &'static ChainParams) -> PeerPool {
        PeerPool {
            slots: Arc::new(Mutex::new(Vec::new())),
            addrs: AddrManager::new(MAX_KNOWN_ADDRS),
            our_height: 0,
            last_dns_query: Instant::now(),
            bans: HashMap::new(),
            tor: None,
            store: None,
            last_score_flush: Instant::now(),
            last_addr_flush: Instant::now(),
            params,
            source: PeerSource::Discover,
            store_error: None,
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
    ///
    /// Outbound peers only: an inbound peer chose its own claimed height
    /// and, being keyed by a connection id, can't be banned in any way
    /// that sticks, so it never drives header sync.
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
            .filter(|(_, s)| s.peer.is_some() && !s.inbound)
            .max_by(|(_, a), (_, b)| {
                let wa = a.height as f64 * (a.weight() as f64 / SCORE_DEFAULT as f64);
                let wb = b.height as f64 * (b.weight() as f64 / SCORE_DEFAULT as f64);
                wa.partial_cmp(&wb).unwrap_or(std::cmp::Ordering::Equal)
            })
            .map(|(i, _)| i)?;

        slots[best_idx].checked_out_at = Some(Instant::now());
        slots[best_idx].peer.take()
    }

    /// Return any available outbound peer, temporarily taking it out of the
    /// pool. The caller MUST return it via `return_peer`. Used for block
    /// downloads; inbound peers are left out like in `best_peer`.
    pub fn any_peer(&self) -> Option<Peer> {
        let mut slots = self.slots.lock().unwrap();
        for slot in slots.iter_mut() {
            if slot.peer.is_some() && !slot.inbound {
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
    ///
    /// An inbound peer is only disconnected: its address is a per-connection
    /// id (see `Peer::accept`), so a ban on it would never match again.
    pub fn ban_peer(&mut self, addr: &str) {
        if self.is_inbound(addr) {
            self.remove_peer(addr);
            info!("PeerPool: disconnected inbound peer {} (not bannable)", addr);
            return;
        }
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
        let Some(store) = self.store.as_ref() else {
            return;
        };
        let entries: Vec<(String, i32)> = {
            let slots = self.slots.lock().unwrap();
            // Inbound addresses are per-connection ids: nothing to keep.
            slots
                .iter()
                .filter(|s| !s.inbound)
                .map(|s| (s.addr.clone(), s.score))
                .collect()
        };
        if let Err(e) = store.save_scores_bulk(&entries) {
            warn!("PeerPool: failed to flush scores: {}", e);
        }
        self.last_score_flush = Instant::now();
    }

    /// Flush dirty AddrManager entries (and any queued deletes) to disk in
    /// a pair of transactions. Same rate-limit pattern as `flush_scores`:
    /// called periodically from `maintain()` and one final time on `Drop`.
    /// Deletes run BEFORE inserts so an entry that was evicted-and-readded
    /// in the same flush window ends up in the correct final state.
    pub fn flush_addrs(&mut self) {
        let Some(store) = self.store.as_ref() else {
            return;
        };

        let deletes = self.addrs.take_pending_deletes();
        if !deletes.is_empty() {
            if let Err(e) = store.delete_addrs_bulk(&deletes) {
                warn!("PeerPool: failed to flush addr deletes: {}", e);
            }
        }

        let dirty = self.addrs.take_dirty_records();
        if !dirty.is_empty() {
            if let Err(e) = store.save_addrs_bulk(&dirty) {
                warn!("PeerPool: failed to flush dirty addrs: {}", e);
                // Re-mark as dirty so the next flush retries them, otherwise
                // a transient SQLite error would silently lose the updates.
                for record in &dirty {
                    if let Some(meta) = self.addrs.addrs.get_mut(&record.addr) {
                        meta.dirty = true;
                    }
                }
            }
        }
        self.last_addr_flush = Instant::now();
    }

    /// Record misbehavior for a peer. Subtracts `howmuch` from the peer's
    /// reputation score; if the result drops to `BAN_LOW_THRESHOLD` or below,
    /// the peer is automatically banned. Mirrors Bitcoin Core's Misbehaving()
    /// pattern but uses a graduated 0–200 scale rather than a unidirectional
    /// counter.
    ///
    /// Callers pass a positive penalty (10, 20, 50, 100, …) — this method
    /// handles the sign internally — and the `Offense` class it is for,
    /// which is logged (ticket 052). Local faults have no class: they are
    /// never the peer's fault, so they never reach this method.
    pub fn misbehaving(&mut self, addr: &str, howmuch: u32, offense: Offense) {
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
                    "PeerPool: peer {} misbehaving ({}, -{}), score now {}",
                    addr, offense, howmuch, slot.score
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

    /// Lift a ban (in memory and on disk), e.g. once the invalid block it
    /// was banned for is reconsidered (ticket 024).
    pub fn unban_peer(&mut self, addr: &str) {
        self.bans.remove(addr);
        if let Some(ref store) = self.store {
            if let Err(e) = store.delete_ban(addr) {
                warn!("PeerPool: failed to drop ban for {}: {}", addr, e);
            }
        }
    }

    /// Disconnect a peer without banning it, and make it less attractive
    /// next time: apply `penalty`, persist the resulting score (it is
    /// restored on reconnect), and put its address into retry backoff so
    /// `maintain` doesn't reconnect it straight away. For peers that relay
    /// something bad they probably didn't originate (ticket 024).
    ///
    /// The penalty never takes the score below `SOFT_PENALTY_FLOOR`, so
    /// this never bans, now or combined with a later routine penalty.
    pub fn disconnect_and_deprioritize(&mut self, addr: &str, penalty: u32) {
        {
            let mut slots = self.slots.lock().unwrap();
            if let Some(slot) = slots.iter_mut().find(|s| s.addr == addr) {
                let floor = SOFT_PENALTY_FLOOR.min(slot.score);
                slot.score = (slot.score as i64 - penalty as i64).max(floor as i64) as i32;
                warn!(
                    "PeerPool: peer {} deprioritized (-{}), score now {}",
                    addr, penalty, slot.score
                );
            }
        }
        let score = if self.is_inbound(addr) { None } else { self.get_score(addr) };
        if let (Some(store), Some(score)) = (self.store.as_ref(), score) {
            if let Err(e) = store.save_score(addr, score) {
                warn!("PeerPool: failed to persist score for {}: {}", addr, e);
            }
        }
        self.addrs.record_failure(addr);
        self.remove_peer(addr);
    }

    /// Make a peer less attractive by `penalty` without touching its
    /// reputation score: for evidence short of proof that it sent invalid
    /// data (header cross-check divergence; two colluding witnesses can
    /// outvote an honest peer). The demerit only lowers its weight in
    /// `best_peer` and as a cross-check peer; it never counts toward a ban
    /// (`misbehaving`, for proven-invalid data, does) and lasts only for
    /// this connection.
    pub fn deprioritize(&mut self, addr: &str, penalty: u32) {
        let mut slots = self.slots.lock().unwrap();
        if let Some(slot) = slots.iter_mut().find(|s| s.addr == addr) {
            slot.demerit = (slot.demerit as i64 + penalty as i64).min(SCORE_MAX as i64) as i32;
            warn!(
                "PeerPool: peer {} deprioritized (+{} demerit, now {}), score {}",
                addr, penalty, slot.demerit, slot.score
            );
        }
    }

    /// A connected peer's selection demerit (see `deprioritize`).
    pub fn get_demerit(&self, addr: &str) -> Option<i32> {
        let slots = self.slots.lock().unwrap();
        slots.iter().find(|s| s.addr == addr).map(|s| s.demerit)
    }

    /// True if `addr` is a connected inbound peer.
    pub fn is_inbound(&self, addr: &str) -> bool {
        let slots = self.slots.lock().unwrap();
        slots.iter().any(|s| s.addr == addr && s.inbound)
    }

    /// Cap a peer's claimed height at `height`, e.g. once it has shown it has
    /// no headers beyond our tip despite claiming more at handshake. Lowers
    /// its weight in `best_peer`; never raises the claim.
    pub fn lower_peer_height(&self, addr: &str, height: u32) {
        let mut slots = self.slots.lock().unwrap();
        if let Some(slot) = slots.iter_mut().find(|s| s.addr == addr) {
            slot.height = slot.height.min(height);
        }
    }

    /// Raise a peer's height to `height`, a block it has shown it has (it
    /// sent us that header, or announced a block we have there). Never
    /// lowers it.
    pub fn raise_peer_height(&self, addr: &str, height: u32) {
        let mut slots = self.slots.lock().unwrap();
        if let Some(slot) = slots.iter_mut().find(|s| s.addr == addr) {
            slot.height = slot.height.max(height);
        }
    }

    /// A header batch from `addr` took our chain to `height` (ticket 049):
    /// from now on its height is what it demonstrated, not what it claimed
    /// at handshake. A short batch means the peer has nothing past
    /// `height` (Core's rule too: a non-full `headers` ends the sync with
    /// that peer), so its height becomes exactly that, and `best_peer`
    /// rotates to a peer that may have more. A claim only buys a peer its
    /// first round.
    pub fn record_headers_from(&self, addr: &str, height: u32, full_batch: bool) {
        let mut slots = self.slots.lock().unwrap();
        if let Some(slot) = slots.iter_mut().find(|s| s.addr == addr) {
            slot.height = if full_batch { slot.height.max(height) } else { height };
        }
    }

    /// Update our reported height (used when connecting to new peers).
    pub fn update_our_height(&mut self, height: u32) {
        self.our_height = height;
    }

    /// Number of connected peers (includes peers currently checked out).
    pub fn count(&self) -> usize {
        self.slots.lock().unwrap().len()
    }

    /// Pick an independent peer for the header cross-check (a witness, or
    /// a tiebreaker): an available outbound peer in a different netgroup
    /// (`cross_check_group`) from every peer in `others` (the peer being
    /// checked, and the witness when picking a tiebreaker). Inbound peers
    /// never qualify: whoever connects to us chooses to, and two inbound
    /// connections from one attacker could otherwise outvote an honest
    /// outbound peer. Highest score wins, the earliest slot on a tie, so
    /// the choice is deterministic.
    pub fn cross_check_peer(&self, others: &[String]) -> Option<String> {
        let diversity = self.params.enforce_netgroup_diversity;
        let slots = self.slots.lock().unwrap();
        // An onion's group depends on whether it had connected before
        // this connection (the slot's `proven`, ticket 052).
        let proven = |addr: &str| {
            slots
                .iter()
                .find(|s| s.addr == addr)
                .map_or_else(|| self.addrs.is_proven(addr), |s| s.proven)
        };
        let taken: HashSet<String> =
            others.iter().map(|a| cross_check_group(a, diversity, proven(a))).collect();
        let mut best: Option<&PeerSlot> = None;
        for s in slots.iter() {
            if s.inbound
                || s.peer.is_none()
                || others.iter().any(|o| o == &s.addr)
                || taken.contains(&cross_check_group(&s.addr, diversity, s.proven))
            {
                continue;
            }
            if best.map_or(true, |b| s.weight() > b.weight()) {
                best = Some(s);
            }
        }
        best.map(|s| s.addr.clone())
    }

    /// The next peer a wake asks for headers (ticket 054): an available
    /// outbound peer not in `asked`. The first is the highest-weighted
    /// (reputation, never a claimed height). After that a second opinion
    /// is wanted, so a peer claiming more than `tip_height` goes first (it
    /// may have what the others withheld), then one independent
    /// (`cross_check_group`) of every peer in `agreeing`, then weight;
    /// the earliest slot on a tie.
    pub fn wake_header_peer(
        &self,
        asked: &[String],
        agreeing: &[String],
        tip_height: u32,
    ) -> Option<String> {
        let diversity = self.params.enforce_netgroup_diversity;
        let slots = self.slots.lock().unwrap();
        let taken: HashSet<String> =
            agreeing.iter().map(|a| wake_group(&slots, a, diversity)).collect();
        let second_opinion = !asked.is_empty();
        let rank = |s: &PeerSlot| {
            let taller = second_opinion && s.height > tip_height;
            let independent = !taken.contains(&cross_check_group(&s.addr, diversity, s.proven));
            (taller, independent, s.weight())
        };
        let mut best: Option<&PeerSlot> = None;
        for s in slots.iter() {
            if s.inbound || s.peer.is_none() || asked.iter().any(|a| a == &s.addr) {
                continue;
            }
            if best.map_or(true, |b| rank(s) > rank(b)) {
                best = Some(s);
            }
        }
        best.map(|s| s.addr.clone())
    }

    /// How many of `addrs` are independent of each other: the number of
    /// distinct `cross_check_group`s among them (ticket 054: two peers in
    /// one /16 agreeing is one opinion).
    pub fn independent_count(&self, addrs: &[String]) -> usize {
        let diversity = self.params.enforce_netgroup_diversity;
        let slots = self.slots.lock().unwrap();
        addrs
            .iter()
            .map(|a| wake_group(&slots, a, diversity))
            .collect::<HashSet<_>>()
            .len()
    }

    /// Every available outbound peer not in `excluded`, highest weight
    /// first (earliest slot on a tie): a wake spreads its block requests
    /// over them (ticket 054).
    pub fn available_outbound_excluding(&self, excluded: &[String]) -> Vec<String> {
        let slots = self.slots.lock().unwrap();
        let mut found: Vec<&PeerSlot> = slots
            .iter()
            .filter(|s| !s.inbound && s.peer.is_some() && !excluded.iter().any(|e| e == &s.addr))
            .collect();
        found.sort_by_key(|s| std::cmp::Reverse(s.weight()));
        found.into_iter().map(|s| s.addr.clone()).collect()
    }

    /// Pick an available outbound peer not in `excluded`, highest score
    /// first: a block download retried after `excluded` served bad copies.
    pub fn peer_addr_excluding(&self, excluded: &[String]) -> Option<String> {
        let slots = self.slots.lock().unwrap();
        let mut best: Option<&PeerSlot> = None;
        for s in slots.iter() {
            if s.inbound || s.peer.is_none() || excluded.iter().any(|e| e == &s.addr) {
                continue;
            }
            if best.map_or(true, |b| s.weight() > b.weight()) {
                best = Some(s);
            }
        }
        best.map(|s| s.addr.clone())
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
            .filter(|s| !s.inbound)
            .max_by(|a, b| {
                let wa = a.height as f64 * (a.weight() as f64 / SCORE_DEFAULT as f64);
                let wb = b.height as f64 * (b.weight() as f64 / SCORE_DEFAULT as f64);
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
            // Simple inbound eviction (ticket 052): make room by dropping
            // the inbound peer silent the longest, if it has been silent
            // for `INBOUND_EVICTION_IDLE` (a live peer answers our pings
            // well within that). Otherwise every slot is busy: refuse the
            // newcomer. Checked-out peers are in use, never evicted.
            let idlest = slots
                .iter()
                .enumerate()
                .filter(|(_, s)| s.inbound)
                .filter_map(|(i, s)| s.peer.as_ref().map(|p| (i, p.idle_for())))
                .max_by_key(|(_, idle)| *idle);
            match idlest {
                Some((i, idle)) if idle >= INBOUND_EVICTION_IDLE => {
                    info!(
                        "PeerPool: evicting inbound peer {} (silent {}s) for {}",
                        slots[i].addr,
                        idle.as_secs(),
                        addr
                    );
                    slots.remove(i);
                }
                _ => {
                    info!("PeerPool: rejecting inbound peer (at capacity {}/{})", inbound, MAX_INBOUND);
                    return false;
                }
            }
        }

        info!("PeerPool: accepted inbound peer {} ({}) at height {}", addr, user_agent, height);

        // No persisted score to restore: the address is a per-connection
        // id (see `Peer::accept`), not an identity. Core's single starting
        // addr token: we never ask an inbound peer for addresses.
        slots.push(PeerSlot {
            user_agent,
            height,
            ..PeerSlot::base(Some(peer), addr, true)
        });
        true
    }

    /// Add an already-connected peer as an outbound slot, for tests that
    /// drive the pool with loopback peers. It is one of the clean
    /// connections (never self-advertised to).
    #[cfg(test)]
    pub(crate) fn add_outbound_peer_for_test(&self, peer: Peer) {
        let addr = peer.addr().to_string();
        self.slots.lock().unwrap().push(PeerSlot {
            user_agent: "/test/".to_string(),
            ..PeerSlot::base(Some(peer), addr, false)
        });
    }

    /// `add_outbound_peer_for_test`, for a peer we told our onion on
    /// connect (not one of the `OWN_TX_OUTBOUND` clean connections).
    #[cfg(test)]
    pub(crate) fn add_self_advertised_peer_for_test(&self, peer: Peer) {
        let addr = peer.addr().to_string();
        self.slots.lock().unwrap().push(PeerSlot {
            user_agent: "/test/".to_string(),
            self_advertised: true,
            ..PeerSlot::base(Some(peer), addr, false)
        });
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
    /// Last-chance flush of in-memory scores and addresses so a clean
    /// shutdown after a shorter session than the flush intervals doesn't
    /// lose the work. Particularly load-bearing on iOS, where the OS
    /// terminates backgrounded apps aggressively.
    fn drop(&mut self) {
        if self.store.is_some() {
            self.flush_scores();
            self.flush_addrs();
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
            last_addr_flush: Instant::now(),
            params: ChainParams::mainnet(),
            source: PeerSource::Discover,
            store_error: None,
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
            last_addr_flush: Instant::now(),
            params: ChainParams::mainnet(),
            source: PeerSource::Discover,
            store_error: None,
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
            demerit: 0,
            checked_out_at: None,
            ..PeerSlot::base(None, String::new(), false)
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
    fn lower_peer_height_caps_but_never_raises() {
        let pool = test_pool();
        add_slot(&pool, "liar.peer:8333", 900_000);
        add_slot(&pool, "honest.peer:8333", 500_000);
        assert_eq!(pool.best_peer_addr(), Some("liar.peer:8333".to_string()));
        pool.lower_peer_height("liar.peer:8333", 400_000);
        assert_eq!(pool.get_peer_height("liar.peer:8333"), Some(400_000));
        assert_eq!(pool.best_peer_addr(), Some("honest.peer:8333".to_string()));
        pool.lower_peer_height("liar.peer:8333", 950_000);
        assert_eq!(pool.get_peer_height("liar.peer:8333"), Some(400_000));
    }

    #[test]
    fn header_batches_replace_claimed_heights_with_demonstrated_ones() {
        // Ticket 049: a claim buys one round. A short batch ends at what the
        // peer has, so the sync rotates to a peer that may have more.
        let pool = test_pool();
        add_slot(&pool, "liar.peer:8333", i32::MAX as u32);
        add_slot(&pool, "honest.peer:8333", 400);
        assert_eq!(pool.best_peer_addr(), Some("liar.peer:8333".to_string()));
        pool.record_headers_from("liar.peer:8333", 1, false);
        assert_eq!(pool.get_peer_height("liar.peer:8333"), Some(1));
        assert_eq!(pool.best_peer_addr(), Some("honest.peer:8333".to_string()));
        // A full batch only ever raises; so does an announcement of a
        // block we have (`raise_peer_height`).
        pool.record_headers_from("honest.peer:8333", 2_000, true);
        assert_eq!(pool.get_peer_height("honest.peer:8333"), Some(2_000));
        pool.record_headers_from("honest.peer:8333", 1_500, true);
        assert_eq!(pool.get_peer_height("honest.peer:8333"), Some(2_000));
        pool.raise_peer_height("liar.peer:8333", 3);
        pool.raise_peer_height("liar.peer:8333", 2);
        assert_eq!(pool.get_peer_height("liar.peer:8333"), Some(3));
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
        pool.misbehaving("sketchy.peer:8333", 70, Offense::Delivery);
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

        pool.misbehaving("peer:8333", 10, Offense::Delivery);
        assert_eq!(pool.get_score("peer:8333"), Some(SCORE_DEFAULT - 10));

        pool.misbehaving("peer:8333", 20, Offense::Delivery);
        assert_eq!(pool.get_score("peer:8333"), Some(SCORE_DEFAULT - 30));
    }

    #[test]
    fn misbehaving_auto_bans_at_low_threshold() {
        let mut pool = test_pool();
        add_slot(&pool, "peer:8333", 100);

        // Drop to just above ban threshold — not banned
        // 100 - 79 = 21, > BAN_LOW_THRESHOLD (20)
        pool.misbehaving("peer:8333", 79, Offense::Delivery);
        assert!(!pool.is_banned("peer:8333"));
        assert_eq!(pool.count(), 1);

        // One more point — score = 20, == BAN_LOW_THRESHOLD → banned
        pool.misbehaving("peer:8333", 1, Offense::Delivery);
        assert!(pool.is_banned("peer:8333"));
        assert_eq!(pool.count(), 0);
    }

    #[test]
    fn misbehaving_score_clamps_at_min() {
        let mut pool = test_pool();
        add_slot(&pool, "peer:8333", 100);

        pool.misbehaving("peer:8333", u32::MAX, Offense::Delivery);
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
        pool.misbehaving("peer:8333", 100, Offense::Delivery); // score = 50
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
        pool.misbehaving("peer.b:8333", 10, Offense::Delivery); // 90

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
                demerit: 0,
                checked_out_at: Some(Instant::now() - Duration::from_secs(300)),
                ..PeerSlot::base(None, String::new(), false)
            });
            // Also add a healthy slot with no checkout
            slots.push(PeerSlot {
                peer: None,
                addr: "healthy:8333".to_string(),
                user_agent: "/test/".to_string(),
                height: 200,
                score: SCORE_DEFAULT,
                inbound: false,
                demerit: 0,
            checked_out_at: None,
            ..PeerSlot::base(None, String::new(), false)
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
                demerit: 0,
                checked_out_at: Some(Instant::now()), // just now
                ..PeerSlot::base(None, String::new(), false)
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

    // ── Inbound peers and cross-check peer selection (PR #24 review) ──

    /// A slot holding a live loopback connection under `addr`. Returns the
    /// server half, which must outlive the test's use of the slot.
    fn add_live_slot(
        pool: &PeerPool,
        addr: &str,
        height: u32,
        score: i32,
        inbound: bool,
    ) -> std::net::TcpStream {
        let (mut peer, server) = crate::p2p::tests::loopback_peer_pair();
        peer.set_addr_for_test(addr, inbound);
        pool.slots.lock().unwrap().push(PeerSlot {
            peer: Some(peer),
            addr: addr.to_string(),
            user_agent: "/test/".to_string(),
            height,
            score,
            inbound,
            demerit: 0,
            checked_out_at: None,
            ..PeerSlot::base(None, String::new(), false)
        });
        server
    }

    #[test]
    fn inbound_peers_are_never_best_peer_witness_or_block_source() {
        let pool = test_pool();
        // The inbound peer claims a far higher tip and has the top score.
        let _a = add_live_slot(&pool, "inbound#1", 2_000_000, SCORE_MAX, true);
        let _b = add_live_slot(&pool, "1.2.3.4:8333", 850_000, SCORE_DEFAULT, false);
        let _c = add_live_slot(&pool, "5.6.7.8:8333", 850_000, SCORE_DEFAULT, false);

        assert_eq!(pool.best_peer_addr().as_deref(), Some("5.6.7.8:8333"));
        let best = pool.best_peer().expect("an outbound peer");
        assert!(!best.inbound);
        pool.return_peer(best);
        let any = pool.any_peer().expect("an outbound peer");
        assert!(!any.inbound);
        pool.return_peer(any);
        assert_ne!(pool.peer_addr_excluding(&[]).as_deref(), Some("inbound#1"));

        let witness = pool.cross_check_peer(&["1.2.3.4:8333".to_string()]);
        assert_eq!(witness.as_deref(), Some("5.6.7.8:8333"));
        let tiebreaker =
            pool.cross_check_peer(&["1.2.3.4:8333".to_string(), "5.6.7.8:8333".to_string()]);
        assert_eq!(tiebreaker, None, "only the inbound peer is left: no tiebreaker");
    }

    #[test]
    fn only_inbound_peers_means_no_header_peer() {
        let pool = test_pool();
        let _a = add_live_slot(&pool, "inbound#1", 900_000, SCORE_DEFAULT, true);
        let _b = add_live_slot(&pool, "inbound#2", 900_000, SCORE_DEFAULT, true);
        assert!(pool.best_peer().is_none());
        assert!(pool.any_peer().is_none());
        assert_eq!(pool.best_peer_addr(), None);
        assert_eq!(pool.cross_check_peer(&[]), None);
    }

    #[test]
    fn cross_check_peers_come_from_distinct_netgroups() {
        let pool = test_pool();
        let _a = add_live_slot(&pool, "1.2.3.4:8333", 850_000, SCORE_DEFAULT, false);
        // Same /16 as the active peer, best score: still not a witness.
        let _b = add_live_slot(&pool, "1.2.9.9:8333", 850_000, SCORE_MAX, false);
        let _c = add_live_slot(&pool, "5.6.7.8:8333", 850_000, SCORE_DEFAULT, false);
        // Same /16 as the witness: not a tiebreaker.
        let _d = add_live_slot(&pool, "5.6.1.1:8333", 850_000, SCORE_MAX, false);
        let _e = add_live_slot(&pool, "[2001:db8::1]:8333", 850_000, SCORE_DEFAULT, false);
        let _f = add_live_slot(&pool, "[2001:db8::2]:8333", 850_000, SCORE_MAX, false);

        let active = "1.2.3.4:8333".to_string();
        // Highest score outside the active /16: 5.6.1.1 (SCORE_MAX), ahead
        // of the equal-scored [2001:db8::2] by slot order.
        let witness = pool.cross_check_peer(&[active.clone()]).unwrap();
        assert_eq!(witness, "5.6.1.1:8333");
        let tiebreaker = pool.cross_check_peer(&[active.clone(), witness.clone()]).unwrap();
        assert_eq!(tiebreaker, "[2001:db8::2]:8333");
        // With the IPv6 /32 taken as well, nothing independent is left.
        assert_eq!(
            pool.cross_check_peer(&[active, witness, "[2001:db8::1]:8333".to_string()]),
            None
        );
    }

    #[test]
    fn cross_check_peer_counts_proven_onions_per_address_and_breaks_ties_by_slot_order() {
        let pool = test_pool();
        let _a = add_live_slot(&pool, "aaaa.onion:8333", 0, SCORE_DEFAULT, false);
        let _b = add_live_slot(&pool, "bbbb.onion:8333", 0, SCORE_DEFAULT, false);
        let _c = add_live_slot(&pool, "cccc.onion:8333", 0, SCORE_DEFAULT, false);
        // Each connected before (ticket 052: unproven onions share a group).
        pool.slots.lock().unwrap().iter_mut().for_each(|s| s.proven = true);
        let others = ["aaaa.onion:8333".to_string()];
        assert_eq!(pool.cross_check_peer(&others).as_deref(), Some("bbbb.onion:8333"));
        // The same onion on another port is the same group.
        assert_eq!(
            cross_check_group("bbbb.onion:8333", true, true),
            cross_check_group("bbbb.onion:18333", true, true)
        );
        assert_ne!(
            cross_check_group("bbbb.onion:8333", true, true),
            cross_check_group("cccc.onion:8333", true, true)
        );
    }

    #[test]
    fn deprioritize_never_bans_or_compounds_with_later_penalties() {
        let mut pool = test_pool();
        add_slot(&pool, "1.2.3.4:8333", 100);
        add_slot(&pool, "5.6.7.8:8333", 100);
        for _ in 0..10 {
            pool.deprioritize("1.2.3.4:8333", 50);
        }
        assert!(!pool.is_banned("1.2.3.4:8333"));
        assert_eq!(pool.get_score("1.2.3.4:8333"), Some(SCORE_DEFAULT), "demerits touched the score");
        assert_eq!(pool.get_demerit("1.2.3.4:8333"), Some(SCORE_MAX));
        // Selection sees the demerit...
        assert_eq!(pool.best_peer_addr().as_deref(), Some("5.6.7.8:8333"));
        // ...but a later routine penalty doesn't turn it into a ban.
        pool.misbehaving("1.2.3.4:8333", 10, Offense::Delivery);
        assert!(!pool.is_banned("1.2.3.4:8333"));
        assert_eq!(pool.get_score("1.2.3.4:8333"), Some(SCORE_DEFAULT - 10));
    }

    #[test]
    fn disconnect_and_deprioritize_stops_at_the_soft_floor() {
        let mut pool = test_pool_with_store();
        for _ in 0..5 {
            add_slot(&pool, "1.2.3.4:8333", 100);
            if let Some(score) = pool.store.as_ref().unwrap().load_score("1.2.3.4:8333").unwrap() {
                pool.slots.lock().unwrap()[0].score = score;
            }
            pool.disconnect_and_deprioritize("1.2.3.4:8333", 40);
            assert!(!pool.is_banned("1.2.3.4:8333"));
        }
        let saved = pool.store.as_ref().unwrap().load_score("1.2.3.4:8333").unwrap();
        assert_eq!(saved, Some(SOFT_PENALTY_FLOOR));
    }

    #[test]
    fn banning_an_inbound_peer_only_disconnects_it() {
        let mut pool = test_pool_with_store();
        let _a = add_live_slot(&pool, "inbound#7", 0, SCORE_DEFAULT, true);
        pool.ban_peer("inbound#7");
        assert_eq!(pool.count(), 0);
        assert!(!pool.is_banned("inbound#7"));
        let store = pool.store.as_ref().unwrap();
        assert!(!store.load_active_bans().unwrap().contains_key("inbound#7"));
    }

    #[test]
    fn netgroup_diversity_only_relaxed_when_params_say_so() {
        // Mainnet enforces /16 buckets — loopback mock peers would share one.
        assert!(ChainParams::mainnet().enforce_netgroup_diversity);
        assert_eq!(netgroup("127.0.0.1:18444", true, false), Some("v4:127.0".to_string()));
        assert_eq!(netgroup("127.0.0.1:18445", true, false), netgroup("127.0.0.1:18444", true, false));
        // Regtest (test-only) disables the bucket entirely.
        assert!(!ChainParams::regtest().enforce_netgroup_diversity);
        assert_eq!(netgroup("127.0.0.1:18444", false, false), None);
    }

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

    /// An outbound peer in `pool` with a full addr token bucket, to gossip
    /// from (ticket 052: gossip from a peer not in the pool is dropped).
    fn gossip_source(pool: &PeerPool) -> String {
        let addr = "198.51.100.7:8333".to_string();
        let mut slots = pool.slots.lock().unwrap();
        if !slots.iter().any(|s| s.addr == addr) {
            slots.push(PeerSlot { addr_tokens: ADDR_TOKEN_BURST, ..PeerSlot::base(None, addr.clone(), false) });
        }
        addr
    }

    /// Shorthand for tests: insert with the gossip source tag (most common).
    fn ti(m: &mut AddrManager, addr: &str) -> bool {
        // Each address its own source: these tests are about eviction
        // order, not the per-source cap.
        m.insert(addr.to_string(), AddrSource::Gossip, &format!("gossip:{}", addr))
    }

    #[test]
    fn addrman_insert_dedupes() {
        let mut m = AddrManager::new(100);
        assert!(ti(&mut m, "1.2.3.4:8333"));
        assert!(!ti(&mut m, "1.2.3.4:8333"));
        assert_eq!(m.len(), 1);
    }

    #[test]
    fn addrman_insert_many_counts_only_new() {
        let mut m = AddrManager::new(100);
        let added = m.insert_many(
            vec![
                "1.2.3.4:8333".to_string(),
                "5.6.7.8:8333".to_string(),
                "1.2.3.4:8333".to_string(), // duplicate
            ],
            AddrSource::Gossip,
            "gossip:test",
        );
        assert_eq!(added, 2);
        assert_eq!(m.len(), 2);
    }

    #[test]
    fn addrman_record_success_marks_known_good() {
        let mut m = AddrManager::new(100);
        ti(&mut m, "1.2.3.4:8333");
        m.record_success("1.2.3.4:8333");
        let meta = m.addrs.get("1.2.3.4:8333").unwrap();
        assert!(meta.last_success.is_some());
        assert_eq!(meta.failure_count, 0);
        assert_eq!(meta.tier(Instant::now()), 0); // tier 0 = known-good
    }

    #[test]
    fn addrman_record_failure_increments_count() {
        let mut m = AddrManager::new(100);
        ti(&mut m, "1.2.3.4:8333");
        m.record_failure("1.2.3.4:8333");
        m.record_failure("1.2.3.4:8333");
        let meta = m.addrs.get("1.2.3.4:8333").unwrap();
        assert_eq!(meta.failure_count, 2);
        assert!(meta.last_success.is_none());
    }

    #[test]
    fn addrman_record_success_after_failures_resets() {
        let mut m = AddrManager::new(100);
        ti(&mut m, "1.2.3.4:8333");
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
        let mut meta = AddrMeta::new(AddrSource::Gossip, "gossip:test");
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
        let mut meta = AddrMeta::new(AddrSource::Gossip, "gossip:test");
        meta.last_tried = Some(Instant::now());
        meta.failure_count = 50;
        assert_eq!(meta.current_backoff(), ADDR_RETRY_MAX);
    }

    #[test]
    fn addrman_eligible_for_never_tried() {
        let meta = AddrMeta::new(AddrSource::Gossip, "gossip:test");
        assert!(meta.is_eligible(Instant::now()));
    }

    #[test]
    fn addrman_eligible_after_backoff_elapsed() {
        // Synthesise an entry whose last_tried was long ago, so even with
        // failures the backoff has elapsed.
        let mut meta = AddrMeta::new(AddrSource::Gossip, "gossip:test");
        meta.failure_count = 1;
        meta.last_tried = Some(Instant::now() - (ADDR_RETRY_BASE * 2));
        assert!(meta.is_eligible(Instant::now()));
    }

    #[test]
    fn addrman_pick_candidates_orders_known_good_first() {
        let mut m = AddrManager::new(100);
        ti(&mut m, "never:8333");
        ti(&mut m, "good:8333");
        m.record_success("good:8333");

        let picked = m.pick_candidates(10, &|_| false);
        assert_eq!(picked[0], "good:8333");
        assert_eq!(picked[1], "never:8333");
    }

    #[test]
    fn addrman_pick_candidates_respects_exclude() {
        let mut m = AddrManager::new(100);
        ti(&mut m, "a:8333");
        ti(&mut m, "b:8333");
        ti(&mut m, "c:8333");

        let picked = m.pick_candidates(10, &|addr| addr == "b:8333");
        assert_eq!(picked.len(), 2);
        assert!(!picked.contains(&"b:8333".to_string()));
    }

    #[test]
    fn addrman_pick_candidates_respects_limit() {
        let mut m = AddrManager::new(100);
        for i in 0..10 {
            ti(&mut m, &format!("peer{}:8333", i));
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
        ti(&mut m, "good:8333");
        m.record_success("good:8333");
        ti(&mut m, "never:8333");
        assert_eq!(m.len(), 2);

        // Inserting a third should evict "never", not "good".
        ti(&mut m, "new:8333");
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
        ti(&mut m, "flaky:8333");
        m.record_failure("flaky:8333");
        m.record_failure("flaky:8333");
        m.record_failure("flaky:8333");
        ti(&mut m, "fresh:8333");
        assert_eq!(m.len(), 2);

        // A new insertion should evict "flaky" (3 failures) over "fresh"
        // (0 failures).
        ti(&mut m, "newcomer:8333");
        assert_eq!(m.len(), 2);
        assert!(!m.addrs.contains_key("flaky:8333"));
        assert!(m.addrs.contains_key("fresh:8333"));
        assert!(m.addrs.contains_key("newcomer:8333"));
    }

    #[test]
    fn addrman_eviction_queues_pending_delete() {
        // The flush layer drives `delete_addrs_bulk` from the queue that
        // `evict_if_full` populates — verify the queue actually gets the
        // evicted addr so the on-disk view doesn't grow without bound.
        let mut m = AddrManager::new(2);
        ti(&mut m, "loser:8333");
        m.record_failure("loser:8333");
        ti(&mut m, "fresh:8333");
        ti(&mut m, "newcomer:8333"); // evicts "loser"

        let pending = m.take_pending_deletes();
        assert_eq!(pending, vec!["loser:8333".to_string()]);
        // After taking the queue should be empty so the next flush doesn't
        // re-issue the same DELETE.
        assert!(m.take_pending_deletes().is_empty());
    }

    #[test]
    fn addrman_candidate_count_excludes_in_backoff() {
        let mut m = AddrManager::new(100);
        ti(&mut m, "eligible:8333");
        ti(&mut m, "backoff:8333");
        m.record_failure("backoff:8333");
        // backoff:8333 just failed → not eligible until ADDR_RETRY_BASE elapses
        assert_eq!(m.candidate_count(), 1);
    }

    #[test]
    fn addrman_insert_from_record_preserves_failure_count() {
        // Restored entries should come back at the same tier they had on
        // disk — a peer with three failures stays in backoff after a
        // restart, doesn't get promoted to "never tried".
        let mut m = AddrManager::new(100);
        let record = AddrRecord {
            addr: "restored:8333".to_string(),
            first_seen: 1_700_000_000,
            last_tried: Some(1_700_000_500),
            last_success: None,
            failure_count: 3,
            source: "gossip".to_string(),
            source_group: String::new(),
        };
        assert!(m.insert_from_record(&record));
        let meta = m.addrs.get("restored:8333").unwrap();
        assert_eq!(meta.failure_count, 3);
        assert!(meta.last_success.is_none());
        assert!(!meta.dirty); // freshly restored, not yet modified
    }

    #[test]
    fn addrman_take_dirty_records_clears_dirty_flag() {
        // After a successful flush the entries should not be re-flushed on
        // the next tick — `take_dirty_records` clears the flag inline.
        let mut m = AddrManager::new(100);
        ti(&mut m, "1.2.3.4:8333");
        let first = m.take_dirty_records();
        assert_eq!(first.len(), 1);
        let second = m.take_dirty_records();
        assert!(second.is_empty(), "second flush should be a no-op");
    }

    #[test]
    fn addrman_record_failure_marks_dirty() {
        // Mutating an existing entry should re-arm the dirty flag so the
        // updated failure_count gets persisted on the next flush.
        let mut m = AddrManager::new(100);
        ti(&mut m, "peer:8333");
        m.take_dirty_records(); // clear initial dirty
        m.record_failure("peer:8333");
        let dirty = m.take_dirty_records();
        assert_eq!(dirty.len(), 1);
        assert_eq!(dirty[0].addr, "peer:8333");
        assert_eq!(dirty[0].failure_count, 1);
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
        let added = pool.ingest_gossip_addrs(&gossip_source(&pool), vec![
            "1.2.3.4:8333".to_string(),
            "5.6.7.8:8333".to_string(),
        ]);
        assert_eq!(added, 2);
        assert_eq!(pool.known_addr_count(), 2);

        // Re-ingesting the same addresses adds zero new entries.
        let added2 = pool.ingest_gossip_addrs(&gossip_source(&pool), vec!["1.2.3.4:8333".to_string()]);
        assert_eq!(added2, 0);
        assert_eq!(pool.known_addr_count(), 2);
    }

    // ── Persistence wiring tests ─────────────────────────────────────

    #[test]
    fn flush_addrs_writes_dirty_entries_to_store() {
        let mut pool = test_pool_with_store();
        pool.ingest_gossip_addrs(&gossip_source(&pool), vec![
            "1.2.3.4:8333".to_string(),
            "5.6.7.8:8333".to_string(),
        ]);
        pool.flush_addrs();

        // The store should now hold both addresses.
        let store = pool.store.as_ref().unwrap().clone();
        let loaded = store.load_all_addrs().unwrap();
        assert_eq!(loaded.len(), 2);
        let addrs: HashSet<String> = loaded.iter().map(|r| r.addr.clone()).collect();
        assert!(addrs.contains("1.2.3.4:8333"));
        assert!(addrs.contains("5.6.7.8:8333"));
        // Both came in via ingest_gossip_addrs → tagged "gossip".
        assert!(loaded.iter().all(|r| r.source == "gossip"));
    }

    #[test]
    fn flush_addrs_drains_pending_deletes_from_eviction() {
        // Force an eviction by stuffing the manager past its cap, then verify
        // the evicted row is DELETEd from the store on flush.
        let store = Arc::new(PeerStore::open(":memory:").unwrap());
        let mut pool = PeerPool {
            slots: Arc::new(Mutex::new(Vec::new())),
            addrs: AddrManager::new(2),
            our_height: 0,
            last_dns_query: Instant::now(),
            bans: HashMap::new(),
            tor: None,
            store: Some(store.clone()),
            last_score_flush: Instant::now(),
            last_addr_flush: Instant::now(),
            params: ChainParams::mainnet(),
            source: PeerSource::Discover,
            store_error: None,
        };

        pool.addrs.insert("a:8333".into(), AddrSource::Gossip, "gossip:1");
        pool.addrs.insert("b:8333".into(), AddrSource::Gossip, "gossip:2");
        pool.flush_addrs(); // baseline: both written

        // Insert a third → cap=2 forces eviction. Eviction prefers the
        // entry with most failures, but with all-zero failures it falls
        // through to "highest failure_count among never-success" (0 here)
        // which then breaks ties on first_seen age, evicting the oldest.
        pool.addrs.insert("c:8333".into(), AddrSource::Gossip, "gossip:3");
        pool.flush_addrs();

        let loaded = store.load_all_addrs().unwrap();
        assert_eq!(loaded.len(), 2, "store should reflect the post-eviction cap");
        let addrs: HashSet<String> = loaded.iter().map(|r| r.addr.clone()).collect();
        assert!(addrs.contains("c:8333"), "newest entry should still be present");
    }

    #[test]
    fn flush_addrs_is_idempotent_when_nothing_dirty() {
        // A second flush with no intervening mutation should issue zero
        // INSERTs (verified indirectly: no panic, store contents unchanged).
        let mut pool = test_pool_with_store();
        pool.ingest_gossip_addrs(&gossip_source(&pool), vec!["a:8333".to_string()]);
        pool.flush_addrs();
        let before = pool.store.as_ref().unwrap().load_all_addrs().unwrap();
        pool.flush_addrs();
        let after = pool.store.as_ref().unwrap().load_all_addrs().unwrap();
        assert_eq!(before.len(), after.len());
    }

    #[test]
    fn restored_addrs_skip_dns_fallback_threshold() {
        // The hydration path in PeerPool::new is what makes second-launch
        // skip DNS, so verify the in-memory shape: insert_from_record on
        // enough entries should push candidate_count above the threshold.
        let mut m = AddrManager::new(MAX_KNOWN_ADDRS);
        for i in 0..(DNS_FALLBACK_THRESHOLD + 10) {
            let record = AddrRecord {
                addr: format!("restored{}:8333", i),
                first_seen: 1_700_000_000,
                last_tried: None,
                last_success: None,
                failure_count: 0,
                source: "dns".to_string(),
                source_group: "dns".to_string(),
            };
            assert!(m.insert_from_record(&record));
        }
        assert!(m.candidate_count() >= DNS_FALLBACK_THRESHOLD);
    }

    // ── Address poisoning (tests/network-app) ────────────────────────
    //
    // Ticket 011 keeps the address manager deliberately simple (no
    // new/tried buckets). What it promises: known-good addresses are never
    // evicted, gossip never resets an entry's history, and known-good ones
    // are dialed first; ticket 052 adds per-source caps and a protected
    // set (seeds, known-good) gossip can never evict.

    /// Capacity for the flood tests: eviction scans the whole manager per
    /// insert, so a 10k-entry flood test takes seconds; the policy is the
    /// same at any size.
    const FLOOD_CAP: usize = 1_000;

    /// A full manager: `good` known-good, `dns` hour-old untried DNS
    /// entries, then a gossip flood twice its capacity from one peer.
    fn flooded(good: usize, dns: usize) -> AddrManager {
        flooded_from(good, dns, 1)
    }

    /// `flooded`, the flood spread over `sources` gossip source groups.
    fn flooded_from(good: usize, dns: usize, sources: u32) -> AddrManager {
        let mut m = AddrManager::new(FLOOD_CAP);
        let hour_ago = unix_now() - 3600;
        for i in 0..good {
            m.insert(format!("good{}:8333", i), AddrSource::Dns, "dns");
            m.record_success(&format!("good{}:8333", i));
        }
        for i in 0..dns {
            m.insert_from_record(&AddrRecord {
                addr: format!("dns{}:8333", i),
                first_seen: hour_ago,
                last_tried: None,
                last_success: None,
                failure_count: 0,
                source: "dns".into(),
                source_group: "dns".into(),
            });
        }
        for i in 0..2 * FLOOD_CAP as u32 {
            let addr = format!("{}.{}.{}.{}:8333", 100 + (i >> 16), (i >> 8) & 0xff, i & 0xff, 7);
            m.insert(addr, AddrSource::Gossip, &format!("gossip:src{}", i % sources));
        }
        m
    }

    #[test]
    fn gossip_flood_never_evicts_known_good_addresses_and_stays_bounded() {
        // Enough sources to fill the book despite per-source caps.
        let m = flooded_from(50, 0, 40);
        assert_eq!(m.len(), FLOOD_CAP);
        for i in 0..50 {
            assert!(m.addrs.contains_key(&format!("good{}:8333", i)), "good{} evicted", i);
        }
        // Evictions are queued for the on-disk copy too.
        assert!(!m.pending_deletes.is_empty());
    }

    #[test]
    fn known_good_addresses_are_dialed_before_a_flood() {
        let m = flooded(12, 0);
        let picked = m.pick_candidates(MAX_OUTBOUND, &|_| false);
        assert_eq!(picked.len(), MAX_OUTBOUND);
        assert!(picked.iter().all(|a| a.starts_with("good")), "{:?}", picked);
    }

    #[test]
    fn gossip_never_resets_an_entrys_history() {
        let mut m = AddrManager::new(100);
        m.insert("flaky:8333".into(), AddrSource::Dns, "dns");
        for _ in 0..3 {
            m.record_failure("flaky:8333");
        }
        m.insert("good:8333".into(), AddrSource::Dns, "dns");
        m.record_success("good:8333");
        // The same addresses gossiped back by a peer.
        assert_eq!(m.insert_many(["flaky:8333".to_string(), "good:8333".to_string()], AddrSource::Gossip, "gossip:test"), 0);
        assert_eq!(m.addrs["flaky:8333"].failure_count, 3);
        assert!(!m.addrs["flaky:8333"].is_eligible(Instant::now()), "gossip lifted a backoff");
        assert!(m.addrs["good:8333"].last_success.is_some());
        assert_eq!(m.addrs["good:8333"].source, AddrSource::Dns, "dns");
    }

    /// One gossiping peer used to push every untried DNS-learned address
    /// out of a full manager (oldest untried go first), leaving only its
    /// own addresses plus the known-good ones as candidates. Ticket 052's
    /// per-source caps (Core's source buckets) prevent this.
    #[test]
    fn one_gossip_source_cannot_evict_all_dns_addresses() {
        let m = flooded(0, 200);
        let survivors = (0..200).filter(|i| m.addrs.contains_key(&format!("dns{}:8333", i))).count();
        assert!(survivors >= 100, "only {} of 200 DNS addresses survived a single peer's flood", survivors);
    }

    /// One source holds at most 1/ADDR_SOURCE_SHARE of the book; and
    /// however many sources flood it, DNS and known-good entries survive
    /// (they are protected, ticket 052).
    #[test]
    fn per_source_cap_and_protected_set_survive_a_many_source_flood() {
        let m = flooded(0, 0);
        assert_eq!(m.len(), FLOOD_CAP / ADDR_SOURCE_SHARE, "one source past its share");
        let m = flooded_from(20, 300, 64);
        assert_eq!(m.len(), FLOOD_CAP);
        for i in 0..300 {
            assert!(m.addrs.contains_key(&format!("dns{}:8333", i)), "dns{} evicted by gossip", i);
        }
        for i in 0..20 {
            assert!(m.addrs.contains_key(&format!("good{}:8333", i)));
        }
        // Gossip can't push protected entries out, even into a book that
        // is all protected: it is dropped instead.
        let mut full = AddrManager::new(4);
        for i in 0..4 {
            full.insert(format!("seed{}:8333", i), AddrSource::Dns, "dns");
        }
        assert!(!full.insert("1.2.3.4:8333".into(), AddrSource::Gossip, "gossip:x"));
        assert_eq!(full.len(), 4);
    }

    /// Within a tier, seeds are tried before gossip.
    #[test]
    fn untried_seeds_are_dialed_before_untried_gossip() {
        let mut m = AddrManager::new(100);
        for i in 0..10 {
            m.insert(format!("10.0.0.{}:8333", i), AddrSource::Gossip, "gossip:x");
        }
        m.insert("seed:8333".into(), AddrSource::Dns, "dns");
        assert_eq!(m.pick_candidates(1, &|_| false), vec!["seed:8333".to_string()]);
    }

    /// Ticket 052: Core's addr token bucket. An inbound peer starts with
    /// one token and gains 0.1 a second; an outbound peer we sent `getaddr`
    /// to may answer with a full 1,000.
    #[test]
    fn addr_gossip_is_rate_limited_per_peer() {
        let pool = test_pool();
        add_slot_with_inbound(&pool, "inbound#1", 0, true);
        assert_eq!(pool.take_addr_tokens("inbound#1", 1000), 1);
        assert_eq!(pool.take_addr_tokens("inbound#1", 1000), 0);
        {
            // Ten seconds later: one more.
            let mut slots = pool.slots.lock().unwrap();
            let s = slots.iter_mut().find(|s| s.addr == "inbound#1").unwrap();
            s.addr_tokens_at -= Duration::from_secs(10);
        }
        assert_eq!(pool.take_addr_tokens("inbound#1", 1000), 1);
        pool.slots.lock().unwrap().push(PeerSlot {
            addr_tokens: 1.0 + ADDR_TOKEN_BURST,
            ..PeerSlot::base(None, "1.2.3.4:8333".into(), false)
        });
        assert_eq!(pool.take_addr_tokens("1.2.3.4:8333", 1000), 1000);
        assert_eq!(pool.take_addr_tokens("1.2.3.4:8333", 1000), 1);
        assert_eq!(pool.take_addr_tokens("not-connected:8333", 10), 0);
    }

    /// Inbound gossip is the unverified bucket: every inbound peer shares
    /// one source group, so together they hold at most one share.
    #[test]
    fn all_inbound_gossip_shares_one_source() {
        let mut pool = test_pool();
        for i in 0..3 {
            let id = format!("inbound#{}", i);
            pool.slots.lock().unwrap().push(PeerSlot {
                addr_tokens: ADDR_TOKEN_BURST,
                ..PeerSlot::base(None, id, true)
            });
        }
        let cap = MAX_KNOWN_ADDRS / ADDR_SOURCE_SHARE;
        let mut added = 0;
        for i in 0..3u32 {
            let batch: Vec<String> =
                (0..cap as u32).map(|j| format!("45.{}.{}.{}:8333", i, j >> 8, j & 0xff)).collect();
            added += pool.ingest_gossip_addrs(&format!("inbound#{}", i), batch);
        }
        assert_eq!(added, cap);
        assert!(pool.addrs.addrs.values().all(|m| m.source == AddrSource::Inbound && m.source_group == INBOUND_SOURCE));
    }

    /// Ticket 052: onions we never connected to are one netgroup, for
    /// outbound diversity and the cross-check; a proven one is its own.
    #[test]
    fn unproven_onions_are_one_netgroup() {
        assert_eq!(netgroup("aaaa.onion:8333", true, false), netgroup("bbbb.onion:8333", true, false));
        assert_eq!(netgroup("aaaa.onion:8333", true, true), None);
        assert_eq!(cross_check_group("aaaa.onion:8333", true, false), cross_check_group("bbbb.onion:8333", true, false));
        assert_ne!(cross_check_group("aaaa.onion:8333", true, true), cross_check_group("bbbb.onion:8333", true, true));
        assert_eq!(netgroup("aaaa.onion:8333", false, false), None, "regtest: no diversity");

        let pool = test_pool();
        let _a = add_live_slot(&pool, "1.2.3.4:8333", 0, SCORE_DEFAULT, false);
        let _b = add_live_slot(&pool, "bbbb.onion:8333", 0, SCORE_MAX, false);
        let _c = add_live_slot(&pool, "cccc.onion:8333", 0, SCORE_DEFAULT, false);
        // Witness: the best-scored onion. Tiebreaker: not the other
        // unproven onion (same operator, as far as we know).
        let w = pool.cross_check_peer(&["1.2.3.4:8333".to_string()]).unwrap();
        assert_eq!(w, "bbbb.onion:8333");
        assert_eq!(pool.cross_check_peer(&["1.2.3.4:8333".to_string(), w]), None);
    }

    /// Ticket 052: own transactions go only to outbound peers we never
    /// told our onion; the onion is only offered to peers that know it.
    #[test]
    fn own_tx_and_self_ad_eligibility_by_connection() {
        let pool = test_pool();
        add_slot_with_inbound(&pool, "inbound#1", 0, true);
        add_slot(&pool, "1.1.1.1:8333", 0);
        pool.slots.lock().unwrap().push(PeerSlot {
            self_advertised: true,
            ..PeerSlot::base(None, "2.2.2.2:8333".into(), false)
        });
        assert!(!pool.may_carry_own_txs("inbound#1"));
        assert!(pool.may_carry_own_txs("1.1.1.1:8333"));
        assert!(!pool.may_carry_own_txs("2.2.2.2:8333"));
        assert!(!pool.may_carry_own_txs("unknown:8333"));
        assert!(pool.may_self_advertise("inbound#1"));
        assert!(!pool.may_self_advertise("1.1.1.1:8333"));
        assert!(pool.may_self_advertise("2.2.2.2:8333"));
    }

    /// Ticket 052: with inbound slots full, a newcomer evicts the peer
    /// silent the longest, if it has been silent long enough; otherwise
    /// it is refused.
    #[test]
    fn full_inbound_evicts_the_idlest_or_refuses() {
        let pool = test_pool();
        let mut servers = Vec::new();
        for i in 0..MAX_INBOUND {
            let (mut peer, server) = crate::p2p::tests::loopback_peer_pair();
            peer.set_addr_for_test(&format!("inbound#{}", i), true);
            if i == 3 {
                peer.set_idle_for_test(INBOUND_EVICTION_IDLE + Duration::from_secs(1));
            } else if i == 5 {
                peer.set_idle_for_test(INBOUND_EVICTION_IDLE + Duration::from_secs(60));
            }
            assert!(pool.add_inbound_peer(peer));
            servers.push(server);
        }
        let newcomer = |n: &str| {
            let (mut peer, server) = crate::p2p::tests::loopback_peer_pair();
            peer.set_addr_for_test(n, true);
            (peer, server)
        };
        let (p, _s1) = newcomer("inbound#new1");
        assert!(pool.add_inbound_peer(p));
        assert_eq!(pool.inbound_count(), MAX_INBOUND);
        assert!(!pool.is_inbound("inbound#5"), "idlest not evicted");
        let (p, _s2) = newcomer("inbound#new2");
        assert!(pool.add_inbound_peer(p));
        assert!(!pool.is_inbound("inbound#3"));
        // Everyone left is active: refused.
        let (p, _s3) = newcomer("inbound#new3");
        assert!(!pool.add_inbound_peer(p));
        assert_eq!(pool.inbound_count(), MAX_INBOUND);
    }

    /// Ticket 052: a peer store that can't be opened leaves the session
    /// running, and its status says it isn't remembering bans.
    #[test]
    fn unopenable_peer_store_is_reported() {
        let dir = tempfile::TempDir::new().unwrap();
        // A directory where the file should be: SQLite can't open it.
        let path = dir.path().join("peers.sqlite3");
        std::fs::create_dir(&path).unwrap();
        let mut chain = crate::testkit::FixtureChain::new();
        chain.mine(1);
        let peer = crate::testkit::MockPeer::spawn(&chain, vec![]);
        let pool = PeerPool::new(0, None, path.to_str(), ChainParams::regtest(), PeerSource::Static(vec![peer.addr()]))
            .expect("runs without persistence");
        let warning = pool.persistence_warning().expect("warning");
        assert!(warning.contains("not remembered"), "{}", warning);
        assert!(test_pool().persistence_warning().is_none());
    }

    /// Ticket 052, against real (mock) peers: gossip addresses fill at most
    /// MAX_OUTBOUND - RESERVED_PROTECTED_OUTBOUND outbound slots, at most
    /// MAX_OUTBOUND_PER_SOURCE from one source, and seeds come first.
    #[test]
    fn outbound_slots_reserved_for_protected_addresses_and_capped_per_source() {
        let mut chain = crate::testkit::FixtureChain::new();
        chain.mine(1);
        let peers: Vec<crate::testkit::MockPeer> =
            (0..16).map(|_| crate::testkit::MockPeer::spawn(&chain, vec![])).collect();
        let mut pool = PeerPool::new_for_test_with(ChainParams::regtest());
        // Two seeds; ten gossip addresses from source A, four from B.
        for p in &peers[..2] {
            pool.addrs.insert(p.addr(), AddrSource::Dns, "dns");
        }
        for (i, p) in peers[2..].iter().enumerate() {
            let src = if i < 10 { "gossip:A" } else { "gossip:B" };
            pool.addrs.insert(p.addr(), AddrSource::Gossip, src);
        }
        pool.maintain();
        let slots = pool.slots.lock().unwrap();
        let from = |src: &str| slots.iter().filter(|s| s.gossip_source.as_deref() == Some(src)).count();
        assert_eq!(slots.iter().filter(|s| s.gossip_source.is_none()).count(), 2, "both seeds dialed");
        assert_eq!(from("gossip:A"), MAX_OUTBOUND_PER_SOURCE);
        assert_eq!(from("gossip:B"), MAX_OUTBOUND_PER_SOURCE);
        assert!(slots.len() <= 2 + MAX_OUTBOUND - RESERVED_PROTECTED_OUTBOUND);
        // The first OWN_TX_OUTBOUND connections (all, without an onion) are
        // clean for own transactions.
        assert!(slots.iter().all(|s| !s.self_advertised));
    }

    /// The same limits for a wake, which dials `WAKE_CONNECT_PARALLEL` at
    /// once (ticket 054): a batch counts its own gossip addresses, so it
    /// can't take three from one source because none had connected yet.
    #[test]
    fn wake_parallel_dials_keep_the_gossip_limits() {
        let mut chain = crate::testkit::FixtureChain::new();
        chain.mine(1);
        let peers: Vec<crate::testkit::MockPeer> =
            (0..12).map(|_| crate::testkit::MockPeer::spawn(&chain, vec![])).collect();
        let mut pool = PeerPool::new_for_test_with(ChainParams::regtest());
        for p in &peers {
            pool.addrs.insert(p.addr(), AddrSource::Gossip, "gossip:A");
        }
        pool.maintain_until(Some(Instant::now() + Duration::from_secs(10)));
        let slots = pool.slots.lock().unwrap();
        assert_eq!(slots.len(), MAX_OUTBOUND_PER_SOURCE, "{} slots from one source", slots.len());
    }
}
