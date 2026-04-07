# Ticket 001: Multi-Peer Connections with Eclipse Attack Protection

## Status (as of 2026-04-06): Complete (parallel range download deferred)

**Implemented:**
- Multi-peer outbound pool — `MAX_OUTBOUND = 8` in `hercules-core/src/peer_pool.rs`.
- Multiple DNS seeds for peer discovery; UI surfaces connected peer count and per-peer info.
- Graduated reputation scoring with `pool.misbehaving()` / `pool.reward()` and auto-ban at `BAN_LOW_THRESHOLD = 20`. See ticket 007 for the full reputation model.
- **Header cross-validation** — `HeaderSync::cross_check_headers` in `sync.rs` re-issues every batch's `getheaders` locator to an independent witness peer and compares the first hash. Disagreement escalates to a third tiebreaker peer; majority wins, and divergent peers take a 50-point misbehavior penalty. 2-peer disagreements with no tiebreaker reject the batch and apply a lighter penalty to both peers — refusing to commit dubious headers is the safer default.
- **Subnet diversity** — `subnet_bucket()` in `peer_pool.rs` buckets outbound peers into /16 (IPv4) or /32 (IPv6) groups; `maintain()` rejects new candidates whose bucket is already represented. `.onion` addresses are exempt because Tor circuits provide their own diversity.
- **Persistent ban list** — `peer_store.rs` writes bans through to SQLite immediately on `ban_peer()`, with expiry restored across restarts via `load_active_bans()`.

**Deferred:**
- **Parallel range download** — chunking `getheaders` across peers for faster initial sync was dropped from this ticket. AssumeUTXO already collapses initial sync into a 10-minute snapshot import on Wi-Fi, so the marginal benefit doesn't justify the protocol complexity. Can be revisited if a future change makes header sync the dominant cost again.

Eclipse resistance is now the cross-check + subnet diversity combo: an attacker would need to control multiple /16 subnets AND outvote our witness peers in the cross-check on every batch.

## Problem

Hercules currently connects to a single peer for header sync. If that peer is malicious, they could serve a fake header chain (an eclipse attack). While PoW verification makes this extremely expensive, it doesn't protect against a well-funded attacker or a compromised DNS seed returning only attacker-controlled nodes.

## Proposed Changes

### 1. Peer Manager (`peer_manager.rs`)
- Maintain a pool of 4-8 concurrent outbound peer connections
- Track peer state: connected, handshake complete, last seen, misbehavior score
- Rotate peers that become unresponsive or misbehave
- Diversify peer selection across different DNS seeds and IP ranges (different /16 subnets) to reduce chance of connecting to a single operator

### 2. Header Cross-Validation
- Download headers from at least 2 independent peers
- Compare header hashes at each height — if peers disagree, flag and fetch from additional peers
- Require majority agreement (e.g., 3 of 4 peers) before accepting a header batch
- Ban peers that serve headers with invalid PoW or that diverge from the majority chain

### 3. Peer Scoring and Banning
- Score peers based on: response time, valid data served, uptime
- Misbehavior penalties: invalid headers (-100), timeout (-10), protocol violations (-50)
- Ban threshold: peers below score threshold are disconnected and banned for 24 hours
- Persist ban list in SQLite

### 4. Parallel Download
- Assign different header ranges to different peers for faster initial sync
- Peer A: headers 0-100,000, Peer B: headers 100,001-200,000, etc.
- Validate that the ranges link together (hash chain continuity at boundaries)

### 5. Connection Diversity
- Ensure peers are from different /16 subnets
- Use multiple DNS seeds (already implemented, but currently we take first success)
- Optional: support manual peer addition for users who run their own node

## Files to Create/Modify

- **New:** `hercules-core/src/peer_manager.rs` — peer pool, scoring, banning
- **Modify:** `hercules-core/src/p2p.rs` — make `Peer` clonable/shareable, add ban tracking
- **Modify:** `hercules-core/src/sync.rs` — use peer manager instead of single peer, add cross-validation
- **Modify:** `hercules-core/src/store.rs` — add banned_peers table
- **Modify:** `hercules-core/src/hercules.udl` — expose peer count and peer list to UI
- **Modify:** `HerculesApp/ContentView.swift` — show multiple peers in UI

## Acceptance Criteria

- [ ] Connects to at least 4 peers simultaneously
- [ ] Headers are validated against 2+ independent peers before storage
- [ ] Divergent peers are detected, flagged, and disconnected
- [ ] Peers from the same /16 subnet are limited to 1 connection
- [ ] Ban list persists across app launches
- [ ] UI shows connected peer count and individual peer status
