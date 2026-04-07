# Ticket 001: Multi-Peer Connections with Eclipse Attack Protection

## Status (as of 2026-04-06): Partially Complete

**Implemented:**
- Multi-peer outbound pool — `MAX_OUTBOUND = 8` in `hercules-core/src/peer_pool.rs:11`
- Misbehavior scoring with automatic ban at threshold 100 (`PeerSlot.misbehavior`, `pool.misbehaving()`)
- Multiple DNS seeds for peer discovery
- UI surfaces connected peer count and per-peer info

**Still required to close this ticket:**
- **Header cross-validation** — header sync currently runs from a single active peer at a time. No comparison across 2+ independent peers before headers are stored, which is the core eclipse-resistance mechanism this ticket was opened for.
- **Subnet diversity** — no /16 enforcement when filling outbound slots; an attacker controlling one /16 could in principle dominate the pool.
- **Parallel range download** — `getheaders` is sequential from one peer, not chunked across peers for faster initial sync.
- **Persistent ban list** — bans live in-memory only, lost on restart.

The remaining gaps are what would matter most against a sophisticated eclipse attempt; the current pool gives us breadth but not cross-validation.

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
