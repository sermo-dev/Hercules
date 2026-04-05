# Ticket 007: Peer Reputation and Scoring System

## Summary

Replace the current binary ban/allow peer model with a graduated reputation scoring system that tracks peer behavior over time, penalizes misbehavior proportionally, and rewards reliable peers with preferential selection.

## Background

- **Current model:** Peers are either connected or banned. Banning is permanent (until the ban set fills up and gets cleared). There's no middle ground for peers that are slow, occasionally unresponsive, or serve stale data.
- **Problem:** A peer that times out once gets the same treatment as one that's perfectly reliable. Conversely, a peer that serves subtly bad data (e.g., always slow, consistently behind by a few blocks) never gets penalized at all.
- **Bitcoin Core reference:** Core uses a misbehavior score (0-100) where different offenses add different point values. Score >= 100 triggers a ban. Scores decay over time.

## Design

### Score Model

Each connected peer gets a reputation score starting at 100 (neutral). Score range: 0-200.

| Event | Score Delta |
|---|---|
| Successfully served a batch of headers | +1 |
| Successfully served a full block | +2 |
| Responded to ping within timeout | +1 |
| Timed out on a request | -10 |
| Served invalid header (bad PoW, etc.) | -50 |
| Height lie detected (claims far above tip, can't serve) | -100 (immediate ban) |
| Served oversized header batch (>2000) | -100 (immediate ban) |
| Connection dropped unexpectedly | -5 |

### Thresholds

- **Score < 20:** Peer is disconnected and banned for 24 hours (not permanently).
- **Score > 150:** Peer is preferred for block downloads and header sync (priority selection in `best_peer()`).
- **Timed bans:** Store ban expiry timestamps. On `maintain()`, check if any bans have expired and allow reconnection.

### Storage

- Reputation scores should be stored in-memory (in `PeerSlot`) for the current session.
- Optionally persist ban list + scores to SQLite across restarts (low priority, can be a follow-up).

### Peer Selection

- Modify `best_peer()` to weight selection by both height and reputation score, not just height alone.
- A peer at height 900,000 with score 30 should be less preferred than a peer at height 899,999 with score 180.
- Simple formula: `selection_weight = height * (score / 100.0)`

## Integration Points

- **`peer_pool.rs`:** Add `score: i32` to `PeerSlot`. Add methods: `adjust_score(addr, delta)`, `get_score(addr)`. Modify `best_peer()` selection. Replace `banned_addrs: HashSet` with `bans: HashMap<SocketAddr, Instant>` for timed bans.
- **`sync.rs`:** Call `adjust_score()` after successful header batches, failed requests, height lie detection, etc.
- **`lib.rs` / UDL:** Optionally expose per-peer scores in `PeerInfo` for UI display.

## Testing Strategy

- Unit tests: Score adjustments, threshold-triggered bans, ban expiry, weighted peer selection.
- Simulation: Create mock peers with different score profiles, verify selection distribution matches expected weights.

## Estimated Effort

Medium. Mostly contained to `peer_pool.rs` and `sync.rs`. The current ban infrastructure (ticket 006-adjacent) provides a foundation to build on.
