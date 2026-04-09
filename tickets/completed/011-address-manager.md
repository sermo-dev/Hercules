# Ticket 011: Address Manager (addrman) + Self-Advertisement

## Summary

Two coupled pieces of work that together let Hercules become a discoverable, gossip-mesh-participating node:

1. **Persistent address manager** — store known peer addresses across restarts so we can answer `GetAddr` with real data, bootstrap without hitting DNS, and bias outbound peer selection toward known-good addresses.
2. **Self-advertisement of our .onion address** — actively announce our own listening address into the gossip mesh so other nodes can discover and connect to us inbound.

The two pieces are conceptually one feature ("become a discoverable node") — shipping addrman without self-advertisement would let us *consume* gossip but never *contribute* our own existence to it, leaving inbound connection counts stuck at zero forever.

## Current state (2026-04-07)

An **in-memory** AddrManager has already landed on the peer-discovery branch:
- `peer_pool.rs::AddrManager` with per-address state (first_seen, last_tried, last_success, failure_count), exponential backoff (60s → 1h cap), and tier-based candidate ranking (known-good → never-tried → in-backoff)
- `addr` / `addrv2` gossip ingestion via `pending_gossip_addrs` drain in the monitor loop
- `getaddr` sent automatically on outbound connect
- DNS demoted to fallback-only (only consulted when candidate count drops below 50)
- Opportunistic refill in the monitor loop when outbound count drops

This ticket finishes the job by adding **persistence** and **self-advertisement**, the two pieces that were intentionally deferred from the in-memory version.

## Background

Bitcoin Core's `addrman` (address manager) maintains a database of known peer addresses, organized into "new" (heard about but never connected) and "tried" (successfully connected at least once) buckets. This serves multiple purposes:

1. **Faster startup** — don't need DNS seeds every time
2. **Network health** — relay addresses to help peers discover each other
3. **Eclipse resistance** — diverse address sources make it harder for an attacker to surround the node with malicious peers

### What we're missing (after the in-memory AddrManager landed)

- **Persistence:** the in-memory AddrManager throws away all per-address reputation on restart, so on iOS (where the OS aggressively kills backgrounded apps) we re-learn the network from scratch every launch.
- **`GetAddr` responses are still empty** (sync.rs:1308) — we receive gossip into the in-memory manager but have no read path back out to share addresses with peers asking us.
- **Self-advertisement is missing entirely** — we never tell other peers that we exist at our own .onion address. This is the actual root cause of `inbound_peers = 0`. Discovering peers (which the in-memory manager solves) is only half of being on the network; *being discoverable* is the other half.
- DNS-only bootstrap on first launch (cold start) — once persistence lands, the second-launch path skips DNS entirely.

## Design

### Part 1 — Address persistence

#### Storage

SQLite table sitting next to the existing peer store (`peers.sqlite`), since both files share a "peer reputation / addressing" lifecycle and are loaded together at pool startup:

```sql
CREATE TABLE known_addrs (
    addr TEXT PRIMARY KEY,       -- "ip:port" or "[ipv6]:port"
    first_seen INTEGER NOT NULL, -- unix timestamp
    last_tried INTEGER,          -- unix timestamp of last connection attempt
    last_success INTEGER,        -- unix timestamp of last successful connection
    failure_count INTEGER DEFAULT 0,
    source TEXT NOT NULL         -- 'dns' | 'gossip' | 'inbound' | 'manual'
);
CREATE INDEX known_addrs_last_success ON known_addrs(last_success);
```

The columns map 1:1 to the existing in-memory `AddrMeta` struct in `peer_pool.rs`, plus a `source` tag for diagnostics.

#### Integration

- `PeerStore` gets `save_addrs_bulk(&[(String, AddrMeta)])`, `load_all_addrs() -> HashMap<String, AddrMeta>`, and `delete_addr(&str)`.
- `PeerPool::new()` hydrates the in-memory `AddrManager` from `load_all_addrs()` before falling back to DNS, and only queries DNS when the loaded set is below `DNS_FALLBACK_THRESHOLD`.
- A periodic flush (piggyback on the existing `SCORE_FLUSH_INTERVAL` in `maintain()`) writes dirty entries back to disk in a single transaction. `Drop` does a final flush, mirroring the existing score-flush pattern.
- Eviction in `AddrManager::evict_if_full` already drops never-tried entries first; the flush should also `DELETE` evicted rows so the on-disk view stays bounded at MAX_KNOWN_ADDRS.

#### Address hygiene (already enforced in the in-memory layer; carry forward to persistence)

- `is_routable()` filter rejects loopback / multicast / unspecified / link-local before insertion (already in sync.rs)
- Port = 0 is rejected (already in sync.rs)
- Cap at MAX_KNOWN_ADDRS = 10,000 (already in peer_pool.rs)
- Exponential backoff drives down priority of failing addresses (already in peer_pool.rs)

---

### Part 2 — Self-advertisement of our .onion address

This is the piece that closes the inbound-connection loop. The Tor onion service keypair is *already* persisted (`tor.rs:136` wires up `state_dir`), so the .onion address is stable across restarts. What's missing is the gossip path that tells the rest of the network that this address exists.

#### Where we get our own address

- Already captured: `TorManager.onion_address: Option<String>` is set during `start_onion_service` (`tor.rs:311`).
- Add a getter `TorManager::our_onion_address(&self) -> Option<String>` and thread it down to `HeaderSync` so the message handlers can reach it.

#### `getaddr` response — include ourselves

- `handle_peer_message::GetAddr` (sync.rs:1308) currently returns `Addr(Vec::new())`. Change it to:
  1. Pull up to 999 random addresses from the persistent addrman (Part 1's read path)
  2. Splice our own .onion address into the list as a TorV3 entry (BIP 155 `addrv2` format)
  3. Reply with `AddrV2` if the peer announced `sendaddrv2` during handshake (we already track this), otherwise fall back to v1 `Addr` (which will *omit* our entry, since v1 can't encode TorV3)
- Bitcoin Core only responds to one `getaddr` per connection per peer; mirror that with a per-peer `getaddr_responded` flag in `relay_state`.

#### Unsolicited periodic re-advertisement

- Bitcoin Core does this every ~24h via `SetupAddressRelay`. For us, "every connection" + "every 24h" is sufficient:
  - **On every successful outbound connect**, send an unsolicited `addrv2(self)` immediately after the handshake's `getaddr` we already send. This is the fastest way to enter the mesh: each new outbound peer immediately learns we exist.
  - **Every 24h** (piggyback on the periodic maintenance tick), re-broadcast `addrv2(self)` to all currently-connected peers so the gossip stays alive even on long-lived connections.

#### Encoding TorV3 in addrv2

The `bitcoin` crate exposes `AddrV2::TorV3([u8; 32])`. The 32-byte payload is the *raw ed25519 public key* embedded in the .onion v3 hostname (the hostname is `base32(pubkey || checksum || version)` per rend-spec-v3). To extract it:
1. Strip the `.onion` suffix from the hostname (everything before `:port`)
2. Base32-decode (RFC4648 lowercase)
3. The first 32 bytes are the pubkey; the next 2 are the checksum (verify before use); the last byte is the version (must be `0x03`)

This conversion is small (~30 lines) and belongs in `tor.rs` next to `our_onion_address()`. **No new crates needed** — `data-encoding` or even a hand-rolled base32 decoder works; the Bitcoin protocol layer doesn't need SHA-3 (we're going *encoded address → bytes*, not the reverse).

---

## Verification

- **Persistence:** kill the app between launches, observe that `PeerPool::new()` log line shows "loaded N addresses from disk" and skips DNS. Inspect `peers.sqlite` directly with `sqlite3` to confirm rows.
- **GetAddr serving:** connect a second node (e.g., a local Bitcoin Core in regtest pointed at our onion) and send `getaddr`. It should receive a non-empty `addrv2` response containing our own .onion as one of the entries.
- **Self-advertisement loop:** run two Hercules instances, A and B. Connect A → B as outbound. Within seconds, B should appear in A's addrman (because B sent unsolicited `addrv2(self)` on connect). Then disconnect A from B and start a third instance C; C → A should now learn about B via gossip.
- **Inbound counter:** after sharing the .onion address with at least one cooperating peer, `inbound_peer_count` should rise above 0 — the smoking-gun acceptance test for this whole ticket.

## Dependencies

- The in-memory AddrManager (already landed on the peer-discovery branch — this ticket extends it).
- Persistent Tor onion service keypair (already wired up via `tor.rs:136` `state_dir`).

## Estimated Effort

- Part 1 (persistence): ~150 lines on `PeerStore` + ~30 lines of integration in `PeerPool::new` / `maintain` / `Drop`.
- Part 2 (self-advertisement): ~30 lines for the base32 decode in `tor.rs`, ~40 lines to extend `handle_peer_message::GetAddr` and `handle_peer_message::AddrV2` paths, ~20 lines for the periodic re-advertisement tick in the monitor loop.
