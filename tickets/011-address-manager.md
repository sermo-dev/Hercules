# Ticket 011: Address Manager (addrman)

## Summary

Add a persistent address manager so the node can properly respond to `GetAddr` requests, learn new peer addresses from `Addr` messages, and bootstrap faster on subsequent launches. Currently we only discover peers from DNS seeds on each startup and respond to `GetAddr` with an empty list.

## Background

Bitcoin Core's `addrman` (address manager) maintains a database of known peer addresses, organized into "new" (heard about but never connected) and "tried" (successfully connected at least once) buckets. This serves multiple purposes:

1. **Faster startup** — don't need DNS seeds every time
2. **Network health** — relay addresses to help peers discover each other
3. **Eclipse resistance** — diverse address sources make it harder for an attacker to surround the node with malicious peers

### What we're missing

- `Addr` messages from peers are ignored (we receive them but don't store the addresses)
- `GetAddr` responses are empty (we have no addresses to share)
- Every startup requires DNS resolution (slow, especially over Tor)
- No address diversity — we only know DNS seed results

## Design

### Storage

SQLite table (new file or add to existing header DB):
```sql
CREATE TABLE addresses (
    addr TEXT PRIMARY KEY,       -- "ip:port" or "onion:port"
    services INTEGER NOT NULL,   -- ServiceFlags bitmask
    last_seen INTEGER NOT NULL,  -- unix timestamp
    last_tried INTEGER,          -- unix timestamp of last connection attempt
    last_success INTEGER,        -- unix timestamp of last successful connection
    source TEXT NOT NULL,        -- how we learned about this address
    attempts INTEGER DEFAULT 0   -- failed connection attempts
);
```

### Integration points

- **`Addr` message handler** — store addresses from peers (with rate limiting to prevent addr-stuffing)
- **`GetAddr` response** — return up to 1000 random addresses from the database, biased toward recently-seen addresses. Only respond to inbound peers, max once per connection.
- **Startup** — try stored addresses before falling back to DNS seeds
- **`peer_pool.rs` maintain()** — draw from stored addresses when filling outbound slots

### Address hygiene

- Cap at 10,000 addresses (evict oldest-unseen)
- Don't store addresses from the future (timestamp > now + 10 minutes)
- Don't store addresses with bad ports (0, >65535)
- Decay: reduce priority of addresses that fail connection attempts

## Dependencies

- None (standalone module)

## Estimated Effort

Small-medium. ~200 lines for the address store, ~50 lines for handler integration.
