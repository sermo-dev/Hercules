# Ticket 049: Peer I/O Deadlines — No Single Peer Can Stall the Node

## Summary

Every peer read and write runs on the one sync thread. Reads only have a per-`read()` timeout, and writes have no timeout at all. A single peer, including an anonymous inbound peer on the onion address we advertise ourselves, can therefore stall syncing indefinitely. While the sync thread is stuck it holds the node session, so every background wake reports `Busy` and `NodeHost.reset` times out.

This ticket gives every peer operation an absolute deadline, takes inbound handshakes off the sync thread, caps what one request can make us do, and makes sure peer chatter can't starve the rest of the loop.

**Severity: Critical.** A remote, unauthenticated peer can freeze validation, wakes and own-transaction broadcast with no error shown. Found independently by the P2P and architecture reviewers (2026-10-28 team review of main @ 7732755). It was also item 4 of the earlier whole-repo review, where this ticket number was reserved.

## Background

Line numbers are at main 7732755.

### Writes never time out

- `p2p.rs:490-509` (`send`): no `set_write_timeout`; there is none anywhere in the crate.
- `tor.rs:99-109`: `TorStream::write` and `flush` block on Arti with no timeout.
- `sync.rs:3975-4031` (`handle_getdata`): serves up to 50,000 items from one message, one after another, on the sync thread.

**Attack:** a peer sends `getdata` for the tip block many times and stops reading. The socket buffer or Tor stream window fills, `send_block` blocks forever, and `run_sync` never checks `stop` again. One 1.8 MB message can also pull up to 50k × ~2 MB of uploads, with no cellular gate.

### Reads have no total deadline

`receive_until(None)` (`p2p.rs:522`) bounds each `read()` call, not the message. A peer can send a valid header announcing a 4 MB payload, then one byte every 50 s. Exposed paths:

- `Peer::accept` for inbound peers, called inside the monitor loop (`sync.rs:3152-3170`), up to 10 per tick.
- The handshake in `maintain` / `PeerPool::new_until`. A wake's `connect_deadline` does not bound a handshake already in progress.
- Main-loop `get_headers` and `get_block` (`sync.rs:2724`, `2914`) and cross-check witnesses outside a wake.

### `poll_message` loses framing

`p2p.rs:537-574` and `795-815` (called from `sync.rs:3704`) use a 100 ms per-read timeout. If a message's bytes arrive with a gap over 100 ms (common on Tor and cellular), `read_exact` times out midway. `poll_message` then returns `Ok(None)` after consuming bytes. The next poll reads mid-payload bytes as a header, hits `WrongMagic`, and drops the peer, losing the message.

### Sync peer chosen by claimed height

`best_peer` ranks peers by their self-reported `start_height` (`peer_pool.rs:1142-1162`). A peer claiming `i32::MAX` is always the sync peer. It can drip one valid header per batch: short batches are accepted and the same peer is asked again, stretching first sync from hours to days.

### Peer chatter starves the loop

`handle_inv` sets `new_block_announced` for any unknown block hash (`sync.rs:4054`). The monitor loop breaks out at `3136`, before:

- `drain_relay_queue` (`3142`), which is the only place own transactions are sent;
- inbound accepts;
- the 30 s maintenance.

`last_maintain` is also reset each time the monitor loop is re-entered. **Attack:** one peer sends `inv(Block(random))` every ~500 ms. Header sync keeps working, so nothing looks wrong, but own transactions never leave the phone, and rebroadcast, `expire_old` and inbound accepts never run.

### Unbounded request work

- `handle_getheaders` (`sync.rs:3934`) has no locator cap; Core's is 101. About 125k hashes means about 125k SQLite lookups per message.
- `handle_inv` does up to 50k SQLite lookups per message.
- BIP35 `mempool` is answered to any peer, unchunked, and can exceed 50k inv entries (`sync.rs:3788-3808`).

### Wallet API server

`wallet_rpc.rs:97-123`: `read_line` reads the whole line before checking its length, so memory is unbounded before authentication. The server is single-threaded, so one slow client pins it (slowloris).

## Proposed fix

### 1. Deadlines on every peer operation

- **Writes:** `set_write_timeout` on TCP. Wrap Arti writes and flushes in `tokio::time::timeout`. A write timeout drops the peer.
- **Messages:** an absolute deadline per message (header plus payload), with a minimum byte rate once the header is in. Never report "no message" after bytes were consumed. Keep a per-peer partial-frame buffer, or switch to the full deadline once the first byte arrives.
- **Handshake:** an overall deadline of about 10–20 s, independent of per-read timeouts.
- **Requests:** a per-request deadline for `getheaders` and `getdata` in the main loop, as wakes already have.

### 2. Inbound off the sync thread

Accept inbound peers and complete their handshakes in the tokio accept task. Hand only finished, version-checked peers to the sync thread.

### 3. Cap what one request costs us

| Request | Limit |
|---|---|
| `getdata` | at most 1000 items per message (Core). Serve incrementally with back-pressure, check `stop` between items, and count blocks served per peer per interval. |
| `getheaders` | locator capped at 101 entries; more means disconnect. |
| `inv` | per-message cap and per-peer rate. Unknown-block announcements that never become headers cost the peer score. |
| BIP35 `mempool` | answer only peers we chose to serve, in chunks, rate-limited (or not at all; Core gates it behind a permission). |
| Wallet RPC | bounded reader (`take()`) before parsing, request-size cap before auth, read/write timeouts, one connection can't block others. |

### 4. Keep the loop live

- Relay draining, inbound accepts and maintenance run on their own timers, so a block announcement can't skip them.
- Pick the sync peer by demonstrated work, not claimed height.
- A batch of fewer than 2000 headers means "this peer has no more"; rotate peers.
- Add a headers-sync stall timeout like Core's: penalize and drop a peer whose header download falls below a minimum rate.

## Files touched

| File | Action |
|---|---|
| `hercules-core/src/p2p.rs` | Write timeouts; per-message and handshake deadlines; partial-frame buffer in `poll_message` |
| `hercules-core/src/tor.rs` | Timeouts on `TorStream` writes/flushes; inbound handshake in the accept task |
| `hercules-core/src/sync.rs` | Request deadlines; monitor-loop timers; getdata/getheaders/inv/mempool caps; sync-peer choice and stall timeout |
| `hercules-core/src/peer_pool.rs` | `best_peer` by demonstrated work; per-peer serve accounting |
| `hercules-core/src/wallet_rpc.rs` | Bounded reader, size cap before auth, timeouts |
| `hercules-core/src/testkit/mock_peer.rs` | Trickle, non-reading, inflated-height and flood behaviors |

## Dependencies

- **027** test harness (mock peers).
- The `tests/network-app` PR from the 2026-10-28 test pass adds reproducer tests for most of these, marked `#[ignore = "BUG: ..."]`. Un-ignoring them is part of this ticket's definition of done.

## Estimated effort

4–5 days: deadlines and partial frames 1.5 days, inbound off-thread 1 day, request caps 1 day, loop timers and sync-peer choice 1 day, tests throughout.

## Verification

All through the 027 harness:

- **Non-reading peer:** `getdata` for the tip ×1000, never reads. `stop` is honored within N s, and the next `wake_catch_up` is not `Busy`.
- **Trickle:** a 4 MB-length header, then one byte at a time, during handshake, `getheaders` and `getdata`. The peer is dropped and sync moves on; a wake returns within budget.
- **Inbound silent/trickling stream:** the monitor loop keeps servicing other peers.
- **Split message:** header, 150 ms pause, payload. The message is delivered and the peer kept.
- **Inv spam plus own tx:** with `inv(Block(random))` every 500 ms, an honest mock still receives our own tx `inv` within N s.
- **Inflated height:** the tallest peer returns one header per batch; the node switches sync peer.
- **`getheaders` with 100k locator hashes:** disconnect, bounded work.
- **Wallet RPC:** an oversized line is rejected before allocation; a trickling client doesn't block a second client.
- Full suite stable under load (`--test-threads` high), several runs.

## Open questions

- **Serve BIP35 `mempool` at all?** Recommendation: no. Nothing in our product needs it, and it reveals our mempool.
- **Upload budget on cellular.** Should serving blocks be off entirely on metered networks? Recommendation: yes, gate serving on `NetworkPolicy`'s unmetered state (needs a Swift → Rust signal).

## Roadmap position

**First** in the pre-wallet hardening block: **049 → 050 → 053 → 054 → 052 → 025**, then 035. Wallet sends, rebroadcasts and wake-driven "payment received" all assume the sync loop is alive.
