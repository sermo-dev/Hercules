# Ticket 028: Fit Background Wakes in the iOS Budget + One Node Per Process

## Summary

Every background wake (silent push or `BGAppRefreshTask`) builds a fresh `HerculesNode`. When Tor is configured, that constructor blocks on Tor bootstrap (5–15 s) **before** the 25-second block budget even starts. The real wall-clock time of a wake can therefore exceed the ~30 s iOS gives a silent push. iOS punishes that: the process is killed, and future background launches are throttled. That breaks the core promise that the phone validates every block as it lands.

The same code path can also open a **second** node inside a process where the foreground node is already running. That means a second Tor client and a second set of handles on the same LMDB and SQLite files.

This ticket:
1. Measures where wake time actually goes.
2. Makes one process-wide node host the only owner of `HerculesNode`.
3. Starts the deadline at wake receipt and passes it into Rust, so transport bootstrap counts against it.
4. Adds real cancellation and expiration handling.

## Amendment (2026-10-24, from the PR #20 / #21 reviews)

- **The second node is worse than assumed.** The push handler has no "foreground node running" check (`NotificationManager.swift:342`), and silent pushes are delivered while the app is in the foreground too. heed 0.20.5 does *not* refuse the second open: its process-global `OPENED_ENV` returns the same env when the options match, and fails with `BadOpenOptions` only when they differ (e.g. map size, see 030). So two `HeaderSync`s can apply blocks to the same UTXO set concurrently.
- **033 adds an open-time step that assumes no block is mid-apply.** `HeaderSync::new` demotes own txs settled above `validated_height` (crash recovery). If a wake node opens while the foreground node sits between a block hook and `set_validated_height`, a confirmed own tx is wrongly put back to pending, and it later expires. The single-node host in this ticket removes the race; until then the window is a few milliseconds per block.

## Background

**Tor bootstrap blocks inside the constructor.** `hercules-core/src/lib.rs:303-330`: `HerculesNode::new(db_path, tor_data_dir)` calls `TorManager::bootstrap(&path)` and then `start_onion_service(8333)` synchronously. The doc comment at `lib.rs:306-307` says "This blocks during Tor bootstrap (~5-15 seconds)."

**Wake paths construct a new node every time, with Tor always on.**
- Silent push: `NotificationManager.swift:163-167` calls `HerculesNode(dbPath:torDataDir:)` then `catchUpBlocks(maxBlocks: 7, budgetSecs: 25)`. The comment says "leaving 5s margin within the 30s iOS window", but that margin ignores the constructor.
- The second push path, `NotificationManager.swift:245-248`, does the same.
- BG task: `NotificationManager.swift:409-415` does the same.
- `torDataDir()` (`NotificationManager.swift:461-464`) always returns a path, so Tor is never skipped.

**The BG task expiration handler is empty.** `NotificationManager.swift:407`: `task.expirationHandler = { /* Rust respects budget_secs */ }`. When iOS expires the task, nothing cancels the Rust work and nothing calls `setTaskCompleted`. Rust's `budget_secs` also doesn't cover the Tor bootstrap that came before it.

**BG task type differs from ticket 015.** Ticket 015 Approach B (`tickets/completed/015-offline-catch-up.md:60-84`) specified a `BGProcessingTask` for batched catch-up. The code registers and submits only a `BGAppRefreshTask` (`NotificationManager.swift:400`, `:445`). That task type has a much shorter budget, and the Rust budget is hardcoded to 25 s regardless.

**Two nodes in one process.** The foreground app builds its own node at `ContentView.swift:339`. If a silent push or BG task arrives while that node is running, a second `HerculesNode` is constructed against the same paths. Each owns:
- `sync::HeaderSync`, which opens `hercules-headers.sqlite3`, `blocks.sqlite3`, `peers.sqlite3`, and LMDB `utxo-lmdb` (`sync.rs:374-397`, via `derive_sibling_path`).
- A separate Arti client over the same `Documents/tor` state directory.

heed (`Cargo.toml:19`, 0.20) is believed to refuse a second `Env` open of the same path in one process. **Unverified — confirm on device.** SQLite has WAL enabled (`store.rs:23`, `block_store.rs:28`, `peer_store.rs:58`) but no `busy_timeout`, so concurrent writers get `SQLITE_BUSY` immediately.

**Wake timing was never measured.** Ticket 016 said not to change outbound fanout until wake timings were measured. `MAX_OUTBOUND` is 12 (`peer_pool.rs:15`), justified as eclipse resistance "per wake", and no wake-phase instrumentation exists.

## Proposed fix

### 1. Instrument wake phases first
Record monotonic timestamps for each phase:
- wake received
- node ready (reused or constructed)
- transport ready (Tor bootstrapped / clearnet)
- first peer handshake
- headers checked
- block(s) downloaded
- validated
- completion handler called

Store them on `BlockNotificationRecord` and show them in Settings → Notification history. Ship this alone first, so every later change can be compared against real numbers on hardware.

### 2. One process-wide node host
Add a Swift `NodeHost` (an actor, or a singleton with a serial queue) that is the **only** code allowed to construct a `HerculesNode`.
- Foreground (`ContentView`) and every wake path ask `NodeHost` for the node.
- If the process is still alive from an earlier wake or foreground session, the existing node and its warm transport are reused. iOS usually suspends rather than kills a process, so reuse will be common.
- If foreground sync is running when a wake arrives, the wake doesn't build anything. It records "foreground active" and completes immediately, because foreground is already validating.

Add `PRAGMA busy_timeout` (e.g. 2 s) to all three SQLite stores as defense in depth.

### 3. The deadline starts at wake receipt
Capture `wakeStart` at the top of `handleSilentPush` and `handleCatchUpTask`. Pass an absolute deadline (or remaining milliseconds) into Rust, and split node construction from transport start (`HerculesNode::new` must not block on the network). Transport bootstrap then counts against the same deadline as block work. If transport isn't ready with enough budget left for one block (a configurable floor, e.g. 8 s), skip the block fetch and record "transport slow".

### 4. Real cancellation
- Add `HerculesNode::cancel()` over FFI, setting an `AtomicBool`.
- `catch_up_blocks`, `validate_latest_block`, and the peer-connect loops check the flag between steps and return a partial `CatchUpStatus`.
- The BG task `expirationHandler` calls `cancel()`, then `setTaskCompleted(success: false)` exactly once (guard with a flag), then reschedules.
- The silent-push path gets a watchdog timer at about 27 s after receipt. It calls `cancel()` and invokes `completionHandler` itself if Rust hasn't returned. The handler must be called exactly once.

### 5. Wakes do the minimum
A wake does a tip header check (016) and fetches and validates new blocks, and nothing else. No address discovery, no addrman refill beyond what's needed, no self-advertisement, no mempool work. Those belong to foreground or (later) relay shifts (045).

### 6. Small wake peer set
Wake fanout is its own constant (2–3 peers: one for block download, one or two for the 016 tip cross-check), independent of `MAX_OUTBOUND`. Keep `MAX_OUTBOUND = 12` for foreground, or revisit it once step 1 produces data.

### 7. BG task type
Use `BGProcessingTask` for large backlogs, as 015 Phase 2 intended (with `requiresExternalPower` decided there). Keep `BGAppRefreshTask` for short top-ups. Each passes its own budget into Rust instead of the hardcoded 25.

### Relation to 029 and 030
- Ticket 029 (clearnet default) takes Tor bootstrap off the critical path for most users. This ticket must still be correct for Tor-mode users.
- For Tor mode, Arti's state and cache must persist between wakes and be readable while the phone is locked. That's a file-protection class issue in ticket 030. A cold Arti directory fetch is the slow case.

### Follow-up from ticket 022 review

`Peer::get_block` sets a per-read timeout of 120 s (clearnet) / 300 s (Tor) and `receive_block` reads up to 20 messages, so a slow-drip peer can hold one block request far past the ~30 s push window. Since 022, `fetch_requested_block` (sync.rs) may also retry a second peer. Make block download deadline-aware: pass the wake deadline down and clamp the read timeout to `min(download_timeout, deadline - now)`.

## Files touched

| File | Action |
|---|---|
| `HerculesApp/HerculesApp/NodeHost.swift` | **New** — sole owner of `HerculesNode`; reuse and foreground-coordination logic |
| `HerculesApp/HerculesApp/NotificationManager.swift` | Use `NodeHost`; `wakeStart` deadline; watchdog; real expiration handler; BGProcessingTask |
| `HerculesApp/HerculesApp/ContentView.swift` | Get the node from `NodeHost` instead of constructing one (`:339`) |
| `HerculesApp/HerculesApp/NotificationHistory.swift` | Add per-phase timings to `BlockNotificationRecord` |
| `HerculesApp/HerculesApp/SettingsView.swift` | Show wake timings in notification history |
| `HerculesApp/project.yml` | `BGTaskSchedulerPermittedIdentifiers` for the processing task |
| `hercules-core/src/lib.rs` | Split construct vs. start transport; `cancel()`; deadline-based APIs |
| `hercules-core/src/sync.rs` | Check cancel flag and deadline in catch-up, validate-latest, connect loops |
| `hercules-core/src/peer_pool.rs` | Wake-specific peer count |
| `hercules-core/src/store.rs`, `block_store.rs`, `peer_store.rs` | `busy_timeout` |
| `hercules-core/src/hercules.udl` | Expose `cancel`, deadline params, phase timings |

## Dependencies

- **029** (clearnet default) makes the common case fast, but this ticket doesn't block on it.
- **030** (file protection classes) for Arti and chain state readable during locked wakes.
- **027** (mock peer harness) for testing cancellation and deadline behavior in Rust.

## Estimated effort

~4–6 days:
- instrumentation: 0.5 day
- `NodeHost`: 1.5 days
- deadline plumbing and transport split: 1 day
- cancellation and watchdog: 1 day
- BGProcessingTask: 0.5 day
- on-device measurement: 1 day

## Verification

- On a physical iPhone, send 20 consecutive silent pushes in Tor mode and in clearnet mode. Record the per-phase timings. 100% of wakes must call `completionHandler` within 28 s of receipt.
- Force a slow transport (block Tor) and confirm the wake records "transport slow" and completes before the watchdog.
- Fire a push while the app is in the foreground and syncing. No second node is constructed (log assertion) and the wake completes immediately.
- Let a `BGProcessingTask` expire mid-catch-up. `cancel()` fires, `setTaskCompleted` is called once, and a new request is submitted.
- Wake twice within one process lifetime. The second wake reuses the node, and transport-ready time drops to about 0.
- Rust: unit tests for cancel-flag and deadline exit using the 027 mock peer.

## Open questions

- **Should the wake fanout ever go above 3?** The 016 cross-check wants peer diversity, but every extra handshake costs wake time. Decide with step 1 data.
- **Live Activity during wakes.** Ticket 031 flags that starting a Live Activity from a background push is probably not allowed. If so, the wake path should stop trying, which saves time.
- **Is reusing the node after a long suspension safe?** Sockets will be dead after suspension. `NodeHost` needs a cheap "reconnect transport" path, not a full reconstruct.

## Roadmap position

Tier 1 (platform reliability). Do it immediately after the Tier 0 safety tickets (022–024, 027). Wakes are how Hercules "validates every block", so wake reliability is a correctness property of the product, not polish.
