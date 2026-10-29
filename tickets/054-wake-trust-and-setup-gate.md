# Ticket 054: Wakes — Don't Trust One Peer, Don't Run Before Setup

## Summary

Two wake-path problems:

1. **A wake can report "caught up" on one peer's word.** `catch_up_blocks_in` asks a single peer, chosen by its claimed height. If that peer returns no headers, the wake reports `caught_up = true` with no cross-check and no penalty. Over Tor the first connect pass usually yields only one peer, and outside strict mode a lone peer's batch is accepted without a witness. A peer that withholds new blocks (the ticket 016 threat) gets a green "caught up" on every push wake.
2. **Wakes run before the node is set up.** Push and refresh wakes don't check that the user has chosen a validation mode or that the AssumeUTXO snapshot is loaded; only the processing task does.
   - If the user picked AssumeUTXO but the snapshot never landed, each push syncs a batch of headers and posts "Block #0 Header Verified" with sound.
   - Once headers reach the anchor, `activate_pending_snapshot` returns true for a floor of 0, and wakes start validating from genesis.
   - From then on `needs_snapshot()` is false, so the "AssumeUTXO" node is silently a weeks-long genesis sync; only a mode reset recovers it.

**Severity: High.** Item 1 undermines the eclipse protection (016) exactly where wallet confirmations will be shown (035/040). Item 2 silently converts a node into the wrong mode.

Found by the P2P and iOS reviewers (2026-10-28 team review of main @ 7732755).

## Background

Line numbers are at main 7732755.

### One peer decides the tip

`catch_up_blocks_in`, `sync.rs:4620-4672` and `4958`:

- The peer is `best_peer`, ranked by claimed height (`peer_pool.rs:1142-1162`).
- An empty `headers` reply: no cross-check, no penalty, `caught_up = true`, wake `Completed`.
- Any other error fails the whole wake, with no retry on another peer.
- The first connect pass is sequential and checks `REFILL_BUDGET` (2 s) only between attempts (`peer_pool.rs:951`). Over Tor that usually leaves one peer, so `cross_check_peer` finds no witness. Outside strict mode the batch is accepted (`sync.rs:2341-2352`).
- Addrman order is deterministic (oldest known-good first), so the same peer tends to win.

Ticket 028 called for a fanout of 2–3 peers in wakes; the code doesn't reach it in practice.

### No setup gate on push and refresh

- **Push:** `NotificationManager.swift:313-449`.
- **Refresh:** `NotificationManager.swift:954-1001`.
- **Processing** (gated): `1086` and `1227-1232` (`nodeIsSetUp`).
- **App side:** `ContentView.swift:506`.
- **Rust:** `sync.rs:1020-1026` (activation with floor 0), `1193-1204` (`needs_snapshot`) and `4778` (catch-up).

The same happens if notifications were enabled before any mode was chosen.

### Notifications-off isn't honored in a warm process

`handleSilentPush` never checks `isEnabled` (`NotificationManager.swift:292-310`, `AppDelegate.swift:76`). If unregistering fails (offline, 429, 5xx), it is retried only at launch. While the process stays warm, every push still opens Tor and P2P, validates, and posts sound notifications the user turned off.

## Proposed fix

### 1. Wakes need agreement

- **Peer count:** wakes connect to 2–3 peers in parallel within the connect budget (028's intended fanout), from different netgroups. With 052, all onions count as one netgroup.
- **Peer choice:** pick by demonstrated work and diversity, not claimed height. 049 changes `best_peer`.
- **Empty replies need a second opinion:** if the sync peer returns no headers but another peer is taller (claims more), ask that peer. `caught_up` means "at least two peers agree there's nothing new", or "one peer, and we're above min chain work and the tip is recent". Otherwise the wake reports `Unconfirmed` (new state), not `Completed`.
- **Retry:** a failure from one peer retries the next peer within the budget instead of failing the wake.
- **Penalty:** a peer whose claimed height is beaten by headers from another peer, after it returned none, loses score (the 016 withholding signal).
- **App:** shows "Couldn't confirm the latest block" (calm, not red) for `Unconfirmed`, and stops claiming a fresh "caught up".

### 2. One wake gate, enforced in Rust

- **Persist the mode:** persist the validation mode and the snapshot-pending state in the node at first open (the header store's meta). Rust is then the source of truth, not `UserDefaults`.
- **Header-only wakes:** while the mode is AssumeUTXO and no snapshot is loaded, `catch_up_blocks_in` / `wake_catch_up` sync headers only and never validate blocks.
- **Activation:** `activate_pending_snapshot` never activates with a floor of 0 in AssumeUTXO mode. Combined with 050's `best_block` check.
- **Notifications:** wake notifications in that state say "Headers synced — finish setup to validate", once, without sound. They never say "Block #0".
- **Swift:** one shared `WakeGate` decision used by push, refresh and processing:
  - mode chosen;
  - snapshot state;
  - `NetworkPolicy`;
  - notifications `isEnabled`;
  - storage floor.
  It is a pure function, so it can be unit-tested.
- **Notifications off:** `guard isEnabled` at the top of `handleSilentPush` (complete with `.noData` and retry the unregister). Call `unregisterForRemoteNotifications()` on disable.

### 3. Related small iOS fixes (same files)

- **Snapshot download settings** (`SnapshotDownloader.swift:66-75`): set `allowsExpensiveNetworkAccess` and `allowsConstrainedNetworkAccess` from `NetworkPolicy`, not just `allowsCellularAccess`. When the policy changes mid-download, cancel with resume data and resume on a session whose config matches (background configs are immutable).
- **Snapshot file location:** move the completed snapshot out of `Library/Caches` (`SnapshotDownloader.swift:104-107`) to Application Support with `isExcludedFromBackup`, and delete it after import. iOS purges Caches under storage pressure, which this flow causes.
- **Quieter block notifications:** use the `.passive` interruption level with no sound, or replace one notification in place (`NotificationManager.swift:722-731`, `914`). At ~144 a day they would drown out wallet payment alerts.

## Files touched

| File | Action |
|---|---|
| `hercules-core/src/sync.rs` | Wake fanout, agreement rule, retry, withholding penalty; header-only mode; activation guard |
| `hercules-core/src/peer_pool.rs` | Parallel connects within budget; diverse selection |
| `hercules-core/src/store.rs` | Persisted mode and snapshot-pending state |
| `hercules-core/src/lib.rs`, `hercules.udl` | `Unconfirmed` wake state; mode at open |
| `HerculesApp/HerculesApp/NotificationManager.swift` | Shared `WakeGate`; `isEnabled` guard; quieter notifications; new states |
| `HerculesApp/HerculesApp/SnapshotDownloader.swift` | Network flags; file location |
| `HerculesApp/HerculesApp/ContentView.swift`, `NodeHost.swift` | Pass the mode at open |
| `Tools/NodeHostScenarios` | `WakeGate` scenarios |

## Dependencies

- **049**: `best_peer` choice and connect deadlines.
- **050**: the activation `best_block` check.
- **052**: onion netgroup grouping.
- **016 / 028**: the cross-check and fanout this enforces.

## Estimated effort

3 days:
- wake agreement and fanout: 1.5 days
- Rust gate and persisted mode: 0.5 day
- Swift gate and notification fixes: 0.5 day
- downloader fixes: 0.5 day

## Verification

- **Inflated height:** a wake with an inflated-height peer plus `WithholdHeaders` doesn't report `caught_up`; it reports `Unconfirmed`, and the withholding peer loses score once another peer shows new headers.
- **Single peer:** a wake where only one peer connects, below min chain work, doesn't report `caught_up`.
- **Retry:** a wake whose first peer errors succeeds via the second within budget.
- **Snapshot pending:** `wake_catch_up` on a snapshot-pending store with headers past the anchor validates zero blocks, and `needs_snapshot()` stays true. A 027 harness test; the `tests/network-app` PR may add it ignored.
- **`WakeGate` table test:** every combination of mode, snapshot, policy, enabled and storage, for push, refresh and processing.
- **Device checks:**
  - join a Personal Hotspot mid-download with cellular off; the download pauses;
  - toggle cellular mid-download; the session follows.

## Roadmap position

Fourth in the pre-wallet hardening block: **049 → 050 → 053 → 054 → 052 → 025**. It must land before 035/040 show confirmations or "payment received" from wake results.
