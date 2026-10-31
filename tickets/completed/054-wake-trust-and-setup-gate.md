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

### 4. When the app is open, sync from peers directly (owner request, 2026-10-30)

Today a push that arrives while a foreground sync is running is already skipped (`NodeHost.admitWake` → `.foregroundActive`). But foreground sync starts only when the user taps Start, or restarts after a wake stopped it in the same process (`ContentView.swift:161-167`, `resumeSyncWhenActive`). After any relaunch or jetsam, an open app sits idle, and new blocks arrive only through push wakes.

- **Persist "sync wanted".** When the node is set up (`WakeGate`: mode chosen, snapshot loaded or genesis mode, policy allows), opening the app starts the foreground sync automatically. The Start button becomes Pause/Resume, and a user Pause is remembered.
- **While foreground sync runs, pushes and refreshes are no-ops** (already true), and the app doesn't depend on the relay at all. The node follows the tip through its own peers and `inv` announcements.
- **On backgrounding**, foreground sync stops as today, and pushes take over.
- The relay is then only the background trigger. Blocks always come from peers in both cases; the relay never supplies chain data.

### 5. A Swift unit test target

There is no XCTest target; `Tools/NodeHostScenarios` is a swiftc script that CI now runs (PR #30). Add a `HerculesAppTests` target (xcodegen `project.yml`) and run it in CI's simulator job:

- `WakeGate`: the full decision table for push, refresh and processing.
- `NetworkPolicy`: with a fake monitor, `afterFirstPath` timeout vs notify, with the body running exactly once.
- `SnapshotDownloader`: session flags match the policy; the `didCompleteWithError` cases (user cancel, system cancel with resume data, transient error, stale task, 206).
- Relay registration state machine, with an injected `URLSession`: enable/disable, `unregisterPending`, 403, 429, URL change, re-enable during unregister.
- `NotificationHistory` / `StoragePaths` / auto-start "sync wanted" persistence.

Move the NodeHostScenarios checks into it over time.

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
| `HerculesApp/project.yml`, new `HerculesAppTests/` | XCTest target |
| `.github/workflows/ci.yml` | Run the XCTest target in the simulator job |

## Dependencies

- **049**: `best_peer` choice and connect deadlines.
- **050**: the activation `best_block` check.
- **052**: onion netgroup grouping.
- **016 / 028**: the cross-check and fanout this enforces.

## Estimated effort

4 days:
- wake agreement and fanout: 1.5 days
- auto-start foreground sync: 0.5 day
- XCTest target and first tests: 0.5 day (it grows with later tickets)
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

## Status (2026-10-31)

Merged in PR #34 (`60afe18`). A wake needs two independent agreeing peers, or one when the chain has minimum work and the tip is at most an hour old (`WakeOutcome::Unconfirmed`, `CatchUpStatus.tip_confirmed`); a second opinion on another branch leaves the tip unconfirmed; wakes dial 3 peers in parallel within an 8 s budget; `NodeMode` is stored, so AssumeUTXO mode never validates without the snapshot (`awaiting_snapshot`); one Swift `WakeGate`, auto-start sync, the snapshot moved to Application Support, and the `HerculesAppTests` XCTest target.

Owner decisions taken as recommended: withholding during a wake is a selection demerit only (`PeerPool::deprioritize`, not persisted, never toward a ban; test `a_peer_with_no_new_headers_during_a_wake_keeps_its_score`); the one-hour single-peer rule stays; installs the old bug converted are recorded as genesis (Settings shows the mode); background catch-up keeps running with notifications off; header-only pushes while the snapshot is pending.

**Follow-ups (059):** Switch & Wipe deleting pending own txs; a one-time in-app notice for installs recorded as genesis because the old bug converted them (decided, not yet built).
