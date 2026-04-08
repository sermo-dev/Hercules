# Ticket 013: Live Activity, Widget, and Cellular Data Policy

## Summary

Three coupled iOS surfaces that share a single state model and ship in three independently-shippable phases:

1. **Cellular Data Policy (Phase 1)** — single global "Use Cellular Data" toggle (default OFF), `NWPathMonitor`-based detection that honors `isExpensive` and `isConstrained`, three-state cellular icon on the main app screen, and a gate in the silent-push wake handler that pauses block validation on metered networks.
2. **Home/Lock Screen Widget (Phase 2)** — persistent glance surface showing block height, time-since-last-block (auto-updating), idle/awake dot, last-known peer count.
3. **Live Activity + Dynamic Island (Phase 3)** — transient per-wake activity that animates the node's brief moment of consciousness: connecting → headers → block → validating → done.

The three phases share an App Group container and a JSON state file, so once Phase 1 lands the rest is largely additive UI surfaces over the same state.

## Background

- The push-wake validation path (`NotificationManager.handleSilentPush` → `HerculesNode.validateLatestBlock`) is currently unguarded by network type. On cellular it will happily fetch ~2 MB per block (`sync.rs:1740-1862`, single peer, full block — no BIP152 yet).
- Steady-state cellular cost: ~290 MB/day → ~8–9 GB/month, enough to chew through a typical US plan in days.
- Snapshot download is already gated to Wi-Fi via `SnapshotDownloader.swift:57` (`allowsCellularAccess = false`). This ticket extends that pattern to a global setting and applies it to push-wake validation.
- iOS does not allow third-party apps to add icons to the system status bar (per Apple HIG, reserved area). The cellular state must live inside the app's own UI surface.
- Hercules has no Widget extension and no Live Activity today.

## Design

### Phase 1 — Cellular Data Policy

#### The setting

- New toggle in `SettingsView`, in a new "Network" card sitting above the existing "Validation Mode" card:
  - **Label**: "Use Cellular Data"
  - **Subtitle**: "Allow Hercules to validate blocks over cellular and Personal Hotspot. May use ~9 GB/month if always on cellular."
  - **Default**: OFF
  - **Storage**: `UserDefaults.standard.bool(forKey: "useCellularData")`
- One global toggle. Snapshot download remains hard-gated to Wi-Fi regardless of this setting (8 GB on cellular is qualitatively different and never reasonable as a default).

#### The detector

New file `HerculesApp/HerculesApp/NetworkPolicy.swift`:

- Wraps `NWPathMonitor` from the `Network` framework on a background queue
- `ObservableObject` with `@Published` properties:
  - `pathStatus: NWPath.Status`
  - `isExpensive: Bool`
  - `isConstrained: Bool`
  - `isMetered: Bool` — derived `isExpensive || isConstrained`
- Singleton (`NetworkPolicy.shared`) so the wake handler and the SwiftUI views read the same instance
- Critically: `isExpensive` is true on cellular **and** Personal Hotspot (which appears as Wi-Fi but bills against cellular). `isConstrained` is true when the user has enabled iOS Low Data Mode for the current network. Treating both as "metered" honors Apple's guidance and avoids surprise bills via tethering.

#### The gate

In `NotificationManager.handleSilentPush`, before calling `node.validateLatestBlock(...)`:

```
let policy = NetworkPolicy.shared
let cellularAllowed = UserDefaults.standard.bool(forKey: "useCellularData")
if policy.isMetered && !cellularAllowed {
    // log "skipped due to network policy"
    // record a "paused" entry in NotificationHistory so the user sees it
    // do NOT open peer connections, do NOT spend wake budget
    return
}
```

Snapshot download: extend `SnapshotDownloader` to refuse to start when `policy.isMetered` is true regardless of the toggle (the toggle does not relax the snapshot rule).

#### The icon (main app screen)

Three states, rendered as a small badge in the top-right of the node status header in `ContentView`:

| State | Trigger | Icon | On tap |
|---|---|---|---|
| Normal | `!isMetered` | (nothing) | — |
| Yellow | `isMetered && cellularAllowed` | `cellularbars` in `Theme.warning` | Popover: "Hercules is using cellular data. ~2 MB per block, ~290 MB/day if always on cellular. Tap Settings to disable." |
| Red | `isMetered && !cellularAllowed` | `wifi.exclamationmark` in `Theme.error` | Popover: "Block validation paused — connect to Wi-Fi, or enable Use Cellular Data in Settings." Two buttons: **Open Settings** (in-app), **Wi-Fi Settings** (deep link to `App-Prefs:WIFI`). |

The icon is reactive — `NetworkPolicy.shared` is observed via `@StateObject`/`@ObservedObject` in `ContentView` so flips happen instantly when the user toggles airplane mode, switches networks, etc.

#### Phase 1 footprint

- `NetworkPolicy.swift` (~80 lines)
- `SettingsView.swift`: new card (~50 lines)
- `ContentView.swift`: icon + popover (~60 lines)
- `NotificationManager.swift`: gate at the start of `handleSilentPush` (~20 lines)
- `SnapshotDownloader.swift`: respect the new detector (~10 lines, mostly removing the hardcoded `false`)
- No Rust changes, no new targets, no new entitlements.

### Phase 2 — Widget

#### Target setup

- Add a new Widget Extension target: `HerculesWidget`
- Add an App Group entitlement to **both** the main app target and the widget target: `group.com.hercules.app`
- Shared state file: `node_state.json` in the App Group container

#### Shared state model

```swift
struct NodeWidgetState: Codable {
    let blockHeight: UInt32
    let blockHash: String
    let lastBlockTime: Date     // when this block was validated
    let peerCount: UInt32       // last-known, may be stale
    let isAwake: Bool           // true during a push wake
    let isPaused: Bool          // true when blocked by cellular policy
    let updatedAt: Date         // when this state was written
}
```

The main app writes this file at every meaningful state change: wake start, wake end, validation success, validation failure, paused-by-policy, network state change.

After writing, call `WidgetCenter.shared.reloadAllTimelines()` to nudge the OS to rebuild the widget render. Subject to WidgetKit's reload budget (~40-70/day) — measure and back off if exceeded.

#### Widget families

- **Small (square)**: block height (big), time-since-last-block as `Text(_:style:.relative)` (auto-updates without needing app code), idle/awake dot
- **Medium (rectangle)**: adds peer count + cellular state + truncated block hash
- **Lock Screen circular**: just the dot
- **Lock Screen rectangular**: `⛓ 887123 · 4m ago`
- **Lock Screen inline**: `⛓ 887123`

The time-since field is the killer feature — `Text(_:style:.relative)` is rendered by the OS and ticks forward without any app process running. Anchor only changes when a new block arrives.

### Phase 3 — Live Activity + Dynamic Island

#### Activity attributes

```swift
struct NodeActivityAttributes: ActivityAttributes {
    public struct ContentState: Codable, Hashable {
        var blockHeight: UInt32
        var phase: WakePhase
        var peerCount: UInt32
        var startedAt: Date
    }
    var wakeId: UUID
}

enum WakePhase: String, Codable {
    case connecting, headers, block, validating, done, failed
}
```

#### Lifecycle

- **Started** at the very beginning of `handleSilentPush` via `Activity<NodeActivityAttributes>.request(...)`
- Updated at each phase transition via `activity.update(state:)`
- **Ended** at the end of the wake via `activity.end(...)` after a brief lingering display (~2 s on `.done`)
- One short-lived activity per wake (~25 s max). Decided against a long-lived 8-hour activity because (a) the persistent surface is the Phase 2 Widget, (b) short activities don't need restart logic, (c) a stuck "validating" indicator after a failed end would be embarrassing.

#### Dynamic Island compact view (24×24 pt each side)

- **Left of camera**: phase icon
  - `.connecting` → `network` with `.symbolEffect(.pulse)`
  - `.headers` → `arrow.down.doc`
  - `.block` → `cube` with `.symbolEffect(.rotate)`
  - `.validating` → `checkmark.shield` with `.symbolEffect(.pulse)`
  - `.done` → `checkmark.circle.fill` (briefly)
  - `.failed` → `xmark.octagon` (briefly)
- **Right of camera**: block height (`887123` — 6 digits fits)

#### Dynamic Island expanded view (long-press)

- Header: "Validating block 887123"
- Center: 5-dot phase indicator
- Footer: "1 of 8 peers · 4s elapsed"

#### Lock Screen banner

Same widget code, larger layout. iPhone 13 / non-Pro models see this in place of Dynamic Island.

#### Rust → Swift phase callback

`validate_latest_block` currently returns when done. To drive the activity through phases, add a callback to the UDL:

```
callback interface WakeProgressCallback {
    void on_phase(WakePhase phase, u32 peer_count);
};
```

And `sync.rs::validate_latest_block` fires the callback at: connect → headers received → block received → validation start → done. Swift bridges these to `activity.update(...)`.

This is the only Rust change in the whole ticket and it's small (~30 lines in `sync.rs` + UDL definition).

## Phasing summary

| Phase | Surface | Lines (rough) | New target | Rust changes | Independently shippable? |
|---|---|---|---|---|---|
| 1 | Cellular policy | ~220 Swift | No | No | **Yes** — solves the wifi/data concern alone |
| 2 | Widget | ~500 Swift | Yes (Widget Extension) | No | Yes — needs Phase 1's shared state writer |
| 3 | Live Activity | ~400 Swift + 30 Rust | Activity widget within Phase 2 target | Yes (phase callback) | Yes — needs Phase 2's shared state |

Recommended order: 1 → 2 → 3. Phase 1 ships standalone and addresses the most pressing concern (cellular bill safety). Phase 2 adds the persistent glance. Phase 3 adds the magic moment.

## Verification

**Phase 1**:
- Toggle off, Wi-Fi: normal operation, no icon
- Toggle off, switch to cellular: icon turns red, push-wake validation skipped, log shows "skipped due to network policy", history records a "paused" entry
- Toggle off, on Personal Hotspot: also red (`isExpensive` = true even though interface is Wi-Fi-like)
- Toggle off, on Wi-Fi with iOS Low Data Mode enabled: also red (`isConstrained` = true)
- Toggle on, on cellular: icon turns yellow, validation proceeds, history records normal entry
- Snapshot download: hard-blocked on cellular regardless of toggle

**Phase 2**:
- Add widget to Home Screen, observe block height matches main app
- Trigger a push, observe widget reloads within ~30 seconds
- Force-quit app, observe widget still shows last-known state and the time-since timer continues advancing on its own
- iPhone with no Dynamic Island: same widget renders correctly

**Phase 3**:
- Trigger a push wake on iPhone 14 Pro+, observe Dynamic Island appears with phase swirl
- Long-press to expand, see phases progressing
- Wake completes, activity dismisses after brief `.done` display
- Pre-Pro iPhone: Lock Screen banner appears in place of Dynamic Island, same content

## Dependencies

- iOS 16.1+ for ActivityKit (Phase 3 only)
- iOS 14+ for WidgetKit (Phase 2)
- App Group entitlement (Phase 2+) — needs provisioning profile update
- New Widget Extension target (Phase 2+)
- **Ticket 015** (offline catch-up) is a follow-on that builds on Phase 1's gating logic

## Open questions

- **Widget reload budget**: WidgetKit gives apps ~40-70 timeline reloads per day. Per-block reloads (~144/day) will exceed this. Mitigation: reload only when state actually changes, accept some staleness, and let the time-since field carry the perceived freshness. Worth measuring early.
- **Live Activity update budget vs. APNs activity push**: in-wake updates from app code are unlimited, so phase transitions during a 25 s wake are fine. We only need APNs `activity` push if we want updates while the app isn't already running, which we don't for this design (the activity *is* the wake).
- **Stale peer count honesty**: widget shows last-known peer count, which may be 10 minutes old. Label it explicitly ("8 peers · last sync 4m ago"), or just show "8" and trust the time-since-block field to imply staleness? Recommendation: just "8", since the time-since field is right next to it.
- **Snapshot toggle override**: should there be *any* path to download the snapshot on cellular, even with explicit double-confirmation? Recommendation: no. 8 GB on cellular is never the right default and the friction protects users. A determined user can always toggle wifi back on.
