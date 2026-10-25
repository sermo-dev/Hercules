# Ticket 051: iOS Robustness Fixes

## Summary

A whole-repo review of `main` (after 028) found eight iOS-side problems. Most are small, but several hit the paths the product depends on: cold-launch wakes, the 8.8 GB snapshot download, and the multi-minute snapshot import. Each finding below was checked against the code before it was fixed. One finding (#8) turned out to be wrong and is recorded as such.

| # | Finding | Verdict |
|---|---|---|
| 1 | `NetworkPolicy` reports "offline" until its first main-queue hop | Confirmed, fixed |
| 2 | `startSync` stuck after a reset | Confirmed (different mechanism than reported), fixed |
| 3 | `SnapshotDownloader` drops resume data on a system cancel | Confirmed, fixed |
| 4 | No idle-timer or background-task cover during snapshot import | Confirmed, fixed |
| 5 | No `PrivacyInfo.xcprivacy` | Confirmed, fixed |
| 6 | `TARGETED_DEVICE_FAMILY = "1,2"` on an iPhone-only app | Confirmed, fixed |
| 7 | `BGProcessingTask` declared vs registered | No mismatch, but the README's processing task was never built; built it |
| 8 | Low-disk check uses `volumeAvailableCapacityKey` | **Wrong**, already correct; no change |

## Findings

### 1. NetworkPolicy reads "offline" on a cold launch

`NetworkPolicy.pathStatus` starts as `.requiresConnection`. It is only set from `pathUpdateHandler` through `DispatchQueue.main.async`, and `shouldValidate` reads that `@Published` copy. A silent push that cold-launches the app runs `handleSilentPush` on the main thread from `didFinishLaunching` → `didReceiveRemoteNotification`, before the main queue has run the monitor's first update. So `shouldValidate` is false, the wake is recorded as "Validation paused: metered network", and no block is validated, even on Wi-Fi. The BG refresh handler has the same race on its own queue.

**Fix.** The monitor queue writes the path into a lock-protected snapshot first. `shouldValidate`, `indicator` and `isMetered` read that snapshot. The `@Published` copies are still bounced to main for SwiftUI. A first-path latch lets callers wait a bounded time (`firstPathTimeout`, 1.5 s) for the first update:
- `waitForFirstPath()` blocks; for background threads (BG refresh, BG processing, the foreground session before the snapshot download).
- `afterFirstPath(_:)` is non-blocking for the main thread. The silent-push handler now runs its gates inside it. It runs inline when the path is already known (the common, warm case). The wait counts against the wake budget, which started at receipt.

### 2. `startSync` stuck after a reset

The reported cause was a flag left set by a timed-out reset. That is not quite it. `NodeHost.reset` clears `resetting` in a `defer`, on every path. The real bug is in `NodeViewModel`'s deferred start:

1. `startSync()` sets `isSyncRunning = true`. If a session thread is still in flight, it sets `startWhenSessionEnds` and returns.
2. When that thread ends, `sessionEnded` calls `startSync()` again.
3. Only the *active* session's cleanup resets `isSyncRunning`. A reset retires the session first (`retireActiveSession` nils `activeSession`), so a retired session's end never clears it. The deferred `startSync()` then hits `guard !isSyncRunning` and returns. No session runs, and the UI is stuck on "Connecting to Tor…" with the button disabled until relaunch.

This happens in two ways:
- **After a timed-out reset.** The retired session is often what held the node past the timeout. The user taps Start while it is still winding down.
- **After a successful reset.** Step 5's `startSync()` can be queued on main before the retired session's `sessionEnded` hop. The node reference drops when `runSession` returns, which is before that hop.

**Fix.** The deferred start clears `isSyncRunning` before calling `startSync()`, since `startSync` already set the UI flags when it deferred. It is skipped if a wake-preemption restart already launched a session. `retireActiveSession` drops any pending deferred start: a reset that succeeds starts sync itself, and one that fails leaves the node stopped.

### 3. SnapshotDownloader drops resume data on a system cancel

`urlSession(_:task:didCompleteWithError:)` returned early for every `NSURLErrorCancelled`, on the assumption that only `cancel()` (the user) cancels. iOS also cancels background-session tasks itself, for example when the user force-quits, background app refresh is turned off, or the system is low on resources (`NSURLErrorBackgroundTaskCancelledReasonKey`). Those cancels carry `NSURLSessionDownloadTaskResumeData`. That data was thrown away. Worse, `status` stayed `.downloading` and `activeTask` stayed set, so `awaitSnapshotDownload`'s waiter never fired. The foreground session thread then blocked forever, and with it every later `startSync` (see #2's deferred start).

A connectivity error with no fresh resume data also deleted the *previous* blob. One flaky reconnect therefore threw away hours of progress.

**Fix.** Kept small and local to the error path, so it merges cleanly with PR #27 (per-snapshot file names, `deleteLegacyFiles`, `isCurrent` guards):
- `cancel()` records which task the user cancelled. Only that task's `NSURLErrorCancelled` is ignored.
- Any other failure saves resume data when the error carries it, and always moves `status` to `.failed`, which releases the waiter.
- With no fresh resume data, the old blob is kept for connectivity errors (`notConnectedToInternet`, `networkConnectionLost`, `timedOut`, `cannotConnectToHost`, `cannotFindHost`, `dnsLookupFailed`, `internationalRoamingOff`, `dataNotAllowed`) and for a system cancel. It is deleted otherwise, for example when the blob itself was stale.
- Resume data is still discarded on user cancel (`cancel()`), on a bad HTTP status (`didFinishDownloadingTo`; PR #27 also deletes resume data there), and when the import rejects the file (`deleteDownloadedFile`).

### 4. Snapshot import has no idle-timer or background-task cover

The import is ~12 GB of LMDB writes and takes minutes. While it runs:
- the screen auto-locks, which backgrounds the app;
- a brief app switch suspends the import thread at once.

**Fix.** `LongTaskAssertion` (ContentView.swift) wraps `loadSnapshot`. It disables the idle timer and restores the previous value afterwards. It also holds a `beginBackgroundTask` so a short trip to the background doesn't freeze the import. All of its state is touched on the main thread. `endBackgroundTask` runs exactly once, whether the import finishes first or the expiration handler fires first. On expiration the import thread is simply suspended with the process: LMDB is crash-safe, and an aborted import's pages are reused (030).

### 5. No privacy manifest

There was no `PrivacyInfo.xcprivacy`, which App Store Connect requires for apps that use required-reason APIs. The app uses:

| Category | Where | Reason |
|---|---|---|
| `UserDefaults` | settings, relay registration markers, validation mode | `CA92.1` (app's own defaults) |
| File timestamp | `FileManager.attributesOfItem` (size / protection class); `stat`/`fstat` from Rust std, SQLite, LMDB | `C617.1` (files in the app container) |
| Disk space | `volumeAvailableCapacityForImportantUsageKey` (StorageGuard), shown in banners | `E174.1` (enough space to write), `85F4.1` (shown to the user) |
| System boot time | `mach_absolute_time` / `CLOCK_UPTIME_RAW` behind Rust `Instant` (wake budget, peer timeouts, Arti) | `35F9.1` (elapsed time between in-app events) |

No tracking, no tracking domains. No collected data types are declared: the relay receives an APNs token plus a random per-install secret, neither linked to identity nor used for tracking. See Open questions. The manifest goes into the app target's resources through `project.yml` (xcodegen picks it up from `HerculesApp/`). The widget calls none of these APIs, so it gets no manifest.

### 6. `TARGETED_DEVICE_FAMILY`

Both targets built as `"1,2"` (iPhone + iPad). The app target took that from xcodegen's default, and the widget set it explicitly. The README describes an iPhone-only product ("Turn your iPhone into…", "on the phone they already own") and never mentions iPad. **Fix:** `TARGETED_DEVICE_FAMILY: "1"` for both targets in `project.yml`, then regenerate.

### 7. BGProcessingTask

The reported mismatch isn't there. `BGTaskSchedulerPermittedIdentifiers` lists only `BGTASK_CATCHUP_ID`, which is registered (`AppDelegate`) as a `BGAppRefreshTask` and scheduled (`requestFollowUpWake`), and `UIBackgroundModes` has `fetch` (refresh) but not `processing`. Declaration and code agree.

What is missing is the processing task itself. The README's architecture box lists "BGProcessingTask: historical block validation". 015 Phase 2 specified it, and 046 folded it into 028. 028 §7 says to use it for large backlogs, but 028 shipped without it. The README's intent is to have one, so this ticket adds a minimal version:
- New identifier `BGTASK_PROCESSING_ID` (`$(BUNDLE_ID_PREFIX).processing`) in `Shared.xcconfig`, added to `BGTaskSchedulerPermittedIdentifiers` along with the `processing` background mode, and read through `AppIdentifiers.processingTaskID`.
- `AppDelegate` registers it. `NotificationManager.scheduleProcessingTask()` submits it with `requiresExternalPower = true` (015's recommendation) and `requiresNetworkConnectivity = true`. It is submitted when the app enters the background and when a wake ends still behind.
- `handleProcessingTask` waits for the first path and honors `NetworkPolicy` (no metered catch-up without opt-in) and the low-disk floor. It skips a node that hasn't picked a validation mode, or that is in AssumeUTXO mode and still needs its snapshot. Otherwise it runs wake catch-ups on the shared node in rounds (`WakeConfig.processingRoundMs` / `processingMaxBlocks`) until caught up, out of progress, or expired. Each round goes through `NodeHost.runWake`, so the 028 rules still hold: it yields to foreground sync and is cancelled by a reset. The expiration handler cancels the current round, completes the task once (`OnceGate`), and resubmits.

### 8. Low-disk check capacity key

**Not a bug.** `StorageGuard.availableBytes()` (StoragePaths.swift) already uses `volumeAvailableCapacityForImportantUsageKey`, and has since 030 (`ea543ef`). Every space check goes through it: the snapshot preflight, the import space watch, the low-disk pause, and the wake gates. No code uses `volumeAvailableCapacityKey`. No change.

## Also noticed (not fixed here)

- `SnapshotDownloader.start()` creates its task inside an async `getAllTasks` callback. A `cancel()` that lands between `start()` and that callback (a reset racing a just-started download) finds `activeTask == nil`, reports "cancelled", and the callback then starts the task anyway. The download carries on unowned. Closing this needs a generation check in `start()`, which overlaps with PR #27's `start()` changes, so it is left for after #27 merges.

## Files touched

| File | Action |
|---|---|
| `HerculesApp/HerculesApp/NetworkPolicy.swift` | Locked path snapshot, first-path latch, `waitForFirstPath` / `afterFirstPath` |
| `HerculesApp/HerculesApp/NotificationManager.swift` | Push gates after first path; refresh waits for path; BGProcessingTask handler + scheduling |
| `HerculesApp/HerculesApp/AppDelegate.swift` | Register processing task; schedule on entering background |
| `HerculesApp/HerculesApp/NodeHost.swift`, `WakeCoordination.swift` | `maxBlocks` per wake; processing-round config |
| `HerculesApp/HerculesApp/ContentView.swift` | Deferred-start fix; `LongTaskAssertion` around import; first-path wait before download |
| `HerculesApp/HerculesApp/SnapshotDownloader.swift` | Error/cancel path only |
| `HerculesApp/HerculesApp/AppIdentifiers.swift` | `processingTaskID` |
| `HerculesApp/HerculesApp/PrivacyInfo.xcprivacy` | **New** |
| `HerculesApp/project.yml`, `Config/Shared.xcconfig`, `HerculesApp/Info.plist`, `project.pbxproj` | Device family, processing task id + mode, manifest (regenerated) |

## Verification

- Cold launch from a silent push on Wi-Fi (kill the app, send a push): the wake validates rather than recording "Validation paused". The log shows the wake waited ≤ 1.5 s for the path.
- Start a snapshot download, then force-quit from the app switcher, or turn off Background App Refresh mid-download. Relaunch and tap Start: the download resumes (HTTP 206), the status card shows "retry will resume", and the session thread is released.
- Switch validation mode while a wake is running, so the reset times out. Then tap Start: sync starts once the old session ends. Repeat a successful switch 10× in a row: sync always restarts.
- During import, leave the phone untouched past the auto-lock interval: the screen stays on. Swipe home for ~10 s and back: the import progressed. After import, auto-lock works again.
- `xcrun` / App Store Connect validation reports no missing required-reason declarations.
- The app installs as iPhone-only (no iPad-native slot on an iPad).
- Debugger: `e -l objc -- (void)[[BGTaskScheduler sharedScheduler] _simulateLaunchForTaskWithIdentifier:@"dev.sermo.hercules.processing"]` runs a catch-up. Expiring it with `_simulateExpirationForTaskWithIdentifier:` completes the task once and resubmits.

## Open questions

- **Collected data types.** Does the relay's APNs token + install secret need a declaration under App Privacy (`NSPrivacyCollectedDataTypeDeviceID`, not linked, not tracking, purpose App Functionality)? Apple's guidance treats push tokens loosely. Decide before the first TestFlight upload (019 / 031).
- **Processing task with `requiresExternalPower = false`?** 015 recommended `true`. Revisit with on-device data on how often wakes leave a backlog.

## Roadmap position

Tier 1 (platform reliability), right after 028. #1 and #3 directly undermine "validates every block" and first-run setup, and #5 blocks App Store submission.
