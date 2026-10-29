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

If there is still no path when the push gate decides (no network, or no first path within the wait), the wake is recorded as a new `.noNetwork` source ("Validation skipped: no network connection", shown as "Offline") instead of the metered-network message.

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
- `cancel()` records the tasks the user cancelled (a set). A cancelled task's completion is ignored whatever its error code. If it ends with a network error instead of `NSURLErrorCancelled`, saving its resume data would undo the wipe that `cancel()` (or a reset) just did.
- Any other failure saves resume data when the error carries it and moves `status` to `.failed`, which releases the waiter. Only the task that is still `activeTask` clears it and fails the waiter, so a stale task's failure can't kill a newer download. `didFinishDownloadingTo` uses the same identity check, under the lock, for every `activeTask` clear. A stale task's resume data is kept only if nothing else is downloading, for example a task from the previous process reporting after relaunch.
- A resumed download finishes with **206** Partial Content. `didFinishDownloadingTo` accepted only 200, so the resume data kept above would have ended in "Server returned HTTP 206" and a deleted file. It now accepts `200 || 206` and deletes resume data on any other status. The change is textually identical to PR #27's (`ff36235`), so the two merge cleanly (checked with `git merge-tree`).
- With no fresh resume data, the old blob is kept for connectivity errors (`notConnectedToInternet`, `networkConnectionLost`, `timedOut`, `cannotConnectToHost`, `cannotFindHost`, `dnsLookupFailed`, `internationalRoamingOff`, `dataNotAllowed`) and for a system cancel. It is deleted otherwise, for example when the blob itself was stale.
- Resume data is still discarded on user cancel (`cancel()`), on a bad HTTP status (`didFinishDownloadingTo`; PR #27 also deletes resume data there), and when the import rejects the file (`deleteDownloadedFile`).

### 4. Snapshot import has no idle-timer or background-task cover

The import is ~12 GB of LMDB writes and takes minutes. While it runs:
- the screen auto-locks, which backgrounds the app;
- a brief app switch suspends the import thread at once.

**Fix.** `LongTaskAssertion` (ContentView.swift) wraps `loadSnapshot`. It disables the idle timer and restores the previous value afterwards. It also holds a `beginBackgroundTask` so a short trip to the background doesn't freeze the import. All of its state is touched on the main thread. `endBackgroundTask` runs exactly once, whether the import finishes first or the expiration handler fires first. On expiration the import thread is simply suspended with the process: LMDB is crash-safe, and an aborted import's pages are reused (030). The background task covers only the first trip to the background. It isn't re-armed after it expires, so a later trip suspends the import at once, and it resumes on return.

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
- `handleProcessingTask` waits for the first path. If the task expired during that wait, it stops there without opening the node or starting Tor. Next comes the `NetworkPolicy` gate (no metered catch-up without opt-in), which must run **before** anything opens the node: `HerculesNode.open` bootstraps Tor and the onion service, which is network traffic. On a metered or offline path the task resubmits itself; `scheduleProcessingTask` is a no-op until a validation mode has been chosen. Only after the gate does it check whether the node is set up. That check skips a node that hasn't picked a validation mode, or that is in AssumeUTXO mode and still needs its snapshot, and in AssumeUTXO mode it opens the node. The loop also honors the low-disk floor. It then runs wake catch-ups on the shared node in rounds (`WakeConfig.processingRoundMs` / `processingMaxBlocks`) until caught up, out of progress, or expired.
  - Rounds that run to their end are capped at `processingMaxRounds` (30).
  - Rounds that give way to a push or refresh are counted apart, under a separate generous cap (`processingMaxYields`, 200), so block wakes don't use up the round budget and the loop stays bounded. Each round goes through `NodeHost.runWake`, so the 028 rules still hold: it yields to foreground sync and is cancelled by a reset. The expiration handler cancels the current round, completes the task once (`OnceGate`), and resubmits.
- **Pushes and refreshes go first.** In Rust, a push only polls the session lock (`acquire_within`) and gives up as "busy" once less than 8 s of its budget is left. Back-to-back 120 s rounds would therefore starve it: no block notification, and `.noData`, which counts against iOS's push budget.
  - `NodeSessionState` tags processing rounds (`WakeKind.processing`). Admitting a push or refresh cancels any running round, and the round's cancel reason is recorded as `.preemptedByWake`.
  - Before each round, the processing loop waits until no push or refresh is in flight (`inFlightShortWakes == 0`). The wait alone isn't enough: a push admitted between that check and the round's admission would find no round to cancel, and would then wait the round out. So `admitWake(kind: .processing)` itself returns a new `Admission.yield`, under the same lock that admits pushes, when any short wake is in flight. The round is not registered, and the loop waits and asks again.
  - A preempted round keeps what it validated, since blocks are committed one at a time. One that validated nothing, or that yielded, is not treated as a stall (`WakeRun.preempted`): the loop runs another round, counted under the yield cap. Its "yielded" reason never becomes the task's history record.
  - This can't deadlock. Short wakes never wait on the processing loop, and each one is bounded by its own budget. The NodeHostScenarios harness covers it (s14), including 200 racing push/round admissions in which a round never runs alongside a push without being cancelled.
  - Remaining gap: Rust checks for cancellation between steps, so a block download already in progress finishes, or times out, first. A push can therefore still wait a few seconds for the round to let go.
- **Policy gate audit (every wake entry point).** No background path opens the node before the policy gate:
  - The silent push checks `shouldValidate` (after the first-path wait) before `performWake`.
  - The BG refresh does the same.
  - The BG processing task now checks it before `nodeIsSetUp`.
  - Foreground sync and the Settings "test notification" open the node without the gate. Both are user-initiated and on screen, where the status icon shows the metered/blocked state. 013 deliberately scoped the gate to background wakes. Gating foreground sync would be a product change, so it is left out of this ticket.
- **Publishing.** The widget is updated after every round that validated blocks (`SharedNodeStore.publishValidation`). The task writes one history record: the final tip, with the rounds and the total blocks validated in its `WakeTimings`, shown in Settings as e.g. "processing · 3 rounds · 412 blocks". The task is resubmitted whenever the node isn't known to be caught up, whatever the outcome. `setTaskCompleted(success:)` is true if any block was validated or the node is caught up.

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
| `HerculesApp/HerculesApp/NodeHost.swift`, `WakeCoordination.swift` | `maxBlocks` and `kind` per wake; pushes preempt processing rounds; processing-round config |
| `HerculesApp/HerculesApp/NotificationHistory.swift`, `SettingsView.swift` | `.noNetwork` source; processing rounds / blocks in `WakeTimings` and the history row |
| `HerculesApp/Tools/NodeHostScenarios/main.swift` | s14: processing preemption |
| `HerculesApp/HerculesApp/ContentView.swift` | Deferred-start fix; `LongTaskAssertion` around import; first-path wait before download |
| `HerculesApp/HerculesApp/SnapshotDownloader.swift` | Error/cancel path; accept 206 (same text as PR #27) |
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
- During a processing task on a long backlog, send a silent push. The push validates its block (not "Node busy"). The round in progress logs as preempted and keeps its blocks, and the next round starts after the push. The widget advances between rounds, and history shows one "processing · N rounds · M blocks" row.
- Cold launch from a push in airplane mode: the history row says "Offline", not "Paused" for metered data.
- `HerculesApp/Tools/NodeHostScenarios/run.sh`: ALL PASS (includes s14).

## Open questions

- **Collected data types.** Does the relay's APNs token + install secret need a declaration under App Privacy (`NSPrivacyCollectedDataTypeDeviceID`, not linked, not tracking, purpose App Functionality)? Apple's guidance treats push tokens loosely. Decide before the first TestFlight upload (019 / 031).
- **Processing task with `requiresExternalPower = false`?** 015 recommended `true`. Revisit with on-device data on how often wakes leave a backlog.

## Roadmap position

Tier 1 (platform reliability), right after 028. #1 and #3 directly undermine "validates every block" and first-run setup, and #5 blocks App Store submission.

## Status (2026-10-28)

Merged in PR #28 (`3fbae39`). Findings 1–7 fixed; #8 was not a bug. Review fixes added processing-round preemption by push/refresh wakes (NodeHostScenarios s14), a 206 accept for resumed downloads, and offline push wording.

**Still needs a device:** the hardware checks under Verification (cold-launch push, force-quit mid-download, reset → Start, idle timer during import, `_simulateLaunchForTaskWithIdentifier` for the processing task).
