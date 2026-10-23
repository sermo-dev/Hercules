# Ticket 031: Build Configuration Fixes + Rename Readiness

## Summary

The Xcode project has drifted from its source of truth, and several App Store blockers are sitting in the config:

- `project.yml` (XcodeGen) has no widget target, but the hand-edited `project.pbxproj` does. The next `xcodegen generate` would silently delete the widget and the Live Activity.
- `NSSupportsLiveActivities` is missing, so Live Activities probably never appear.
- The app and widget report different version strings, which App Store validation rejects.
- The app has no display name.

The app will also be renamed. Some identifiers can change at any time; others **must be frozen before the first TestFlight build** because changing them later breaks existing installs. This ticket fixes the config and centralizes every identifier so the rename is one edit.

## Background (verified)

**XcodeGen drift.**
- `HerculesApp/project.yml` defines one target, `HerculesApp`.
- `project.pbxproj` also contains `HerculesWidget.appex`, its sources, entitlements, and an Embed Foundation Extensions phase (`project.pbxproj:22-23, 36, 47, 70-73, 102`), with bundle ID `dev.sermo.hercules.app.HerculesWidget` (`:508`).
- That target exists only in the generated file.

**Live Activities.**
- There's no `NSSupportsLiveActivities` key in `HerculesApp/Info.plist`, `project.yml`, or the pbxproj.
- `WakeActivityController` calls `Activity<NodeActivityAttributes>.request(...)` (`NotificationManager.swift:524`) from the silent-push wake path (`:142-152`). As far as we know, iOS doesn't allow starting a Live Activity from the background without push-to-start. **Needs on-device verification.**

**Version mismatch.**
- `HerculesApp/Info.plist:17-18` hardcodes `CFBundleShortVersionString` = `1.0`.
- `project.yml` sets `MARKETING_VERSION: "0.1.0"`, and the widget's Info.plist uses `$(MARKETING_VERSION)` (`HerculesWidget/Info.plist:19-20`).
- An embedded extension's version must match its parent app's version.

**Display name.** The widget sets `INFOPLIST_KEY_CFBundleDisplayName = Hercules` (`project.pbxproj:499, 529`). The app has none, so the home screen label falls back to `$(PRODUCT_NAME)` = "HerculesApp".

**Signing and push.**
- `CODE_SIGNING_ALLOWED: "NO"` and `DEVELOPMENT_TEAM: ""` in `project.yml`.
- `aps-environment` = `development` in `HerculesApp.entitlements`.
- Release and TestFlight need a team, signing, and `production` APNs (coordinate with 019, which deploys the relay against sandbox APNs first).

## Identifier inventory

| Identifier | Where | Rename cost |
|---|---|---|
| Bundle ID prefix `dev.sermo.hercules` | `project.yml` `bundleIdPrefix`, `PRODUCT_BUNDLE_IDENTIFIER: dev.sermo.hercules.app`; widget `…app.HerculesWidget` | **Freeze before TestFlight.** Changing it creates a new app: no update path, data lost, new APNs topic |
| App Group `group.dev.sermo.hercules.shared` | Both `.entitlements` files; `SharedNodeState.swift:78` | **Freeze.** The shared container (widget state) moves; old data is orphaned |
| APNs topic | Equals bundle ID; `server/template.yaml:22` default `dev.sermo.hercules.app` | **Freeze** (follows bundle ID) |
| Keychain access group (future, 036) | Not yet created | **Freeze before the wallet ships.** Changing it loses access to stored keys |
| BGTask ID `dev.sermo.hercules.catchup` | `project.yml`, `Info.plist`, `NotificationManager.swift:397` | Cheap, but must change in all three places together |
| Background URLSession ID `io.hercules.snapshot-download` | `SnapshotDownloader.swift:29` | Cheap (an in-flight download is lost once) |
| Dispatch queue labels `io.hercules.*` | e.g. `NetworkPolicy.swift:85` | Free |
| Display name and user-visible strings | Widget display name; header "HERCULES" (`ContentView.swift` ~578); About copy; about 9 `"Hercules…"` string literals in app Swift | Free |
| Rust crate `hercules-core`, UniFFI namespace `hercules`, `HerculesNode`, `herculesFFI.xcframework`, `build-ios.sh` | Core and build | Free (internal); rename whenever convenient, or never |
| Server resources `hercules-devices`, `hercules-new-blocks` | `server/template.yaml:36, 52` | Free before 019 deploys; a migration after |
| On-disk filenames `hercules-headers.sqlite3`, `hercules-utxo.hutx.gz` | Swift paths, `assumeutxo.rs` | Free with a migration (do it together with 030's move) |

**Rule:** choose the final product name and bundle ID prefix **before** the first TestFlight upload. Everything else can follow.

## Proposed fix

1. **Make `project.yml` the source of truth again.**
   - Add the `HerculesWidget` app-extension target: sources, Info.plist, entitlements, embed into the app, `bundleId: ${BUNDLE_PREFIX}.app.widget`.
   - Regenerate and diff against the current pbxproj to confirm nothing else drifted.
   - Add a CI or pre-commit check that `xcodegen generate` produces no diff.
2. **Centralize identifiers** in a `Config/Shared.xcconfig` (or `project.yml` `settings.base`):
   - `APP_DISPLAY_NAME`, `BUNDLE_PREFIX`, `APP_GROUP_ID`, `BGTASK_CATCHUP_ID`, `SNAPSHOT_SESSION_ID`, `MARKETING_VERSION`.
   - Expose them to Swift through Info.plist keys (e.g. `HRCAppGroupID = $(APP_GROUP_ID)`) and read them in one `AppIdentifiers.swift`, replacing hardcoded literals.
   - Entitlements files use `$(APP_GROUP_ID)`.
3. **Versions.** Remove the hardcoded `1.0`; the app's Info.plist uses `$(MARKETING_VERSION)` and `$(CURRENT_PROJECT_VERSION)`, same as the widget.
4. **Display name.** Set `CFBundleDisplayName = $(APP_DISPLAY_NAME)` for the app and widget.
5. **Live Activities.**
   - Add `NSSupportsLiveActivities = YES`.
   - Start the activity only from the foreground, or adopt push-to-start tokens (iOS 17.2+; the deployment target is 17.0, so gate on availability).
   - If neither fits the wake model, drop the wake-time Live Activity and keep the widget. Verify on device first.
6. **Release signing.** Add a Release configuration with team, signing, and `aps-environment = production` (Debug stays `development`).

## Files touched

| File | Action |
|---|---|
| `HerculesApp/project.yml` | Widget target; xcconfig include; Release config; Info.plist keys |
| `HerculesApp/Config/Shared.xcconfig` | **New** — all identifiers |
| `HerculesApp/HerculesApp/Info.plist`, `HerculesWidget/Info.plist` | Versions, display name, `NSSupportsLiveActivities`, identifier keys |
| `HerculesApp/HerculesApp/*.entitlements`, `HerculesWidget/*.entitlements` | `$(APP_GROUP_ID)` |
| `HerculesApp/HerculesApp/AppIdentifiers.swift` | **New** — read identifiers from Info.plist |
| `SharedNodeState.swift`, `NotificationManager.swift`, `SnapshotDownloader.swift`, `NetworkPolicy.swift` | Use `AppIdentifiers` |
| `HerculesApp/HerculesApp.xcodeproj/project.pbxproj` | Regenerated |

## Dependencies

- **019**: APNs topic and production environment.
- **030**: combine any on-disk filename renames with the storage migration.
- **044**: product naming and positioning.

## Estimated effort

~2–3 days:
- widget target in XcodeGen plus regen and diff: 1 day
- xcconfig centralization: 0.5–1 day
- Live Activity verification and fix: 0.5–1 day

## Verification

- `xcodegen generate && git diff --exit-code HerculesApp/HerculesApp.xcodeproj` is clean (after the first regen commit).
- The archive builds, and Xcode's "Validate App" passes (versions match, extension embedded).
- The home screen shows the display name, not "HerculesApp".
- Changing `APP_DISPLAY_NAME` / `BUNDLE_PREFIX` in one file renames everything (test on a scratch branch).
- A Live Activity appears on device under the chosen start strategy.

## Open questions

- **Final name and bundle prefix.** Is `dev.sermo` the long-term org prefix?
- **Is the wake-time Live Activity worth keeping** if it needs push-to-start (an extra APNs token per device for the relay)?
- **Minimum iOS version:** stay at 17.0, or move to 17.2 for push-to-start?

## Roadmap position

Tier 1. Fix the XcodeGen drift immediately (it's a landmine for anyone who runs `xcodegen`). Everything else must land before the first TestFlight build.
