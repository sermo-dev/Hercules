# Ticket 019: End-to-End Relay Deployment

## Summary

Stand up the production push-notification relay so a real iPhone running Hercules wakes and validates a real Bitcoin block within seconds of it landing on the network. All three components — the iOS wake-up handler, the AWS Lambda relay, and the node-side `blocknotify` script — already exist as code or templates. None of them are deployed, and the iOS app still points at a placeholder relay URL. This ticket walks each piece from "exists in repo" to "exists in production" in dependency order.

The goal at the end of this ticket: a personally-owned full node, running on your own hardware, signals an SQS queue when it sees a new block; an AWS Lambda fans that signal out to APNs; the Hercules iOS app on your physical iPhone wakes from a silent push, fetches the new tip from one of its own peers, validates it, and surfaces a Live Activity — all within ~25 seconds, with no app foreground required.

This is the first ticket where Hercules graduates from "an iOS app you can run" to "a real always-on Bitcoin node experience on your phone."

## Background

Three layers of work are already in place:

### Layer 1 — iOS wake handler (Phase 1, ~90% built)

`HerculesApp/HerculesApp/NotificationManager.swift` already implements:
- Permission request and APNs device-token capture (`requestPermission`, `handleDeviceToken`)
- Registration POST to the relay (`registerWithRelay`, `relayServerURL` on line 20)
- Silent-push entrypoint (`handleSilentPush(userInfo, completionHandler)`):
  - Honors `NetworkPolicy.shared.shouldValidate` (cellular gate from ticket 013)
  - Marks awake state, starts the Live Activity controller
  - Spawns `HerculesNode`, calls `node.validateLatestBlock(timeoutSecs: 25)`
  - Publishes via `SharedNodeStore`, posts the local notification

`HerculesApp/HerculesApp/HerculesApp.entitlements` already declares `aps-environment=development` and the `group.dev.sermo.hercules.shared` App Group.

What's missing in code:
- `relayServerURL` (line 20) is the literal placeholder `https://hercules-relay.example.com`
- `Info.plist`'s `UIBackgroundModes` array needs `remote-notification` confirmed present
- `AppDelegate` needs `didRegisterForRemoteNotificationsWithDeviceToken` and `didFailToRegisterForRemoteNotificationsWithError` plumbed into `NotificationManager`
- A toggle in `SettingsView` to opt into push (default off until the user explicitly enables — sending an APNs token to a third-party server is privacy-relevant and should be informed consent)

### Layer 2 — AWS relay (100% written, 0% deployed)

`server/template.yaml` is a complete SAM template:
- `DevicesTable` (DynamoDB on-demand, `device_token` PK, 30-day TTL)
- `BlockQueue` (SQS, 60s visibility timeout)
- `RegisterFunction` (Lambda + API Gateway, POST `/register`, writes the device token)
- `NotifyFunction` (Lambda, SQS event source, batch size 1, builds APNs JWT, fans out to every device row, prunes `BadDeviceToken`)
- `Outputs`: `ApiEndpoint`, `QueueUrl`, `QueueArn`

Defaults to `api.sandbox.push.apple.com` (matches the dev entitlement). Cost is essentially $0 within the free tier at single-user scale.

What's missing:
- It hasn't been `sam deploy`'d once. No DynamoDB table, no SQS queue, no Lambdas, no API Gateway URL.
- APNs key (.p8), Key ID, and Team ID need to exist in an Apple Developer account first.

### Layer 3 — Node-side `blocknotify` script (documented, 0% deployed)

`server/README.md:42-49` has the reference shell script. It uses `torsocks` to route the SQS API call through Tor, which mitigates the IP-leak from your node's residential IP to AWS. It pipes the block hash + timestamp into the queue.

What's missing:
- No IAM user / access key provisioned
- No AWS CLI installed on the actual node machine
- No script written to disk
- `blocknotify=...` line not added to `bitcoin.conf`
- `bitcoind` not restarted to pick up the hook

### Why these three are coupled

Any one of them in isolation doesn't get you a working push. You need all three live, plus the iOS app pointed at the right registration URL, plus a real device with a valid APNs token in the DynamoDB table, plus an actual block landing on mainnet to trigger the chain. This ticket is the integration ticket that closes all of those gaps in the right order.

## Deployment plan

Five phases. Each phase is independently testable, so you can stop and verify before moving to the next.

### Phase 0 — Prerequisites

One-time setup that doesn't depend on any of the other phases.

1. **Apple Developer Program enrollment** — $99/yr. The free Personal Team cannot enable the Push Notifications capability. This is the gating dependency for everything else; without it, neither real-device pushes nor TestFlight is possible.
2. **Apple Developer Console setup**:
   - Register the app's bundle identifier (matches `ApnsTopic` in `template.yaml`, default `dev.sermo.hercules.app`)
   - Enable the Push Notifications capability on the App ID
   - Create an APNs Authentication Key (Keys → "+" → Apple Push Notifications service). Download the `.p8` file once — Apple will not let you re-download it.
   - Capture the **Key ID** (10 characters, on the key detail page) and **Team ID** (top-right of the developer portal)
3. **AWS account** — any region. Enable billing alerts at $5 to be safe. Install SAM CLI locally (`brew install aws-sam-cli` on macOS).
4. **Provisioning profile** for the physical device:
   - In Xcode, sign in with the Apple ID enrolled in step 1
   - Project → Signing & Capabilities → Team set to your dev team
   - Add the Push Notifications capability (this rewrites the entitlements file — confirm `aps-environment=development` survives)
   - Connect the iPhone, register it as a development device

### Phase 1 — Deploy the AWS relay

Deploy the relay first because the iOS app needs the API Gateway URL, and you can smoke-test the SQS→Lambda→APNs path before either of the other layers exist.

1. From `server/`:
   ```bash
   APNS_KEY=$(base64 < AuthKey_XXXXXXXXXX.p8)
   sam deploy --guided \
     --parameter-overrides \
       ApnsKeyId=YOUR_KEY_ID \
       ApnsTeamId=YOUR_TEAM_ID \
       ApnsKeyBase64=$APNS_KEY \
       ApnsTopic=dev.sermo.hercules.app \
       ApnsHost=api.sandbox.push.apple.com
   ```
2. Capture the `ApiEndpoint`, `QueueUrl`, and `QueueArn` outputs into a local secrets file (do not commit).
3. Smoke-test the register endpoint with a fake token:
   ```bash
   curl -X POST "$API_ENDPOINT" \
     -H 'Content-Type: application/json' \
     -d '{"device_token":"deadbeef..."}'
   ```
   Confirm the row appears in the `hercules-devices` DynamoDB table.
4. Smoke-test the notify Lambda by sending a synthetic SQS message:
   ```bash
   aws sqs send-message --queue-url "$QUEUE_URL" \
     --message-body '{"hash":"0000...","time":1700000000}'
   ```
   Confirm CloudWatch Logs show the Lambda invoking and (expectedly) failing on the fake token with `BadDeviceToken`. The `BadDeviceToken` cleanup path will then prune the fake row from DynamoDB — that's the expected end state.

At this point the relay is live but has no real subscribers.

### Phase 2 — Wire up the iOS app and register a real device

1. **Replace the placeholder URL** in `NotificationManager.swift:20`:
   ```swift
   private let relayServerURL = "https://your-api-id.execute-api.us-east-1.amazonaws.com/Prod/register"
   ```
   This value is environment-specific. Either bake it in via a `Config.xcconfig` file or hard-code for now and revisit before any public release.
2. **Audit `Info.plist`**: confirm `UIBackgroundModes` array contains `remote-notification`. If absent, add it.
3. **Audit `AppDelegate`** (or the SwiftUI `@UIApplicationDelegateAdaptor` equivalent): confirm `application(_:didRegisterForRemoteNotificationsWithDeviceToken:)` and `application(_:didFailToRegisterForRemoteNotificationsWithError:)` both call into `NotificationManager`.
4. **Add a "Push Notifications" toggle** to `SettingsView`, default OFF. Only call `requestPermission()` when the user explicitly enables it. Sending an APNs token off-device is informed-consent territory.
5. Build to your physical iPhone (Xcode → Run, device selected). Enable the toggle. Accept the system permission prompt.
6. Observe the device token POST in CloudWatch Logs for `RegisterFunction`. Confirm a real row appears in the `hercules-devices` DynamoDB table with a 30-day TTL.
7. **Manual end-to-end test from a laptop** — fire the notify Lambda directly to confirm the push reaches the device:
   ```bash
   aws sqs send-message --queue-url "$QUEUE_URL" \
     --message-body '{"hash":"0000000000000000000000000000000000000000000000000000000000000000","time":1700000000}'
   ```
   The `validateLatestBlock` path ignores the hash in the payload — it fetches whatever the real tip is from its own peers — so any well-formed JSON works. Within seconds the iPhone should:
   - Wake silently
   - Start the Live Activity (Dynamic Island on Pro models, Lock Screen banner otherwise)
   - Run a real header fetch + block validation against the real network
   - Post the local notification
   - Update the App Group state file

If this works, you have a working push pipeline using a manual SQS push instead of a real block trigger. Phase 3 closes that last gap.

### Phase 3 — Connect your full node

This phase only matters if you want pushes triggered by real blocks instead of by manual SQS injection. You can stop after Phase 2 and still have a working "tap a button on my laptop, my phone wakes and validates the tip" loop.

1. **Provision a least-privilege IAM user** in the AWS console:
   - Username: `hercules-node-blocknotify`
   - No console access, programmatic access only
   - Inline policy: exactly the JSON in `server/README.md:60-65` (`sqs:SendMessage` on `$QUEUE_ARN`, nothing else)
   - Generate an access key, capture once
2. **On the node machine**, install AWS CLI v2 and configure with the new access key. Use a non-default profile so the credentials stay scoped to this one job:
   ```bash
   aws configure --profile hercules-notify
   ```
3. **Install `torsocks`** (`apt install torsocks` on Debian/Ubuntu, `brew install torsocks` on macOS). Tor needs to be running locally — Hercules's bundled arti-client is iOS-side, so the node machine needs its own `tor` daemon.
4. **Write `/usr/local/bin/hercules-notify.sh`** matching `server/README.md:43-49`:
   ```bash
   #!/bin/bash
   torsocks aws --profile hercules-notify sqs send-message \
     --queue-url "$QUEUE_URL" \
     --message-body "{\"hash\": \"$1\", \"time\": $(date +%s)}" \
     >> /var/log/hercules-notify.log 2>&1
   ```
   `chmod +x` it. Pipe stdout/stderr to a log file because `bitcoind` discards `blocknotify` output.
5. **Add to `bitcoin.conf`**:
   ```
   blocknotify=/usr/local/bin/hercules-notify.sh %s
   ```
6. **Restart `bitcoind`**. Tail `debug.log` for `blocknotify` mentions to confirm it's hooked.
7. **Wait for the next real block** (~10 minutes). Watch `/var/log/hercules-notify.log` for the SQS call. Watch CloudWatch Logs for the `NotifyFunction` invocation. Watch your iPhone.

### Phase 4 — End-to-end validation

After Phase 3, exercise the full chain a handful of times to flush out timing edge cases.

1. **Real-block test (the headline test)**: Lock the iPhone, wait for a real block. Confirm:
   - Lock Screen wakes briefly with the Live Activity
   - The activity progresses through `connecting → headers → block → validating → done`
   - Local notification posts with the new height
   - Time-to-validate is < 25 s end-to-end (the silent push budget)
2. **Cellular gate test**: Toggle "Use Cellular Data" off in Settings, switch to cellular, trigger a manual SQS push. Confirm the wake handler short-circuits without burning data (per ticket 013).
3. **Stale-token cleanup**: Uninstall the app on the iPhone, trigger another push. Confirm the next `NotifyFunction` invocation logs `BadDeviceToken` and removes the row from DynamoDB on its own.
4. **Concurrency**: Manually fire two SQS messages back-to-back. Confirm both Lambda invocations succeed and the iPhone handles overlapping wakes gracefully (the second wake should either coalesce with the in-progress one or queue cleanly).
5. **Multi-device** (optional): Install on a second device — old iPhone, family member's phone — register, confirm both receive the push.

## Files modified / created

| File | Action | Phase |
|---|---|---|
| `tickets/019-relay-deployment.md` | **New** (this file) | — |
| `HerculesApp/HerculesApp/NotificationManager.swift` | Modify (real `relayServerURL`) | 2 |
| `HerculesApp/HerculesApp/Info.plist` | Audit / modify (`UIBackgroundModes`) | 2 |
| `HerculesApp/HerculesApp/AppDelegate*.swift` | Audit / wire device-token callbacks | 2 |
| `HerculesApp/HerculesApp/SettingsView.swift` | Add Push Notifications toggle | 2 |
| AWS account | Deploy `server/template.yaml` via SAM | 1 |
| Apple Developer account | Register App ID, generate APNs key | 0 |
| Bitcoin node host | IAM user, AWS CLI, `hercules-notify.sh`, `bitcoin.conf` | 3 |

No code changes are required to `hercules-core`. Everything in this ticket is iOS, infrastructure, and operational.

## Out of scope

These are deliberately not part of this ticket and should be tracked separately if pursued:

- **Simulator delivery**: APNs cannot deliver to the iOS Simulator over the network. Local injection via `xcrun simctl push` works for UI iteration but does not exercise the SQS→Lambda→APNs path. If we want a "fire the relay and have the simulator wake" loop for development, that's its own piece of tooling (shell script polling SQS, pulling the message, calling `xcrun simctl push`). Decide separately whether the dev-loop ergonomics justify it.
- **Production APNs migration**: This ticket lands on `api.sandbox.push.apple.com` because the entitlement is `development`. Moving to TestFlight or the App Store requires a second `sam deploy` with `ApnsHost=api.push.apple.com` and `aps-environment=production`, plus a fresh device-token capture (sandbox and production tokens are not interchangeable). Track as a release-engineering follow-up.
- **Block-height enrichment**: The current notify Lambda passes the hash through. If we want the push payload to carry a height (so the Live Activity can render the new height before the local validation completes), the script needs to call `bitcoin-cli getblockheader` and bake it into the SQS body. Cosmetic, not on the critical path.
- **Multi-relay redundancy**: One AWS region = one point of failure. Acceptable for v1; revisit if we ever care about 99.9% delivery.

## Open questions

- **Push opt-in default**: The toggle should default OFF, but should the *first-launch onboarding* nudge users to enable it? Push is the entire point of the always-on experience — users who skip it get a much weaker product. Recommendation: explain the privacy trade-off in onboarding (your APNs token leaves the device and lives in our DynamoDB; we never see your IP because the wake handler talks directly to Bitcoin peers over Tor) and offer the toggle then.
- **Where does `relayServerURL` live**: hard-coded constant, `Config.xcconfig`, or a build-time env var? For one developer with one relay this doesn't matter. For multi-environment (dev/staging/prod relays) it needs to be a build setting.
- **Should we self-host instead of AWS**: Lambda + DynamoDB + SQS works but ties us to one cloud. A small self-hosted alternative (a Tor-onion-fronted Rust HTTP service backed by SQLite) would be more aligned with Hercules's ethos. Not blocking — ship the AWS version first, revisit when the user count justifies the operational overhead.
- **Coalescing rapid wakes**: If two blocks land within seconds (rare but happens), do we want to debounce in the Lambda or let both pushes through and have the iOS handler dedupe? Current design lets both through. Probably fine, but worth measuring.

## Dependencies

- **Ticket 013** (live activity + cellular policy) — must be merged. The wake handler relies on `NetworkPolicy.shared.shouldValidate` and the Live Activity controller that 013 introduces. ✅ Already complete.
- **Phase 5 fully participating node** — must be merged. The wake handler validates by pulling headers and blocks from real peers; without 008 there are no peers to pull from. ✅ Already complete.
- **Apple Developer Program enrollment** — gates everything. Until this is paid for, neither device pushes nor TestFlight builds are possible.

## Verification

Phase 0: Apple Developer key downloaded, AWS account ready, SAM CLI installed locally.
Phase 1: `sam deploy` succeeds. Manual `aws sqs send-message` produces a CloudWatch log entry from `NotifyFunction`. DynamoDB table exists and is empty.
Phase 2: Real device receives a push from a manual SQS injection. App Group state file updates. Live Activity renders. Local notification posts.
Phase 3: A real Bitcoin block triggers the chain end-to-end without manual intervention.
Phase 4: All edge cases (cellular gate, stale token, concurrent wakes) behave correctly.

The ticket is **done** when, after locking the iPhone and putting it down, you see a Live Activity wake up on its own ten minutes later because a block landed on mainnet — and the height in the activity matches what `bitcoin-cli getblockcount` reports.
