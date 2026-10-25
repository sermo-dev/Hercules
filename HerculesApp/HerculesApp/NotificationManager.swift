import ActivityKit
import BackgroundTasks
import CryptoKit
import Foundation
import Security
import UserNotifications
import UIKit

/// Push relay configuration.
enum RelayConfig {
    /// PLACEHOLDER: replace with the deployed stack's `ApiBaseUrl` output
    /// (`server/README.md`), e.g. `https://abc123.execute-api.us-east-1.amazonaws.com/Prod`.
    /// Deployment is tracked in ticket 019; per-environment build config in 031.
    /// The app appends `/register` and `/unregister`. Users can override this
    /// in Settings → Relay Server.
    static let defaultBaseURL = "https://hercules-relay.example.com"

    /// Minimum gap between re-registrations of an unchanged token. The relay
    /// expires rows 30 days after the last registration, so daily refreshes
    /// on launch keep a live install registered indefinitely without POSTing
    /// on every background wake.
    static let reregisterInterval: TimeInterval = 24 * 60 * 60
}

/// Central coordinator for push notifications. Handles permission requests,
/// device token registration with the relay server, silent push handling
/// (background block validation), and local notification posting.
class NotificationManager: ObservableObject {
    static let shared = NotificationManager()

    @Published var isEnabled: Bool {
        didSet { UserDefaults.standard.set(isEnabled, forKey: "notificationsEnabled") }
    }
    @Published var deviceToken: String?
    @Published var registrationError: String?
    @Published var notificationHistory: [BlockNotificationRecord] = []

    var relayServerURL: String {
        get { UserDefaults.standard.string(forKey: "relayServerURL") ?? RelayConfig.defaultBaseURL }
        set { UserDefaults.standard.set(newValue, forKey: "relayServerURL") }
    }

    private enum Keys {
        static let registrationFingerprint = "relayRegistrationFingerprint"
        static let registrationDate = "relayRegistrationDate"
        static let unregisterPending = "relayUnregisterPending"
    }

    private init() {
        isEnabled = UserDefaults.standard.bool(forKey: "notificationsEnabled")
        if let loaded = NotificationHistory.loadIfReadable() {
            notificationHistory = loaded
            historyLoaded = true
        }
    }

    /// False if the history file couldn't be read at init (locked since
    /// reboot). `appendRecord` retries the load before saving so the real
    /// history is never replaced by an empty in-memory copy.
    private var historyLoaded = false

    // MARK: - Permission & Registration

    /// Request notification permission and register for remote notifications.
    func requestPermission() {
        UNUserNotificationCenter.current().requestAuthorization(
            options: [.alert, .sound, .badge]
        ) { granted, error in
            DispatchQueue.main.async {
                if let error = error {
                    self.registrationError = error.localizedDescription
                    return
                }
                if granted {
                    UIApplication.shared.registerForRemoteNotifications()
                } else {
                    self.registrationError = "Notification permission denied"
                }
            }
        }
    }

    /// Called at every app launch (including background launches for a
    /// silent push). If the user has opted in and permission is still
    /// granted, ask APNs for the (possibly rotated) token; `handleDeviceToken`
    /// then re-registers with the relay if the token changed or the last
    /// registration is older than `RelayConfig.reregisterInterval`. This keeps
    /// the relay's 30-day TTL from silently expiring.
    ///
    /// If the user turned notifications off and the relay unregister didn't
    /// complete, fetch the token again so it can be retried.
    func refreshRegistrationOnLaunch() {
        if isEnabled {
            UNUserNotificationCenter.current().getNotificationSettings { settings in
                switch settings.authorizationStatus {
                case .authorized, .provisional, .ephemeral:
                    DispatchQueue.main.async {
                        UIApplication.shared.registerForRemoteNotifications()
                    }
                default:
                    break
                }
            }
        } else if UserDefaults.standard.bool(forKey: Keys.unregisterPending) {
            UIApplication.shared.registerForRemoteNotifications()
        }
    }

    /// Opt in: request permission, then register with the relay once APNs
    /// hands us a token.
    func enableNotifications() {
        isEnabled = true
        UserDefaults.standard.removeObject(forKey: Keys.unregisterPending)
        requestPermission()
    }

    /// Opt out: remove this install's row from the relay so it stops pushing
    /// immediately instead of waiting for the 30-day TTL. Retried on next
    /// launch if the request fails.
    func disableNotifications() {
        isEnabled = false
        clearRegistrationMarker()
        UserDefaults.standard.set(true, forKey: Keys.unregisterPending)
        if let token = deviceToken {
            deviceToken = nil
            unregisterFromRelay(token: token, relayURL: relayServerURL)
        } else {
            // Token not known in this process yet: fetch it, and
            // handleDeviceToken will unregister.
            UIApplication.shared.registerForRemoteNotifications()
        }
    }

    /// Point the app at a different relay. Unregisters from the old one and
    /// registers with the new one when notifications are on.
    func updateRelayURL(_ newURL: String) {
        let trimmed = newURL.trimmingCharacters(in: .whitespacesAndNewlines)
        let oldURL = relayServerURL
        guard !trimmed.isEmpty, trimmed != oldURL else { return }
        relayServerURL = trimmed
        clearRegistrationMarker()
        if isEnabled, let token = deviceToken {
            unregisterFromRelay(token: token, relayURL: oldURL)
            registerWithRelay(token: token)
        }
    }

    /// Called when APNs returns a device token.
    func handleDeviceToken(_ token: String) {
        if isEnabled {
            DispatchQueue.main.async {
                self.deviceToken = token
                self.registrationError = nil
            }
            registerWithRelay(token: token)
        } else if UserDefaults.standard.bool(forKey: Keys.unregisterPending) {
            unregisterFromRelay(token: token, relayURL: relayServerURL)
        }
    }

    /// Called when APNs registration fails (e.g., no developer account).
    func handleRegistrationError(_ error: Error) {
        DispatchQueue.main.async {
            self.registrationError = error.localizedDescription
        }
    }

    // MARK: - Relay Registration

    /// Send the device token and this install's secret to the relay. Skipped
    /// when the same token was registered with the same relay within
    /// `RelayConfig.reregisterInterval`.
    private func registerWithRelay(token: String) {
        let relayURL = relayServerURL
        let fingerprint = Self.registrationFingerprint(token: token, relayURL: relayURL)
        let defaults = UserDefaults.standard
        if defaults.string(forKey: Keys.registrationFingerprint) == fingerprint,
           Date().timeIntervalSince1970 - defaults.double(forKey: Keys.registrationDate)
               < RelayConfig.reregisterInterval {
            return
        }

        guard let request = Self.relayRequest(
            relayURL: relayURL,
            path: "register",
            body: ["device_token": token, "platform": "ios"]
        ) else { return }

        URLSession.shared.dataTask(with: request) { _, response, error in
            if let error = error {
                // Not critical: retried on next launch.
                print("Relay registration failed: \(error.localizedDescription)")
                return
            }
            let status = (response as? HTTPURLResponse)?.statusCode ?? 0
            switch status {
            case 200:
                defaults.set(fingerprint, forKey: Keys.registrationFingerprint)
                defaults.set(Date().timeIntervalSince1970, forKey: Keys.registrationDate)
            case 403:
                // Token is bound to a different install secret (e.g. the
                // Keychain item was lost). The old row expires within 30 days.
                DispatchQueue.main.async {
                    self.registrationError = "Relay rejected this install's registration"
                }
            default:
                print("Relay registration failed: HTTP \(status)")
            }
        }.resume()
    }

    /// Remove this install's row from the relay.
    private func unregisterFromRelay(token: String, relayURL: String) {
        guard let request = Self.relayRequest(
            relayURL: relayURL,
            path: "unregister",
            body: ["device_token": token]
        ) else { return }

        URLSession.shared.dataTask(with: request) { _, response, error in
            if let error = error {
                print("Relay unregister failed: \(error.localizedDescription)")
                return
            }
            let status = (response as? HTTPURLResponse)?.statusCode ?? 0
            // 403 means the row belongs to another secret; nothing more we can do.
            guard status == 200 || status == 403 else {
                print("Relay unregister failed: HTTP \(status)")
                return
            }
            DispatchQueue.main.async {
                // Only clear the retry flag if the user hasn't re-enabled in
                // the meantime and this was the current relay.
                if !self.isEnabled && relayURL == self.relayServerURL {
                    UserDefaults.standard.removeObject(forKey: Keys.unregisterPending)
                } else if self.isEnabled, relayURL == self.relayServerURL, let current = self.deviceToken {
                    // Re-enabled while the unregister was in flight: make
                    // sure the row exists again.
                    self.clearRegistrationMarker()
                    self.registerWithRelay(token: current)
                }
            }
        }.resume()
    }

    /// Build a POST to `<relayURL>/<path>` carrying `body` plus the
    /// per-install secret for that relay. Nil if the URL is invalid or the
    /// Keychain is unavailable (e.g. before first unlock after reboot).
    private static func relayRequest(relayURL: String, path: String, body: [String: String]) -> URLRequest? {
        var base = relayURL.trimmingCharacters(in: .whitespacesAndNewlines)
        while base.hasSuffix("/") { base.removeLast() }
        guard let url = URL(string: "\(base)/\(path)"), let host = url.host else { return nil }
        guard let secret = RelayInstallSecret.secret(forRelayHost: host) else {
            print("Relay \(path) skipped: install secret unavailable")
            return nil
        }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.timeoutInterval = 15
        var payload = body
        payload["install_secret"] = secret
        request.httpBody = try? JSONSerialization.data(withJSONObject: payload)
        return request
    }

    /// Hash of token + relay, so UserDefaults never holds the raw token.
    private static func registrationFingerprint(token: String, relayURL: String) -> String {
        let digest = SHA256.hash(data: Data("\(token)|\(relayURL)".utf8))
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    private func clearRegistrationMarker() {
        UserDefaults.standard.removeObject(forKey: Keys.registrationFingerprint)
        UserDefaults.standard.removeObject(forKey: Keys.registrationDate)
    }

    // MARK: - Silent Push Handling

    /// Handle a silent push notification. Catches up on the process's shared
    /// node (`NodeHost`) within a budget that starts now, at receipt, and
    /// posts a local notification. A watchdog guarantees the completion
    /// handler is called exactly once, before iOS's ~30 s limit (ticket 028).
    ///
    /// If the device is on a metered network and the user has not opted into
    /// "Use Cellular Data", we skip the block download entirely — opening a
    /// P2P connection during a silent-push wake on cellular would burn the
    /// user's allowance without warning. We still record the wake (using the
    /// push payload's height/hash) and post a notification so the user sees
    /// what would have happened, marked clearly as paused.
    func handleSilentPush(
        userInfo: [AnyHashable: Any],
        completionHandler: @escaping (UIBackgroundFetchResult) -> Void
    ) {
        // The wake's clock starts here: node open and transport bootstrap
        // count against the same budget as block work (ticket 028).
        let budget = WakeBudget(budgetMs: WakeConfig.budgetMs)
        let receivedAt = Date()

        // Parse block info from push payload (used as fallback if validation fails)
        let pushBlock = parsePushPayload(userInfo)

        // Network policy gate: refuse to validate over metered links unless
        // the user has explicitly opted in. Record a paused entry so the
        // user can see in the notification history that we declined the wake.
        if !NetworkPolicy.shared.shouldValidate {
            // Republish shared state with isPaused=true so the home-screen
            // widget flips to its red "paused" indicator without waiting
            // for the user to open the app.
            SharedNodeStore.markPaused(true)
            if let push = pushBlock {
                let record = BlockNotificationRecord(
                    id: UUID(),
                    height: push.height ?? 0,
                    blockHash: push.hash,
                    timestamp: push.timestamp,
                    timestampHuman: "",
                    validated: false,
                    headerValidated: false,
                    receivedAt: receivedAt,
                    source: .networkPolicyPaused,
                    validationError: "Validation skipped: metered network without Use Cellular Data opt-in"
                )
                DispatchQueue.main.async {
                    self.appendRecord(record)
                }
                Self.postLocalNotification(for: record)
            }
            completionHandler(.noData)
            return
        }

        // Low storage (ticket 030): don't let a wake push LMDB/SQLite into
        // ENOSPC. Record a visible skip instead.
        if let free = StorageGuard.availableBytes(), free < StorageGuard.pauseBelowBytes {
            if let push = pushBlock {
                let record = BlockNotificationRecord(
                    id: UUID(),
                    height: push.height ?? 0,
                    blockHash: push.hash,
                    timestamp: push.timestamp,
                    timestampHuman: "",
                    validated: false,
                    headerValidated: false,
                    receivedAt: receivedAt,
                    source: .pushPayload,
                    validationError: "Validation skipped: storage almost full (\(StorageGuard.format(free)) free)"
                )
                appendRecord(record)
            }
            completionHandler(.noData)
            return
        }

        // Read here, on the main thread (AppDelegate delivers pushes on it).
        // `.inactive` (e.g. Control Center pulled down) still counts as on
        // screen: the app is about to be active again.
        let appInForeground = UIApplication.shared.applicationState != .background

        // The app is on screen and syncing: foreground is already
        // validating. Record that and finish at once, with no Live Activity
        // and no node call (ticket 028). `runWake` re-checks atomically in
        // case foreground sync starts in between.
        if appInForeground && NodeHost.shared.sessions.isForegroundActive {
            var record = Self.payloadRecord(
                pushBlock: pushBlock, receivedAt: receivedAt, source: .foregroundActive, error: nil
            )
            record.wakeTimings = WakeTimings(trigger: "push", completedMs: budget.elapsedMs())
            appendRecord(record)
            completionHandler(.noData)
            return
        }

        // Mark the wake start so the widget can flip to its "awake" dot.
        // Cleared in every exit path below (success, failure, paused).
        SharedNodeStore.markAwake(true)

        // Request a Live Activity for the wake. The controller drives a
        // heuristic phase progression on a side timer because the FFI
        // surface is single-shot — there's no progress callback we can
        // hook into. The expected/known initial values come from either
        // the push payload or the widget's last-known state.
        let initialState = SharedNodeStore.load()
        let initialHeight = pushBlock?.height ?? initialState.blockHeight
        let activityController: WakeActivityControllerProtocol
        if #available(iOS 16.2, *) {
            activityController = WakeActivityController()
        } else {
            activityController = NoopWakeActivityController()
        }
        activityController.start(initialHeight: initialHeight, peerCount: initialState.peerCount)

        // The completion handler must be called exactly once, by whichever
        // of Rust's return and the watchdog gets there first.
        let gate = OnceGate()
        // The watchdog's record id is fixed up front, so a late result can
        // replace it whichever lands first; its completion time is kept.
        let watchdogRecordID = UUID()
        let watchdogCompletedMs = LockedBox<UInt64?>(nil)

        // Watchdog (ticket 028): if Rust hasn't returned ~27 s after
        // receipt (a blocking read on a slow peer can outlast the budget),
        // cancel it and complete ourselves so iOS never kills the wake.
        let watchdogDelay = max(0, WakeConfig.watchdogSeconds - Double(budget.elapsedMs()) / 1000)
        DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + watchdogDelay) {
            budget.cancel()
            gate.fire {
                StoragePaths.log.notice("wake: watchdog fired at \(budget.elapsedMs()) ms")
                SharedNodeStore.markAwake(false)
                activityController.finishFailure(height: initialHeight, peerCount: initialState.peerCount)
                var record = Self.payloadRecord(
                    pushBlock: pushBlock, receivedAt: receivedAt, source: .wakeCancelled,
                    error: "No result within \(Int(WakeConfig.watchdogSeconds)) s; cancelled"
                )
                record = record.replacing(id: watchdogRecordID)
                record.wakeTimings = WakeTimings(trigger: "push", completedMs: budget.elapsedMs())
                watchdogCompletedMs.value = record.wakeTimings?.completedMs
                DispatchQueue.main.async {
                    self.appendRecord(record, ifAbsent: true)
                }
                completionHandler(.failed)
            }
        }

        DispatchQueue.global(qos: .userInitiated).async {
            let run = self.performWake(
                budget: budget, receivedAt: receivedAt, pushBlock: pushBlock,
                appInForeground: appInForeground, trigger: "push"
            )
            let completed = gate.fire {
                self.publish(
                    run, budget: budget, pushBlock: pushBlock, activity: activityController,
                    initialHeight: initialHeight, initialPeers: initialState.peerCount, isPush: true
                )
                completionHandler(run.fetchResult)
            }
            if !completed {
                // The watchdog already completed this wake. Keep widget and
                // history consistent with what Rust actually did: the real
                // result replaces the watchdog's record (same id, and the
                // completion time stays the watchdog's).
                StoragePaths.log.notice("wake: Rust returned after the watchdog, at \(budget.elapsedMs()) ms")
                if let status = run.status, status.blocksValidated > 0 {
                    SharedNodeStore.publishValidation(
                        height: status.currentHeight, blockHash: status.tipBlockHash, peerCount: run.peerCount
                    )
                }
                if var late = run.record, run.status != nil {
                    late = late.replacing(id: watchdogRecordID)
                    late.wakeTimings?.completedMs = watchdogCompletedMs.value ?? budget.elapsedMs()
                    DispatchQueue.main.async {
                        self.replaceRecord(late)
                    }
                }
            }
        }
    }

    // MARK: - Test Notification (for development without APNs)

    /// Simulate a push notification: runs the same wake path on the shared
    /// node. Reports "foreground active" if foreground sync is running.
    func testNotification(completion: @escaping (Result<BlockNotificationRecord, Error>) -> Void) {
        let budget = WakeBudget(budgetMs: WakeConfig.budgetMs)
        let receivedAt = Date()
        let appInForeground = UIApplication.shared.applicationState != .background
        SharedNodeStore.markAwake(true)
        let initialState = SharedNodeStore.load()
        let activityController: WakeActivityControllerProtocol
        if #available(iOS 16.2, *) {
            activityController = WakeActivityController()
        } else {
            activityController = NoopWakeActivityController()
        }
        activityController.start(
            initialHeight: initialState.blockHeight,
            peerCount: initialState.peerCount
        )

        DispatchQueue.global(qos: .userInitiated).async {
            let run = self.performWake(
                budget: budget, receivedAt: receivedAt, pushBlock: nil,
                appInForeground: appInForeground, trigger: "test"
            )
            self.publish(
                run, budget: budget, pushBlock: nil, activity: activityController,
                initialHeight: initialState.blockHeight, initialPeers: initialState.peerCount, isPush: true
            )
            DispatchQueue.main.async {
                if let record = run.record {
                    completion(.success(record))
                } else {
                    completion(.failure(StorageError.protectedDataUnavailable))
                }
            }
        }
    }

    // MARK: - Wake (ticket 028)

    /// One wake's result, ready to publish.
    private struct WakeRun {
        var record: BlockNotificationRecord?
        var status: CatchUpStatus?
        var peerCount: UInt32 = 0
        var fetchResult: UIBackgroundFetchResult
        /// Worth a local notification (wakes with a push payload, or progress).
        var notify: Bool
        var lockedSinceReboot = false
        /// Nothing failed (foreground handled it, node busy, reset): end the
        /// Live Activity without a failure state.
        var neutral = false
    }

    /// Run one wake on the shared node. Blocks; call off the main thread.
    /// Never throws: every outcome becomes a record.
    private func performWake(
        budget: WakeBudget,
        receivedAt: Date,
        pushBlock: PushBlockInfo?,
        appInForeground: Bool,
        trigger: String
    ) -> WakeRun {
        let fromPayload = { (source: NotificationSource, error: String?, timings: WakeTimings) -> BlockNotificationRecord in
            var record = Self.payloadRecord(pushBlock: pushBlock, receivedAt: receivedAt, source: source, error: error)
            record.wakeTimings = timings
            return record
        }
        do {
            switch try NodeHost.shared.runWake(budget: budget, appInForeground: appInForeground) {
            case .foregroundActive:
                return WakeRun(
                    record: fromPayload(.foregroundActive, nil, WakeTimings(trigger: trigger)),
                    fetchResult: .noData,
                    notify: false,
                    neutral: true
                )
            case let .ran(report, nodeReadyMs, nodeReused, peerCount, cancelReason):
                let timings = Self.timings(report, trigger: trigger, nodeReadyMs: nodeReadyMs, nodeReused: nodeReused)
                switch report.outcome {
                case .completed, .cancelled, .timedOut:
                    // A status counts only if headers were checked against
                    // peers (completed), blocks were actually validated, or
                    // peers disagreed (the eclipse alert survives a cancel);
                    // otherwise it is just the local tip.
                    if let status = report.status,
                       report.outcome == .completed || status.blocksValidated > 0 || status.tipDisagreement {
                        var record = Self.makeRecord(from: status, receivedAt: receivedAt)
                        record.wakeTimings = timings
                        return WakeRun(
                            record: record, status: status, peerCount: peerCount,
                            fetchResult: status.blocksValidated > 0 ? .newData : .noData,
                            notify: true
                        )
                    }
                    switch cancelReason {
                    case .foregroundStarted:
                        // Foreground sync started and took over the node.
                        return WakeRun(
                            record: fromPayload(.foregroundActive, nil, timings),
                            fetchResult: .noData, notify: false, neutral: true
                        )
                    case .reset:
                        return WakeRun(
                            record: fromPayload(.nodeReset, "Cancelled: the node is being reset", timings),
                            fetchResult: .noData, notify: false, neutral: true
                        )
                    case .none:
                        break
                    }
                    let why = report.outcome == .timedOut
                        ? (report.error ?? "Budget spent before peers answered")
                        : "Cancelled at \(report.elapsedMs) ms"
                    return WakeRun(
                        record: fromPayload(.wakeCancelled, why, timings),
                        fetchResult: .failed, notify: pushBlock != nil
                    )
                case .transportSlow:
                    return WakeRun(
                        record: fromPayload(.transportSlow, report.error ?? "Transport not ready", timings),
                        fetchResult: .failed, notify: pushBlock != nil
                    )
                case .busy:
                    return WakeRun(
                        record: fromPayload(.wakeBusy, "Node busy for the whole wake budget", timings),
                        fetchResult: .noData, notify: false, neutral: true
                    )
                case .failed:
                    return WakeRun(
                        record: fromPayload(.pushPayload, report.error ?? "Wake failed", timings),
                        fetchResult: .failed, notify: pushBlock != nil
                    )
                }
            }
        } catch StorageError.protectedDataUnavailable {
            // Locked since reboot (ticket 030): chain data is
            // completeUntilFirstUserAuthentication, so nothing can be
            // opened until the user unlocks once. Detected by the open(2)
            // probe in prepareForNodeOpen before any database is touched.
            // Deliberately NOT gated on UIApplication.isProtectedDataAvailable:
            // that tracks the `complete` class and goes false ~10 s after
            // every passcode lock, so it would skip every pocketed wake.
            return WakeRun(record: nil, fetchResult: .noData, notify: false, lockedSinceReboot: true)
        } catch NodeHost.HostError.resetting {
            return WakeRun(
                record: fromPayload(
                    .nodeReset, NodeHost.HostError.resetting.localizedDescription,
                    WakeTimings(trigger: trigger)
                ),
                fetchResult: .noData, notify: false, neutral: true
            )
        } catch {
            return WakeRun(
                record: fromPayload(.pushPayload, "\(error)", WakeTimings(trigger: trigger, completedMs: nil)),
                fetchResult: .failed, notify: pushBlock != nil
            )
        }
    }

    /// Publish a wake's result: widget, Live Activity, history, local
    /// notification, follow-up wake. `isPush` keeps the BG task's quieter
    /// behavior (widget only on progress, no notifications).
    private func publish(
        _ run: WakeRun,
        budget: WakeBudget,
        pushBlock: PushBlockInfo?,
        activity: WakeActivityControllerProtocol,
        initialHeight: UInt32,
        initialPeers: UInt32,
        isPush: Bool
    ) {
        if run.lockedSinceReboot {
            // markAwake is best-effort here (the App Group is unreadable
            // too, so the write usually fails).
            SharedNodeStore.markAwake(false)
            activity.finishFailure(height: initialHeight, peerCount: initialPeers)
            if isPush {
                Self.recordLockedSinceReboot(pushBlock: pushBlock)
            } else {
                // A BG refresh announced no block: nothing to tell the user.
                StoragePaths.log.notice("refresh skipped: device locked since reboot")
            }
            return
        }

        if let status = run.status {
            if isPush || status.blocksValidated > 0 {
                SharedNodeStore.publishValidation(
                    height: status.currentHeight,
                    blockHash: status.tipBlockHash,
                    peerCount: run.peerCount
                )
            }
            activity.finishSuccess(height: status.currentHeight, peerCount: run.peerCount)
            // If still behind, request a follow-up wake for accelerated catch-up
            if !status.caughtUp && status.blocksValidated > 0 {
                Self.requestFollowUpWake()
            }
        } else if run.neutral {
            SharedNodeStore.markAwake(false)
            activity.finishNeutral()
        } else {
            SharedNodeStore.markAwake(false)
            activity.finishFailure(height: initialHeight, peerCount: initialPeers)
        }

        guard var record = run.record else { return }
        if record.wakeTimings != nil {
            record.wakeTimings?.completedMs = budget.elapsedMs()
        }
        DispatchQueue.main.async {
            self.appendRecord(record)
        }
        guard isPush && run.notify else { return }
        if let status = run.status {
            Self.postLocalNotification(
                for: record,
                blocksValidated: status.blocksValidated,
                remaining: status.targetHeight - status.currentHeight
            )
        } else {
            Self.postLocalNotification(for: record)
        }
    }

    private static func timings(
        _ report: WakeReport,
        trigger: String,
        nodeReadyMs: UInt64,
        nodeReused: Bool
    ) -> WakeTimings {
        WakeTimings(
            trigger: trigger,
            nodeReadyMs: nodeReadyMs,
            nodeReused: nodeReused,
            transportReadyMs: report.timings.transportReadyMs,
            peersReadyMs: report.timings.peersReadyMs,
            headersCheckedMs: report.timings.headersCheckedMs,
            blocksDownloadedMs: report.timings.blocksDownloadedMs,
            validatedMs: report.timings.validatedMs,
            completedMs: nil,
            preemptedSync: report.preemptedSync ? true : nil
        )
    }

    /// A record built from the push payload (or, without one, the widget's
    /// last-known height) for wakes that didn't produce a catch-up status.
    private static func payloadRecord(
        pushBlock: PushBlockInfo?,
        receivedAt: Date,
        source: NotificationSource,
        error: String?
    ) -> BlockNotificationRecord {
        let known = pushBlock == nil ? SharedNodeStore.load() : nil
        return BlockNotificationRecord(
            id: UUID(),
            height: pushBlock?.height ?? known?.blockHeight ?? 0,
            blockHash: pushBlock?.hash ?? known?.blockHash ?? "",
            timestamp: pushBlock?.timestamp ?? 0,
            timestampHuman: "",
            validated: false,
            headerValidated: false,
            receivedAt: receivedAt,
            source: source,
            validationError: error
        )
    }

    // MARK: - Record Creation

    private static func makeRecord(from result: BlockNotification) -> BlockNotificationRecord {
        BlockNotificationRecord(
            id: UUID(),
            height: result.height,
            blockHash: result.blockHash,
            timestamp: result.timestamp,
            timestampHuman: result.timestampHuman,
            validated: result.validated,
            headerValidated: result.headerValidated,
            receivedAt: Date(),
            source: result.validated ? .fullValidation : (result.headerValidated ? .headerOnly : .pushPayload),
            validationError: result.validationError
        )
    }

    private static func makeRecord(from status: CatchUpStatus, receivedAt: Date = Date()) -> BlockNotificationRecord {
        let source: NotificationSource
        if status.tipDisagreement {
            source = .tipDisagreement
        } else if status.caughtUp {
            source = .fullValidation
        } else if status.blocksValidated > 0 {
            source = .catchUpProgress
        } else {
            source = .headerOnly
        }
        return BlockNotificationRecord(
            id: UUID(),
            height: status.currentHeight,
            blockHash: status.tipBlockHash,
            timestamp: status.tipTimestamp,
            timestampHuman: "",
            validated: status.caughtUp,
            headerValidated: true,
            receivedAt: receivedAt,
            source: source,
            validationError: status.error
        )
    }

    // MARK: - History

    /// `ifAbsent`: skip if a record with this id is already there (the
    /// watchdog's placeholder, when the real result landed first).
    private func appendRecord(_ record: BlockNotificationRecord, ifAbsent: Bool = false) {
        if ifAbsent && notificationHistory.contains(where: { $0.id == record.id }) {
            return
        }
        if !historyLoaded {
            guard let loaded = NotificationHistory.loadIfReadable() else {
                // Still unreadable: keep it in memory only, don't clobber the file.
                notificationHistory.insert(record, at: 0)
                return
            }
            // In-memory records arrived after the file was last written
            // (appended while it was unreadable), so they are newer: keep them first
            // so the prefix cap below drops the oldest, not the newest.
            notificationHistory = notificationHistory + loaded
            historyLoaded = true
        }
        notificationHistory.insert(record, at: 0)
        if notificationHistory.count > NotificationHistory.maxRecords {
            notificationHistory = Array(notificationHistory.prefix(NotificationHistory.maxRecords))
        }
        NotificationHistory.save(notificationHistory)
    }

    /// Replace the record with `record.id` (a watchdog placeholder) in
    /// place; append it if it's gone. Main thread.
    private func replaceRecord(_ record: BlockNotificationRecord) {
        guard historyLoaded, let i = notificationHistory.firstIndex(where: { $0.id == record.id }) else {
            appendRecord(record)
            return
        }
        notificationHistory[i] = record
        NotificationHistory.save(notificationHistory)
    }

    // MARK: - Local Notifications

    private static func postLocalNotification(
        for record: BlockNotificationRecord,
        blocksValidated: UInt32 = 1,
        remaining: UInt32 = 0
    ) {
        let content = UNMutableNotificationContent()

        switch record.source {
        case .fullValidation:
            content.title = "Block #\(record.height) Validated"
            content.body = "Fully validated with script verification"
        case .catchUpProgress:
            let startHeight = record.height - blocksValidated + 1
            content.title = "Catching up: blocks #\(startHeight)–#\(record.height)"
            content.body = "\(blocksValidated) blocks validated, \(remaining) remaining"
        case .tipDisagreement:
            content.title = "Chain Tip Disagreement"
            content.body = "Peers disagree on the chain tip at block #\(record.height). Retrying next wake."
        case .headerOnly:
            content.title = "Block #\(record.height) Header Verified"
            content.body = "PoW validated, full block validation pending"
        case .pushPayload:
            content.title = record.height > 0 ? "New Block #\(record.height)" : "New Block"
            content.body = "Received from relay (not yet validated)"
        case .networkPolicyPaused:
            content.title = "\(record.displayTitle) — Validation Paused"
            content.body = "Skipped to save cellular data. Connect to Wi-Fi or enable Use Cellular Data."
        case .foregroundActive:
            content.title = record.displayTitle
            content.body = "Being validated by the running app"
        case .transportSlow:
            content.title = "\(record.displayTitle) — Not Yet Validated"
            content.body = "The network was too slow during this wake. Hercules will validate on the next one."
        case .wakeBusy:
            content.title = "\(record.displayTitle) — Not Yet Validated"
            content.body = "The node was busy. Hercules will validate on the next wake."
        case .wakeCancelled:
            content.title = "\(record.displayTitle) — Not Yet Validated"
            content.body = "Ran out of background time. Hercules will validate on the next wake."
        case .nodeReset:
            content.title = "\(record.displayTitle) — Not Yet Validated"
            content.body = "The node is being reset."
        case .unknown:
            content.title = record.displayTitle
            content.body = record.validationError ?? ""
        }

        content.sound = .default
        content.userInfo = ["height": record.height, "hash": record.blockHash]

        let request = UNNotificationRequest(
            identifier: record.height > 0 ? "block-\(record.height)" : "block-\(record.blockHash)",
            content: content,
            trigger: nil // Deliver immediately
        )

        UNUserNotificationCenter.current().add(request)
    }

    // MARK: - Push Payload Parsing

    private struct PushBlockInfo {
        /// Nil when the relay didn't know the height. Older relays sent 0
        /// for unknown, which is treated the same way.
        let height: UInt32?
        let hash: String
        let timestamp: UInt32
    }

    private func parsePushPayload(_ userInfo: [AnyHashable: Any]) -> PushBlockInfo? {
        guard let block = userInfo["block"] as? [String: Any],
              let hash = block["hash"] as? String
        else {
            return nil
        }
        let rawHeight = (block["height"] as? NSNumber)?.uint32Value ?? 0
        let timestamp = (block["timestamp"] as? NSNumber)?.uint32Value ?? 0
        return PushBlockInfo(height: rawHeight > 0 ? rawHeight : nil, hash: hash, timestamp: timestamp)
    }

    // MARK: - Background Catch-Up Task

    /// `BGTASK_CATCHUP_ID` in Config/Shared.xcconfig (also generates the
    /// `BGTaskSchedulerPermittedIdentifiers` entry).
    static let catchUpTaskIdentifier = AppIdentifiers.catchUpTaskID

    /// Handle a BGAppRefreshTask for accelerated catch-up after a gap.
    func handleCatchUpTask(_ task: BGAppRefreshTask) {
        let budget = WakeBudget(budgetMs: WakeConfig.budgetMs)
        let receivedAt = Date()
        // setTaskCompleted exactly once: normal finish or expiration.
        let gate = OnceGate()

        // Expiration (ticket 028): cancel the Rust work, complete the task
        // ourselves, and ask for another wake to carry on.
        task.expirationHandler = {
            budget.cancel()
            gate.fire {
                StoragePaths.log.notice("refresh task expired at \(budget.elapsedMs()) ms")
                task.setTaskCompleted(success: false)
            }
            Self.requestFollowUpWake()
        }

        // Respect the same network policy gate as silent push wakes.
        guard NetworkPolicy.shared.shouldValidate else {
            gate.fire { task.setTaskCompleted(success: true) }
            return
        }

        if let free = StorageGuard.availableBytes(), free < StorageGuard.pauseBelowBytes {
            gate.fire { task.setTaskCompleted(success: true) }
            return
        }

        DispatchQueue.global(qos: .userInitiated).async {
            // Locked since reboot: performWake reports it without opening
            // anything (open(2) probe; this handler runs off the main thread).
            let run = self.performWake(
                budget: budget, receivedAt: receivedAt, pushBlock: nil,
                appInForeground: Self.appInForegroundNow(), trigger: "refresh"
            )
            // Published even if expiration already completed the task, so a
            // late result still reaches history and the widget.
            self.publish(
                run, budget: budget, pushBlock: nil, activity: NoopWakeActivityController(),
                initialHeight: 0, initialPeers: 0, isPush: false
            )
            gate.fire {
                task.setTaskCompleted(success: run.status != nil)
            }
        }
    }

    /// `applicationState` from any thread.
    private static func appInForegroundNow() -> Bool {
        if Thread.isMainThread {
            return UIApplication.shared.applicationState != .background
        }
        return DispatchQueue.main.sync { UIApplication.shared.applicationState != .background }
    }

    /// Request iOS to wake us again soon for continued catch-up.
    private static func requestFollowUpWake() {
        let request = BGAppRefreshTaskRequest(identifier: catchUpTaskIdentifier)
        request.earliestBeginDate = Date(timeIntervalSinceNow: 30)
        do {
            try BGTaskScheduler.shared.submit(request)
        } catch {
            // Non-fatal: next natural push wake from APNs will continue catch-up
        }
    }

    // MARK: - Locked since reboot

    /// Record a wake that arrived after a reboot but before the first
    /// unlock. Nothing on disk is writable in this state (history JSON,
    /// App Group, chain data), so the record is a log line plus one local
    /// notification with a fixed identifier: repeated wakes replace it
    /// rather than stacking, and it disappears from relevance once the user
    /// unlocks and the next wake validates normally.
    private static func recordLockedSinceReboot(pushBlock: PushBlockInfo?) {
        StoragePaths.log.notice("wake skipped: device locked since reboot (height \(pushBlock?.height ?? 0))")
        let content = UNMutableNotificationContent()
        content.title = pushBlock?.height.map { "Block #\($0) — Not Validated" } ?? "New Block — Not Validated"
        content.body = "iPhone locked since restart. Unlock once and Hercules will validate on the next block."
        let request = UNNotificationRequest(
            identifier: "locked-since-reboot",
            content: content,
            trigger: nil
        )
        UNUserNotificationCenter.current().add(request)
    }
}

// MARK: - Display

extension BlockNotificationRecord {
    /// "Block #N", or "New Block" when the height is unknown (0), e.g. a
    /// push from a relay whose blocknotify script didn't include height.
    var displayTitle: String {
        height > 0 ? "Block #\(height)" : "New Block"
    }
}

// MARK: - Relay install secret (Keychain)

/// Random per-install secret sent with relay registration so only this
/// install can update or unregister its row. One secret per relay host, so a
/// relay never learns a secret that works against another relay. Stored in
/// the Keychain with `AfterFirstUnlockThisDeviceOnly`: readable during
/// background wakes, never synced or migrated to another device.
enum RelayInstallSecret {
    private static let service = "dev.sermo.hercules.relay-install-secret"

    /// Returns the existing secret, creating one if none exists. Nil if the
    /// Keychain can't be read (e.g. before first unlock); never overwrites an
    /// existing item it failed to read.
    static func secret(forRelayHost host: String) -> String? {
        let account = host.lowercased()
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        if status == errSecSuccess,
           let data = item as? Data,
           let existing = String(data: data, encoding: .utf8) {
            return existing
        }
        guard status == errSecItemNotFound else { return nil }

        var bytes = [UInt8](repeating: 0, count: 32)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            return nil
        }
        let secret = bytes.map { String(format: "%02x", $0) }.joined()
        let add: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecValueData as String: Data(secret.utf8),
        ]
        return SecItemAdd(add as CFDictionary, nil) == errSecSuccess ? secret : nil
    }
}

// MARK: - Live Activity controller

/// Common surface so the wake handler doesn't need to branch on
/// `#available(iOS 16.2, *)` at every call site. The real implementation
/// (`WakeActivityController`) is gated; everything else gets a no-op.
protocol WakeActivityControllerProtocol {
    func start(initialHeight: UInt32, peerCount: UInt32)
    func finishSuccess(height: UInt32, peerCount: UInt32)
    func finishFailure(height: UInt32, peerCount: UInt32)
    /// End without a success or failure state (nothing ran, or it was
    /// handed off): the activity just goes away.
    func finishNeutral()
}

/// Fallback for iOS 16.0/16.1 — Live Activities aren't available so we
/// satisfy the protocol with no-ops. The widget extension still ships
/// (the home/lock-screen widget is iOS 17+ via project deployment target,
/// but the protocol surface is decoupled from the OS check).
final class NoopWakeActivityController: WakeActivityControllerProtocol {
    func start(initialHeight: UInt32, peerCount: UInt32) {}
    func finishSuccess(height: UInt32, peerCount: UInt32) {}
    func finishFailure(height: UInt32, peerCount: UInt32) {}
    func finishNeutral() {}
}

/// Owns one `Activity<NodeActivityAttributes>` for the lifetime of a
/// single push wake. Schedules heuristic phase transitions on a side
/// timer because the FFI's `validateLatestBlock` is a single blocking
/// call with no progress callback — we step through the visual phases on
/// fixed delays, then snap to `.done` or `.failed` when the call returns.
///
/// The heuristic schedule (4 s → 9 s → 16 s) is sized for the typical
/// 25-second wake budget. If validation finishes earlier than 16 s, the
/// `validating` transition simply never fires because `finishSuccess`
/// cancels the timer first.
@available(iOS 16.2, *)
final class WakeActivityController: WakeActivityControllerProtocol {
    private var activity: Activity<NodeActivityAttributes>?
    private var phaseTimer: DispatchSourceTimer?
    private let startedAt = Date()
    private let lock = NSLock()
    private var finished = false

    func start(initialHeight: UInt32, peerCount: UInt32) {
        guard ActivityAuthorizationInfo().areActivitiesEnabled else {
            // User has disabled Live Activities globally — silently bail.
            // The widget timeline still updates so they're not blind to
            // node state, just no per-wake activity.
            return
        }

        let attributes = NodeActivityAttributes(wakeId: UUID())
        let state = NodeActivityAttributes.ContentState(
            blockHeight: initialHeight,
            phase: .connecting,
            peerCount: peerCount,
            startedAt: startedAt
        )

        do {
            let content = ActivityContent(state: state, staleDate: nil)
            activity = try Activity<NodeActivityAttributes>.request(
                attributes: attributes,
                content: content,
                pushType: nil
            )
        } catch {
            print("Live Activity request failed: \(error.localizedDescription)")
            return
        }

        scheduleHeuristicTransitions(height: initialHeight, peerCount: peerCount)
    }

    func finishSuccess(height: UInt32, peerCount: UInt32) {
        end(phase: .done, height: height, peerCount: peerCount)
    }

    func finishFailure(height: UInt32, peerCount: UInt32) {
        end(phase: .failed, height: height, peerCount: peerCount)
    }

    func finishNeutral() {
        lock.lock()
        let alreadyFinished = finished
        finished = true
        lock.unlock()
        guard !alreadyFinished else { return }

        phaseTimer?.cancel()
        phaseTimer = nil
        guard let activity = activity else { return }
        Task {
            await activity.end(nil, dismissalPolicy: .immediate)
        }
    }

    // MARK: - Private

    private func scheduleHeuristicTransitions(height: UInt32, peerCount: UInt32) {
        // Three transitions: connecting → headers → block → validating.
        // The .done transition fires from finishSuccess instead.
        let transitions: [(delay: TimeInterval, phase: WakePhase)] = [
            (4, .headers),
            (9, .block),
            (16, .validating),
        ]

        let timer = DispatchSource.makeTimerSource(
            queue: DispatchQueue.global(qos: .utility)
        )
        var index = 0
        timer.schedule(deadline: .now() + transitions[0].delay)
        timer.setEventHandler { [weak self] in
            guard let self = self else { return }
            self.lock.lock()
            let stillRunning = !self.finished
            self.lock.unlock()
            guard stillRunning, index < transitions.count else {
                timer.cancel()
                return
            }
            let phase = transitions[index].phase
            self.update(phase: phase, height: height, peerCount: peerCount)
            index += 1
            if index < transitions.count {
                let next = transitions[index].delay - transitions[index - 1].delay
                timer.schedule(deadline: .now() + next)
            } else {
                timer.cancel()
            }
        }
        timer.resume()
        phaseTimer = timer
    }

    private func update(phase: WakePhase, height: UInt32, peerCount: UInt32) {
        guard let activity = activity else { return }
        let state = NodeActivityAttributes.ContentState(
            blockHeight: height,
            phase: phase,
            peerCount: peerCount,
            startedAt: startedAt
        )
        let content = ActivityContent(state: state, staleDate: nil)
        Task {
            await activity.update(content)
        }
    }

    private func end(phase: WakePhase, height: UInt32, peerCount: UInt32) {
        lock.lock()
        let alreadyFinished = finished
        finished = true
        lock.unlock()
        guard !alreadyFinished else { return }

        phaseTimer?.cancel()
        phaseTimer = nil

        guard let activity = activity else { return }
        let finalState = NodeActivityAttributes.ContentState(
            blockHeight: height,
            phase: phase,
            peerCount: peerCount,
            startedAt: startedAt
        )
        let content = ActivityContent(state: finalState, staleDate: nil)
        // Leave the activity on screen briefly so the user can glance at
        // the result, then let iOS dismiss it. 8 s is long enough to
        // notice but short enough that it doesn't clutter the Lock Screen.
        Task {
            await activity.end(
                content,
                dismissalPolicy: .after(Date().addingTimeInterval(8))
            )
        }
    }
}

/// A value shared between threads (the push watchdog and Rust's return).
final class LockedBox<T> {
    private let lock = NSLock()
    private var _value: T

    init(_ value: T) {
        _value = value
    }

    var value: T {
        get { lock.lock(); defer { lock.unlock() }; return _value }
        set { lock.lock(); _value = newValue; lock.unlock() }
    }
}

extension BlockNotificationRecord {
    /// The same record under another id.
    func replacing(id: UUID) -> BlockNotificationRecord {
        var copy = BlockNotificationRecord(
            id: id,
            height: height,
            blockHash: blockHash,
            timestamp: timestamp,
            timestampHuman: timestampHuman,
            validated: validated,
            headerValidated: headerValidated,
            receivedAt: receivedAt,
            source: source,
            validationError: validationError
        )
        copy.wakeTimings = wakeTimings
        return copy
    }
}
