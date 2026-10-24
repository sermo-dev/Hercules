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
        notificationHistory = NotificationHistory.load()
    }

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

    /// Handle a silent push notification. Creates a HerculesNode, validates
    /// the latest block within 25 seconds, and posts a local notification.
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
                    receivedAt: Date(),
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

        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let dbPath = Self.dbPath()
                let torDir = Self.torDataDir()
                let node = try HerculesNode(dbPath: dbPath, torDataDir: torDir)

                // 25 seconds, up to 7 blocks — leaving 5s margin within the 30s iOS window
                let status = try node.catchUpBlocks(maxBlocks: 7, budgetSecs: 25)
                let record = Self.makeRecord(from: status)

                let peerCount = (try? node.getStatus().peers.count) ?? 0
                SharedNodeStore.publishValidation(
                    height: status.currentHeight,
                    blockHash: status.tipBlockHash,
                    peerCount: UInt32(peerCount)
                )

                activityController.finishSuccess(
                    height: status.currentHeight,
                    peerCount: UInt32(peerCount)
                )

                DispatchQueue.main.async {
                    self.appendRecord(record)
                }

                Self.postLocalNotification(for: record, blocksValidated: status.blocksValidated, remaining: status.targetHeight - status.currentHeight)

                // If still behind, request a follow-up wake for accelerated catch-up
                if !status.caughtUp && status.blocksValidated > 0 {
                    Self.requestFollowUpWake()
                }

                completionHandler(.newData)

            } catch {
                SharedNodeStore.markAwake(false)
                activityController.finishFailure(
                    height: initialHeight,
                    peerCount: initialState.peerCount
                )
                // Validation failed — post notification from push payload if available
                if let push = pushBlock {
                    let record = BlockNotificationRecord(
                        id: UUID(),
                        height: push.height ?? 0,
                        blockHash: push.hash,
                        timestamp: push.timestamp,
                        timestampHuman: "",
                        validated: false,
                        headerValidated: false,
                        receivedAt: Date(),
                        source: .pushPayload,
                        validationError: "\(error)"
                    )
                    DispatchQueue.main.async {
                        self.appendRecord(record)
                    }
                    Self.postLocalNotification(for: record)
                }
                completionHandler(.failed)
            }
        }
    }

    // MARK: - Test Notification (for development without APNs)

    /// Simulate a push notification by running validate_latest_block directly.
    func testNotification(completion: @escaping (Result<BlockNotificationRecord, Error>) -> Void) {
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
            do {
                let dbPath = Self.dbPath()
                let torDir = Self.torDataDir()
                let node = try HerculesNode(dbPath: dbPath, torDataDir: torDir)

                let status = try node.catchUpBlocks(maxBlocks: 7, budgetSecs: 25)
                let record = Self.makeRecord(from: status)

                let peerCount = (try? node.getStatus().peers.count) ?? 0
                SharedNodeStore.publishValidation(
                    height: status.currentHeight,
                    blockHash: status.tipBlockHash,
                    peerCount: UInt32(peerCount)
                )

                activityController.finishSuccess(
                    height: status.currentHeight,
                    peerCount: UInt32(peerCount)
                )

                DispatchQueue.main.async {
                    self.appendRecord(record)
                    Self.postLocalNotification(for: record, blocksValidated: status.blocksValidated, remaining: status.targetHeight - status.currentHeight)
                    completion(.success(record))
                }
            } catch {
                SharedNodeStore.markAwake(false)
                activityController.finishFailure(
                    height: initialState.blockHeight,
                    peerCount: initialState.peerCount
                )
                DispatchQueue.main.async {
                    completion(.failure(error))
                }
            }
        }
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

    private static func makeRecord(from status: CatchUpStatus) -> BlockNotificationRecord {
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
            receivedAt: Date(),
            source: source,
            validationError: status.error
        )
    }

    // MARK: - History

    private func appendRecord(_ record: BlockNotificationRecord) {
        notificationHistory.insert(record, at: 0)
        if notificationHistory.count > NotificationHistory.maxRecords {
            notificationHistory = Array(notificationHistory.prefix(NotificationHistory.maxRecords))
        }
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
        // Respect the same network policy gate as silent push wakes.
        guard NetworkPolicy.shared.shouldValidate else {
            task.setTaskCompleted(success: true)
            return
        }

        task.expirationHandler = { /* Rust respects budget_secs */ }

        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let node = try HerculesNode(
                    dbPath: Self.dbPath(),
                    torDataDir: Self.torDataDir()
                )
                let status = try node.catchUpBlocks(maxBlocks: 7, budgetSecs: 25)

                // Update widget with new height
                if status.blocksValidated > 0 {
                    let peerCount = (try? node.getStatus().peers.count) ?? 0
                    SharedNodeStore.publishValidation(
                        height: status.currentHeight,
                        blockHash: status.tipBlockHash,
                        peerCount: UInt32(peerCount)
                    )
                }

                if !status.caughtUp && status.blocksValidated > 0 {
                    Self.requestFollowUpWake()
                }

                let record = Self.makeRecord(from: status)
                DispatchQueue.main.async {
                    self.appendRecord(record)
                }

                task.setTaskCompleted(success: true)
            } catch {
                task.setTaskCompleted(success: false)
            }
        }
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

    // MARK: - Paths

    private static func dbPath() -> String {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
        return docs.appendingPathComponent("hercules-headers.sqlite3").path
    }

    private static func torDataDir() -> String {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
        return docs.appendingPathComponent("tor").path
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
}

/// Fallback for iOS 16.0/16.1 — Live Activities aren't available so we
/// satisfy the protocol with no-ops. The widget extension still ships
/// (the home/lock-screen widget is iOS 17+ via project deployment target,
/// but the protocol surface is decoupled from the OS check).
final class NoopWakeActivityController: WakeActivityControllerProtocol {
    func start(initialHeight: UInt32, peerCount: UInt32) {}
    func finishSuccess(height: UInt32, peerCount: UInt32) {}
    func finishFailure(height: UInt32, peerCount: UInt32) {}
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
