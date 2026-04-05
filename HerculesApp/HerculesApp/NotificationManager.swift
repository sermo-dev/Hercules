import Foundation
import UserNotifications
import UIKit

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
        get { UserDefaults.standard.string(forKey: "relayServerURL") ?? "https://hercules-relay.example.com" }
        set { UserDefaults.standard.set(newValue, forKey: "relayServerURL") }
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

    /// Called when APNs returns a device token.
    func handleDeviceToken(_ token: String) {
        DispatchQueue.main.async {
            self.deviceToken = token
            self.registrationError = nil
        }
        registerWithRelay(token: token)
    }

    /// Called when APNs registration fails (e.g., no developer account).
    func handleRegistrationError(_ error: Error) {
        DispatchQueue.main.async {
            self.registrationError = error.localizedDescription
        }
    }

    // MARK: - Relay Registration

    /// Send device token to the relay server.
    private func registerWithRelay(token: String) {
        guard let url = URL(string: "\(relayServerURL)/register") else { return }

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.timeoutInterval = 15

        let body: [String: String] = ["device_token": token, "platform": "ios"]
        request.httpBody = try? JSONSerialization.data(withJSONObject: body)

        URLSession.shared.dataTask(with: request) { _, response, error in
            if let error = error {
                // Relay registration failed — not critical, will retry on next launch
                print("Relay registration failed: \(error.localizedDescription)")
                return
            }
            if let http = response as? HTTPURLResponse, http.statusCode == 200 {
                print("Relay registration successful")
            }
        }.resume()
    }

    // MARK: - Silent Push Handling

    /// Handle a silent push notification. Creates a HerculesNode, validates
    /// the latest block within 25 seconds, and posts a local notification.
    func handleSilentPush(
        userInfo: [AnyHashable: Any],
        completionHandler: @escaping (UIBackgroundFetchResult) -> Void
    ) {
        // Parse block info from push payload (used as fallback if validation fails)
        let pushBlock = parsePushPayload(userInfo)

        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let dbPath = Self.dbPath()
                let torDir = Self.torDataDir()
                let node = try HerculesNode(dbPath: dbPath, torDataDir: torDir)

                // 25 seconds — leaving 5s margin within the 30s iOS window
                let result = try node.validateLatestBlock(timeoutSecs: 25)

                let record = BlockNotificationRecord(
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

                DispatchQueue.main.async {
                    self.appendRecord(record)
                }

                Self.postLocalNotification(for: record)
                completionHandler(.newData)

            } catch {
                // Validation failed — post notification from push payload if available
                if let push = pushBlock {
                    let record = BlockNotificationRecord(
                        id: UUID(),
                        height: push.height,
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
        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let dbPath = Self.dbPath()
                let torDir = Self.torDataDir()
                let node = try HerculesNode(dbPath: dbPath, torDataDir: torDir)

                let result = try node.validateLatestBlock(timeoutSecs: 25)

                let record = BlockNotificationRecord(
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

                DispatchQueue.main.async {
                    self.appendRecord(record)
                    Self.postLocalNotification(for: record)
                    completion(.success(record))
                }
            } catch {
                DispatchQueue.main.async {
                    completion(.failure(error))
                }
            }
        }
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

    private static func postLocalNotification(for record: BlockNotificationRecord) {
        let content = UNMutableNotificationContent()

        switch record.source {
        case .fullValidation:
            content.title = "Block #\(record.height) Validated"
            content.body = "Fully validated with script verification"
        case .headerOnly:
            content.title = "Block #\(record.height) Header Verified"
            content.body = "PoW validated, full block validation pending"
        case .pushPayload:
            content.title = "New Block #\(record.height)"
            content.body = "Received from relay (not yet validated)"
        }

        content.sound = .default
        content.userInfo = ["height": record.height, "hash": record.blockHash]

        let request = UNNotificationRequest(
            identifier: "block-\(record.height)",
            content: content,
            trigger: nil // Deliver immediately
        )

        UNUserNotificationCenter.current().add(request)
    }

    // MARK: - Push Payload Parsing

    private struct PushBlockInfo {
        let height: UInt32
        let hash: String
        let timestamp: UInt32
    }

    private func parsePushPayload(_ userInfo: [AnyHashable: Any]) -> PushBlockInfo? {
        guard let block = userInfo["block"] as? [String: Any],
              let height = block["height"] as? UInt32,
              let hash = block["hash"] as? String,
              let timestamp = block["timestamp"] as? UInt32
        else {
            return nil
        }
        return PushBlockInfo(height: height, hash: hash, timestamp: timestamp)
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
