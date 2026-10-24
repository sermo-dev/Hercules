import Foundation

/// How the block notification was verified.
enum NotificationSource: String, Codable {
    case fullValidation     // Block downloaded and scripts verified
    case headerOnly         // Header PoW verified, no full block
    case pushPayload        // Info from push relay only, not verified
    case catchUpProgress    // Multi-block catch-up (some blocks validated, more remain)
    case tipDisagreement    // Header cross-check detected peer disagreement (possible eclipse)
    case networkPolicyPaused // Validation skipped: metered network without opt-in
}

/// A record of a block notification, persisted to disk.
struct BlockNotificationRecord: Codable, Identifiable {
    let id: UUID
    let height: UInt32
    let blockHash: String
    let timestamp: UInt32
    let timestampHuman: String
    let validated: Bool
    let headerValidated: Bool
    let receivedAt: Date
    let source: NotificationSource
    let validationError: String?
}

/// Simple JSON file persistence for notification history.
enum NotificationHistory {
    static let maxRecords = 100

    private static var filePath: URL {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
        return docs.appendingPathComponent("notification-history.json")
    }

    static func load() -> [BlockNotificationRecord] {
        loadIfReadable() ?? []
    }

    /// Like `load`, but returns nil when the file exists and can't be read
    /// (e.g. a push wake after reboot before first unlock — the file is
    /// `completeUntilFirstUserAuthentication`). Lets the caller avoid
    /// overwriting real history with an empty in-memory copy (ticket 030).
    static func loadIfReadable() -> [BlockNotificationRecord]? {
        let data: Data
        do {
            data = try Data(contentsOf: filePath)
        } catch {
            return FileManager.default.fileExists(atPath: filePath.path) ? nil : []
        }
        return (try? JSONDecoder().decode([BlockNotificationRecord].self, from: data)) ?? []
    }

    static func save(_ records: [BlockNotificationRecord]) {
        let trimmed = Array(records.prefix(maxRecords))
        guard let data = try? JSONEncoder().encode(trimmed) else { return }
        try? data.write(to: filePath, options: .atomic)
    }
}
