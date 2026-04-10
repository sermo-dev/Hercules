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
        guard let data = try? Data(contentsOf: filePath),
              let records = try? JSONDecoder().decode([BlockNotificationRecord].self, from: data)
        else {
            return []
        }
        return records
    }

    static func save(_ records: [BlockNotificationRecord]) {
        let trimmed = Array(records.prefix(maxRecords))
        guard let data = try? JSONEncoder().encode(trimmed) else { return }
        try? data.write(to: filePath, options: .atomic)
    }
}
