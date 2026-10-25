import Foundation

/// How the block notification was verified.
enum NotificationSource: String, Codable {
    case fullValidation     // Block downloaded and scripts verified
    case headerOnly         // Header PoW verified, no full block
    case pushPayload        // Info from push relay only, not verified
    case catchUpProgress    // Multi-block catch-up (some blocks validated, more remain)
    case tipDisagreement    // Header cross-check detected peer disagreement (possible eclipse)
    case networkPolicyPaused // Validation skipped: metered network without opt-in
    // Ticket 028 wake outcomes
    case foregroundActive   // App on screen and syncing: the wake left it to foreground
    case transportSlow      // Transport not up with enough budget left for a block
    case wakeBusy           // Node busy (e.g. snapshot import) for the whole budget
    case wakeCancelled      // BG task expired or the push watchdog fired
}

/// Where a wake's time went, in milliseconds since it arrived (ticket 028).
/// Nil phases weren't reached. Collected to size the wake budget, peer
/// fanout and transport choices on real hardware.
struct WakeTimings: Codable, Equatable {
    /// "push", "refresh" (BG task) or "test".
    var trigger: String?
    var nodeReadyMs: UInt64?
    /// The node was already open in this process (no DB open, warm Tor).
    var nodeReused: Bool?
    var transportReadyMs: UInt64?
    /// The wake's peer pool finished its initial handshakes.
    var peersReadyMs: UInt64?
    var headersCheckedMs: UInt64?
    var blocksDownloadedMs: UInt64?
    var validatedMs: UInt64?
    /// Just before the completion handler / setTaskCompleted was called.
    var completedMs: UInt64?
    /// A sync loop left running in the background was stopped for this wake.
    var preemptedSync: Bool?
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
    /// Wake records only; nil for older records and non-wake sources.
    var wakeTimings: WakeTimings? = nil
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
