import XCTest

/// Ticket 054: record sources for wake results, quiet notifications, the
/// history file staying readable, and the storage layout helpers.
final class NotificationHistoryTests: XCTestCase {
    private func source(
        caughtUp: Bool = false, validated: UInt32 = 0, behind: Bool = false,
        confirmed: Bool = true, awaiting: Bool = false, disagreement: Bool = false, invalid: Bool = false
    ) -> NotificationSource {
        .catchUp(
            caughtUp: caughtUp, blocksValidated: validated, behind: behind, tipConfirmed: confirmed,
            awaitingSnapshot: awaiting, tipDisagreement: disagreement, invalidChain: invalid
        )
    }

    func testCatchUpSources() {
        XCTAssertEqual(source(caughtUp: true, validated: 1), .fullValidation)
        XCTAssertEqual(source(validated: 3, behind: true, confirmed: false), .catchUpProgress)
        XCTAssertEqual(source(validated: 1, confirmed: false), .unconfirmed,
                       "validated to the tip, but the tip wasn't confirmed: no fresh 'caught up'")
        XCTAssertEqual(source(confirmed: false), .unconfirmed)
        XCTAssertEqual(source(), .headerOnly)
        // Alerts win over everything.
        XCTAssertEqual(source(caughtUp: true, invalid: true), .invalidChain)
        XCTAssertEqual(source(disagreement: true, awaiting: true), .tipDisagreement)
        // Snapshot not loaded: never "Block #0 Header Verified".
        XCTAssertEqual(source(awaiting: true), .awaitingSetup)
        XCTAssertEqual(source(confirmed: false, awaiting: true), .awaitingSetup)
    }

    func testRoutineNotificationsAreQuietAndReplaceEachOther() {
        for routine: NotificationSource in [.fullValidation, .catchUpProgress, .headerOnly, .unconfirmed,
                                            .pushPayload, .networkPolicyPaused, .noNetwork, .wakeCancelled] {
            let style = routine.notificationStyle
            XCTAssertFalse(style.alerts, "\(routine)")
            XCTAssertEqual(style.identifier(height: 900_000, blockHash: "ab"), "block-latest", "\(routine)")
        }
        for alert: NotificationSource in [.tipDisagreement, .invalidChain] {
            let style = alert.notificationStyle
            XCTAssertTrue(style.alerts, "\(alert)")
            XCTAssertEqual(style.identifier(height: 7, blockHash: "ab"), "block-7")
            XCTAssertEqual(style.identifier(height: 0, blockHash: "ab"), "block-ab")
        }
        let setup = NotificationSource.awaitingSetup.notificationStyle
        XCTAssertFalse(setup.alerts, "finish setup comes without sound")
        XCTAssertEqual(setup.identifier(height: 5, blockHash: ""), "finish-setup")
    }

    func testNewSourcesRoundTripAndUnknownOnesDoNotCostTheHistory() throws {
        let record = BlockNotificationRecord(
            id: UUID(), height: 5, blockHash: "", timestamp: 0, timestampHuman: "",
            validated: false, headerValidated: true, receivedAt: Date(timeIntervalSince1970: 1),
            source: .unconfirmed, validationError: nil
        )
        let data = try JSONEncoder().encode([record])
        XCTAssertEqual(NotificationHistory.decode(data)?.first?.source, .unconfirmed)

        var json = String(data: data, encoding: .utf8)!
        json = json.replacingOccurrences(of: "\"unconfirmed\"", with: "\"fromTheFuture\"")
        let decoded = NotificationHistory.decode(Data(json.utf8))
        XCTAssertEqual(decoded?.count, 1)
        XCTAssertEqual(decoded?.first?.source, .unknown)
        XCTAssertNil(NotificationHistory.decode(Data("not json".utf8)))
    }

    func testParkedStampsAndAFreshLayoutIsReadable() throws {
        XCTAssertEqual(StoragePaths.parkedStamp("blocks.sqlite3.1700000000"), 1_700_000_000)
        XCTAssertNil(StoragePaths.parkedStamp("blocks.sqlite3"))
        let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: root) }
        let layout = StoragePaths.Layout(
            documents: root.appendingPathComponent("Documents"),
            applicationSupport: root.appendingPathComponent("Support")
        )
        XCTAssertTrue(StoragePaths.protectedDataReadable(layout), "nothing written yet: nothing locked")
    }
}
