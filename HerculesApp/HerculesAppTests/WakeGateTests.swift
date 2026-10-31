import XCTest

/// Ticket 054: the whole `WakeGate` table, for every kind of wake.
final class WakeGateTests: XCTestCase {
    private let floor: Int64 = 1_000

    /// The table, written as the ticket states it, independently of
    /// `WakeGate.decide`'s code.
    private func expected(_ kind: WakeGate.Kind, _ i: WakeGate.Inputs) -> WakeGate.Decision {
        if kind == .push, i.notificationsEnabled == false { return .skip(.notificationsOff) }
        if kind == .foreground, i.userPaused { return .skip(.userPaused) }
        if i.mode == nil { return .skip(.modeNotChosen) }
        if i.network == .offline { return .skip(.offline) }
        if i.network == .metered { return .skip(.metered) }
        if let free = i.freeBytes, free < floor { return .skip(.lowStorage(free: free)) }
        let pending = i.mode == .assumeUtxo && i.snapshotPending
        if pending {
            switch kind {
            case .processing, .foreground: return .skip(.snapshotPending)
            case .push, .test, .refresh: return .run(headersOnly: true)
            }
        }
        return .run(headersOnly: false)
    }

    func testEveryCombination() {
        let modes: [ValidationMode?] = [nil, .assumeUtxo, .fromGenesis]
        let enabled: [Bool?] = [true, false, nil]
        let storage: [Int64?] = [nil, floor - 1, floor, 10 * floor]
        var checked = 0
        for kind in WakeGate.Kind.allCases {
            for mode in modes {
                for pending in [false, true] {
                    for network in WakeGate.Network.allCases {
                        for on in enabled {
                            for free in storage {
                                for paused in [false, true] {
                                    let inputs = WakeGate.Inputs(
                                        mode: mode, snapshotPending: pending, network: network,
                                        notificationsEnabled: on, freeBytes: free,
                                        pauseBelowBytes: floor, userPaused: paused
                                    )
                                    XCTAssertEqual(
                                        WakeGate.decide(kind, inputs), expected(kind, inputs),
                                        "\(kind) \(inputs)"
                                    )
                                    checked += 1
                                }
                            }
                        }
                    }
                }
            }
        }
        XCTAssertEqual(checked, 5 * 3 * 2 * 3 * 3 * 4 * 2)
    }

    private func inputs(
        mode: ValidationMode? = .fromGenesis, pending: Bool = false,
        network: WakeGate.Network = .allowed, enabled: Bool? = true, free: Int64? = nil,
        paused: Bool = false
    ) -> WakeGate.Inputs {
        WakeGate.Inputs(
            mode: mode, snapshotPending: pending, network: network, notificationsEnabled: enabled,
            freeBytes: free, pauseBelowBytes: floor, userPaused: paused
        )
    }

    /// The bugs the ticket names, spelled out.
    func testTheTicketsCases() {
        // Notifications off in a warm process: the push does nothing.
        XCTAssertEqual(WakeGate.decide(.push, inputs(enabled: false)), .skip(.notificationsOff))
        // Before the first unlock the opt-in can't be read: not "off".
        XCTAssertEqual(WakeGate.decide(.push, inputs(enabled: nil)), .run(headersOnly: false))
        // Notifications enabled before any mode was chosen.
        XCTAssertEqual(WakeGate.decide(.push, inputs(mode: nil)), .skip(.modeNotChosen))
        XCTAssertEqual(WakeGate.decide(.refresh, inputs(mode: nil)), .skip(.modeNotChosen))
        // AssumeUTXO without its snapshot: wakes sync headers, nothing more.
        XCTAssertEqual(WakeGate.decide(.push, inputs(mode: .assumeUtxo, pending: true)), .run(headersOnly: true))
        XCTAssertEqual(WakeGate.decide(.processing, inputs(mode: .assumeUtxo, pending: true)), .skip(.snapshotPending))
        // Genesis mode never waits for a snapshot, whatever the hint says.
        XCTAssertEqual(WakeGate.decide(.processing, inputs(mode: .fromGenesis, pending: true)), .run(headersOnly: false))
        // Refresh and processing don't depend on notifications.
        XCTAssertEqual(WakeGate.decide(.refresh, inputs(enabled: false)), .run(headersOnly: false))
        XCTAssertEqual(WakeGate.decide(.processing, inputs(enabled: false)), .run(headersOnly: false))
        // The test button runs even with notifications off.
        XCTAssertEqual(WakeGate.decide(.test, inputs(enabled: false)), .run(headersOnly: false))
    }

    /// Section 4: opening the app starts sync once the node is set up,
    /// and a user Pause sticks.
    func testForegroundAutoStart() {
        XCTAssertEqual(WakeGate.decide(.foreground, inputs()), .run(headersOnly: false))
        XCTAssertEqual(WakeGate.decide(.foreground, inputs(mode: .assumeUtxo)), .run(headersOnly: false))
        XCTAssertEqual(WakeGate.decide(.foreground, inputs(paused: true)), .skip(.userPaused))
        XCTAssertEqual(WakeGate.decide(.foreground, inputs(mode: nil)), .skip(.modeNotChosen))
        // The first AssumeUTXO start downloads 8.8 GB: never on its own.
        XCTAssertEqual(WakeGate.decide(.foreground, inputs(mode: .assumeUtxo, pending: true)), .skip(.snapshotPending))
        XCTAssertEqual(WakeGate.decide(.foreground, inputs(network: .metered)), .skip(.metered))
        // Notifications have nothing to do with foreground sync.
        XCTAssertEqual(WakeGate.decide(.foreground, inputs(enabled: false)), .run(headersOnly: false))
    }
}

/// `NodeSetupState`: the app-side hints and the "sync wanted" memory.
final class NodeSetupStateTests: XCTestCase {
    private var suite: String!
    private var defaults: UserDefaults!

    override func setUp() {
        suite = "NodeSetupStateTests.\(UUID().uuidString)"
        defaults = UserDefaults(suiteName: suite)
    }

    override func tearDown() {
        defaults.removePersistentDomain(forName: suite)
    }

    func testPauseIsRememberedAcrossInstances() {
        XCTAssertFalse(NodeSetupState(defaults: defaults).syncPausedByUser, "sync wanted by default")
        NodeSetupState(defaults: defaults).syncPausedByUser = true
        XCTAssertTrue(NodeSetupState(defaults: defaults).syncPausedByUser)
        NodeSetupState(defaults: defaults).syncPausedByUser = false
        XCTAssertFalse(NodeSetupState(defaults: defaults).syncPausedByUser)
    }

    func testSnapshotPendingOnlyInAssumeUtxoMode() {
        let s = NodeSetupState(defaults: defaults)
        XCTAssertTrue(s.snapshotPending(mode: .assumeUtxo))
        XCTAssertFalse(s.snapshotPending(mode: .fromGenesis))
        XCTAssertFalse(s.snapshotPending(mode: nil))
        s.snapshotLoaded = true
        XCTAssertFalse(s.snapshotPending(mode: .assumeUtxo))
    }

    func testResetForgetsTheOldNode() {
        let s = NodeSetupState(defaults: defaults)
        s.snapshotLoaded = true
        s.finishSetupNotified = true
        s.syncPausedByUser = true
        s.resetForNewNode()
        XCTAssertFalse(s.snapshotLoaded)
        XCTAssertFalse(s.finishSetupNotified)
        XCTAssertTrue(s.syncPausedByUser, "a reset doesn't undo the user's Pause by itself")
    }
}
