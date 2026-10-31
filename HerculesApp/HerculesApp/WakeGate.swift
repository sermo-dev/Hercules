import Foundation

/// How the node builds its UTXO set on first run. (Moved here from
/// ContentView so wakes and the unit tests can use it, ticket 054.)
///
/// `assumeUtxo` downloads a hash-anchored snapshot — fast but anchored to a
/// constant baked into the app. `fromGenesis` validates every block from
/// height 0 — slower (weeks on a phone) but trusts only Bitcoin's consensus
/// rules. The choice is part of the node's identity for a given DB; switching
/// is destructive and goes through `NodeViewModel.resetAndRestart`.
///
/// The node records it too (ticket 054) and its copy is the one that
/// counts: `NodeHost` passes this one at open and adopts the node's.
enum ValidationMode: String {
    case assumeUtxo
    case fromGenesis
}

enum ValidationModePreference {
    static let key = "validationMode"

    static var current: ValidationMode? {
        get {
            UserDefaults.standard.string(forKey: key).flatMap(ValidationMode.init(rawValue:))
        }
        set {
            if let m = newValue {
                UserDefaults.standard.set(m.rawValue, forKey: key)
            } else {
                UserDefaults.standard.removeObject(forKey: key)
            }
        }
    }
}

/// App-side setup state that wakes read before opening the node (ticket
/// 054). Hints only: the node enforces the same rules itself (no block is
/// validated in AssumeUTXO mode before the snapshot loads), so a stale
/// value here costs a wasted or skipped wake, never a wrong chain.
final class NodeSetupState {
    static let shared = NodeSetupState()

    private enum Keys {
        static let snapshotLoaded = "nodeSetup.snapshotLoaded"
        static let syncPausedByUser = "nodeSetup.syncPausedByUser"
        static let finishSetupNotified = "nodeSetup.finishSetupNotified"
    }

    private let defaults: UserDefaults

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
    }

    /// The AssumeUTXO snapshot is in the node: set from the node's own
    /// answer (`needsSnapshot`, a wake's `awaitingSnapshot`), cleared by a
    /// reset.
    var snapshotLoaded: Bool {
        get { defaults.bool(forKey: Keys.snapshotLoaded) }
        set { defaults.set(newValue, forKey: Keys.snapshotLoaded) }
    }

    /// The user paused foreground sync (section 4: "sync wanted" is the
    /// default once set up). Survives relaunch; Resume clears it.
    var syncPausedByUser: Bool {
        get { defaults.bool(forKey: Keys.syncPausedByUser) }
        set { defaults.set(newValue, forKey: Keys.syncPausedByUser) }
    }

    /// The one "finish setup" notification was posted. Cleared when the
    /// snapshot loads or the node is reset, so it can be said again.
    var finishSetupNotified: Bool {
        get { defaults.bool(forKey: Keys.finishSetupNotified) }
        set { defaults.set(newValue, forKey: Keys.finishSetupNotified) }
    }

    /// A reset wiped the node: nothing about the old one carries over.
    func resetForNewNode() {
        snapshotLoaded = false
        finishSetupNotified = false
    }

    /// Whether the node, in `mode`, still waits for its snapshot.
    func snapshotPending(mode: ValidationMode?) -> Bool {
        mode == .assumeUtxo && !snapshotLoaded
    }
}

/// The one decision every wake makes before it touches the node (ticket
/// 054): push, BG refresh and BG processing all ask here, and so does
/// opening the app (whether to start foreground sync on its own). A pure
/// function of its inputs, so the whole table is unit-tested.
enum WakeGate {
    enum Kind: Equatable, CaseIterable {
        /// Silent push from the relay.
        case push
        /// The Settings "Test Notification" button: a push without the
        /// notifications-enabled check (the user asked for it).
        case test
        /// BGAppRefreshTask follow-up.
        case refresh
        /// BGProcessingTask: minutes of catch-up on power.
        case processing
        /// The app came to the foreground (section 4: auto-start sync).
        case foreground
    }

    enum Network: Equatable, CaseIterable {
        case allowed
        case offline
        /// Cellular, hotspot or Low Data Mode without the user's opt-in.
        case metered
    }

    struct Inputs: Equatable {
        var mode: ValidationMode?
        /// AssumeUTXO mode and the snapshot isn't loaded yet.
        var snapshotPending: Bool
        var network: Network
        /// Nil when it can't be known: a push that cold-launches the app
        /// before the first unlock reads UserDefaults as empty, and must
        /// not take that for "off" (the wake then reports "locked since
        /// reboot" instead of vanishing).
        var notificationsEnabled: Bool?
        /// Free bytes, nil if unknown.
        var freeBytes: Int64?
        var pauseBelowBytes: Int64
        /// Foreground only: the user paused sync.
        var userPaused: Bool = false
    }

    enum Skip: Equatable {
        /// Notifications are off; a push still arriving is the relay not
        /// having heard yet (ticket 054).
        case notificationsOff
        /// No validation mode chosen: nothing to sync for.
        case modeNotChosen
        case offline
        case metered
        case lowStorage(free: Int64)
        /// AssumeUTXO without its snapshot: long catch-up (and foreground
        /// auto-start, which would start the 8.8 GB download) wait for it.
        case snapshotPending
        /// Foreground: the user paused sync.
        case userPaused
    }

    enum Decision: Equatable {
        /// `headersOnly`: AssumeUTXO without its snapshot; the node syncs
        /// headers only and the wake says setup isn't finished.
        case run(headersOnly: Bool)
        case skip(Skip)
    }

    static func decide(_ kind: Kind, _ inputs: Inputs) -> Decision {
        if kind == .push && inputs.notificationsEnabled == false {
            return .skip(.notificationsOff)
        }
        if kind == .foreground && inputs.userPaused {
            return .skip(.userPaused)
        }
        guard inputs.mode != nil else { return .skip(.modeNotChosen) }
        switch inputs.network {
        case .offline: return .skip(.offline)
        case .metered: return .skip(.metered)
        case .allowed: break
        }
        if let free = inputs.freeBytes, free < inputs.pauseBelowBytes {
            return .skip(.lowStorage(free: free))
        }
        let pending = inputs.mode == .assumeUtxo && inputs.snapshotPending
        if pending && (kind == .processing || kind == .foreground) {
            return .skip(.snapshotPending)
        }
        return .run(headersOnly: pending)
    }
}
