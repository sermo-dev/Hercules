import Foundation

/// Wake budget numbers (ticket 028). Everything is measured from wake
/// receipt, when the `WakeBudget` is created, so node open and Tor
/// bootstrap count against the same clock as block work.
enum WakeConfig {
    /// Rust's budget for one silent push or BG refresh. iOS allows ~30 s.
    static let budgetMs: UInt32 = 25_000
    /// The push watchdog cancels Rust and calls the completion handler
    /// itself if Rust hasn't returned by then. Must stay under ~28 s.
    static let watchdogSeconds: TimeInterval = 27
    /// Skip network work if less than this is left once the transport is
    /// up: not enough for one block.
    static let minBlockMs: UInt32 = 8_000
    static let maxBlocks: UInt32 = 7

    // BG processing task (ticket 051): on power, minutes long, so it works
    // through a backlog in rounds. Each round is one wake on the shared
    // node, which re-checks the network policy and yields to foreground
    // sync between rounds; the expiration handler cancels the current one.
    static let processingRoundMs: UInt32 = 120_000
    static let processingMaxBlocks: UInt32 = 1_000
    static let processingMaxRounds = 30
}

/// Runs a body at most once. Wakes have several ways to finish (Rust
/// returns, the push watchdog, the BG task expiration handler) and iOS's
/// completion handler / `setTaskCompleted` must be called exactly once.
final class OnceGate {
    private let lock = NSLock()
    private var fired = false

    /// Runs `body` if nothing has fired yet. True if it ran.
    @discardableResult
    func fire(_ body: () -> Void) -> Bool {
        lock.lock()
        guard !fired else {
            lock.unlock()
            return false
        }
        fired = true
        lock.unlock()
        body()
        return true
    }
}

/// Something a wake can be cancelled through (`WakeBudget` in the app).
protocol WakeCancellable: AnyObject {
    func cancel()
}

/// Who is using the process's node (ticket 028). Pure bookkeeping with no
/// FFI, so `Tools/NodeHostScenarios` can drive it on macOS. Thread-safe.
///
/// Rust's session lock is what actually keeps two block appliers apart;
/// this decides whether a wake should run at all, and whether foreground
/// sync needs restarting after a wake stopped it.
final class NodeSessionState {
    enum Admission: Equatable {
        /// Run the wake. `preemptsForeground`: a foreground session was
        /// left running while the app is in the background; Rust stops its
        /// sync loop and the app restarts it when next active.
        case run(preemptsForeground: Bool)
        /// The app is on screen and syncing: foreground is already
        /// validating, so the wake records that and completes at once.
        case foregroundActive
    }

    private let lock = NSLock()
    private var foregroundSessions = 0
    private var foregroundPreempted = false
    private var wakes: [ObjectIdentifier: WakeCancellable] = [:]
    /// Why we (not iOS) cancelled a wake, so its record says "foreground"
    /// or "reset" rather than "ran out of time".
    private var cancelReasons: [ObjectIdentifier: WakeCancelReason] = [:]

    var isForegroundActive: Bool {
        lock.lock(); defer { lock.unlock() }
        return foregroundSessions > 0
    }

    var inFlightWakes: Int {
        lock.lock(); defer { lock.unlock() }
        return wakes.count
    }

    func admitWake(_ token: WakeCancellable, appInForeground: Bool) -> Admission {
        lock.lock(); defer { lock.unlock() }
        if foregroundSessions > 0 && appInForeground {
            return .foregroundActive
        }
        wakes[ObjectIdentifier(token)] = token
        if foregroundSessions > 0 {
            // Marked now, not when Rust reports back: the sync loop returns
            // (and asks `endForeground`) before the wake's call does.
            foregroundPreempted = true
            return .run(preemptsForeground: true)
        }
        return .run(preemptsForeground: false)
    }

    /// The wake returned. `stoppedForegroundSync` is Rust's report. If it
    /// didn't have to stop a sync loop (the session was between Rust calls,
    /// e.g. downloading the snapshot), nothing needs restarting. Returns
    /// why we cancelled the wake, if we did.
    @discardableResult
    func finishWake(_ token: WakeCancellable, stoppedForegroundSync: Bool) -> WakeCancelReason {
        lock.lock(); defer { lock.unlock() }
        let id = ObjectIdentifier(token)
        wakes.removeValue(forKey: id)
        if !stoppedForegroundSync && wakes.isEmpty {
            foregroundPreempted = false
        }
        return cancelReasons.removeValue(forKey: id) ?? .none
    }

    /// Foreground sync is starting. Cancels in-flight wakes so the node's
    /// session frees quickly.
    func beginForeground() {
        lock.lock()
        foregroundSessions += 1
        foregroundPreempted = false
        let running = Array(wakes.values)
        for id in wakes.keys where cancelReasons[id] == nil {
            cancelReasons[id] = .foregroundStarted
        }
        lock.unlock()
        running.forEach { $0.cancel() }
    }

    /// Foreground sync returned. True if a wake stopped it, so the app
    /// should start it again when it is next active.
    func endForeground() -> Bool {
        lock.lock(); defer { lock.unlock() }
        foregroundSessions = max(0, foregroundSessions - 1)
        let preempted = foregroundPreempted
        foregroundPreempted = false
        return preempted
    }

    /// The node is being reset: cancel every wake.
    func cancelAllWakes() {
        lock.lock()
        let running = Array(wakes.values)
        for id in wakes.keys where cancelReasons[id] == nil {
            cancelReasons[id] = .reset
        }
        lock.unlock()
        running.forEach { $0.cancel() }
    }
}

/// Why the app cancelled a wake (iOS cancelling it is `.none`).
enum WakeCancelReason: Equatable {
    case none
    case foregroundStarted
    case reset
}

/// What to do when a foreground sync session ends (ticket 028).
enum ForegroundRestart: Equatable {
    case none
    /// Start sync again now (the app is on screen).
    case now
    /// Start sync again when the app next becomes active.
    case whenActive

    /// A background wake stopped the session (`preempted`). Its loop
    /// either returned cleanly or, commonly after a long suspension with
    /// dead sockets, with an error such as "all peers disconnected". Either
    /// way it restarts, unless the user stopped it. The error from a
    /// preempted session isn't shown.
    static func decide(preempted: Bool, userStopped: Bool, appInForeground: Bool) -> ForegroundRestart {
        guard preempted && !userStopped else { return .none }
        return appInForeground ? .now : .whenActive
    }
}

/// One foreground sync session's flags, readable from its background
/// thread. `stopped`: the user pressed Stop; `retired`: a reset owns the
/// node now, so this session must stop touching the UI and cancel what it
/// can (a snapshot import).
final class SyncSessionToken {
    let generation: Int
    private let lock = NSLock()
    private var _stopped = false
    private var _retired = false
    private var _ended = false

    init(generation: Int) {
        self.generation = generation
    }

    var stopped: Bool {
        lock.lock(); defer { lock.unlock() }
        return _stopped
    }

    var retired: Bool {
        lock.lock(); defer { lock.unlock() }
        return _retired
    }

    /// Stopped or retired: don't start anything new.
    var isOver: Bool {
        lock.lock(); defer { lock.unlock() }
        return _stopped || _retired
    }

    func stop() {
        lock.lock(); _stopped = true; lock.unlock()
    }

    func retire() {
        lock.lock(); _retired = true; lock.unlock()
    }

    /// The session's thread has returned.
    var ended: Bool {
        lock.lock(); defer { lock.unlock() }
        return _ended
    }

    func markEnded() {
        lock.lock(); _ended = true; lock.unlock()
    }
}
