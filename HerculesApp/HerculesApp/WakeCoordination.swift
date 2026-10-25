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

    var isForegroundActive: Bool {
        lock.lock(); defer { lock.unlock() }
        return foregroundSessions > 0
    }

    var inFlightWakes: Int {
        lock.lock(); defer { lock.unlock() }
        return wakes.count
    }

    func admitWake(_ token: WakeCancellable, appIsActive: Bool) -> Admission {
        lock.lock(); defer { lock.unlock() }
        if foregroundSessions > 0 && appIsActive {
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
    /// e.g. downloading the snapshot), nothing needs restarting.
    func finishWake(_ token: WakeCancellable, stoppedForegroundSync: Bool) {
        lock.lock(); defer { lock.unlock() }
        wakes.removeValue(forKey: ObjectIdentifier(token))
        if !stoppedForegroundSync && wakes.isEmpty {
            foregroundPreempted = false
        }
    }

    /// Foreground sync is starting. Cancels in-flight wakes so the node's
    /// session frees quickly.
    func beginForeground() {
        lock.lock()
        foregroundSessions += 1
        foregroundPreempted = false
        let running = Array(wakes.values)
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

    func cancelAllWakes() {
        lock.lock()
        let running = Array(wakes.values)
        lock.unlock()
        running.forEach { $0.cancel() }
    }
}
