import Foundation

/// The only code allowed to construct a `HerculesNode` (ticket 028).
///
/// Foreground sync and every background wake share one node per process.
/// Two nodes on the same files would mean two Tor clients and, worse, two
/// `HeaderSync`s applying blocks to the same LMDB env: heed hands the
/// second open the same env rather than refusing it. (Rust now refuses a
/// second open of the same database too.) The node also keeps its warm Tor
/// client across wakes, since iOS usually suspends the process between
/// them rather than killing it.
///
/// Reusing a node after a long suspension is safe: peer connections
/// belong to one sync or catch-up session, so every wake opens fresh ones,
/// and Arti rebuilds its circuits on demand.
final class NodeHost {
    static let shared = NodeHost()

    let sessions = NodeSessionState()

    enum HostError: LocalizedError {
        /// `reset` is running; nothing may open the node until it's done.
        case resetting
        /// The old node didn't let go of its files in time; nothing was deleted.
        case resetTimedOut

        var errorDescription: String? {
            switch self {
            case .resetting:
                return "The node is being reset"
            case .resetTimedOut:
                return "The node is still shutting down. Nothing was deleted; try again in a moment."
            }
        }
    }

    private let lock = NSLock()
    private var current: HerculesNode?
    private var resetting = false
    /// Nodes opened in this process, for the "no second node" log check.
    private var opens = 0

    private init() {}

    /// The process's node, opened on first use. Opening doesn't wait for
    /// Tor: bootstrap runs in the background and each caller waits only
    /// as long as its own budget allows. Throws
    /// `StorageError.protectedDataUnavailable` if locked since reboot, and
    /// `HostError.resetting` while a reset runs.
    func node() throws -> (node: HerculesNode, reused: Bool) {
        lock.lock(); defer { lock.unlock() }
        if resetting {
            throw HostError.resetting
        }
        if let node = current {
            return (node, true)
        }
        try StoragePaths.prepareForNodeOpen()
        let node = try HerculesNode.open(
            dbPath: StoragePaths.headersDBPath,
            torDataDir: StoragePaths.torDataDir
        )
        opens += 1
        StoragePaths.log.notice("NodeHost: opened node (\(self.opens) in this process)")
        current = node
        return (node, false)
    }

    /// Close the node and delete its chain data (validation-mode switch).
    /// Blocks; call off the main thread, after dropping any reference of
    /// your own to the node.
    ///
    /// `node()` is refused for the whole operation, so no wake or
    /// foreground start can reopen it halfway. The node is closed (sync
    /// loop stopped, transport waits ended, wakes cancelled), then the
    /// files are deleted once every holder has let go: Rust's
    /// `resetDatabase` refuses while any reference to the old node is
    /// alive, and is retried. One `timeout` covers the close and the
    /// retries together; on timeout nothing has been deleted.
    func reset(timeout: TimeInterval = 30) throws {
        let deadline = Date().addingTimeInterval(timeout)
        lock.lock()
        if resetting {
            lock.unlock()
            throw HostError.resetting
        }
        resetting = true
        var old = current
        current = nil
        lock.unlock()
        defer {
            lock.lock()
            resetting = false
            lock.unlock()
        }

        sessions.cancelAllWakes()
        if let node = old {
            let left = max(0, deadline.timeIntervalSinceNow)
            _ = node.close(timeoutMs: UInt32(left * 1000))
        }
        old = nil
        StoragePaths.log.notice("NodeHost: node closed for reset")

        try StoragePaths.prepareForNodeOpen()
        while true {
            do {
                try resetDatabase(dbPath: StoragePaths.headersDBPath)
                StoragePaths.log.notice("NodeHost: reset complete")
                return
            } catch HerculesError.NodeOpen {
                // A wake or the old sync thread hasn't returned yet.
                guard Date() < deadline else { throw HostError.resetTimedOut }
                Thread.sleep(forTimeInterval: 0.1)
            }
        }
    }

    enum WakeResult {
        /// The app is on screen and syncing; nothing was run.
        case foregroundActive
        /// `cancelReason`: why the app (not iOS) cancelled the wake, if it did.
        case ran(
            WakeReport, nodeReadyMs: UInt64, nodeReused: Bool, peerCount: UInt32,
            cancelReason: WakeCancelReason
        )
    }

    /// Run one wake's catch-up on the shared node. Blocks; call it off the
    /// main thread. `appInForeground` must be read on the main thread when the
    /// wake arrives. `maxBlocks` is larger for a BG processing round.
    func runWake(
        budget: WakeBudget,
        appInForeground: Bool,
        maxBlocks: UInt32 = WakeConfig.maxBlocks
    ) throws -> WakeResult {
        switch sessions.admitWake(budget, appInForeground: appInForeground) {
        case .foregroundActive:
            StoragePaths.log.notice("wake: foreground sync active, not running")
            return .foregroundActive
        case .run(let preemptsForeground):
            var stoppedSync = false
            var finished = false
            defer {
                if !finished { sessions.finishWake(budget, stoppedForegroundSync: false) }
            }
            if preemptsForeground {
                StoragePaths.log.notice("wake: app in background with sync running, preempting it")
            }
            let (node, reused) = try node()
            let nodeReadyMs = budget.elapsedMs()
            let report = node.wakeCatchUp(
                budget: budget,
                maxBlocks: maxBlocks,
                minBlockMs: WakeConfig.minBlockMs
            )
            stoppedSync = report.preemptedSync
            let peerCount = UInt32((try? node.getStatus().peers.count) ?? 0)
            finished = true
            let reason = sessions.finishWake(budget, stoppedForegroundSync: stoppedSync)
            StoragePaths.log.notice(
                "wake: \(String(describing: report.outcome)) in \(report.elapsedMs) ms (node \(reused ? "reused" : "opened") at \(nodeReadyMs) ms)"
            )
            return .ran(
                report, nodeReadyMs: nodeReadyMs, nodeReused: reused, peerCount: peerCount,
                cancelReason: reason
            )
        }
    }
}

extension WakeBudget: WakeCancellable {}
