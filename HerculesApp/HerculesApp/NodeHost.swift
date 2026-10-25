import Foundation

/// The only code allowed to construct a `HerculesNode` (ticket 028).
///
/// Foreground sync and every background wake share one node per process.
/// Two nodes on the same files would mean two Tor clients and, worse, two
/// `HeaderSync`s applying blocks to the same LMDB env: heed hands the
/// second open the same env rather than refusing it. The node also keeps
/// its warm Tor client across wakes, since iOS usually suspends the
/// process between them rather than killing it.
///
/// Reusing a node after a long suspension is safe: peer connections
/// belong to one sync or catch-up session, so every wake opens fresh ones,
/// and Arti rebuilds its circuits on demand.
final class NodeHost {
    static let shared = NodeHost()

    let sessions = NodeSessionState()

    private let lock = NSLock()
    private var current: HerculesNode?
    /// Nodes opened in this process, for the "no second node" log check.
    private var opens = 0

    private init() {}

    /// The process's node, opened on first use. Opening doesn't wait for
    /// Tor: bootstrap runs in the background and each caller waits only
    /// as long as its own budget allows. Throws
    /// `StorageError.protectedDataUnavailable` if locked since reboot.
    func node() throws -> (node: HerculesNode, reused: Bool) {
        lock.lock(); defer { lock.unlock() }
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

    /// Drop the node so its files can be deleted (reset). Callers stop
    /// foreground sync first; in-flight wakes are cancelled and release
    /// their reference when they return.
    func discard() {
        sessions.cancelAllWakes()
        lock.lock()
        current = nil
        lock.unlock()
        StoragePaths.log.notice("NodeHost: node discarded")
    }

    enum WakeResult {
        /// The app is on screen and syncing; nothing was run.
        case foregroundActive
        case ran(WakeReport, nodeReadyMs: UInt64, nodeReused: Bool, peerCount: UInt32)
    }

    /// Run one wake's catch-up on the shared node. Blocks; call it off the
    /// main thread. `appIsActive` must be read on the main thread when the
    /// wake arrives.
    func runWake(budget: WakeBudget, appIsActive: Bool) throws -> WakeResult {
        switch sessions.admitWake(budget, appIsActive: appIsActive) {
        case .foregroundActive:
            StoragePaths.log.notice("wake: foreground sync active, not running")
            return .foregroundActive
        case .run(let preemptsForeground):
            var stoppedSync = false
            defer { sessions.finishWake(budget, stoppedForegroundSync: stoppedSync) }
            if preemptsForeground {
                StoragePaths.log.notice("wake: app in background with sync running, preempting it")
            }
            let (node, reused) = try node()
            let nodeReadyMs = budget.elapsedMs()
            let report = node.wakeCatchUp(
                budget: budget,
                maxBlocks: WakeConfig.maxBlocks,
                minBlockMs: WakeConfig.minBlockMs
            )
            stoppedSync = report.preemptedSync
            let peerCount = UInt32((try? node.getStatus().peers.count) ?? 0)
            StoragePaths.log.notice(
                "wake: \(String(describing: report.outcome)) in \(report.elapsedMs) ms (node \(reused ? "reused" : "opened") at \(nodeReadyMs) ms)"
            )
            return .ran(report, nodeReadyMs: nodeReadyMs, nodeReused: reused, peerCount: peerCount)
        }
    }
}

extension WakeBudget: WakeCancellable {}
