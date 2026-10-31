import Combine
import SwiftUI

// MARK: - Theme

struct Theme {
    static let bg = Color(red: 0.06, green: 0.07, blue: 0.13)
    static let card = Color(red: 0.10, green: 0.12, blue: 0.20)
    static let cardBorder = Color.white.opacity(0.06)
    static let accent = Color(red: 0.25, green: 0.52, blue: 1.0)
    static let accentGlow = Color(red: 0.25, green: 0.52, blue: 1.0).opacity(0.3)
    static let success = Color(red: 0.18, green: 0.80, blue: 0.44)
    static let warning = Color(red: 1.0, green: 0.72, blue: 0.25)
    static let error = Color(red: 1.0, green: 0.35, blue: 0.37)
    static let textPrimary = Color.white
    static let textSecondary = Color.white.opacity(0.55)
    static let textTertiary = Color.white.opacity(0.35)
}

// MARK: - Validation Mode

// `ValidationMode` and `ValidationModePreference` live in WakeGate.swift
// (ticket 054), next to the wake gate that reads them.

// MARK: - View Model

class NodeViewModel: ObservableObject {
    @Published var syncStatus: SyncStatus?
    @Published var isConnecting = false
    @Published var isSyncRunning = false
    @Published var errorMessage: String?
    @Published var isLoadingSnapshot = false
    @Published var snapshotProgress: Double = 0
    @Published var isValidationPaused = false
    @Published var torStatus: TorStatus?
    @Published var isBootstrappingTor = false
    @Published var isDownloadingSnapshot = false
    @Published var snapshotDownloadProgress: Double = 0
    @Published var snapshotBytesDownloaded: Int64 = 0
    @Published var snapshotBytesTotal: Int64 = SnapshotDownloader.expectedBytes

    /// User-selected validation mode. `nil` means the user hasn't picked yet
    /// — the main view shows the picker card and the SyncButton is disabled.
    @Published var validationMode: ValidationMode? = ValidationModePreference.current

    /// True while `resetAndRestart` is wiping DB files. UI shows a transient
    /// "Resetting…" state and blocks the SyncButton.
    @Published var isResetting = false

    // Phase 5 participation stats — populated by the 5s polling timer once
    // the node has reached tip and the monitor loop is running.
    @Published var mempoolStatus: MempoolStatus?
    @Published var nodeStatus: NodeStatus?

    // Trust verification info (snapshot height, forward-validated blocks).
    @Published var trustInfo: TrustInfo?

    // Wallet API (ticket 014) — external wallet connectivity.
    @Published var isWalletApiRunning = false
    @Published var walletApiConnectionString: String?
    @Published var walletApiError: String?

    // Disk-space guard (ticket 030). `storageWarning` drives the banner on
    // the main view; `pausedForLowDisk` records that *we* paused validation
    // (so recovery never overrides a manual pause).
    @Published var storageWarning: String?
    private var pausedForLowDisk = false
    private var lowDiskBannerShown = false
    private var lastDiskCheck = Date.distantPast

    // Foreground sync bookkeeping (ticket 028). A background wake can stop
    // a sync loop the app left running; it's restarted when the app is
    // next active, unless the user stopped it. Main thread only.
    private var syncGeneration = 0
    /// The session whose callbacks own the UI; nil once it ended or a
    /// reset retired it.
    private var activeSession: SyncSessionToken?
    /// A session's background thread hasn't returned yet.
    private var sessionInFlight = false
    /// Start was tapped while a stopped session was still winding down.
    private var startWhenSessionEnds = false
    private var resumeSyncWhenActive = false

    // Thread-safe access to the node: set from background thread, read from main thread.
    // The node itself belongs to NodeHost (ticket 028); this is our handle on it.
    private var _node: HerculesNode?
    private let nodeLock = NSLock()
    private var node: HerculesNode? {
        get { nodeLock.lock(); defer { nodeLock.unlock() }; return _node }
        set { nodeLock.lock(); defer { nodeLock.unlock() }; _node = newValue }
    }

    // Subscriptions to SnapshotDownloader's @Published state and the
    // participation-stats polling timer.
    private var downloadCancellables = Set<AnyCancellable>()
    // Continuation that the download flow awaits while the download runs.
    private var downloadWaiter: ((Result<URL, Error>) -> Void)?

    /// Tracks the last block height we wrote to the App Group container so
    /// the home-screen widget gets a single republish per validated block
    /// instead of one per `SyncProgressCallback` tick. Per-tick writes
    /// would burn the WidgetKit reload budget within minutes.
    private var lastPublishedHeight: UInt32 = 0

    init() {
        // Mirror SnapshotDownloader's @Published state into ours so the UI
        // observing NodeViewModel sees download progress without depending on
        // the singleton directly.
        let dl = SnapshotDownloader.shared
        dl.$progress
            .receive(on: DispatchQueue.main)
            .sink { [weak self] p in self?.snapshotDownloadProgress = p }
            .store(in: &downloadCancellables)
        dl.$bytesDownloaded
            .receive(on: DispatchQueue.main)
            .sink { [weak self] b in self?.snapshotBytesDownloaded = b }
            .store(in: &downloadCancellables)
        dl.$bytesTotal
            .receive(on: DispatchQueue.main)
            .sink { [weak self] b in self?.snapshotBytesTotal = b }
            .store(in: &downloadCancellables)
        dl.$status
            .receive(on: DispatchQueue.main)
            .sink { [weak self] status in self?.handleDownloadStatus(status) }
            .store(in: &downloadCancellables)

        // Poll mempool + node-status stats every 5s. The Rust calls are cheap
        // (uncontended locks + a few u32/u64 reads) so the cost is negligible
        // even when we're not yet a full participant.
        Timer.publish(every: 5, on: .main, in: .common)
            .autoconnect()
            .sink { [weak self] _ in self?.pollParticipationStats() }
            .store(in: &downloadCancellables)

        // Restart foreground sync a background wake stopped (ticket 028),
        // or start it because the app is open (ticket 054 section 4).
        NotificationCenter.default.publisher(for: UIApplication.didBecomeActiveNotification)
            .sink { [weak self] _ in
                guard let self = self else { return }
                if self.resumeSyncWhenActive {
                    self.resumeSyncWhenActive = false
                    self.startSync()
                } else {
                    self.autoStartIfWanted()
                }
            }
            .store(in: &downloadCancellables)
    }

    /// Section 4 of ticket 054: with the app open, the node follows the
    /// tip from its own peers rather than waiting for relay pushes. Once
    /// it is set up (`WakeGate`'s foreground row: a mode, the snapshot in
    /// or genesis mode, the network policy allowing it), opening the app
    /// starts sync, unless the user paused it. Never the first start of an
    /// AssumeUTXO node: that one downloads 8.8 GB and waits for a tap.
    func autoStartIfWanted() {
        // The policy reads "offline" until the monitor's first path.
        NetworkPolicy.shared.afterFirstPath { [weak self] in
            guard let self = self, !self.isSyncRunning, !self.isResetting else { return }
            let inputs = NotificationManager.gateInputs(
                userPaused: NodeSetupState.shared.syncPausedByUser
            )
            guard WakeGate.decide(.foreground, inputs) == .run(headersOnly: false) else { return }
            StoragePaths.log.notice("foreground: app open and node set up; starting sync")
            self.startSync()
        }
    }

    /// The user's Resume (or first Start): clears a remembered Pause.
    func resumeSync() {
        NodeSetupState.shared.syncPausedByUser = false
        startSync()
    }

    /// The user's Pause: remembered, so opening the app doesn't undo it.
    func pauseSync() {
        NodeSetupState.shared.syncPausedByUser = true
        stopSync()
    }

    /// Publish a fresh `SharedNodeState` to the App Group container so the
    /// home-screen widget reflects the current tip. Gated on
    /// `validatedBlocks` actually advancing — we don't want to spend
    /// WidgetKit reload budget on the dozens of header-sync ticks per
    /// second. Always called on the main thread; cheap (one JSON encode +
    /// one atomic file write + one WidgetCenter nudge).
    func maybePublishWidgetState(from status: SyncStatus) {
        guard status.validatedBlocks > lastPublishedHeight else { return }
        // We don't have a per-block hash in `SyncStatus` (the chain tip
        // hash isn't on the struct). Leave it empty for the foreground
        // path; the silent-push path is the one that has the canonical
        // BlockNotification with hash bytes, and it republishes through
        // `publishValidation` directly.
        SharedNodeStore.write(SharedNodeState(
            blockHeight: status.validatedBlocks,
            blockHash: "",
            lastBlockTime: Date(),
            peerCount: UInt32(status.peers.count),
            isAwake: false,
            isPaused: false,
            updatedAt: Date()
        ))
        lastPublishedHeight = status.validatedBlocks
    }

    /// Read mempool + node-status from the live HerculesNode. Off main thread
    /// because the FFI calls hop into Rust and we don't want to block UI even
    /// for a few milliseconds. Silently no-ops if the node isn't running.
    private func pollParticipationStats() {
        guard let node = node, isSyncRunning else {
            // Clear stale stats so the card doesn't show ghost data after stop.
            if mempoolStatus != nil || nodeStatus != nil || trustInfo != nil {
                mempoolStatus = nil
                nodeStatus = nil
                trustInfo = nil
            }
            return
        }
        DispatchQueue.global(qos: .utility).async { [weak self] in
            let mp = node.getMempoolStatus()
            let ns = node.getNodeStatus()
            let ti = try? node.getTrustInfo()
            DispatchQueue.main.async {
                self?.mempoolStatus = mp
                self?.nodeStatus = ns
                self?.trustInfo = ti
            }
        }
    }

    private func handleDownloadStatus(_ status: SnapshotDownloader.Status) {
        switch status {
        case .idle:
            isDownloadingSnapshot = false
        case .downloading:
            isDownloadingSnapshot = true
        case .completed(let url):
            isDownloadingSnapshot = false
            // Hand off to the waiting sync flow, if any.
            if let waiter = downloadWaiter {
                downloadWaiter = nil
                waiter(.success(url))
            }
        case .failed(let msg):
            isDownloadingSnapshot = false
            if let waiter = downloadWaiter {
                downloadWaiter = nil
                waiter(.failure(NSError(
                    domain: "Hercules", code: 1,
                    userInfo: [NSLocalizedDescriptionKey: msg]
                )))
            } else {
                errorMessage = msg
            }
        }
    }

    /// Block the calling background thread until the snapshot download
    /// completes (or fails). Returns the local file URL on success.
    /// Nil if `token`'s session is over before the download starts.
    private func awaitSnapshotDownload(for token: SyncSessionToken) throws -> URL? {
        let semaphore = DispatchSemaphore(value: 0)
        var result: Result<URL, Error>? = .failure(NSError(
            domain: "Hercules", code: -1,
            userInfo: [NSLocalizedDescriptionKey: "Download did not complete"]
        ))
        DispatchQueue.main.async {
            // Checked on main, where a reset retires the session: a
            // retired session never starts a download the reset's cancel
            // has already run past.
            if token.isOver {
                result = nil
                semaphore.signal()
                return
            }
            self.downloadWaiter = { r in
                result = r
                semaphore.signal()
            }
            SnapshotDownloader.shared.start()
        }
        semaphore.wait()
        switch result {
        case .none: return nil
        case .success(let url): return url
        case .failure(let err): throw err
        }
    }

    /// Cancel an in-flight snapshot download. Safe to call from any thread.
    func cancelSnapshotDownload() {
        SnapshotDownloader.shared.cancel()
    }

    /// Persist the user's validation-mode choice. Idempotent — only writes
    /// when the value actually changes.
    func setValidationMode(_ mode: ValidationMode) {
        guard validationMode != mode else { return }
        validationMode = mode
        ValidationModePreference.current = mode
        // A wake may have opened the node before there was a mode: tell it
        // now (ticket 054). The node keeps the first mode it records.
        DispatchQueue.global(qos: .userInitiated).async {
            NodeHost.shared.recordValidationMode(mode)
        }
    }

    /// Wipe all on-disk state and restart sync with a new validation mode.
    /// This is the destructive "Switch validation mode" path: it stops the
    /// running node, drops the open SQLite handles, deletes the headers /
    /// utxo / blocks DB files via Rust's `reset_database`, persists the new
    /// mode, then re-runs `startSync`. Any in-progress snapshot download is
    /// also cancelled and its cached file removed. Safe at any point of a
    /// running `startSync`, including while it waits for Tor (ticket 028).
    ///
    /// `completion` is invoked on the main queue after the wipe finishes
    /// (success) or with the error that aborted it (failure). It runs
    /// *before* `startSync` is re-invoked so the caller can dismiss any
    /// confirmation sheet first.
    func resetAndRestart(mode: ValidationMode, completion: @escaping (Error?) -> Void) {
        DispatchQueue.main.async { self.isResetting = true }

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self = self else { return }

            // 1. Retire the current sync session: its callbacks stop
            // touching the UI, a snapshot import it runs cancels at its next
            // progress tick, and a wake preemption won't restart it. First,
            // so it can't start a fresh download after step 2's cancel.
            DispatchQueue.main.sync {
                self.retireActiveSession()
                self.resumeSyncWhenActive = false
            }

            // 2. Cancel any in-flight download (clears resume data + .gz file).
            SnapshotDownloader.shared.cancel()
            SnapshotDownloader.deleteDownloadedFile()

            // 3. Drop our handle, then have NodeHost close the node and wipe
            // the on-disk DBs (ticket 028). NodeHost refuses to reopen the
            // node until it's done, and the close stops the sync loop, ends
            // a Tor-bootstrap wait and cancels wakes. Nothing is deleted
            // until every holder has let go of the old node: on POSIX an
            // open inode survives unlink, and LMDB would keep using it.
            // (The retired session can't set the handle again: see
            // `adopt(_:for:)`.)
            self.node = nil
            do {
                try NodeHost.shared.reset()
            } catch {
                DispatchQueue.main.async {
                    self.isResetting = false
                    self.isSyncRunning = false
                    self.isConnecting = false
                    self.isBootstrappingTor = false
                    self.isWalletApiRunning = false
                    self.walletApiConnectionString = nil
                    completion(error)
                }
                return
            }

            // 4. Persist the new mode and reset transient UI state.
            DispatchQueue.main.async {
                ValidationModePreference.current = mode
                self.validationMode = mode
                self.syncStatus = nil
                self.errorMessage = nil
                self.isLoadingSnapshot = false
                self.isDownloadingSnapshot = false
                self.snapshotProgress = 0
                self.snapshotDownloadProgress = 0
                self.mempoolStatus = nil
                self.nodeStatus = nil
                self.isResetting = false
                // The retired session's own callbacks are ignored (step 2).
                self.isSyncRunning = false
                self.isConnecting = false
                self.isBootstrappingTor = false
                // The close stopped the wallet API with the old node.
                self.isWalletApiRunning = false
                self.walletApiConnectionString = nil

                completion(nil)

                // 5. Kick off a fresh sync with the new mode (an explicit
                // user action, so a remembered Pause is cleared).
                self.resumeSync()
            }
        }
    }

    func startSync() {
        guard !isSyncRunning else { return }
        isConnecting = true
        isBootstrappingTor = true
        isSyncRunning = true
        errorMessage = nil
        if !lowDiskBannerShown { storageWarning = nil }
        resumeSyncWhenActive = false

        // One session thread at a time (ticket 028). After a quick Stop
        // then Start, wait for the stopped session to actually return
        // rather than queue a second one behind it in Rust.
        if sessionInFlight {
            startWhenSessionEnds = true
            return
        }
        launchSession()
    }

    /// Start a foreground session's background thread. Main thread.
    private func launchSession() {
        syncGeneration += 1
        let token = SyncSessionToken(generation: syncGeneration)
        activeSession = token
        sessionInFlight = true

        // Cancels any in-flight wake so it hands the node over quickly.
        NodeHost.shared.sessions.beginForeground()

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            var failure: Error?
            do {
                try self?.runSession(token)
            } catch {
                failure = error
            }
            let preempted = NodeHost.shared.sessions.endForeground()
            token.markEnded()
            DispatchQueue.main.async {
                self?.sessionEnded(token, preemptedByWake: preempted, error: failure)
            }
        }
    }

    /// Run `body` on the main thread if `token` is still the active session.
    private func onMain(_ token: SyncSessionToken, _ body: @escaping (NodeViewModel) -> Void) {
        DispatchQueue.main.async { [weak self] in
            guard let self = self, self.activeSession === token else { return }
            body(self)
        }
    }

    /// Take `node` as our handle unless the session is already over. Atomic
    /// with `retireActiveSession`'s nil-out (both under `nodeLock`), so a
    /// retired session can never hand a reset's old node back to us.
    private func adopt(_ node: HerculesNode, for token: SyncSessionToken) -> Bool {
        nodeLock.lock(); defer { nodeLock.unlock() }
        guard !token.isOver else { return false }
        _node = node
        return true
    }

    /// A reset (or anything that must own the node) takes over. Main thread.
    private func retireActiveSession() {
        nodeLock.lock()
        activeSession?.retire()
        _node = nil
        nodeLock.unlock()
        activeSession = nil
        syncGeneration += 1
        // A Start deferred behind the retired session belongs to the old
        // node: a successful reset starts sync itself, a failed one leaves
        // it stopped.
        startWhenSessionEnds = false
    }

    /// The foreground session, on its background thread. Returns early
    /// (no error) once the user stops it or a reset retires it; every UI
    /// update goes through `onMain`, which drops it if it's no longer the
    /// active session.
    private func runSession(_ token: SyncSessionToken) throws {
        // The shared node (ticket 028). NodeHost runs the ticket 030
        // storage preparation before opening it.
        let (node, reused) = try NodeHost.shared.node()
        // Our handle before the Tor wait, so Stop and the wallet API see
        // this session's node. Stop itself works through `token` (checked
        // between steps) plus `stopSync`, repeated until we return.
        guard adopt(node, for: token) else { return }

        // Opening doesn't wait for Tor, so wait here (in slices, so a Stop
        // or reset ends the wait) to keep the bootstrapping UI.
        let transportDeadline = Date().addingTimeInterval(150)
        while try !node.waitForTransport(timeoutMs: 1_000) {
            if token.isOver { return }
            if Date() >= transportDeadline {
                throw HerculesError.TorError(msg: "Tor bootstrap timed out")
            }
        }
        if token.isOver { return }

        // Fetch initial Tor status
        let torStatus = node.getTorStatus()
        let nodePaused = node.isValidationPaused()
        onMain(token) { vm in
            if let status = torStatus {
                vm.torStatus = status
            }
            vm.isBootstrappingTor = false
            if reused {
                // NodeHost kept the node from an earlier session (or a
                // wake): it keeps its pause state, and so does the low-disk
                // guard's ownership of that pause.
                vm.isValidationPaused = nodePaused
            } else {
                // A fresh HerculesNode starts unpaused: drop any pause state
                // that belonged to the previous node so the UI matches it,
                // and so the forced check below re-pauses this node if space
                // is still low.
                vm.pausedForLowDisk = false
                vm.isValidationPaused = false
            }
            vm.checkDiskSpace(force: true)
        }

        // Honor the user's explicit validation-mode choice. AssumeUTXO
        // runs the download/import path on a fresh DB; Genesis skips
        // it entirely (block-by-block validation will start from
        // wherever validated_height is — 0 on a clean wipe).
        // NodeHost adopted the node's recorded mode at open (ticket 054);
        // show that one if it differs from ours.
        let adopted = ValidationModePreference.current
        let mode = DispatchQueue.main.sync { () -> ValidationMode? in
            if let adopted = adopted, validationMode != adopted { validationMode = adopted }
            return validationMode
        } ?? .assumeUtxo
        let needsSnapshot = mode == .assumeUtxo ? try node.needsSnapshot() : false
        if mode == .assumeUtxo && !needsSnapshot {
            NodeSetupState.shared.snapshotLoaded = true
        }
        if mode == .assumeUtxo, needsSnapshot {
            onMain(token) { vm in
                vm.isConnecting = false
            }

            // Map-capacity check (ticket 030): if the UTXO env can't
            // be mapped big enough for the snapshot (iOS VA limit
            // forced a small fallback map), say so now rather than
            // after an 8.8 GB download.
            do {
                try node.checkSnapshotCapacity()
            } catch HerculesError.StorageError(let msg) {
                throw StorageError.cannotMapUtxoSet(msg)
            }

            // Free-space preflight: refuse to start an 8.8 GB download
            // that can't be imported. A finished download on disk is
            // credited against the requirement, as are pages a
            // previous (aborted) import left in the LMDB file, which
            // the next import reuses.
            do {
                try StorageGuard.snapshotPreflight(
                    alreadyDownloaded: SnapshotDownloader.hasDownloadedFile()
                        ? SnapshotDownloader.expectedBytes : 0,
                    reusable: StorageGuard.utxoEnvFileBytes()
                )
            } catch {
                onMain(token) { vm in
                    vm.storageWarning = error.localizedDescription
                }
                throw error
            }

            // Don't start an 8.8 GB download for a session that's over.
            if token.isOver { return }

            // The downloader refuses to start while the network policy
            // reads "offline", which it does until the monitor's first
            // path (ticket 051). Normally long since known by now.
            NetworkPolicy.shared.waitForFirstPath()

            // Block until the file is on disk. Surfaces progress to
            // the UI via the SnapshotDownloader subscriptions set up
            // in init().
            guard let snapshotURL = try awaitSnapshotDownload(for: token) else { return }
            if token.isOver { return }

            onMain(token) { vm in
                vm.isLoadingSnapshot = true
            }

            // The import writes ~12 GB; watch free space while it
            // runs (ticket 030) and cancel cleanly below the pause
            // threshold rather than letting LMDB hit ENOSPC. A reset
            // retiring this session cancels it too (Rust also treats
            // the node's close as a cancel).
            let spaceWatch = SnapshotSpaceWatch()
            let snapCallback = SnapshotProgressCallback { [weak self] loaded, total in
                self?.onMain(token) { vm in
                    vm.snapshotProgress = total > 0
                        ? Double(loaded) / Double(total) : 0
                }
                return !token.retired && spaceWatch.shouldContinue()
            }

            // The import runs for minutes: keep the screen from
            // auto-locking (which backgrounds the app), and hold a
            // background task so a brief app switch doesn't freeze it
            // mid-write (ticket 051). Released on every exit below.
            let importAssertion = LongTaskAssertion(name: "Snapshot import")
            defer { importAssertion.end() }

            // Delete the cached .gz after a successful import (it's
            // redundant) or when the file itself was rejected
            // (corrupt, truncated, hash mismatch), so we don't retry
            // the same bad bytes forever. Keep it for any other
            // failure (map or disk full, cancelled): it's fine, and a
            // retry shouldn't re-download 8.8 GB.
            do {
                let _ = try node.loadSnapshot(
                    snapshotPath: snapshotURL.path,
                    callback: snapCallback
                )
                SnapshotDownloader.deleteDownloadedFile()
                NodeSetupState.shared.snapshotLoaded = true
                NodeSetupState.shared.finishSetupNotified = false
            } catch {
                if case HerculesError.SnapshotInvalid = error {
                    SnapshotDownloader.deleteDownloadedFile()
                }
                if token.retired { return }
                if let free = spaceWatch.abortedAtFreeBytes {
                    let lowSpace = StorageError.insufficientSpace(
                        message: StorageGuard.snapshotImportLowSpaceMessage(free: free)
                    )
                    onMain(token) { vm in
                        vm.storageWarning = lowSpace.localizedDescription
                    }
                    throw lowSpace
                }
                throw error
            }

            onMain(token) { vm in
                vm.isLoadingSnapshot = false
            }
        }

        let status = try node.getStatus()
        onMain(token) { vm in
            vm.syncStatus = status
        }

        let callback = SyncProgressCallback { [weak self] status in
            self?.onMain(token) { vm in
                vm.syncStatus = status
                vm.isConnecting = false
                vm.errorMessage = status.error
                vm.maybePublishWidgetState(from: status)
                vm.checkDiskSpace()
            }
        }

        if token.isOver { return }
        // Runs until stopped: by the user, by a reset, or by a
        // background wake (ticket 028). Unrecoverable errors throw.
        try node.startHeaderSync(callback: callback)
    }

    /// A session's thread returned, cleanly or with `error`. Main thread.
    private func sessionEnded(_ token: SyncSessionToken, preemptedByWake: Bool, error: Error?) {
        sessionInFlight = false
        if activeSession === token {
            activeSession = nil
            isSyncRunning = false
            isConnecting = false
            isBootstrappingTor = false
            isLoadingSnapshot = false
            isDownloadingSnapshot = false

            // A wake stopped it: restart, whether the loop returned cleanly
            // or (commonly, sockets dead after suspension) with an error,
            // which then isn't worth showing.
            let restart = ForegroundRestart.decide(
                preempted: preemptedByWake,
                userStopped: token.stopped,
                appInForeground: UIApplication.shared.applicationState != .background
            )
            switch restart {
            case .now:
                startSync()
            case .whenActive:
                resumeSyncWhenActive = true
            case .none:
                if let error = error {
                    showSessionError(error)
                }
            }
        }
        if startWhenSessionEnds {
            startWhenSessionEnds = false
            // `startSync` set `isSyncRunning` when it deferred this start,
            // and only the active session's cleanup above clears it. A
            // session a reset retired never is, so without this the
            // deferred start would hit `startSync`'s guard and nothing
            // would run until relaunch (ticket 051). Skip it if a restart
            // above already launched a session.
            if !sessionInFlight {
                isSyncRunning = false
                startSync()
            }
        }
    }

    private func showSessionError(_ error: Error) {
        // Storage errors carry user-facing copy and the low-disk
        // case already has its own banner.
        if let storageError = error as? StorageError {
            if case .insufficientSpace = storageError {
                errorMessage = nil
            } else {
                errorMessage = storageError.localizedDescription
            }
        } else {
            errorMessage = "\(error)"
        }
        if let s = syncStatus {
            syncStatus = SyncStatus(
                syncedHeaders: s.syncedHeaders,
                peerHeight: 0,
                peers: [],
                activePeerAddr: "",
                isSyncing: false,
                validatedBlocks: s.validatedBlocks,
                error: "\(error)"
            )
        }
    }

    func stopSync() {
        guard let token = activeSession else { return }
        token.stop()
        isSyncRunning = false
        isConnecting = false
        // Rust only knows the session once `startHeaderSync` has registered
        // it, so a single stop could land just before that. Repeat until
        // this session's thread has returned (stops are per session, and no
        // other session runs meanwhile).
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            let deadline = Date().addingTimeInterval(15)
            while !token.ended && Date() < deadline {
                self?.node?.stopSync()
                Thread.sleep(forTimeInterval: 0.25)
            }
        }
    }

    // MARK: - Wallet API

    func startWalletApi() {
        guard let node = node else {
            walletApiError = "Node not running"
            return
        }
        walletApiError = nil
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            do {
                let connString = try node.startWalletApi()
                DispatchQueue.main.async {
                    self?.walletApiConnectionString = connString
                    self?.isWalletApiRunning = true
                    self?.walletApiError = nil
                }
            } catch {
                DispatchQueue.main.async {
                    self?.walletApiError = error.localizedDescription
                    self?.isWalletApiRunning = false
                }
            }
        }
    }

    func stopWalletApi() {
        guard let node = node else { return }
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            node.stopWalletApi()
            DispatchQueue.main.async {
                self?.isWalletApiRunning = false
                self?.walletApiConnectionString = nil
            }
        }
    }

    func rotateWalletAuthToken() {
        guard let node = node else { return }
        walletApiError = nil
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            do {
                let result = try node.rotateWalletAuthToken()
                DispatchQueue.main.async {
                    // If server was running, result is the new connection string.
                    // If not, result is just the new token.
                    if self?.isWalletApiRunning == true {
                        self?.walletApiConnectionString = result
                    }
                    self?.walletApiError = nil
                }
            } catch {
                DispatchQueue.main.async {
                    self?.walletApiError = error.localizedDescription
                }
            }
        }
    }

    func toggleValidationPaused() {
        guard let node = node else { return }
        let newState = !isValidationPaused
        // Dispatch FFI call off main thread, update UI state only after it succeeds
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            node.setValidationPaused(paused: newState)
            DispatchQueue.main.async {
                // A manual toggle takes the pause back from the low-disk
                // guard; if space is still low its next check re-pauses.
                self?.pausedForLowDisk = false
                self?.isValidationPaused = newState
            }
        }
    }

    // MARK: - Disk space guard (ticket 030)

    /// Ongoing low-disk guard, called at node start and from the sync
    /// progress callback (throttled to every 30 s). Below
    /// `StorageGuard.pauseBelowBytes` it pauses block validation — so LMDB
    /// and SQLite never hit ENOSPC mid-transaction — and shows the banner;
    /// above `resumeAboveBytes` it resumes, but only if the guard itself did
    /// the pausing. Main thread only.
    func checkDiskSpace(force: Bool = false) {
        let now = Date()
        guard force || now.timeIntervalSince(lastDiskCheck) >= 30 else { return }
        lastDiskCheck = now
        guard let free = StorageGuard.availableBytes() else { return }

        if free < StorageGuard.pauseBelowBytes {
            storageWarning = StorageGuard.lowSpaceMessage(free: free)
            lowDiskBannerShown = true
            // Take ownership only if validation is running: a manual pause
            // stays the user's, so recovery below never resumes it.
            if !pausedForLowDisk, !isValidationPaused, let node = node {
                pausedForLowDisk = true
                isValidationPaused = true
                DispatchQueue.global(qos: .userInitiated).async {
                    node.setValidationPaused(paused: true)
                }
            }
        } else if free >= StorageGuard.resumeAboveBytes {
            if pausedForLowDisk {
                pausedForLowDisk = false
                isValidationPaused = false
                if let node = node {
                    DispatchQueue.global(qos: .userInitiated).async {
                        node.setValidationPaused(paused: false)
                    }
                }
            }
            // Clear the low-disk banner. (A snapshot-preflight warning is
            // cleared when the user taps Start again.)
            if lowDiskBannerShown {
                lowDiskBannerShown = false
                storageWarning = nil
            }
        }
    }
}

class SyncProgressCallback: SyncCallback {
    let handler: (SyncStatus) -> Void

    init(handler: @escaping (SyncStatus) -> Void) {
        self.handler = handler
    }

    func onProgress(status: SyncStatus) {
        handler(status)
    }
}

class SnapshotProgressCallback: SnapshotCallback {
    /// Returns false to cancel the import.
    let handler: (UInt64, UInt64) -> Bool

    init(handler: @escaping (UInt64, UInt64) -> Bool) {
        self.handler = handler
    }

    func onProgress(loaded: UInt64, total: UInt64) -> Bool {
        handler(loaded, total)
    }
}

/// Free-space watch for the snapshot import (ticket 030), polled from the
/// Rust progress callback (on the import thread, roughly every 100k
/// entries). Checks at most every 5 s; below `StorageGuard.pauseBelowBytes`
/// it records the free space and tells the import to stop.
final class SnapshotSpaceWatch {
    private let lock = NSLock()
    private var lastCheck = Date.distantPast
    private var abortedAt: Int64?

    /// Free bytes when the import was cancelled for low space, else nil.
    var abortedAtFreeBytes: Int64? {
        lock.lock(); defer { lock.unlock() }
        return abortedAt
    }

    func shouldContinue() -> Bool {
        lock.lock(); defer { lock.unlock() }
        if abortedAt != nil { return false }
        let now = Date()
        guard now.timeIntervalSince(lastCheck) >= 5 else { return true }
        lastCheck = now
        if let free = StorageGuard.availableBytes(), free < StorageGuard.pauseBelowBytes {
            abortedAt = free
            return false
        }
        return true
    }
}

/// Keeps a long foreground job (the snapshot import) going (ticket 051):
/// disables the idle timer, so the screen doesn't auto-lock and background
/// the app, and holds a UIKit background task, so a brief trip to the
/// background doesn't suspend it at once. Created and ended from any
/// thread; all state lives on the main thread, and `begin` is queued
/// before `end`. `endBackgroundTask` runs exactly once, from `end` or from
/// the expiration handler, whichever comes first.
///
/// The background task covers the first trip to the background only:
/// once it expires it isn't re-armed when the app comes back, so a later
/// trip suspends the import right away (it resumes on return). The idle
/// timer stays disabled until `end`.
final class LongTaskAssertion {
    // Main thread only.
    private var taskID: UIBackgroundTaskIdentifier = .invalid
    private var savedIdleTimerDisabled = false
    private var ended = false

    init(name: String) {
        DispatchQueue.main.async { self.begin(name) }
    }

    /// Restore the idle timer and end the background task. Idempotent.
    func end() {
        DispatchQueue.main.async {
            guard !self.ended else { return }
            self.ended = true
            self.endBackgroundTask()
            UIApplication.shared.isIdleTimerDisabled = self.savedIdleTimerDisabled
        }
    }

    private func begin(_ name: String) {
        guard !ended else { return }
        let app = UIApplication.shared
        savedIdleTimerDisabled = app.isIdleTimerDisabled
        app.isIdleTimerDisabled = true
        taskID = app.beginBackgroundTask(withName: name) { [self] in
            // Out of background time. iOS kills an app that doesn't end
            // its task here; the import thread is just suspended with the
            // process and carries on when the app is next active (LMDB is
            // crash-safe if it never is).
            endBackgroundTask()
        }
    }

    private func endBackgroundTask() {
        guard taskID != .invalid else { return }
        UIApplication.shared.endBackgroundTask(taskID)
        taskID = .invalid
    }
}

// MARK: - Main View

struct ContentView: View {
    @StateObject private var viewModel = NodeViewModel()
    @State private var showSettings = false
    @State private var showAbout = false

    var body: some View {
        ZStack {
            Theme.bg.ignoresSafeArea(.all)

            VStack(spacing: 0) {
                ScrollView(showsIndicators: false) {
                    VStack(spacing: 20) {
                        // Logo / header area
                        ZStack {
                            VStack(spacing: 8) {
                                Text("HERCULES")
                                    .font(.system(size: 34, weight: .heavy, design: .default))
                                    .tracking(6)
                                    .foregroundStyle(Theme.textPrimary)

                                Text("Bitcoin Full Node")
                                    .font(.system(size: 15, weight: .medium))
                                    .foregroundStyle(Theme.textSecondary)

                                Text(herculesVersion())
                                    .font(.system(size: 11, weight: .regular, design: .monospaced))
                                    .foregroundStyle(Theme.textTertiary)
                            }
                            .frame(maxWidth: .infinity)

                            HStack {
                                Button(action: { showAbout = true }) {
                                    Image(systemName: "questionmark.circle")
                                        .font(.system(size: 16))
                                        .foregroundStyle(Theme.textSecondary)
                                        .padding(8)
                                }

                                Spacer()

                                Button(action: { showSettings = true }) {
                                    Image(systemName: "gearshape.fill")
                                        .font(.system(size: 16))
                                        .foregroundStyle(Theme.textSecondary)
                                        .padding(8)
                                }
                            }
                        }
                        .padding(.top, 16)
                        .padding(.bottom, 4)
                        .sheet(isPresented: $showAbout) {
                            AboutView()
                        }
                        .sheet(isPresented: $showSettings) {
                            SettingsView(viewModel: viewModel)
                                .presentationDetents([.large])
                                .interactiveDismissDisabled()
                        }

                        // High-level state pill (always visible — its job is
                        // to answer "what is my node doing right now").
                        HStack {
                            Spacer()
                            NodeStatePill(viewModel: viewModel)
                            Spacer()
                        }

                        // Validation mode picker — only on first run, before
                        // the user has committed to AssumeUTXO vs Genesis.
                        if viewModel.validationMode == nil && !viewModel.isSyncRunning {
                            ValidationModePickerCard(viewModel: viewModel)
                        }

                        // Tor status card
                        if viewModel.isBootstrappingTor || viewModel.torStatus != nil {
                            TorStatusCard(viewModel: viewModel)
                        }

                        // Node status card
                        NodeStatusCard(viewModel: viewModel)

                        // Header sync progress card
                        if let status = viewModel.syncStatus, status.peerHeight > 0 {
                            SyncProgressCard(status: status)
                        }

                        // Snapshot download card (Phase 5a — pre-import)
                        if viewModel.isDownloadingSnapshot {
                            SnapshotDownloadCard(viewModel: viewModel)
                        }

                        // Snapshot loading card (UTXO import after download)
                        if viewModel.isLoadingSnapshot {
                            SnapshotLoadingCard(progress: viewModel.snapshotProgress)
                        }

                        // Block validation progress card
                        if let status = viewModel.syncStatus, status.validatedBlocks > 0 {
                            BlockValidationCard(status: status, viewModel: viewModel)
                        }

                        // Network participation card — only meaningful once
                        // the monitor loop is running. We show it as soon as
                        // either stat dictionary has been populated, but the
                        // pill above is the canonical "are we participating?"
                        // signal.
                        if viewModel.mempoolStatus != nil || viewModel.nodeStatus != nil {
                            NetworkParticipationCard(viewModel: viewModel)
                        }

                        // Peers card
                        if let status = viewModel.syncStatus, !status.peers.isEmpty {
                            PeersCard(status: status)
                        }

                        // Low-storage banner (ticket 030)
                        if let warning = viewModel.storageWarning {
                            StorageWarningCard(message: warning)
                        }

                        // Error card
                        if let error = viewModel.errorMessage {
                            ErrorCard(message: error)
                        }

                        // Spacer so content doesn't hide behind button
                        Spacer(minLength: 80)
                    }
                    .padding(.horizontal, 16)
                }

                // Button pinned to bottom
                SyncButton(viewModel: viewModel)
                    .padding(.horizontal, 16)
                    .padding(.top, 12)
                    .padding(.bottom, 36)
            }
            .ignoresSafeArea(.container, edges: .bottom)
        }
        .toolbarBackground(Theme.bg, for: .navigationBar)
        .preferredColorScheme(.dark)
    }

}

// MARK: - Node State Pill

/// The four user-visible states a Hercules node moves through, derived in
/// Swift from existing SyncStatus / TorStatus / view-model flags. This is the
/// "what is my node doing right now" answer at a glance — drill-down detail
/// lives in the cards below it.
enum NodeState {
    case offline            // not started yet
    case connecting         // tor bootstrap or no peers
    case downloadingSnapshot // AssumeUTXO download in flight
    case importingSnapshot  // .hutx.gz being decoded into the UTXO DB
    case headerSync         // pulling 80-byte headers from genesis to tip
    case validating         // walking blocks, building UTXO toward tip
    case participant        // at tip, mempool + relay + serving + inbound

    var label: String {
        switch self {
        case .offline:             return "Offline"
        case .connecting:          return "Connecting"
        case .downloadingSnapshot: return "Downloading Snapshot"
        case .importingSnapshot:   return "Importing Snapshot"
        case .headerSync:          return "Header Sync"
        case .validating:          return "Validating"
        case .participant:         return "Participant"
        }
    }

    var color: Color {
        switch self {
        case .offline:             return Theme.textTertiary
        case .connecting:          return Theme.warning
        case .downloadingSnapshot: return Theme.accent
        case .importingSnapshot:   return Theme.accent
        case .headerSync:          return Theme.warning
        case .validating:          return Theme.warning
        case .participant:         return Theme.success
        }
    }

    var icon: String {
        switch self {
        case .offline:             return "moon.zzz.fill"
        case .connecting:          return "network"
        case .downloadingSnapshot: return "icloud.and.arrow.down.fill"
        case .importingSnapshot:   return "arrow.down.doc.fill"
        case .headerSync:          return "list.bullet.rectangle"
        case .validating:          return "cube.fill"
        case .participant:         return "checkmark.shield.fill"
        }
    }
}

extension NodeViewModel {
    /// Compute the visible state from the existing flags + the most recent
    /// sync status. The transitions are sharp: there's no in-between, so we
    /// can match on a few simple conditions.
    var nodeState: NodeState {
        if !isSyncRunning && syncStatus == nil { return .offline }
        if isDownloadingSnapshot { return .downloadingSnapshot }
        if isLoadingSnapshot { return .importingSnapshot }
        if isBootstrappingTor { return .connecting }
        guard let s = syncStatus else { return .connecting }
        if s.peers.isEmpty && !s.isSyncing { return .connecting }

        // Header sync running and we haven't validated anything yet.
        if s.validatedBlocks == 0 && (s.peerHeight == 0 || s.syncedHeaders < s.peerHeight) {
            return .headerSync
        }

        // Validating: we have headers ahead of validated blocks. The monitor
        // loop only fires once validated catches all the way up to the local
        // header tip — until then we're a validator-in-progress.
        if s.peerHeight > 0 && s.validatedBlocks >= s.peerHeight {
            return .participant
        }
        if s.validatedBlocks > 0 || s.syncedHeaders > s.validatedBlocks {
            return .validating
        }
        return .headerSync
    }

    /// Sub-progress hint shown under the pill (e.g. "612,403 / 880,210").
    var nodeStateDetail: String? {
        switch nodeState {
        case .offline, .connecting:
            return nil
        case .downloadingSnapshot:
            return String(format: "%.1f%%", snapshotDownloadProgress * 100)
        case .importingSnapshot:
            return String(format: "%.1f%%", snapshotProgress * 100)
        case .headerSync:
            guard let s = syncStatus, s.peerHeight > 0 else { return nil }
            return "\(formatNumber(s.syncedHeaders)) / \(formatNumber(s.peerHeight))"
        case .validating:
            guard let s = syncStatus, s.syncedHeaders > 0 else { return nil }
            return "\(formatNumber(s.validatedBlocks)) / \(formatNumber(s.syncedHeaders))"
        case .participant:
            guard let s = syncStatus else { return nil }
            return "tip \(formatNumber(s.validatedBlocks))"
        }
    }
}

struct NodeStatePill: View {
    @ObservedObject var viewModel: NodeViewModel

    var body: some View {
        let state = viewModel.nodeState
        HStack(spacing: 8) {
            Image(systemName: state.icon)
                .font(.system(size: 11, weight: .semibold))
            Text(state.label)
                .font(.system(size: 12, weight: .semibold))
                .tracking(0.5)
            if let detail = viewModel.nodeStateDetail {
                Text("·")
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundStyle(state.color.opacity(0.5))
                Text(detail)
                    .font(.system(size: 12, weight: .medium, design: .monospaced))
                    .foregroundStyle(state.color.opacity(0.85))
            }
        }
        .foregroundStyle(state.color)
        .padding(.horizontal, 12)
        .padding(.vertical, 6)
        .background(state.color.opacity(0.12))
        .clipShape(Capsule())
        .overlay(
            Capsule().stroke(state.color.opacity(0.35), lineWidth: 1)
        )
    }
}

// MARK: - Validation Mode Picker Card

/// Shown on the main view when no validation mode is set yet. Two big tap
/// targets so first-run users have to make a deliberate choice — there is no
/// silent default. Once a mode is picked the card disappears and the
/// SyncButton becomes enabled.
struct ValidationModePickerCard: View {
    @ObservedObject var viewModel: NodeViewModel
    @State private var showSnapshotDisclosure = false

    var body: some View {
        CardContainer {
            VStack(alignment: .leading, spacing: 14) {
                HStack(spacing: 8) {
                    Image(systemName: "shield.lefthalf.filled")
                        .font(.system(size: 13))
                        .foregroundStyle(Theme.accent)
                    Text("Choose Validation Mode")
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundStyle(Theme.textSecondary)
                }

                Text("How should this node build its UTXO set? You can switch later from Settings, but switching wipes all validation progress.")
                    .font(.system(size: 12))
                    .foregroundStyle(Theme.textTertiary)

                modeButton(
                    mode: .assumeUtxo,
                    title: "AssumeUTXO",
                    badge: "Recommended",
                    subtitle: "Trusts a hash baked into the app. ~8 GB one-time download, ~10–60 min to tip on Wi-Fi.",
                    icon: "bolt.shield.fill"
                )

                modeButton(
                    mode: .fromGenesis,
                    title: "Validate from Genesis",
                    badge: nil,
                    subtitle: "Trusts only Bitcoin's consensus rules. Downloads & validates every block (~600 GB), ~1–2 days to tip on a phone over Wi-Fi.",
                    icon: "cube.transparent.fill"
                )
            }
        }
        .sheet(isPresented: $showSnapshotDisclosure) {
            SnapshotPrivacyDisclosure {
                showSnapshotDisclosure = false
                viewModel.setValidationMode(.assumeUtxo)
            }
        }
    }

    @ViewBuilder
    private func modeButton(
        mode: ValidationMode,
        title: String,
        badge: String?,
        subtitle: String,
        icon: String
    ) -> some View {
        Button(action: {
            if mode == .assumeUtxo {
                showSnapshotDisclosure = true
            } else {
                viewModel.setValidationMode(mode)
            }
        }) {
            HStack(alignment: .top, spacing: 12) {
                Image(systemName: icon)
                    .font(.system(size: 18))
                    .foregroundStyle(Theme.accent)
                    .frame(width: 24)
                    .padding(.top, 2)

                VStack(alignment: .leading, spacing: 4) {
                    HStack(spacing: 6) {
                        Text(title)
                            .font(.system(size: 14, weight: .semibold))
                            .foregroundStyle(Theme.textPrimary)
                        if let badge = badge {
                            Text(badge)
                                .font(.system(size: 9, weight: .bold))
                                .foregroundStyle(Theme.accent)
                                .padding(.horizontal, 6)
                                .padding(.vertical, 2)
                                .background(Theme.accent.opacity(0.15))
                                .clipShape(Capsule())
                        }
                    }
                    Text(subtitle)
                        .font(.system(size: 11))
                        .foregroundStyle(Theme.textSecondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 0)
            }
            .padding(12)
            .background(Color.white.opacity(0.04))
            .clipShape(RoundedRectangle(cornerRadius: 10))
            .overlay(
                RoundedRectangle(cornerRadius: 10)
                    .stroke(Theme.cardBorder, lineWidth: 1)
            )
        }
        .buttonStyle(.plain)
    }
}

// MARK: - Snapshot Privacy Disclosure

/// One-time disclosure sheet shown before committing to AssumeUTXO mode.
/// Explains that the ~8 GB snapshot download is the only network request
/// not routed through Tor, and suggests practical mitigations.
struct SnapshotPrivacyDisclosure: View {
    let onAccept: () -> Void
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        ZStack {
            Theme.bg.ignoresSafeArea(.all)

            ScrollView(showsIndicators: false) {
                VStack(alignment: .leading, spacing: 20) {
                    HStack {
                        Spacer()
                        Image(systemName: "network.badge.shield.half.filled")
                            .font(.system(size: 36))
                            .foregroundStyle(Theme.warning)
                        Spacer()
                    }
                    .padding(.top, 24)

                    Text("One-Time Download Over Clearnet")
                        .font(.system(size: 20, weight: .bold))
                        .foregroundStyle(Theme.textPrimary)
                        .frame(maxWidth: .infinity)
                        .multilineTextAlignment(.center)

                    VStack(alignment: .leading, spacing: 12) {
                        disclosureRow(
                            icon: "arrow.down.circle",
                            text: "Hercules needs to download an ~8 GB snapshot from Cloudflare to bootstrap your node. This is the only network request not routed through Tor."
                        )

                        disclosureRow(
                            icon: "eye",
                            text: "Your IP address will be visible to Cloudflare and your internet provider during this download."
                        )

                        disclosureRow(
                            icon: "lock.shield",
                            text: "After bootstrap, all Bitcoin traffic is routed exclusively through Tor."
                        )

                        disclosureRow(
                            icon: "checkmark.seal",
                            text: "The snapshot is cryptographically verified before use — the download source cannot tamper with your UTXO set."
                        )
                    }

                    CardContainer {
                        VStack(alignment: .leading, spacing: 8) {
                            HStack(spacing: 6) {
                                Image(systemName: "lightbulb.fill")
                                    .font(.system(size: 11))
                                    .foregroundStyle(Theme.accent)
                                Text("To reduce exposure")
                                    .font(.system(size: 12, weight: .semibold))
                                    .foregroundStyle(Theme.textSecondary)
                            }
                            Text("Connect to a VPN or a public Wi-Fi network (e.g. a coffee shop) before starting the download. This prevents your home IP from being associated with the request.")
                                .font(.system(size: 12))
                                .foregroundStyle(Theme.textSecondary)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }

                    Button(action: onAccept) {
                        Text("I Understand — Continue")
                            .font(.system(size: 16, weight: .semibold))
                            .foregroundStyle(.white)
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 16)
                            .background(Theme.accent)
                            .clipShape(RoundedRectangle(cornerRadius: 12))
                    }
                    .buttonStyle(.plain)

                    Button(action: { dismiss() }) {
                        Text("Go Back")
                            .font(.system(size: 14, weight: .medium))
                            .foregroundStyle(Theme.textTertiary)
                            .frame(maxWidth: .infinity)
                    }
                    .buttonStyle(.plain)
                    .padding(.bottom, 24)
                }
                .padding(.horizontal, 24)
            }
        }
        .presentationDetents([.large])
    }

    private func disclosureRow(icon: String, text: String) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: icon)
                .font(.system(size: 14))
                .foregroundStyle(Theme.textSecondary)
                .frame(width: 20)
                .padding(.top, 1)
            Text(text)
                .font(.system(size: 13))
                .foregroundStyle(Theme.textPrimary)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}

// MARK: - Network Participation Card

/// Phase 5 stats: only meaningful once the node has reached tip and the
/// monitor loop is running. Shows mempool size, peer counts, and lifetime
/// served/relayed totals. Hidden until at least one poll has populated data.
struct NetworkParticipationCard: View {
    @ObservedObject var viewModel: NodeViewModel

    var body: some View {
        CardContainer {
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 6) {
                    Image(systemName: "antenna.radiowaves.left.and.right")
                        .font(.system(size: 12))
                        .foregroundStyle(Theme.success)
                    Text("Network Participation")
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundStyle(Theme.textSecondary)
                    Spacer()
                    if viewModel.nodeState == .participant {
                        Text("LIVE")
                            .font(.system(size: 9, weight: .bold))
                            .foregroundStyle(Theme.success)
                            .padding(.horizontal, 6)
                            .padding(.vertical, 2)
                            .background(Theme.success.opacity(0.15))
                            .clipShape(Capsule())
                    }
                }

                if let ns = viewModel.nodeStatus {
                    HStack(spacing: 16) {
                        statBlock(
                            label: "Inbound",
                            value: "\(ns.inboundPeers)",
                            sub: "via .onion",
                            color: Theme.accent
                        )
                        statBlock(
                            label: "Outbound",
                            value: "\(ns.outboundPeers)",
                            sub: "Tor circuits",
                            color: Theme.textSecondary
                        )
                    }
                }

                if let mp = viewModel.mempoolStatus {
                    Divider().background(Theme.cardBorder)
                    HStack {
                        VStack(alignment: .leading, spacing: 2) {
                            Text("Mempool")
                                .font(.system(size: 11, weight: .medium))
                                .foregroundStyle(Theme.textTertiary)
                            Text("\(formatNumber(mp.txCount)) txs")
                                .font(.system(size: 14, weight: .semibold, design: .monospaced))
                                .foregroundStyle(Theme.textPrimary)
                        }
                        Spacer()
                        Text(byteSize(mp.totalSize) + " / " + byteSize(mp.maxSize))
                            .font(.system(size: 11, weight: .medium, design: .monospaced))
                            .foregroundStyle(Theme.textSecondary)
                    }
                }

                if let ns = viewModel.nodeStatus {
                    Divider().background(Theme.cardBorder)
                    HStack(spacing: 16) {
                        statBlock(
                            label: "Blocks Served",
                            value: formatNumber(UInt32(min(ns.blocksServed, UInt64(UInt32.max)))),
                            sub: "to peers",
                            color: Theme.success
                        )
                        statBlock(
                            label: "Txs Relayed",
                            value: formatNumber(UInt32(min(ns.txsRelayed, UInt64(UInt32.max)))),
                            sub: "lifetime",
                            color: Theme.success
                        )
                    }
                }
            }
        }
    }

    @ViewBuilder
    private func statBlock(label: String, value: String, sub: String, color: Color) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(label)
                .font(.system(size: 11, weight: .medium))
                .foregroundStyle(Theme.textTertiary)
            Text(value)
                .font(.system(size: 18, weight: .semibold, design: .monospaced))
                .foregroundStyle(color)
            Text(sub)
                .font(.system(size: 10))
                .foregroundStyle(Theme.textTertiary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func byteSize(_ bytes: UInt64) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(bytes), countStyle: .file)
    }
}

// MARK: - Node Status Card

struct NodeStatusCard: View {
    @ObservedObject var viewModel: NodeViewModel

    var statusColor: Color {
        if viewModel.syncStatus?.isSyncing == true { return Theme.warning }
        if let s = viewModel.syncStatus, s.peerHeight > 0, s.syncedHeaders >= s.peerHeight {
            return Theme.success
        }
        if viewModel.isConnecting { return Theme.warning }
        if viewModel.errorMessage != nil { return Theme.error }
        return Theme.textTertiary
    }

    var statusText: String {
        if viewModel.isConnecting { return "Connecting" }
        if viewModel.syncStatus?.isSyncing == true { return "Syncing" }
        if let s = viewModel.syncStatus, s.peerHeight > 0, s.syncedHeaders >= s.peerHeight {
            return "Synced"
        }
        if viewModel.errorMessage != nil { return "Disconnected" }
        if viewModel.syncStatus != nil { return "Idle" }
        return "Offline"
    }

    var body: some View {
        CardContainer {
            HStack(spacing: 14) {
                // Status indicator dot
                Circle()
                    .fill(statusColor)
                    .frame(width: 10, height: 10)
                    .shadow(color: statusColor.opacity(0.6), radius: 4)

                VStack(alignment: .leading, spacing: 2) {
                    Text("Node Status")
                        .font(.system(size: 13, weight: .medium))
                        .foregroundStyle(Theme.textSecondary)
                    Text(statusText)
                        .font(.system(size: 18, weight: .semibold))
                        .foregroundStyle(Theme.textPrimary)
                }

                Spacer()

                if let status = viewModel.syncStatus {
                    VStack(alignment: .trailing, spacing: 2) {
                        Text("Headers")
                            .font(.system(size: 11, weight: .medium))
                            .foregroundStyle(Theme.textTertiary)
                        Text(formatNumber(status.syncedHeaders))
                            .font(.system(size: 18, weight: .semibold, design: .monospaced))
                            .foregroundStyle(Theme.textPrimary)
                    }
                }
            }
        }
    }
}

// MARK: - Sync Progress Card

struct SyncProgressCard: View {
    let status: SyncStatus

    var progress: Double {
        guard status.peerHeight > 0 else { return 0 }
        return min(Double(status.syncedHeaders) / Double(status.peerHeight), 1.0)
    }

    var percentText: String {
        let pct = isSynced ? progress * 100 : min(progress * 100, 99.9)
        return String(format: "%.1f%%", pct)
    }

    var isSynced: Bool {
        status.syncedHeaders >= status.peerHeight
    }

    var body: some View {
        CardContainer {
            VStack(alignment: .leading, spacing: 14) {
                HStack {
                    Text("Header Sync Progress")
                        .font(.system(size: 13, weight: .medium))
                        .foregroundStyle(Theme.textSecondary)
                    Spacer()
                    Text(percentText)
                        .font(.system(size: 13, weight: .bold, design: .monospaced))
                        .foregroundStyle(isSynced ? Theme.success : Theme.accent)
                }

                // Custom progress bar
                GeometryReader { geo in
                    ZStack(alignment: .leading) {
                        RoundedRectangle(cornerRadius: 4)
                            .fill(Color.white.opacity(0.08))
                            .frame(height: 8)

                        RoundedRectangle(cornerRadius: 4)
                            .fill(
                                LinearGradient(
                                    colors: isSynced
                                        ? [Theme.success, Theme.success]
                                        : [Theme.accent, Theme.accent.opacity(0.7)],
                                    startPoint: .leading,
                                    endPoint: .trailing
                                )
                            )
                            .frame(width: geo.size.width * progress, height: 8)
                            .shadow(color: (isSynced ? Theme.success : Theme.accent).opacity(0.4), radius: 6, y: 2)
                    }
                }
                .frame(height: 8)

                HStack {
                    Label(formatNumber(status.syncedHeaders), systemImage: "checkmark.shield.fill")
                        .font(.system(size: 12, weight: .medium, design: .monospaced))
                        .foregroundStyle(Theme.textSecondary)
                    Spacer()
                    Label(formatNumber(status.peerHeight), systemImage: "target")
                        .font(.system(size: 12, weight: .medium, design: .monospaced))
                        .foregroundStyle(Theme.textTertiary)
                }
            }
        }
    }
}

// MARK: - Block Validation Card

struct BlockValidationCard: View {
    let status: SyncStatus
    @ObservedObject var viewModel: NodeViewModel

    var progress: Double {
        guard status.syncedHeaders > 0 else { return 0 }
        return min(Double(status.validatedBlocks) / Double(status.syncedHeaders), 1.0)
    }

    var percentText: String {
        let pct = isComplete ? progress * 100 : min(progress * 100, 99.9)
        return String(format: "%.1f%%", pct)
    }

    var isComplete: Bool {
        status.validatedBlocks >= status.syncedHeaders && status.syncedHeaders > 0
    }

    var isPaused: Bool {
        viewModel.isValidationPaused
    }

    var statusColor: Color {
        if isComplete { return Theme.success }
        if isPaused { return Theme.textTertiary }
        return Theme.warning
    }

    var body: some View {
        CardContainer {
            VStack(alignment: .leading, spacing: 14) {
                HStack {
                    Image(systemName: "cube.fill")
                        .font(.system(size: 12))
                        .foregroundStyle(statusColor)
                    Text(isPaused ? "Block Validation (Paused)" : "Block Validation")
                        .font(.system(size: 13, weight: .medium))
                        .foregroundStyle(Theme.textSecondary)
                    Spacer()
                    Text(percentText)
                        .font(.system(size: 13, weight: .bold, design: .monospaced))
                        .foregroundStyle(statusColor)
                }

                // Progress bar
                GeometryReader { geo in
                    ZStack(alignment: .leading) {
                        RoundedRectangle(cornerRadius: 4)
                            .fill(Color.white.opacity(0.08))
                            .frame(height: 8)

                        RoundedRectangle(cornerRadius: 4)
                            .fill(
                                LinearGradient(
                                    colors: isComplete
                                        ? [Theme.success, Theme.success]
                                        : isPaused
                                            ? [Theme.textTertiary, Theme.textTertiary.opacity(0.7)]
                                            : [Theme.warning, Theme.warning.opacity(0.7)],
                                    startPoint: .leading,
                                    endPoint: .trailing
                                )
                            )
                            .frame(width: geo.size.width * progress, height: 8)
                            .shadow(color: statusColor.opacity(0.4), radius: 6, y: 2)
                    }
                }
                .frame(height: 8)

                HStack {
                    Label(formatNumber(status.validatedBlocks), systemImage: "cube.fill")
                        .font(.system(size: 12, weight: .medium, design: .monospaced))
                        .foregroundStyle(Theme.textSecondary)
                    Spacer()

                    if !isComplete {
                        Button(action: { viewModel.toggleValidationPaused() }) {
                            HStack(spacing: 4) {
                                Image(systemName: isPaused ? "play.fill" : "pause.fill")
                                    .font(.system(size: 10))
                                Text(isPaused ? "Resume" : "Pause")
                                    .font(.system(size: 11, weight: .medium))
                            }
                            .foregroundStyle(isPaused ? Theme.accent : Theme.textSecondary)
                            .padding(.horizontal, 10)
                            .padding(.vertical, 5)
                            .background(isPaused ? Theme.accent.opacity(0.15) : Color.white.opacity(0.06))
                            .clipShape(RoundedRectangle(cornerRadius: 6))
                        }
                    }

                    Label(formatNumber(status.syncedHeaders), systemImage: "target")
                        .font(.system(size: 12, weight: .medium, design: .monospaced))
                        .foregroundStyle(Theme.textTertiary)
                }
            }
        }
    }
}

// MARK: - Snapshot Download Card

struct SnapshotDownloadCard: View {
    @ObservedObject var viewModel: NodeViewModel

    var percentText: String {
        String(format: "%.1f%%", viewModel.snapshotDownloadProgress * 100)
    }

    var byteText: String {
        let downloaded = ByteCountFormatter.string(
            fromByteCount: viewModel.snapshotBytesDownloaded,
            countStyle: .file
        )
        let total = ByteCountFormatter.string(
            fromByteCount: viewModel.snapshotBytesTotal,
            countStyle: .file
        )
        return "\(downloaded) / \(total)"
    }

    var body: some View {
        CardContainer {
            VStack(alignment: .leading, spacing: 14) {
                HStack {
                    Image(systemName: "icloud.and.arrow.down.fill")
                        .font(.system(size: 12))
                        .foregroundStyle(Theme.accent)
                    Text("Downloading UTXO Snapshot")
                        .font(.system(size: 13, weight: .medium))
                        .foregroundStyle(Theme.textSecondary)
                    Spacer()
                    Text(percentText)
                        .font(.system(size: 13, weight: .bold, design: .monospaced))
                        .foregroundStyle(Theme.accent)
                }

                GeometryReader { geo in
                    ZStack(alignment: .leading) {
                        RoundedRectangle(cornerRadius: 4)
                            .fill(Color.white.opacity(0.08))
                            .frame(height: 8)

                        RoundedRectangle(cornerRadius: 4)
                            .fill(
                                LinearGradient(
                                    colors: [Theme.accent, Theme.accent.opacity(0.7)],
                                    startPoint: .leading,
                                    endPoint: .trailing
                                )
                            )
                            .frame(width: geo.size.width * viewModel.snapshotDownloadProgress, height: 8)
                            .shadow(color: Theme.accent.opacity(0.4), radius: 6, y: 2)
                    }
                }
                .frame(height: 8)

                HStack {
                    Text(byteText)
                        .font(.system(size: 12, weight: .medium, design: .monospaced))
                        .foregroundStyle(Theme.textSecondary)
                    Spacer()
                    Text("Wi-Fi only • one-time")
                        .font(.system(size: 11, weight: .regular))
                        .foregroundStyle(Theme.textTertiary)
                }

                Button(action: { viewModel.cancelSnapshotDownload() }) {
                    HStack(spacing: 6) {
                        Image(systemName: "xmark.circle.fill")
                            .font(.system(size: 11))
                        Text("Cancel Download")
                            .font(.system(size: 12, weight: .medium))
                    }
                    .foregroundStyle(Theme.error)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 6)
                    .background(Theme.error.opacity(0.12))
                    .clipShape(RoundedRectangle(cornerRadius: 6))
                }
                .frame(maxWidth: .infinity, alignment: .trailing)
            }
        }
    }
}

// MARK: - Snapshot Loading Card

struct SnapshotLoadingCard: View {
    let progress: Double

    var percentText: String {
        String(format: "%.1f%%", progress * 100)
    }

    var body: some View {
        CardContainer {
            VStack(alignment: .leading, spacing: 14) {
                HStack {
                    Image(systemName: "arrow.down.doc.fill")
                        .font(.system(size: 12))
                        .foregroundStyle(Theme.accent)
                    Text("Loading UTXO Snapshot")
                        .font(.system(size: 13, weight: .medium))
                        .foregroundStyle(Theme.textSecondary)
                    Spacer()
                    Text(percentText)
                        .font(.system(size: 13, weight: .bold, design: .monospaced))
                        .foregroundStyle(Theme.accent)
                }

                GeometryReader { geo in
                    ZStack(alignment: .leading) {
                        RoundedRectangle(cornerRadius: 4)
                            .fill(Color.white.opacity(0.08))
                            .frame(height: 8)

                        RoundedRectangle(cornerRadius: 4)
                            .fill(
                                LinearGradient(
                                    colors: [Theme.accent, Theme.accent.opacity(0.7)],
                                    startPoint: .leading,
                                    endPoint: .trailing
                                )
                            )
                            .frame(width: geo.size.width * progress, height: 8)
                            .shadow(color: Theme.accent.opacity(0.4), radius: 6, y: 2)
                    }
                }
                .frame(height: 8)

                Text("Verifying & importing UTXO set…")
                    .font(.system(size: 12, weight: .regular))
                    .foregroundStyle(Theme.textTertiary)
            }
        }
    }
}

// MARK: - Tor Status Card

struct TorStatusCard: View {
    @ObservedObject var viewModel: NodeViewModel

    var body: some View {
        CardContainer {
            VStack(alignment: .leading, spacing: 10) {
                HStack(spacing: 10) {
                    Image(systemName: "lock.shield.fill")
                        .font(.system(size: 14))
                        .foregroundStyle(
                            viewModel.torStatus?.isBootstrapped == true
                                ? Theme.success : Theme.warning
                        )

                    VStack(alignment: .leading, spacing: 2) {
                        Text("Tor Network")
                            .font(.system(size: 13, weight: .medium))
                            .foregroundStyle(Theme.textSecondary)
                        Text(torStatusText)
                            .font(.system(size: 15, weight: .semibold))
                            .foregroundStyle(Theme.textPrimary)
                    }

                    Spacer()

                    if viewModel.isBootstrappingTor {
                        ProgressView()
                            .progressViewStyle(CircularProgressViewStyle(tint: Theme.warning))
                            .scaleEffect(0.7)
                    }
                }

                // Onion address display
                if let addr = viewModel.torStatus?.onionAddress {
                    HStack(spacing: 6) {
                        Image(systemName: "eye.slash.fill")
                            .font(.system(size: 10))
                            .foregroundStyle(Theme.textTertiary)
                        Text(truncateOnion(addr))
                            .font(.system(size: 11, weight: .medium, design: .monospaced))
                            .foregroundStyle(Theme.textSecondary)
                    }
                    .padding(.top, 2)
                }
            }
        }
    }

    var torStatusText: String {
        if viewModel.isBootstrappingTor { return "Connecting..." }
        if viewModel.torStatus?.isBootstrapped == true { return "Connected" }
        return "Offline"
    }
}

// MARK: - Peers Card

struct PeersCard: View {
    let status: SyncStatus

    var body: some View {
        CardContainer {
            VStack(alignment: .leading, spacing: 10) {
                HStack {
                    Image(systemName: "network")
                        .font(.system(size: 13))
                        .foregroundStyle(Theme.accent)
                    Text("Connected Peers (\(status.peers.count))")
                        .font(.system(size: 13, weight: .medium))
                        .foregroundStyle(Theme.textSecondary)
                }

                VStack(spacing: 6) {
                    ForEach(status.peers, id: \.addr) { peer in
                        HStack(spacing: 8) {
                            Circle()
                                .fill(peer.addr == status.activePeerAddr
                                    ? Theme.success : Theme.textTertiary.opacity(0.4))
                                .frame(width: 6, height: 6)

                            // Truncate .onion addresses for readability
                            Text(truncateOnion(peer.addr))
                                .font(.system(size: 12, weight: .medium, design: .monospaced))
                                .foregroundStyle(Theme.textPrimary)

                            // Show onion icon for .onion peers
                            if peer.addr.contains(".onion") {
                                Image(systemName: "lock.shield.fill")
                                    .font(.system(size: 9))
                                    .foregroundStyle(Theme.success.opacity(0.6))
                            }

                            Spacer()

                            if !peer.userAgent.isEmpty {
                                Text(peer.userAgent)
                                    .font(.system(size: 10, design: .monospaced))
                                    .foregroundStyle(Theme.textTertiary)
                                    .lineLimit(1)
                            }
                        }
                        .padding(.vertical, 4)
                        .padding(.horizontal, 8)
                        .background(peer.addr == status.activePeerAddr
                            ? Theme.accent.opacity(0.08) : Color.clear)
                        .clipShape(RoundedRectangle(cornerRadius: 6))
                    }
                }
            }
        }
    }
}

// MARK: - Error Card

struct ErrorCard: View {
    let message: String

    var body: some View {
        CardContainer {
            VStack(alignment: .leading, spacing: 8) {
                HStack(spacing: 6) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .font(.system(size: 13))
                        .foregroundStyle(Theme.error)
                    Text("Connection Error")
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundStyle(Theme.error)
                }

                Text(message)
                    .font(.system(size: 12, weight: .regular, design: .monospaced))
                    .foregroundStyle(Theme.textSecondary)
                    .lineLimit(4)
            }
        }
    }
}

struct StorageWarningCard: View {
    let message: String

    var body: some View {
        CardContainer {
            VStack(alignment: .leading, spacing: 8) {
                HStack(spacing: 6) {
                    Image(systemName: "externaldrive.fill.badge.exclamationmark")
                        .font(.system(size: 13))
                        .foregroundStyle(Theme.warning)
                    Text("Low Storage")
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundStyle(Theme.warning)
                }

                Text(message)
                    .font(.system(size: 12))
                    .foregroundStyle(Theme.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }
}

// MARK: - Sync Button

struct SyncButton: View {
    @ObservedObject var viewModel: NodeViewModel

    var isSyncing: Bool {
        viewModel.syncStatus?.isSyncing == true
    }

    var isSynced: Bool {
        if let s = viewModel.syncStatus, s.peerHeight > 0, s.syncedHeaders >= s.peerHeight {
            return true
        }
        return false
    }

    var canStop: Bool {
        viewModel.isSyncRunning
            && !viewModel.isConnecting
            && !viewModel.isLoadingSnapshot
            && !viewModel.isDownloadingSnapshot
    }

    var label: String {
        if viewModel.isResetting { return "Resetting..." }
        if viewModel.validationMode == nil { return "Choose Validation Mode" }
        if viewModel.isDownloadingSnapshot { return "Downloading UTXO Snapshot..." }
        if viewModel.isLoadingSnapshot { return "Loading UTXO Snapshot..." }
        if viewModel.isBootstrappingTor { return "Connecting to Tor..." }
        if viewModel.isConnecting { return "Finding Peers via Tor..." }
        if canStop && isSyncing { return "Pause Sync" }
        if canStop && isSynced { return "Pause Node" }
        if canStop { return "Pause Node" }
        if viewModel.syncStatus != nil { return "Resume" }
        return "Connect via Tor"
    }

    var icon: String {
        if viewModel.isConnecting { return "arrow.triangle.2.circlepath" }
        if canStop { return "pause.fill" }
        if isSynced { return "checkmark.shield.fill" }
        return "bolt.fill"
    }

    var body: some View {
        Button(action: { canStop ? viewModel.pauseSync() : viewModel.resumeSync() }) {
            HStack(spacing: 10) {
                if viewModel.isConnecting || isSyncing {
                    ProgressView()
                        .progressViewStyle(CircularProgressViewStyle(tint: .white))
                        .scaleEffect(0.7)
                } else {
                    Image(systemName: icon)
                        .font(.system(size: 15, weight: .semibold))
                }

                Text(label)
                    .font(.system(size: 16, weight: .semibold))
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 16)
            .foregroundStyle(canStop ? Theme.error : (isSynced ? Theme.accent : .white))
            .background(
                Group {
                    if canStop {
                        Color.clear
                    } else if isSyncing {
                        Theme.warning
                    } else {
                        LinearGradient(
                            colors: [Theme.accent, Theme.accent.opacity(0.8)],
                            startPoint: .leading,
                            endPoint: .trailing
                        )
                    }
                }
            )
            .clipShape(RoundedRectangle(cornerRadius: 14))
            .overlay(
                RoundedRectangle(cornerRadius: 14)
                    .stroke(canStop ? Theme.error : (isSynced ? Theme.accent : Color.clear), lineWidth: 1.5)
            )
            .shadow(color: canStop ? Color.clear : (isSyncing ? Theme.warning : Theme.accent).opacity(0.3), radius: 12, y: 6)
        }
        .disabled(
            viewModel.isConnecting
            || viewModel.isLoadingSnapshot
            || viewModel.isDownloadingSnapshot
            || viewModel.isResetting
            || viewModel.validationMode == nil
        )
    }
}

// MARK: - Card Container

struct CardContainer<Content: View>: View {
    @ViewBuilder let content: () -> Content

    var body: some View {
        content()
            .padding(16)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Theme.card)
            .clipShape(RoundedRectangle(cornerRadius: 14))
            .overlay(
                RoundedRectangle(cornerRadius: 14)
                    .stroke(Theme.cardBorder, lineWidth: 1)
            )
    }
}

// MARK: - Helpers

func formatNumber(_ n: UInt32) -> String {
    let formatter = NumberFormatter()
    formatter.numberStyle = .decimal
    return formatter.string(from: NSNumber(value: n)) ?? "\(n)"
}

/// Truncate long .onion addresses for display: "abcdef...xyz.onion:8333"
func truncateOnion(_ addr: String) -> String {
    guard addr.contains(".onion") else { return addr }
    // Format: <56-char-hash>.onion:port
    let parts = addr.split(separator: ":")
    let host = String(parts.first ?? Substring(addr))
    let port = parts.count > 1 ? ":\(parts[1])" : ""
    let onionParts = host.split(separator: ".")
    guard let hash = onionParts.first, hash.count > 16 else { return addr }
    let prefix = hash.prefix(8)
    let suffix = hash.suffix(8)
    return "\(prefix)...\(suffix).onion\(port)"
}

#Preview {
    ContentView()
}
