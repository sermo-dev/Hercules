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

/// How the node builds its UTXO set on first run.
///
/// `assumeUtxo` downloads a hash-anchored snapshot — fast but anchored to a
/// constant baked into the app. `fromGenesis` validates every block from
/// height 0 — slower (weeks on a phone) but trusts only Bitcoin's consensus
/// rules. The choice is part of the node's identity for a given DB; switching
/// is destructive and goes through `NodeViewModel.resetAndRestart`.
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

    // Thread-safe access to the node: set from background thread, read from main thread
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
    private func awaitSnapshotDownload() throws -> URL {
        let semaphore = DispatchSemaphore(value: 0)
        var result: Result<URL, Error> = .failure(NSError(
            domain: "Hercules", code: -1,
            userInfo: [NSLocalizedDescriptionKey: "Download did not complete"]
        ))
        DispatchQueue.main.async {
            self.downloadWaiter = { r in
                result = r
                semaphore.signal()
            }
            SnapshotDownloader.shared.start()
        }
        semaphore.wait()
        switch result {
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
    }

    /// Wipe all on-disk state and restart sync with a new validation mode.
    /// This is the destructive "Switch validation mode" path: it stops the
    /// running node, drops the open SQLite handles, deletes the headers /
    /// utxo / blocks DB files via Rust's `reset_database`, persists the new
    /// mode, then re-runs `startSync`. Any in-progress snapshot download is
    /// also cancelled and its cached file removed.
    ///
    /// `completion` is invoked on the main queue after the wipe finishes
    /// (success) or with the error that aborted it (failure). It runs
    /// *before* `startSync` is re-invoked so the caller can dismiss any
    /// confirmation sheet first.
    func resetAndRestart(mode: ValidationMode, completion: @escaping (Error?) -> Void) {
        DispatchQueue.main.async { self.isResetting = true }

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            guard let self = self else { return }

            // 1. Cancel any in-flight download (clears resume data + .gz file).
            SnapshotDownloader.shared.cancel()
            SnapshotDownloader.deleteDownloadedFile()

            // 2. Ask the running sync loop to stop. This sets a flag the loop
            // checks on its next iteration — it does NOT block.
            if let node = self.node {
                node.stopSync()
            }

            // 3. Spin until the sync loop has actually returned (isSyncRunning
            // flips to false in the catch/finally of startSync's background
            // task). Cap the wait so a wedged loop can't deadlock the user.
            let deadline = Date().addingTimeInterval(15)
            while Date() < deadline {
                var stillRunning = true
                DispatchQueue.main.sync { stillRunning = self.isSyncRunning }
                if !stillRunning { break }
                Thread.sleep(forTimeInterval: 0.1)
            }

            // 4. Drop the HerculesNode reference so its open SQLite handles
            // are released BEFORE we try to delete the files. On POSIX an
            // open inode survives unlink, which would leave stale state.
            self.node = nil

            // 5. Wipe the on-disk DBs via Rust.
            do {
                try resetDatabase(dbPath: Self.dbPath())
            } catch {
                DispatchQueue.main.async {
                    self.isResetting = false
                    completion(error)
                }
                return
            }

            // 6. Persist the new mode and reset transient UI state.
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

                completion(nil)

                // 7. Kick off a fresh sync with the new mode.
                self.startSync()
            }
        }
    }

    func startSync() {
        guard !isSyncRunning else { return }
        isConnecting = true
        isBootstrappingTor = true
        isSyncRunning = true
        errorMessage = nil

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            do {
                let dbPath = Self.dbPath()
                let torDir = Self.torDataDir()
                let node = try HerculesNode(dbPath: dbPath, torDataDir: torDir)

                // Fetch initial Tor status
                if let status = node.getTorStatus() {
                    DispatchQueue.main.async {
                        self?.torStatus = status
                        self?.isBootstrappingTor = false
                    }
                } else {
                    DispatchQueue.main.async {
                        self?.isBootstrappingTor = false
                    }
                }
                self?.node = node

                // Honor the user's explicit validation-mode choice. AssumeUTXO
                // runs the download/import path on a fresh DB; Genesis skips
                // it entirely (block-by-block validation will start from
                // wherever validated_height is — 0 on a clean wipe).
                let mode = self?.validationMode ?? .assumeUtxo
                if mode == .assumeUtxo, try node.needsSnapshot() {
                    DispatchQueue.main.async {
                        self?.isConnecting = false
                    }

                    // Block until the file is on disk. Surfaces progress to
                    // the UI via the SnapshotDownloader subscriptions set up
                    // in init().
                    let downloadedURL = try self?.awaitSnapshotDownload()
                    guard let snapshotURL = downloadedURL else {
                        throw NSError(
                            domain: "Hercules", code: 2,
                            userInfo: [NSLocalizedDescriptionKey: "Snapshot download cancelled"]
                        )
                    }

                    DispatchQueue.main.async {
                        self?.isLoadingSnapshot = true
                    }

                    let snapCallback = SnapshotProgressCallback { loaded, total in
                        DispatchQueue.main.async {
                            self?.snapshotProgress = total > 0
                                ? Double(loaded) / Double(total) : 0
                        }
                    }

                    // Always delete the cached .gz after the import attempt:
                    // on success it's redundant (UTXOs are now in SQLite); on
                    // failure it prevents an infinite hash-mismatch retry loop
                    // against the same bad bytes.
                    do {
                        let _ = try node.loadSnapshot(
                            snapshotPath: snapshotURL.path,
                            callback: snapCallback
                        )
                        SnapshotDownloader.deleteDownloadedFile()
                    } catch {
                        SnapshotDownloader.deleteDownloadedFile()
                        throw error
                    }

                    DispatchQueue.main.async {
                        self?.isLoadingSnapshot = false
                    }
                }

                let status = try node.getStatus()
                DispatchQueue.main.async {
                    self?.syncStatus = status
                }

                let callback = SyncProgressCallback { status in
                    DispatchQueue.main.async {
                        self?.syncStatus = status
                        self?.isConnecting = false
                        self?.errorMessage = status.error
                        self?.maybePublishWidgetState(from: status)
                    }
                }

                // This runs continuously — only returns on unrecoverable error
                try node.startHeaderSync(callback: callback)

            } catch {
                DispatchQueue.main.async {
                    self?.errorMessage = "\(error)"
                    self?.isConnecting = false
                    self?.isSyncRunning = false
                    self?.isLoadingSnapshot = false
                    self?.isDownloadingSnapshot = false
                    if let s = self?.syncStatus {
                        self?.syncStatus = SyncStatus(
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
            }
        }
    }

    func stopSync() {
        guard let node = node else { return }
        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            node.stopSync()
            DispatchQueue.main.async {
                self?.isSyncRunning = false
                self?.isConnecting = false
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
                self?.isValidationPaused = newState
            }
        }
    }

    static func dbPath() -> String {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
        return docs.appendingPathComponent("hercules-headers.sqlite3").path
    }

    static func torDataDir() -> String {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
        return docs.appendingPathComponent("tor").path
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
    let handler: (UInt64, UInt64) -> Void

    init(handler: @escaping (UInt64, UInt64) -> Void) {
        self.handler = handler
    }

    func onProgress(loaded: UInt64, total: UInt64) {
        handler(loaded, total)
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
        if canStop && isSyncing { return "Stop Sync" }
        if canStop && isSynced { return "Stop Node" }
        if canStop { return "Stop Node" }
        if viewModel.syncStatus != nil { return "Resume Sync" }
        return "Connect via Tor"
    }

    var icon: String {
        if viewModel.isConnecting { return "arrow.triangle.2.circlepath" }
        if canStop { return "stop.fill" }
        if isSynced { return "checkmark.shield.fill" }
        return "bolt.fill"
    }

    var body: some View {
        Button(action: { canStop ? viewModel.stopSync() : viewModel.startSync() }) {
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
