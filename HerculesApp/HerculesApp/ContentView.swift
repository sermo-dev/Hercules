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

// MARK: - View Model

class NodeViewModel: ObservableObject {
    @Published var syncStatus: SyncStatus?
    @Published var isConnecting = false
    @Published var isSyncRunning = false
    @Published var errorMessage: String?
    @Published var isLoadingSnapshot = false
    @Published var snapshotProgress: Double = 0
    @Published var isValidationPaused = false

    // Thread-safe access to the node: set from background thread, read from main thread
    private var _node: HerculesNode?
    private let nodeLock = NSLock()
    private var node: HerculesNode? {
        get { nodeLock.lock(); defer { nodeLock.unlock() }; return _node }
        set { nodeLock.lock(); defer { nodeLock.unlock() }; _node = newValue }
    }

    func startSync() {
        guard !isSyncRunning else { return }
        isConnecting = true
        isSyncRunning = true
        errorMessage = nil

        DispatchQueue.global(qos: .userInitiated).async { [weak self] in
            do {
                let dbPath = Self.dbPath()
                let node = try HerculesNode(dbPath: dbPath)
                self?.node = node

                // Check if we need to load a UTXO snapshot
                if try node.needsSnapshot() {
                    let snapshotPath = Self.snapshotPath()
                    if FileManager.default.fileExists(atPath: snapshotPath) {
                        DispatchQueue.main.async {
                            self?.isLoadingSnapshot = true
                            self?.isConnecting = false
                        }

                        let snapCallback = SnapshotProgressCallback { loaded, total in
                            DispatchQueue.main.async {
                                self?.snapshotProgress = total > 0
                                    ? Double(loaded) / Double(total) : 0
                            }
                        }

                        let _ = try node.loadSnapshot(
                            snapshotPath: snapshotPath,
                            callback: snapCallback
                        )

                        DispatchQueue.main.async {
                            self?.isLoadingSnapshot = false
                        }
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

    func toggleValidationPaused() {
        guard let node = node else { return }
        let newState = !isValidationPaused
        isValidationPaused = newState
        // Dispatch FFI call off main thread (setValidationPaused sets an AtomicBool
        // so it's fast, but avoid blocking the main thread for any FFI call)
        DispatchQueue.global(qos: .userInitiated).async {
            node.setValidationPaused(paused: newState)
        }
    }

    static func dbPath() -> String {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
        return docs.appendingPathComponent("hercules-headers.sqlite3").path
    }

    static func snapshotPath() -> String {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first!
        return docs.appendingPathComponent("utxo-snapshot.hutx").path
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

    var body: some View {
        ZStack {
            Theme.bg.ignoresSafeArea(.all)

            VStack(spacing: 0) {
                ScrollView(showsIndicators: false) {
                    VStack(spacing: 20) {
                        // Logo / header area
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
                        .padding(.top, 16)
                        .padding(.bottom, 4)

                        // Node status card
                        NodeStatusCard(viewModel: viewModel)

                        // Header sync progress card
                        if let status = viewModel.syncStatus, status.peerHeight > 0 {
                            SyncProgressCard(status: status)
                        }

                        // Snapshot loading card
                        if viewModel.isLoadingSnapshot {
                            SnapshotLoadingCard(progress: viewModel.snapshotProgress)
                        }

                        // Block validation progress card
                        if let status = viewModel.syncStatus, status.validatedBlocks > 0 {
                            BlockValidationCard(status: status, viewModel: viewModel)
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
        String(format: "%.1f%%", progress * 100)
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
        String(format: "%.1f%%", progress * 100)
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

                Text("Importing verified UTXO set...")
                    .font(.system(size: 12, weight: .regular))
                    .foregroundStyle(Theme.textTertiary)
            }
        }
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

                            Text(peer.addr)
                                .font(.system(size: 12, weight: .medium, design: .monospaced))
                                .foregroundStyle(Theme.textPrimary)

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

    var label: String {
        if viewModel.isLoadingSnapshot { return "Loading UTXO Snapshot..." }
        if viewModel.isConnecting { return "Connecting to Network..." }
        if isSyncing { return "Syncing Headers..." }
        if isSynced { return "Node Active" }
        if viewModel.isSyncRunning { return "Monitoring Network..." }
        if viewModel.syncStatus != nil { return "Resume Sync" }
        return "Connect to Bitcoin Network"
    }

    var icon: String {
        if viewModel.isConnecting || isSyncing { return "arrow.triangle.2.circlepath" }
        if isSynced { return "checkmark.shield.fill" }
        return "bolt.fill"
    }

    var body: some View {
        Button(action: { viewModel.startSync() }) {
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
            .foregroundStyle(isSynced ? Theme.accent : .white)
            .background(
                Group {
                    if isSynced {
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
                    .stroke(isSynced ? Theme.accent : Color.clear, lineWidth: 1.5)
            )
            .shadow(color: isSynced ? Color.clear : (isSyncing ? Theme.warning : Theme.accent).opacity(0.3), radius: 12, y: 6)
        }
        .disabled(viewModel.isSyncRunning)
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

#Preview {
    ContentView()
}
