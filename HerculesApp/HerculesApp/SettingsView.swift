import SwiftUI

struct SettingsView: View {
    @ObservedObject var viewModel: NodeViewModel
    @ObservedObject var notificationManager = NotificationManager.shared
    @ObservedObject private var networkPolicy = NetworkPolicy.shared
    @AppStorage(NetworkPolicy.useCellularDataKey) private var useCellularData: Bool = false
    @State private var relayURL: String = NotificationManager.shared.relayServerURL
    @State private var isTestingNotification = false
    @State private var testResult: String?
    @State private var showSwitchModeConfirm = false
    @State private var pendingSwitchMode: ValidationMode?
    @State private var switchModeError: String?
    @State private var copiedConnectionString = false
    @State private var copiedMuHash = false
    @State private var showRotateConfirm = false
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        ZStack {
            Theme.bg.ignoresSafeArea(.all)

            ScrollView(showsIndicators: false) {
                VStack(spacing: 20) {
                    header
                    validationModeCard
                    if let trust = viewModel.trustInfo, trust.snapshotHeight > 0 {
                        trustCard(trust)
                    }
                    cellularDataCard
                    walletApiCard
                    notificationToggleCard
                    relayServerCard
                    registrationStatusCard
                    testNotificationCard
                    if !notificationManager.notificationHistory.isEmpty {
                        historyCard
                    }
                }
                .padding(.horizontal, 20)
                .padding(.bottom, 40)
            }
        }
        .alert("Regenerate auth token?", isPresented: $showRotateConfirm) {
            Button("Cancel", role: .cancel) {}
            Button("Regenerate", role: .destructive) {
                viewModel.rotateWalletAuthToken()
            }
        } message: {
            Text("This will immediately invalidate the current token. Any wallet using the old connection string will lose access and need the new one.")
        }
        .alert("Switch validation mode?", isPresented: $showSwitchModeConfirm, presenting: pendingSwitchMode) { mode in
            Button("Cancel", role: .cancel) {
                pendingSwitchMode = nil
            }
            Button("Switch & Wipe", role: .destructive) {
                viewModel.resetAndRestart(mode: mode) { error in
                    if let error = error {
                        switchModeError = "\(error)"
                    }
                    pendingSwitchMode = nil
                }
            }
        } message: { mode in
            let validated = viewModel.syncStatus?.validatedBlocks ?? 0
            let target = mode == .assumeUtxo ? "AssumeUTXO" : "Validate from Genesis"
            Text("This will discard \(formatNumber(validated)) validated blocks and the current UTXO set, then restart in \(target) mode. This cannot be undone.")
        }
    }

    // MARK: - Validation Mode

    private var validationModeCard: some View {
        CardContainer {
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 6) {
                    Image(systemName: "shield.lefthalf.filled")
                        .font(.system(size: 13))
                        .foregroundStyle(Theme.accent)
                    Text("Validation Mode")
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundStyle(Theme.textSecondary)
                }

                let current = viewModel.validationMode
                Text(current == .assumeUtxo
                     ? "AssumeUTXO — trusts a hash baked into the app."
                     : current == .fromGenesis
                        ? "Validate from Genesis — trusts only consensus rules."
                        : "Not yet selected.")
                    .font(.system(size: 12))
                    .foregroundStyle(Theme.textPrimary)

                Text("Switching modes wipes all on-disk state (headers, UTXO, blocks) and starts fresh. The node must restart.")
                    .font(.system(size: 11))
                    .foregroundStyle(Theme.textTertiary)

                if let trust = viewModel.trustInfo,
                   trust.snapshotHeight > 0,
                   trust.forwardValidatedBlocks > 0 {
                    HStack(spacing: 4) {
                        Image(systemName: "shield.checkerboard")
                            .font(.system(size: 11))
                            .foregroundStyle(Theme.accent)
                        Text("Forward-validated \(formatNumber(trust.forwardValidatedBlocks)) blocks since snapshot")
                            .font(.system(size: 12))
                            .foregroundStyle(Theme.textSecondary)
                    }
                }

                HStack(spacing: 10) {
                    switchButton(to: .assumeUtxo, label: "Switch to AssumeUTXO")
                    switchButton(to: .fromGenesis, label: "Switch to Genesis")
                }

                if let err = switchModeError {
                    Text(err)
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(Theme.error)
                }
            }
        }
    }

    @ViewBuilder
    private func switchButton(to mode: ValidationMode, label: String) -> some View {
        let isCurrent = viewModel.validationMode == mode
        Button(action: {
            switchModeError = nil
            pendingSwitchMode = mode
            showSwitchModeConfirm = true
        }) {
            Text(label)
                .font(.system(size: 11, weight: .semibold))
                .foregroundStyle(isCurrent ? Theme.textTertiary : Theme.accent)
                .padding(.horizontal, 10)
                .padding(.vertical, 6)
                .frame(maxWidth: .infinity)
                .background((isCurrent ? Theme.textTertiary : Theme.accent).opacity(0.12))
                .clipShape(RoundedRectangle(cornerRadius: 8))
        }
        .buttonStyle(.plain)
        .disabled(isCurrent || viewModel.isResetting)
    }

    // MARK: - Header

    private var header: some View {
        HStack {
            Button(action: { dismiss() }) {
                Image(systemName: "chevron.left")
                    .font(.system(size: 16, weight: .semibold))
                    .foregroundStyle(Theme.accent)
            }
            Spacer()
            Text("Settings")
                .font(.system(size: 20, weight: .bold))
                .foregroundStyle(Theme.textPrimary)
            Spacer()
            // Balance the back button
            Color.clear.frame(width: 24)
        }
        .padding(.top, 16)
    }

    // MARK: - Trust Verification

    private func trustCard(_ trust: TrustInfo) -> some View {
        CardContainer {
            VStack(alignment: .leading, spacing: 10) {
                HStack(spacing: 6) {
                    Image(systemName: "checkmark.seal.fill")
                        .font(.system(size: 13))
                        .foregroundStyle(Theme.success)
                    Text("Trust Verification")
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundStyle(Theme.textSecondary)
                }

                VStack(alignment: .leading, spacing: 6) {
                    trustRow(label: "Snapshot loaded at block", value: "#\(formatNumber(trust.snapshotHeight))")
                    trustRow(label: "Current validated height", value: "#\(formatNumber(trust.validatedHeight))")

                    HStack(spacing: 4) {
                        Image(systemName: "shield.checkerboard")
                            .font(.system(size: 11))
                            .foregroundStyle(Theme.accent)
                        Text("Forward-validated against")
                            .font(.system(size: 12))
                            .foregroundStyle(Theme.textPrimary)
                        Text("\(formatNumber(trust.forwardValidatedBlocks)) blocks")
                            .font(.system(size: 12, weight: .semibold))
                            .foregroundStyle(Theme.accent)
                    }
                }

                Text("Each block validated after the snapshot is an implicit check that the UTXO set is correct. Higher numbers indicate stronger empirical confidence.")
                    .font(.system(size: 11))
                    .foregroundStyle(Theme.textTertiary)

                if let muhash = trust.muhash {
                    Divider().background(Theme.cardBorder)

                    VStack(alignment: .leading, spacing: 6) {
                        HStack(spacing: 6) {
                            Image(systemName: "number.square")
                                .font(.system(size: 13))
                                .foregroundStyle(Theme.accent)
                            Text("UTXO Set MuHash")
                                .font(.system(size: 13, weight: .semibold))
                                .foregroundStyle(Theme.textSecondary)
                        }

                        Text(muhash)
                            .font(.system(size: 10, design: .monospaced))
                            .foregroundStyle(Theme.textPrimary)
                            .textSelection(.enabled)

                        Button(action: {
                            UIPasteboard.general.string = muhash
                            copiedMuHash = true
                            DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
                                copiedMuHash = false
                            }
                        }) {
                            HStack(spacing: 4) {
                                Image(systemName: copiedMuHash ? "checkmark" : "doc.on.doc")
                                    .font(.system(size: 11))
                                Text(copiedMuHash ? "Copied" : "Copy MuHash")
                                    .font(.system(size: 11, weight: .medium))
                            }
                            .foregroundStyle(Theme.accent)
                        }

                        Text("Verify on your Bitcoin Core node (requires coinstatsindex=1):")
                            .font(.system(size: 11))
                            .foregroundStyle(Theme.textTertiary)
                        Text("bitcoin-cli gettxoutsetinfo muhash \(trust.snapshotHeight)")
                            .font(.system(size: 10, design: .monospaced))
                            .foregroundStyle(Theme.textSecondary)
                            .textSelection(.enabled)
                    }
                }
            }
        }
    }

    private func trustRow(label: String, value: String) -> some View {
        HStack {
            Text(label)
                .font(.system(size: 12))
                .foregroundStyle(Theme.textPrimary)
            Spacer()
            Text(value)
                .font(.system(size: 12, weight: .medium, design: .monospaced))
                .foregroundStyle(Theme.textPrimary)
        }
    }

    // MARK: - Cellular Data

    private var cellularDataCard: some View {
        CardContainer {
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 6) {
                    Image(systemName: cellularIcon)
                        .font(.system(size: 13))
                        .foregroundStyle(cellularIconColor)
                    Text("Network Usage")
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundStyle(Theme.textSecondary)
                }

                HStack {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("Use Cellular Data")
                            .font(.system(size: 15, weight: .semibold))
                            .foregroundStyle(Theme.textPrimary)
                        Text("Validate blocks and download the snapshot over cellular, hotspot, or Low Data Mode")
                            .font(.system(size: 12))
                            .foregroundStyle(Theme.textSecondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    Spacer()
                    Toggle("", isOn: $useCellularData)
                        .labelsHidden()
                        .tint(Theme.accent)
                }

                Text(cellularStatusText)
                    .font(.system(size: 11))
                    .foregroundStyle(cellularIconColor)
                    .fixedSize(horizontal: false, vertical: true)

                Text("Off by default. Each validated block uses ~2 MB; the snapshot is ~8 GB. With cellular off, block validation is paused on metered networks but resumes automatically on Wi-Fi.")
                    .font(.system(size: 11))
                    .foregroundStyle(Theme.textTertiary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private var cellularIcon: String {
        switch networkPolicy.indicator {
        case .unmetered: return "wifi"
        case .meteredAllowed: return "antenna.radiowaves.left.and.right"
        case .meteredBlocked: return "antenna.radiowaves.left.and.right.slash"
        case .offline: return "wifi.slash"
        }
    }

    private var cellularIconColor: Color {
        switch networkPolicy.indicator {
        case .unmetered: return Theme.success
        case .meteredAllowed: return Theme.warning
        case .meteredBlocked: return Theme.error
        case .offline: return Theme.textTertiary
        }
    }

    private var cellularStatusText: String {
        switch networkPolicy.indicator {
        case .unmetered:
            return "On Wi-Fi — validating freely."
        case .meteredAllowed:
            return "On metered network — validating with your opt-in. Watch your data usage."
        case .meteredBlocked:
            return "On metered network — validation paused. Toggle on to allow, or wait for Wi-Fi."
        case .offline:
            return "No network — validation paused until reconnected."
        }
    }

    // MARK: - Wallet API

    private var walletApiCard: some View {
        CardContainer {
            VStack(alignment: .leading, spacing: 12) {
                HStack(spacing: 6) {
                    Image(systemName: "link.circle.fill")
                        .font(.system(size: 13))
                        .foregroundStyle(viewModel.isWalletApiRunning ? Theme.success : Theme.accent)
                    Text("Wallet API")
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundStyle(Theme.textSecondary)
                }

                HStack {
                    VStack(alignment: .leading, spacing: 4) {
                        Text("External Wallet Access")
                            .font(.system(size: 15, weight: .semibold))
                            .foregroundStyle(Theme.textPrimary)
                        Text("Serve your node's blockchain data to external wallets over Tor")
                            .font(.system(size: 12))
                            .foregroundStyle(Theme.textSecondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    Spacer()
                    Toggle("", isOn: Binding(
                        get: { viewModel.isWalletApiRunning },
                        set: { newValue in
                            if newValue {
                                viewModel.startWalletApi()
                            } else {
                                viewModel.stopWalletApi()
                            }
                        }
                    ))
                    .labelsHidden()
                    .tint(Theme.accent)
                    .disabled(!viewModel.isSyncRunning)
                }

                if let connString = viewModel.walletApiConnectionString, viewModel.isWalletApiRunning {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("Connection String")
                            .font(.system(size: 11, weight: .medium))
                            .foregroundStyle(Theme.textTertiary)

                        Text(connString)
                            .font(.system(size: 11, design: .monospaced))
                            .foregroundStyle(Theme.textPrimary)
                            .lineLimit(3)
                            .padding(10)
                            .frame(maxWidth: .infinity, alignment: .leading)
                            .background(Color.white.opacity(0.05))
                            .clipShape(RoundedRectangle(cornerRadius: 8))

                        HStack(spacing: 10) {
                            Button(action: {
                                UIPasteboard.general.string = connString
                                copiedConnectionString = true
                                DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
                                    copiedConnectionString = false
                                }
                            }) {
                                HStack(spacing: 6) {
                                    Image(systemName: copiedConnectionString ? "checkmark" : "doc.on.doc")
                                        .font(.system(size: 12))
                                    Text(copiedConnectionString ? "Copied" : "Copy")
                                        .font(.system(size: 13, weight: .medium))
                                }
                                .foregroundStyle(copiedConnectionString ? Theme.success : Theme.accent)
                                .padding(.horizontal, 12)
                                .padding(.vertical, 8)
                                .background((copiedConnectionString ? Theme.success : Theme.accent).opacity(0.12))
                                .clipShape(RoundedRectangle(cornerRadius: 8))
                            }
                            .buttonStyle(.plain)

                            Button(action: { showRotateConfirm = true }) {
                                HStack(spacing: 6) {
                                    Image(systemName: "arrow.triangle.2.circlepath")
                                        .font(.system(size: 12))
                                    Text("Regenerate")
                                        .font(.system(size: 13, weight: .medium))
                                }
                                .foregroundStyle(Theme.warning)
                                .padding(.horizontal, 12)
                                .padding(.vertical, 8)
                                .background(Theme.warning.opacity(0.12))
                                .clipShape(RoundedRectangle(cornerRadius: 8))
                            }
                            .buttonStyle(.plain)
                        }
                    }
                }

                if let error = viewModel.walletApiError {
                    Text(error)
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(Theme.error)
                }

                if !viewModel.isSyncRunning {
                    Text("Start the node first — the wallet API requires an active Tor connection.")
                        .font(.system(size: 11))
                        .foregroundStyle(Theme.textTertiary)
                } else {
                    Text("Paste the connection string into Sparrow, Fully Noded, or any wallet that supports Tor. The string contains your auth token — keep it private.")
                        .font(.system(size: 11))
                        .foregroundStyle(Theme.textTertiary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
    }

    // MARK: - Notifications Toggle

    private var notificationToggleCard: some View {
        CardContainer {
            HStack {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Block Notifications")
                        .font(.system(size: 15, weight: .semibold))
                        .foregroundStyle(Theme.textPrimary)
                    Text("Get notified when new blocks are mined")
                        .font(.system(size: 12))
                        .foregroundStyle(Theme.textSecondary)
                }
                Spacer()
                Toggle("", isOn: Binding(
                    get: { notificationManager.isEnabled },
                    set: { newValue in
                        notificationManager.isEnabled = newValue
                        if newValue {
                            notificationManager.requestPermission()
                        }
                    }
                ))
                .labelsHidden()
                .tint(Theme.accent)
            }
        }
    }

    // MARK: - Relay Server

    private var relayServerCard: some View {
        CardContainer {
            VStack(alignment: .leading, spacing: 10) {
                Text("Relay Server")
                    .font(.system(size: 13, weight: .medium))
                    .foregroundStyle(Theme.textSecondary)

                TextField("https://your-relay.example.com", text: $relayURL)
                    .font(.system(size: 14, design: .monospaced))
                    .foregroundStyle(Theme.textPrimary)
                    .textFieldStyle(.plain)
                    .autocapitalization(.none)
                    .disableAutocorrection(true)
                    .padding(10)
                    .background(Color.white.opacity(0.05))
                    .clipShape(RoundedRectangle(cornerRadius: 8))
                    .onSubmit {
                        notificationManager.relayServerURL = relayURL
                    }

                Text("Your relay server sends push notifications when new blocks arrive. Anyone can run one.")
                    .font(.system(size: 11))
                    .foregroundStyle(Theme.textTertiary)
            }
        }
    }

    // MARK: - Registration Status

    private var registrationStatusCard: some View {
        CardContainer {
            VStack(alignment: .leading, spacing: 8) {
                Text("Registration Status")
                    .font(.system(size: 13, weight: .medium))
                    .foregroundStyle(Theme.textSecondary)

                HStack(spacing: 8) {
                    Circle()
                        .fill(statusColor)
                        .frame(width: 8, height: 8)
                    Text(statusText)
                        .font(.system(size: 14))
                        .foregroundStyle(Theme.textPrimary)
                }

                if let token = notificationManager.deviceToken {
                    Text(truncateToken(token))
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(Theme.textTertiary)
                }
            }
        }
    }

    private var statusColor: Color {
        if notificationManager.deviceToken != nil { return Theme.success }
        if notificationManager.registrationError != nil { return Theme.warning }
        return Theme.textTertiary
    }

    private var statusText: String {
        if notificationManager.deviceToken != nil {
            return "Registered"
        }
        if let error = notificationManager.registrationError {
            if error.contains("3000") || error.contains("simulator") || error.contains("entitlement") {
                return "Requires Apple Developer Account"
            }
            return "Error: \(error)"
        }
        if notificationManager.isEnabled {
            return "Pending..."
        }
        return "Not registered"
    }

    // MARK: - Test Notification

    private var testNotificationCard: some View {
        CardContainer {
            VStack(alignment: .leading, spacing: 10) {
                Text("Development")
                    .font(.system(size: 13, weight: .medium))
                    .foregroundStyle(Theme.textSecondary)

                Button(action: runTestNotification) {
                    HStack(spacing: 8) {
                        if isTestingNotification {
                            ProgressView()
                                .progressViewStyle(CircularProgressViewStyle(tint: Theme.accent))
                                .scaleEffect(0.7)
                        } else {
                            Image(systemName: "bell.badge.fill")
                                .font(.system(size: 14))
                        }
                        Text(isTestingNotification ? "Validating..." : "Test Notification")
                            .font(.system(size: 14, weight: .medium))
                    }
                    .foregroundStyle(Theme.accent)
                }
                .disabled(isTestingNotification)

                Text("Connects to a peer, validates the latest block, and shows a notification. No APNs required.")
                    .font(.system(size: 11))
                    .foregroundStyle(Theme.textTertiary)

                if let result = testResult {
                    Text(result)
                        .font(.system(size: 12, design: .monospaced))
                        .foregroundStyle(result.contains("Error") ? Theme.error : Theme.success)
                }
            }
        }
    }

    private func runTestNotification() {
        isTestingNotification = true
        testResult = nil

        notificationManager.testNotification { result in
            isTestingNotification = false
            switch result {
            case .success(let record):
                if record.validated {
                    testResult = "Block #\(record.height) fully validated"
                } else if record.headerValidated {
                    testResult = "Block #\(record.height) header verified"
                } else {
                    testResult = "Block #\(record.height) (no new blocks)"
                }
            case .failure(let error):
                testResult = "Error: \(error.localizedDescription)"
            }
        }
    }

    // MARK: - Notification History

    private var historyCard: some View {
        CardContainer {
            VStack(alignment: .leading, spacing: 12) {
                Text("Recent Notifications")
                    .font(.system(size: 13, weight: .medium))
                    .foregroundStyle(Theme.textSecondary)

                ForEach(notificationManager.notificationHistory.prefix(20)) { record in
                    HStack(spacing: 10) {
                        Image(systemName: iconForSource(record.source))
                            .font(.system(size: 12))
                            .foregroundStyle(colorForSource(record.source))
                            .frame(width: 20)

                        VStack(alignment: .leading, spacing: 2) {
                            Text("Block #\(record.height)")
                                .font(.system(size: 13, weight: .medium))
                                .foregroundStyle(Theme.textPrimary)
                            Text(record.receivedAt, style: .relative)
                                .font(.system(size: 11))
                                .foregroundStyle(Theme.textTertiary)
                        }

                        Spacer()

                        Text(labelForSource(record.source))
                            .font(.system(size: 10, weight: .medium))
                            .foregroundStyle(colorForSource(record.source))
                            .padding(.horizontal, 6)
                            .padding(.vertical, 2)
                            .background(colorForSource(record.source).opacity(0.15))
                            .clipShape(RoundedRectangle(cornerRadius: 4))
                    }

                    if record.id != notificationManager.notificationHistory.prefix(20).last?.id {
                        Divider().background(Theme.cardBorder)
                    }
                }
            }
        }
    }

    // MARK: - Helpers

    private func truncateToken(_ token: String) -> String {
        if token.count <= 16 { return token }
        return "\(token.prefix(8))...\(token.suffix(8))"
    }

    private func iconForSource(_ source: NotificationSource) -> String {
        switch source {
        case .fullValidation: return "checkmark.shield.fill"
        case .catchUpProgress: return "arrow.triangle.2.circlepath"
        case .tipDisagreement: return "exclamationmark.triangle.fill"
        case .headerOnly: return "checkmark.circle.fill"
        case .pushPayload: return "bell.fill"
        case .networkPolicyPaused: return "pause.circle.fill"
        }
    }

    private func colorForSource(_ source: NotificationSource) -> Color {
        switch source {
        case .fullValidation: return Theme.success
        case .catchUpProgress: return Theme.accent
        case .tipDisagreement: return .purple
        case .headerOnly: return Theme.warning
        case .pushPayload: return Theme.textSecondary
        case .networkPolicyPaused: return Theme.warning
        }
    }

    private func labelForSource(_ source: NotificationSource) -> String {
        switch source {
        case .fullValidation: return "Validated"
        case .catchUpProgress: return "Catching Up"
        case .tipDisagreement: return "Tip Disagreement"
        case .headerOnly: return "Header"
        case .pushPayload: return "Unverified"
        case .networkPolicyPaused: return "Paused"
        }
    }
}
