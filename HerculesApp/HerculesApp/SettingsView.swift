import SwiftUI

struct SettingsView: View {
    @ObservedObject var notificationManager = NotificationManager.shared
    @State private var relayURL: String = NotificationManager.shared.relayServerURL
    @State private var isTestingNotification = false
    @State private var testResult: String?
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        ZStack {
            Theme.bg.ignoresSafeArea(.all)

            ScrollView(showsIndicators: false) {
                VStack(spacing: 20) {
                    header
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
        if let token = notificationManager.deviceToken {
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
        case .headerOnly: return "checkmark.circle.fill"
        case .pushPayload: return "bell.fill"
        }
    }

    private func colorForSource(_ source: NotificationSource) -> Color {
        switch source {
        case .fullValidation: return Theme.success
        case .headerOnly: return Theme.warning
        case .pushPayload: return Theme.textSecondary
        }
    }

    private func labelForSource(_ source: NotificationSource) -> String {
        switch source {
        case .fullValidation: return "Validated"
        case .headerOnly: return "Header"
        case .pushPayload: return "Unverified"
        }
    }
}
