import SwiftUI

struct AboutView: View {
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        ZStack {
            Theme.bg.ignoresSafeArea(.all)

            ScrollView(showsIndicators: false) {
                VStack(spacing: 20) {
                    header

                    heroCard

                    foregroundCard

                    backgroundCard

                    limitationsCard

                    Spacer(minLength: 40)
                }
                .padding(.horizontal, 20)
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
            Text("About Hercules")
                .font(.system(size: 20, weight: .bold))
                .foregroundStyle(Theme.textPrimary)
            Spacer()
            Color.clear.frame(width: 24)
        }
        .padding(.top, 16)
    }

    // MARK: - Hero

    private var heroCard: some View {
        CardContainer {
            VStack(spacing: 12) {
                Text("HERCULES")
                    .font(.system(size: 24, weight: .heavy))
                    .tracking(4)
                    .foregroundStyle(Theme.textPrimary)

                Text("A sovereign Bitcoin full node\nthat fits in your pocket.")
                    .font(.system(size: 15))
                    .foregroundStyle(Theme.textSecondary)
                    .multilineTextAlignment(.center)
                    .lineSpacing(4)
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 8)
        }
    }

    // MARK: - Foreground Mode

    private var foregroundCard: some View {
        CardContainer {
            VStack(alignment: .leading, spacing: 14) {
                Label("When the app is open", systemImage: "sun.max.fill")
                    .font(.system(size: 14, weight: .semibold))
                    .foregroundStyle(Theme.success)

                VStack(alignment: .leading, spacing: 10) {
                    bulletPoint(
                        "Full participant on the Bitcoin network",
                        detail: "Hercules connects to peers over Tor and operates as a pruned full node \u{2014} it validates every block using the same consensus rules as Bitcoin Core."
                    )
                    bulletPoint(
                        "Header chain verification",
                        detail: "Downloads and validates the proof-of-work for every block header back to genesis, ensuring the chain with the most cumulative work."
                    )
                    bulletPoint(
                        "Full block validation with script checks",
                        detail: "Downloads complete blocks and verifies every transaction, including running Bitcoin Script for each input using libbitcoinconsensus."
                    )
                    bulletPoint(
                        "UTXO set tracking",
                        detail: "Maintains the unspent transaction output set to verify that transactions only spend coins that actually exist."
                    )
                }
            }
        }
    }

    // MARK: - Background Mode

    private var backgroundCard: some View {
        CardContainer {
            VStack(alignment: .leading, spacing: 14) {
                Label("When the app is closed", systemImage: "moon.fill")
                    .font(.system(size: 14, weight: .semibold))
                    .foregroundStyle(Theme.accent)

                VStack(alignment: .leading, spacing: 10) {
                    bulletPoint(
                        "Push-triggered block validation",
                        detail: "A lightweight relay server detects new blocks (~every 10 minutes) and sends a silent push notification. iOS wakes the app for up to 30 seconds to validate the block."
                    )
                    bulletPoint(
                        "Tiered validation under deadline",
                        detail: "Reconnects to a peer via cached Tor state, validates the new block header's proof-of-work, and if time permits, downloads and fully validates the block with script checks."
                    )
                    bulletPoint(
                        "Continuous chain maintenance",
                        detail: "Even while you sleep, Hercules keeps your local blockchain up to date and independently verified \u{2014} so when you open the app, you're already synced."
                    )
                }

                HStack(spacing: 8) {
                    Image(systemName: "info.circle")
                        .font(.system(size: 11))
                        .foregroundStyle(Theme.textTertiary)
                    Text("The push relay only sends block hashes \u{2014} your node still independently validates everything. The relay cannot lie about block content.")
                        .font(.system(size: 11))
                        .foregroundStyle(Theme.textTertiary)
                        .lineSpacing(2)
                }
                .padding(.top, 4)
            }
        }
    }

    // MARK: - Limitations

    private var limitationsCard: some View {
        CardContainer {
            VStack(alignment: .leading, spacing: 14) {
                Label("What Hercules is not", systemImage: "exclamationmark.triangle.fill")
                    .font(.system(size: 14, weight: .semibold))
                    .foregroundStyle(Theme.warning)

                VStack(alignment: .leading, spacing: 10) {
                    limitationPoint(
                        "Not a full archival node",
                        detail: "Hercules does not store the entire blockchain history. It uses AssumeUTXO to start from a recent snapshot and only retains recent blocks. It cannot serve historical blocks to other nodes."
                    )
                    limitationPoint(
                        "Not a wallet",
                        detail: "Hercules validates the blockchain but does not manage keys, sign transactions, or hold funds. It is a verification engine, not a spending tool."
                    )
                    limitationPoint(
                        "Background validation depends on a relay",
                        detail: "iOS does not allow apps to wake themselves. Background block validation requires a push notification from an external relay server \u{2014} this is the one non-sovereign component."
                    )
                    limitationPoint(
                        "30-second background window",
                        detail: "iOS limits background execution time. Under poor network conditions, full block validation may not complete, falling back to header-only (proof-of-work) verification."
                    )
                }
            }
        }
    }

    // MARK: - Components

    private func bulletPoint(_ title: String, detail: String) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "checkmark.circle.fill")
                .font(.system(size: 12))
                .foregroundStyle(Theme.success)
                .padding(.top, 2)

            VStack(alignment: .leading, spacing: 3) {
                Text(title)
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(Theme.textPrimary)
                Text(detail)
                    .font(.system(size: 12))
                    .foregroundStyle(Theme.textSecondary)
                    .lineSpacing(2)
            }
        }
    }

    private func limitationPoint(_ title: String, detail: String) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "minus.circle.fill")
                .font(.system(size: 12))
                .foregroundStyle(Theme.warning)
                .padding(.top, 2)

            VStack(alignment: .leading, spacing: 3) {
                Text(title)
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(Theme.textPrimary)
                Text(detail)
                    .font(.system(size: 12))
                    .foregroundStyle(Theme.textSecondary)
                    .lineSpacing(2)
            }
        }
    }
}
