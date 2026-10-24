import SwiftUI

struct TransactionDetailView: View {
    let tx: WalletTransaction
    let currentHeight: UInt32
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            ZStack {
                Theme.bg.ignoresSafeArea(.all)

                ScrollView {
                    VStack(spacing: 20) {
                        // Amount header
                        VStack(spacing: 8) {
                            Image(systemName: tx.netValue >= 0 ? "arrow.down.left.circle.fill" : "arrow.up.right.circle.fill")
                                .font(.system(size: 44))
                                .foregroundStyle(tx.netValue >= 0 ? Theme.success : Theme.error)

                            Text(tx.netValue >= 0 ? "Received" : "Sent")
                                .font(.system(size: 16, weight: .medium))
                                .foregroundStyle(Theme.textSecondary)

                            Text("\(tx.netValue >= 0 ? "+" : "")\(formatSats(UInt64(abs(tx.netValue)))) sats")
                                .font(.system(size: 28, weight: .bold, design: .monospaced))
                                .foregroundStyle(tx.netValue >= 0 ? Theme.success : Theme.error)
                        }
                        .padding(.top, 16)

                        // Detail rows
                        CardContainer {
                            VStack(spacing: 16) {
                                detailRow(label: "Transaction ID", value: tx.txid, monospaced: true)

                                if let h = tx.height {
                                    detailRow(label: "Block Height", value: formatNumber(h))

                                    let confs = currentHeight >= h ? currentHeight - h + 1 : 0
                                    detailRow(label: "Confirmations", value: formatNumber(confs))
                                } else {
                                    detailRow(label: "Status", value: "Unconfirmed")
                                }

                                if let ts = tx.timestampHuman {
                                    detailRow(label: "Timestamp", value: ts)
                                }
                            }
                        }

                        // Copy txid button
                        Button(action: {
                            UIPasteboard.general.string = tx.txid
                        }) {
                            HStack(spacing: 6) {
                                Image(systemName: "doc.on.doc")
                                    .font(.system(size: 13))
                                Text("Copy Transaction ID")
                                    .font(.system(size: 13, weight: .medium))
                            }
                            .foregroundStyle(Theme.accent)
                        }
                        .padding(.top, 4)
                    }
                    .padding(.bottom, 40)
                }
            }
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }
                        .foregroundStyle(Theme.accent)
                }
            }
        }
    }

    private func detailRow(label: String, value: String, monospaced: Bool = false) -> some View {
        VStack(alignment: .leading, spacing: 4) {
            Text(label)
                .font(.system(size: 12, weight: .medium))
                .foregroundStyle(Theme.textTertiary)

            Text(value)
                .font(.system(size: 14, weight: .medium, design: monospaced ? .monospaced : .default))
                .foregroundStyle(Theme.textPrimary)
                .textSelection(.enabled)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }
}
