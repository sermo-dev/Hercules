import SwiftUI

struct WalletView: View {
    @ObservedObject var viewModel: NodeViewModel
    @State private var showImport = false
    @State private var showReceive = false
    @State private var selectedTx: WalletTransaction?

    var body: some View {
        ZStack {
            Theme.bg.ignoresSafeArea(.all)

            if viewModel.isWalletScanning {
                walletScanningView
            } else if viewModel.hasWallet {
                walletContent
            } else {
                noWalletView
            }
        }
    }

    // MARK: - No Wallet

    private var noWalletView: some View {
        VStack(spacing: 24) {
            Spacer()

            Image(systemName: "bitcoinsign.circle")
                .font(.system(size: 64, weight: .thin))
                .foregroundStyle(Theme.textTertiary)

            Text("No Wallet")
                .font(.system(size: 22, weight: .semibold))
                .foregroundStyle(Theme.textPrimary)

            Text("Import an xpub to track your balance,\ntransactions, and receive addresses.")
                .font(.system(size: 14))
                .foregroundStyle(Theme.textSecondary)
                .multilineTextAlignment(.center)

            Button(action: { showImport = true }) {
                HStack(spacing: 8) {
                    Image(systemName: "plus.circle.fill")
                        .font(.system(size: 16))
                    Text("Import Wallet")
                        .font(.system(size: 15, weight: .semibold))
                }
                .foregroundStyle(.white)
                .padding(.horizontal, 24)
                .padding(.vertical, 12)
                .background(Theme.accent)
                .clipShape(Capsule())
            }

            Spacer()
        }
        .sheet(isPresented: $showImport) {
            WalletImportView(viewModel: viewModel)
        }
    }

    // MARK: - Scanning

    private var walletScanningView: some View {
        VStack(spacing: 20) {
            Spacer()

            ProgressView()
                .scaleEffect(1.5)
                .tint(Theme.accent)

            Text("Scanning UTXO Set")
                .font(.system(size: 18, weight: .semibold))
                .foregroundStyle(Theme.textPrimary)

            Text("Checking ~180 million outputs\nfor your addresses...")
                .font(.system(size: 14))
                .foregroundStyle(Theme.textSecondary)
                .multilineTextAlignment(.center)

            Spacer()
        }
    }

    // MARK: - Wallet Content

    private var walletContent: some View {
        VStack(spacing: 0) {
            ScrollView(showsIndicators: false) {
                VStack(spacing: 20) {
                    // Header
                    Text("WALLET")
                        .font(.system(size: 28, weight: .heavy))
                        .tracking(4)
                        .foregroundStyle(Theme.textPrimary)
                        .padding(.top, 16)

                    // Balance card
                    balanceCard

                    // Action buttons
                    HStack(spacing: 16) {
                        Button(action: { showReceive = true }) {
                            HStack(spacing: 6) {
                                Image(systemName: "arrow.down.circle.fill")
                                    .font(.system(size: 14))
                                Text("Receive")
                                    .font(.system(size: 14, weight: .semibold))
                            }
                            .foregroundStyle(.white)
                            .frame(maxWidth: .infinity)
                            .padding(.vertical, 12)
                            .background(Theme.accent)
                            .clipShape(RoundedRectangle(cornerRadius: 12))
                        }
                    }
                    .padding(.horizontal, 20)

                    // Transaction list
                    if !viewModel.walletTransactions.isEmpty {
                        transactionList
                    }

                    // Delete wallet button
                    Button(action: { viewModel.deleteWallet() }) {
                        Text("Remove Wallet")
                            .font(.system(size: 13, weight: .medium))
                            .foregroundStyle(Theme.error.opacity(0.7))
                    }
                    .padding(.top, 8)
                    .padding(.bottom, 40)
                }
            }
        }
        .sheet(isPresented: $showReceive) {
            if let addr = viewModel.walletReceiveAddress {
                ReceiveView(addressInfo: addr)
            }
        }
        .sheet(item: $selectedTx) { tx in
            TransactionDetailView(
                tx: tx,
                currentHeight: viewModel.walletScanHeight
            )
        }
    }

    // MARK: - Balance Card

    private var balanceCard: some View {
        CardContainer {
            VStack(spacing: 8) {
                Text("Balance")
                    .font(.system(size: 13, weight: .medium))
                    .foregroundStyle(Theme.textSecondary)

                if let bal = viewModel.walletBalance {
                    Text(formatSats(bal.confirmed))
                        .font(.system(size: 32, weight: .bold, design: .monospaced))
                        .foregroundStyle(Theme.textPrimary)

                    Text("sats")
                        .font(.system(size: 13, weight: .medium))
                        .foregroundStyle(Theme.textTertiary)

                    if bal.unconfirmed > 0 {
                        HStack(spacing: 4) {
                            Image(systemName: "clock")
                                .font(.system(size: 11))
                            Text("+\(formatSats(bal.unconfirmed)) unconfirmed")
                                .font(.system(size: 12))
                        }
                        .foregroundStyle(Theme.warning)
                        .padding(.top, 4)
                    }
                } else {
                    Text("--")
                        .font(.system(size: 32, weight: .bold, design: .monospaced))
                        .foregroundStyle(Theme.textTertiary)
                }
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 8)
        }
    }

    // MARK: - Transaction List

    private var transactionList: some View {
        CardContainer {
            VStack(alignment: .leading, spacing: 0) {
                Text("Recent Transactions")
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundStyle(Theme.textSecondary)
                    .padding(.bottom, 12)

                ForEach(Array(viewModel.walletTransactions.enumerated()), id: \.offset) { index, tx in
                    Button(action: { selectedTx = tx }) {
                        transactionRow(tx)
                    }

                    if index < viewModel.walletTransactions.count - 1 {
                        Divider()
                            .background(Theme.cardBorder)
                            .padding(.vertical, 8)
                    }
                }
            }
        }
    }

    private func transactionRow(_ tx: WalletTransaction) -> some View {
        HStack {
            // Direction indicator
            Image(systemName: tx.netValue >= 0 ? "arrow.down.left" : "arrow.up.right")
                .font(.system(size: 14, weight: .semibold))
                .foregroundStyle(tx.netValue >= 0 ? Theme.success : Theme.error)
                .frame(width: 28, height: 28)
                .background(
                    (tx.netValue >= 0 ? Theme.success : Theme.error).opacity(0.12)
                )
                .clipShape(Circle())

            VStack(alignment: .leading, spacing: 2) {
                Text(tx.netValue >= 0 ? "Received" : "Sent")
                    .font(.system(size: 14, weight: .medium))
                    .foregroundStyle(Theme.textPrimary)

                if let ts = tx.timestampHuman {
                    Text(ts)
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(Theme.textTertiary)
                } else if let h = tx.height {
                    Text("Block \(formatNumber(h))")
                        .font(.system(size: 11, design: .monospaced))
                        .foregroundStyle(Theme.textTertiary)
                }
            }

            Spacer()

            Text("\(tx.netValue >= 0 ? "+" : "")\(formatSats(UInt64(abs(tx.netValue))))")
                .font(.system(size: 14, weight: .semibold, design: .monospaced))
                .foregroundStyle(tx.netValue >= 0 ? Theme.success : Theme.error)
        }
        .padding(.vertical, 4)
    }
}

// MARK: - Helpers

/// Format a satoshi amount with thousand separators.
func formatSats(_ sats: UInt64) -> String {
    let formatter = NumberFormatter()
    formatter.numberStyle = .decimal
    formatter.groupingSeparator = ","
    return formatter.string(from: NSNumber(value: sats)) ?? "\(sats)"
}

// MARK: - WalletTransaction Identifiable

extension WalletTransaction: @retroactive Identifiable {
    public var id: String { txid }
}
