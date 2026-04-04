import SwiftUI

struct ContentView: View {
    @State private var blockInfo: BlockInfo?
    @State private var version: String = ""

    // Bitcoin block #840,000 header (the 4th halving block, April 2024)
    // This is a real block header from the Bitcoin blockchain
    let block840000Header = "00e0a836a89edb4ca5cbe063ab52f4b365e91c7e346f463a0e000000000000000000000089b4be4fb1c3fe32adcdab01ed286e3aee4cfb1811e050f6cd0f9b9af11ecd7761201f6617c8001913b7c239"

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 20) {
                    // Header
                    VStack(alignment: .leading, spacing: 4) {
                        Text(version)
                            .font(.caption)
                            .foregroundStyle(.secondary)
                        Text("Rust + Bitcoin + iOS")
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                    }
                    .frame(maxWidth: .infinity, alignment: .leading)

                    if let info = blockInfo {
                        // Block Hash
                        InfoCard(title: "Block Hash", value: info.blockHash, monospace: true)

                        // Block Details
                        VStack(alignment: .leading, spacing: 12) {
                            Text("Block Details")
                                .font(.headline)

                            DetailRow(label: "Version", value: "\(info.version)")
                            DetailRow(label: "Timestamp", value: info.timestampHuman)
                            DetailRow(label: "Nonce", value: "\(info.nonce)")
                            DetailRow(label: "Bits", value: String(format: "0x%08x", info.bits))
                        }
                        .padding()
                        .background(.ultraThinMaterial)
                        .clipShape(RoundedRectangle(cornerRadius: 12))

                        // Previous Block Hash
                        InfoCard(title: "Previous Block", value: info.prevBlockHash, monospace: true)

                        // Merkle Root
                        InfoCard(title: "Merkle Root", value: info.merkleRoot, monospace: true)
                    } else {
                        ProgressView("Parsing block header...")
                    }
                }
                .padding()
            }
            .navigationTitle("Block #840,000")
        }
        .onAppear {
            version = herculesVersion()
            blockInfo = parseBlockHeader(hexHeader: block840000Header)
        }
    }
}

struct InfoCard: View {
    let title: String
    let value: String
    var monospace: Bool = false

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text(title)
                .font(.headline)
            Text(value)
                .font(monospace ? .system(.caption, design: .monospaced) : .caption)
                .foregroundStyle(.secondary)
                .textSelection(.enabled)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding()
        .background(.ultraThinMaterial)
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }
}

struct DetailRow: View {
    let label: String
    let value: String

    var body: some View {
        HStack {
            Text(label)
                .foregroundStyle(.secondary)
            Spacer()
            Text(value)
                .font(.system(.body, design: .monospaced))
        }
    }
}

#Preview {
    ContentView()
}
