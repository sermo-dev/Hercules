import SwiftUI

struct MainTabView: View {
    @StateObject private var viewModel = NodeViewModel()
    @State private var selectedTab = 0

    var body: some View {
        TabView(selection: $selectedTab) {
            NodeView(viewModel: viewModel)
                .tabItem {
                    Label("Node", systemImage: "server.rack")
                }
                .tag(0)

            WalletView(viewModel: viewModel)
                .tabItem {
                    Label("Wallet", systemImage: "bitcoinsign.circle")
                }
                .tag(1)
        }
        .tint(Theme.accent)
    }
}

#Preview {
    MainTabView()
}
