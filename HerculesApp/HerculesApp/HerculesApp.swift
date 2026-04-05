import SwiftUI

@main
struct HerculesApp: App {
    @UIApplicationDelegateAdaptor(AppDelegate.self) var appDelegate

    var body: some Scene {
        WindowGroup {
            ContentView()
                .statusBarHidden(false)
                .preferredColorScheme(.dark)
        }
    }
}
