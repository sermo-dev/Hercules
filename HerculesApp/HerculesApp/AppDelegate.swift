import BackgroundTasks
import Combine
import UIKit
import UserNotifications

class AppDelegate: NSObject, UIApplicationDelegate, UNUserNotificationCenterDelegate {

    /// Combine subscriptions held for the lifetime of the app delegate so
    /// the network-policy → widget-state bridge stays live across the
    /// whole foreground process. Cleared on dealloc, which only fires at
    /// app termination.
    private var cancellables = Set<AnyCancellable>()

    func application(
        _ application: UIApplication,
        didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil
    ) -> Bool {
        UNUserNotificationCenter.current().delegate = self

        // Touch NetworkPolicy.shared early so its NWPathMonitor starts
        // before any wake or download attempt; bridge its published
        // metered/blocked state into the App Group container so the
        // home-screen widget reflects it without needing a wake to fire.
        let policy = NetworkPolicy.shared
        policy.objectWillChange
            .sink { _ in
                // `objectWillChange` fires *before* the new value is
                // published, but we read through `cellularAllowed` and
                // `pathStatus` which are settled by the time the next
                // runloop tick processes our handler. A microtask hop
                // gives the publisher a chance to apply.
                DispatchQueue.main.async {
                    SharedNodeStore.markPaused(!policy.shouldValidate)
                }
            }
            .store(in: &cancellables)

        // Initial publish at launch so the widget reflects whatever
        // policy + last-known state is correct *now*, not on the next
        // change.
        SharedNodeStore.markPaused(!policy.shouldValidate)

        // Register BGAppRefreshTask for accelerated catch-up after gaps.
        BGTaskScheduler.shared.register(
            forTaskWithIdentifier: NotificationManager.catchUpTaskIdentifier,
            using: nil
        ) { task in
            NotificationManager.shared.handleCatchUpTask(task as! BGAppRefreshTask)
        }

        return true
    }

    // MARK: - Remote Notification Registration

    func application(
        _ application: UIApplication,
        didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data
    ) {
        let token = deviceToken.map { String(format: "%02x", $0) }.joined()
        NotificationManager.shared.handleDeviceToken(token)
    }

    func application(
        _ application: UIApplication,
        didFailToRegisterForRemoteNotificationsWithError error: Error
    ) {
        NotificationManager.shared.handleRegistrationError(error)
    }

    // MARK: - Silent Push (Background Wake)

    func application(
        _ application: UIApplication,
        didReceiveRemoteNotification userInfo: [AnyHashable: Any],
        fetchCompletionHandler completionHandler: @escaping (UIBackgroundFetchResult) -> Void
    ) {
        NotificationManager.shared.handleSilentPush(
            userInfo: userInfo,
            completionHandler: completionHandler
        )
    }

    // MARK: - Background URLSession (snapshot download)

    func application(
        _ application: UIApplication,
        handleEventsForBackgroundURLSession identifier: String,
        completionHandler: @escaping () -> Void
    ) {
        // Stash the handler; SnapshotDownloader will invoke it once the
        // session has finished delivering all pending events.
        SnapshotDownloader.shared.backgroundCompletionHandler = completionHandler
    }

    // MARK: - Foreground Notification Display

    func userNotificationCenter(
        _ center: UNUserNotificationCenter,
        willPresent notification: UNNotification,
        withCompletionHandler completionHandler: @escaping (UNNotificationPresentationOptions) -> Void
    ) {
        completionHandler([.banner, .sound])
    }
}
