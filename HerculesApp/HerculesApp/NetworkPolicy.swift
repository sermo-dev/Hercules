import Combine
import Foundation
import Network

/// Centralised view of the device's current network path and the user's
/// "Use Cellular Data" preference. All code paths that initiate validation
/// work — silent push wakes, snapshot downloads, foreground catch-up — must
/// consult `shouldValidate` before opening sockets so that a user on cellular
/// (or Personal Hotspot, or Low Data Mode) is never silently billed for the
/// node's traffic.
///
/// Path classification follows Apple's `NWPath` flags:
///
/// - `isExpensive` — set on cellular **and** on Personal Hotspot tethered
///   from another iPhone. Catches the "I plugged into my friend's hotspot"
///   case that a naive `usesInterfaceType(.cellular)` check would miss.
/// - `isConstrained` — set when the user has Low Data Mode enabled for the
///   active interface. We treat this as metered too: the user has explicitly
///   asked iOS to back off on background traffic, and a node validating
///   every block is the opposite of that.
///
/// Either flag → `isMetered` → blocked unless `cellularAllowed` is true.
///
/// Singleton because the underlying `NWPathMonitor` is a system-wide
/// resource and `@AppStorage` / `UserDefaults` writes need a single source
/// of truth that all SwiftUI views observe.
final class NetworkPolicy: ObservableObject {
    static let shared = NetworkPolicy()

    /// `UserDefaults` key for the global "Use Cellular Data" toggle.
    /// Default value is `false` (Wi-Fi only). Settings UI binds to this key
    /// via `@AppStorage`, and `cellularAllowed` reads through it on every
    /// access so a toggle change takes effect immediately without needing
    /// to re-publish from this object.
    static let useCellularDataKey = "useCellularData"

    @Published private(set) var pathStatus: NWPath.Status = .requiresConnection
    @Published private(set) var isExpensive: Bool = false
    @Published private(set) var isConstrained: Bool = false

    /// True if the active path is cellular, Personal Hotspot, or Low Data
    /// Mode — i.e. anywhere we'd burn the user's metered allowance.
    var isMetered: Bool { isExpensive || isConstrained }

    /// User preference: are we allowed to use the network even when it's
    /// metered? Read-through to UserDefaults so a Settings toggle takes
    /// effect on the next access without a republish.
    var cellularAllowed: Bool {
        UserDefaults.standard.bool(forKey: Self.useCellularDataKey)
    }

    /// The single decision callers should consult before opening any
    /// validation socket. Returns true iff:
    ///
    /// 1. There is some kind of network path available, AND
    /// 2. Either the path is unmetered, OR the user has opted in to
    ///    spending cellular data on the node.
    var shouldValidate: Bool {
        guard pathStatus == .satisfied else { return false }
        if isMetered && !cellularAllowed { return false }
        return true
    }

    /// Three-state classification used by the main-screen status icon:
    /// - `.unmetered` — green, free to validate
    /// - `.meteredAllowed` — yellow, the user opted in, validating is fine
    ///   but worth surfacing so they don't forget
    /// - `.meteredBlocked` — red, validation is paused until the user
    ///   either reconnects to Wi-Fi or flips the cellular toggle
    /// - `.offline` — red/grey, no path at all
    enum Indicator {
        case unmetered
        case meteredAllowed
        case meteredBlocked
        case offline
    }

    var indicator: Indicator {
        guard pathStatus == .satisfied else { return .offline }
        if !isMetered { return .unmetered }
        return cellularAllowed ? .meteredAllowed : .meteredBlocked
    }

    private let monitor: NWPathMonitor
    private let queue = DispatchQueue(label: "io.hercules.networkpolicy", qos: .utility)

    private init() {
        monitor = NWPathMonitor()
        monitor.pathUpdateHandler = { [weak self] path in
            // `pathUpdateHandler` fires on `queue`, but the @Published
            // properties drive SwiftUI views — bounce to main.
            DispatchQueue.main.async {
                guard let self = self else { return }
                self.pathStatus = path.status
                self.isExpensive = path.isExpensive
                self.isConstrained = path.isConstrained
            }
        }
        monitor.start(queue: queue)
    }

    deinit {
        monitor.cancel()
    }
}
