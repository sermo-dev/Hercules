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

    /// How long a caller waits for the monitor's first path before deciding
    /// (cold launch from a silent push). `NWPathMonitor` usually delivers
    /// within a few milliseconds of `start`.
    static let firstPathTimeout: TimeInterval = 1.5

    // Mirrors of `currentPath` for SwiftUI, updated on main. Decisions read
    // `currentPath` instead: these lag the monitor by a main-queue hop, and on
    // a cold launch the first hop runs after the push handler has decided.
    @Published private(set) var pathStatus: NWPath.Status = .requiresConnection
    @Published private(set) var isExpensive: Bool = false
    @Published private(set) var isConstrained: Bool = false

    /// One path update, as the policy reads it.
    struct PathState: Equatable {
        var status: NWPath.Status
        var isExpensive: Bool
        var isConstrained: Bool
    }

    /// The latest path, written on the monitor queue. Nil until the first
    /// update arrives.
    private let stateLock = NSLock()
    private var _state: PathState?
    private var currentPath: PathState? {
        stateLock.lock(); defer { stateLock.unlock() }
        return _state
    }

    /// Entered at init, left once on the first path update.
    private let firstPath = DispatchGroup()

    /// Called on the monitor queue with `isMetered` whenever it changes
    /// (ticket 049: the node caps the blocks it serves on a metered path).
    /// Guarded by `stateLock`.
    private var _onMeteredChange: ((Bool) -> Void)?
    var onMeteredChange: ((Bool) -> Void)? {
        get { stateLock.lock(); defer { stateLock.unlock() }; return _onMeteredChange }
        set { stateLock.lock(); _onMeteredChange = newValue; stateLock.unlock() }
    }

    /// True if the active path is cellular, Personal Hotspot, or Low Data
    /// Mode — i.e. anywhere we'd burn the user's metered allowance.
    var isMetered: Bool {
        guard let s = currentPath else { return false }
        return s.isExpensive || s.isConstrained
    }

    /// User preference: are we allowed to use the network even when it's
    /// metered? Read-through to UserDefaults so a Settings toggle takes
    /// effect on the next access without a republish.
    var cellularAllowed: Bool {
        defaults.bool(forKey: Self.useCellularDataKey)
    }

    /// The single decision callers should consult before opening any
    /// validation socket. Returns true iff:
    ///
    /// 1. There is some kind of network path available, AND
    /// 2. Either the path is unmetered, OR the user has opted in to
    ///    spending cellular data on the node.
    ///
    /// Before the monitor's first update this is false ("offline"); wake
    /// and sync entry points call `waitForFirstPath` / `afterFirstPath`
    /// first.
    var shouldValidate: Bool {
        guard let s = currentPath, s.status == .satisfied else { return false }
        if (s.isExpensive || s.isConstrained) && !cellularAllowed { return false }
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
        guard let s = currentPath, s.status == .satisfied else { return .offline }
        if !(s.isExpensive || s.isConstrained) { return .unmetered }
        return cellularAllowed ? .meteredAllowed : .meteredBlocked
    }

    private let source: NetworkPathSource
    private let defaults: UserDefaults
    private let queue = DispatchQueue(label: "io.hercules.networkpolicy", qos: .utility)

    /// `source` and `defaults` are injectable so the unit tests can drive
    /// the first-path wait with a fake monitor (ticket 054). The app uses
    /// `shared`: the system monitor and standard defaults.
    init(source: NetworkPathSource = SystemPathSource(), defaults: UserDefaults = .standard) {
        self.source = source
        self.defaults = defaults
        firstPath.enter()
        source.start(queue: queue) { [weak self] path in
            guard let self = self else { return }
            // Decisions first, on this queue, so a wake that is waiting
            // for the first path sees it now rather than after a hop to
            // main.
            self.stateLock.lock()
            let isFirst = self._state == nil
            let wasMetered = self._state.map { $0.isExpensive || $0.isConstrained }
            self._state = path
            let metered = path.isExpensive || path.isConstrained
            let onMeteredChange = wasMetered == metered ? nil : self._onMeteredChange
            self.stateLock.unlock()
            if isFirst {
                self.firstPath.leave()
            }
            onMeteredChange?(metered)
            // The @Published mirrors drive SwiftUI views — bounce to main.
            DispatchQueue.main.async {
                self.pathStatus = path.status
                self.isExpensive = path.isExpensive
                self.isConstrained = path.isConstrained
            }
        }
    }

    /// Block until the monitor has reported its first path, or `timeout`
    /// passes. Returns at once when the path is already known. True if it
    /// is known. Background threads only; the main thread uses
    /// `afterFirstPath`.
    @discardableResult
    func waitForFirstPath(timeout: TimeInterval = NetworkPolicy.firstPathTimeout) -> Bool {
        firstPath.wait(timeout: .now() + timeout) == .success
    }

    /// Run `body` on the main queue once the first path is known or
    /// `timeout` passes, whichever comes first. Runs it inline when the
    /// path is already known and the caller is on main (a warm process).
    func afterFirstPath(
        timeout: TimeInterval = NetworkPolicy.firstPathTimeout,
        _ body: @escaping () -> Void
    ) {
        if Thread.isMainThread && currentPath != nil {
            body()
            return
        }
        let once = OnceGate()
        firstPath.notify(queue: .main) {
            once.fire(body)
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + timeout) {
            once.fire(body)
        }
    }

    deinit {
        source.cancel()
    }
}

/// Where `NetworkPolicy` gets path updates: `NWPathMonitor` in the app, a
/// fake in the unit tests (ticket 054).
protocol NetworkPathSource: AnyObject {
    /// Start delivering updates to `onUpdate` on `queue`.
    func start(queue: DispatchQueue, onUpdate: @escaping (NetworkPolicy.PathState) -> Void)
    func cancel()
}

final class SystemPathSource: NetworkPathSource {
    private let monitor = NWPathMonitor()

    func start(queue: DispatchQueue, onUpdate: @escaping (NetworkPolicy.PathState) -> Void) {
        monitor.pathUpdateHandler = { path in
            onUpdate(NetworkPolicy.PathState(
                status: path.status,
                isExpensive: path.isExpensive,
                isConstrained: path.isConstrained
            ))
        }
        monitor.start(queue: queue)
    }

    func cancel() {
        monitor.cancel()
    }
}
