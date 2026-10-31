import CryptoKit
import Foundation

/// One POST to the relay, reduced to what registration needs: the HTTP
/// status, or the error. `URLSession` in the app; a fake in the tests.
protocol RelayTransport: AnyObject {
    func post(_ request: URLRequest, completion: @escaping (_ status: Int?, _ error: Error?) -> Void)
}

extension URLSession: RelayTransport {
    func post(_ request: URLRequest, completion: @escaping (Int?, Error?) -> Void) {
        dataTask(with: request) { _, response, error in
            completion((response as? HTTPURLResponse)?.statusCode, error)
        }.resume()
    }
}

/// APNs registration: `UIApplication` in the app; a fake in the tests.
protocol PushRegistrar: AnyObject {
    func registerForRemoteNotifications()
    func unregisterForRemoteNotifications()
}

/// This install's registration with the push relay, as a state machine
/// with its I/O injected (ticket 054, moved out of NotificationManager so
/// it can be unit-tested). All state changes happen on `queue` (main in
/// the app); `onChange` reports them there.
///
/// - Enabled: register the APNs token with the relay, at most once per
///   `RelayConfig.reregisterInterval` for the same token and relay.
/// - Disabled: unregister from the relay so it stops pushing now rather
///   than at its 30-day TTL, and from APNs. A failed unregister (offline,
///   429, 5xx) stays pending and is retried at launch and whenever a push
///   still arrives.
final class RelayRegistration {
    struct State: Equatable {
        var isEnabled: Bool
        var deviceToken: String?
        var registrationError: String?
    }

    enum Keys {
        static let enabled = "notificationsEnabled"
        static let relayURL = "relayServerURL"
        static let registrationFingerprint = "relayRegistrationFingerprint"
        static let registrationDate = "relayRegistrationDate"
        static let unregisterPending = "relayUnregisterPending"
    }

    private let defaults: UserDefaults
    private let transport: RelayTransport
    private let registrar: PushRegistrar
    private let secret: (String) -> String?
    private let now: () -> Date
    private let queue: DispatchQueue
    private let defaultURL: String
    private let reregisterInterval: TimeInterval

    private(set) var state: State {
        didSet {
            if state != oldValue { onChange?(state) }
        }
    }

    /// Called on `queue` after every state change.
    var onChange: ((State) -> Void)?

    init(
        defaults: UserDefaults,
        transport: RelayTransport,
        registrar: PushRegistrar,
        secret: @escaping (_ relayHost: String) -> String?,
        defaultURL: String,
        reregisterInterval: TimeInterval,
        now: @escaping () -> Date = Date.init,
        queue: DispatchQueue = .main
    ) {
        self.defaults = defaults
        self.transport = transport
        self.registrar = registrar
        self.secret = secret
        self.defaultURL = defaultURL
        self.reregisterInterval = reregisterInterval
        self.now = now
        self.queue = queue
        state = State(isEnabled: defaults.bool(forKey: Keys.enabled), deviceToken: nil, registrationError: nil)
    }

    var relayServerURL: String {
        get { defaults.string(forKey: Keys.relayURL) ?? defaultURL }
        set { defaults.set(newValue, forKey: Keys.relayURL) }
    }

    /// An unregister hasn't reached the relay yet.
    var unregisterPending: Bool {
        defaults.bool(forKey: Keys.unregisterPending)
    }

    private func setEnabled(_ enabled: Bool) {
        state.isEnabled = enabled
        defaults.set(enabled, forKey: Keys.enabled)
    }

    /// The opt-in as stored, or nil when the preferences can't be read
    /// (before the first unlock, where every stored value reads as unset).
    static func enabledSetting(stored: Bool, preferencesReadable: Bool) -> Bool? {
        preferencesReadable ? stored : nil
    }

    /// Re-read the opt-in from `defaults`: it may have read as off at init,
    /// before the first unlock (ticket 054 review).
    func reload() {
        state.isEnabled = defaults.bool(forKey: Keys.enabled)
    }

    // MARK: - Events

    /// App launch. Opted in with permission: ask APNs for the (possibly
    /// rotated) token; `handleDeviceToken` re-registers if needed. Opted
    /// out with an unregister pending: fetch the token to retry it.
    func refreshOnLaunch(authorized: Bool) {
        if state.isEnabled {
            if authorized { registrar.registerForRemoteNotifications() }
        } else if unregisterPending {
            registrar.registerForRemoteNotifications()
        }
    }

    /// Opt in. The caller asks for notification permission, which ends in
    /// `registerForRemoteNotifications` and then `handleDeviceToken`.
    func enable() {
        setEnabled(true)
        defaults.removeObject(forKey: Keys.unregisterPending)
    }

    /// Opt out: unregister from the relay and from APNs (ticket 054).
    func disable() {
        setEnabled(false)
        clearRegistrationMarker()
        defaults.set(true, forKey: Keys.unregisterPending)
        if let token = state.deviceToken {
            state.deviceToken = nil
            unregister(token: token, relayURL: relayServerURL)
            registrar.unregisterForRemoteNotifications()
        } else {
            // Token not known in this process yet: fetch it, and
            // `handleDeviceToken` will unregister.
            registrar.registerForRemoteNotifications()
        }
    }

    /// A push arrived while opted out (ticket 054): the relay still has
    /// this install, so its unregister failed. Retry it.
    func pushArrivedWhileDisabled() {
        reload()
        guard !state.isEnabled else { return }
        defaults.set(true, forKey: Keys.unregisterPending)
        if let token = state.deviceToken {
            unregister(token: token, relayURL: relayServerURL)
        } else {
            registrar.registerForRemoteNotifications()
        }
    }

    /// Point at a different relay: unregister from the old one and
    /// register with the new one when opted in.
    func updateRelayURL(_ newURL: String) {
        let trimmed = newURL.trimmingCharacters(in: .whitespacesAndNewlines)
        let oldURL = relayServerURL
        guard !trimmed.isEmpty, trimmed != oldURL else { return }
        relayServerURL = trimmed
        clearRegistrationMarker()
        if state.isEnabled, let token = state.deviceToken {
            unregister(token: token, relayURL: oldURL)
            register(token: token)
        }
    }

    /// APNs returned a device token.
    func handleDeviceToken(_ token: String) {
        if state.isEnabled {
            state.deviceToken = token
            state.registrationError = nil
            register(token: token)
        } else if unregisterPending {
            unregister(token: token, relayURL: relayServerURL)
            registrar.unregisterForRemoteNotifications()
        }
    }

    func handleRegistrationError(_ message: String) {
        state.registrationError = message
    }

    // MARK: - Relay requests

    /// Send the token and this install's secret to the relay, unless the
    /// same token was registered with the same relay recently.
    private func register(token: String) {
        let relayURL = relayServerURL
        let fingerprint = Self.fingerprint(token: token, relayURL: relayURL)
        if defaults.string(forKey: Keys.registrationFingerprint) == fingerprint,
           now().timeIntervalSince1970 - defaults.double(forKey: Keys.registrationDate)
               < reregisterInterval {
            return
        }
        guard let request = request(relayURL: relayURL, path: "register",
                                    body: ["device_token": token, "platform": "ios"]) else { return }
        transport.post(request) { [weak self] status, error in
            guard let self = self else { return }
            self.queue.async {
                if let error = error {
                    // Not critical: retried on next launch.
                    print("Relay registration failed: \(error.localizedDescription)")
                    return
                }
                switch status ?? 0 {
                case 200:
                    // A registration landing after an opt-out must not mark
                    // the token registered: the unregister removes the row,
                    // and a quick re-enable would then skip re-registering.
                    guard self.state.isEnabled else { return }
                    self.defaults.set(fingerprint, forKey: Keys.registrationFingerprint)
                    self.defaults.set(self.now().timeIntervalSince1970, forKey: Keys.registrationDate)
                case 403:
                    // Token is bound to a different install secret (e.g. the
                    // Keychain item was lost). The old row expires within 30 days.
                    self.state.registrationError = "Relay rejected this install's registration"
                default:
                    print("Relay registration failed: HTTP \(status ?? 0)")
                }
            }
        }
    }

    /// Remove this install's row from the relay.
    private func unregister(token: String, relayURL: String) {
        guard let request = request(relayURL: relayURL, path: "unregister",
                                    body: ["device_token": token]) else { return }
        transport.post(request) { [weak self] status, error in
            guard let self = self else { return }
            self.queue.async {
                if let error = error {
                    print("Relay unregister failed: \(error.localizedDescription)")
                    return
                }
                // 403 means the row belongs to another secret; nothing more we can do.
                guard status == 200 || status == 403 else {
                    print("Relay unregister failed: HTTP \(status ?? 0)")
                    return
                }
                // Only clear the retry flag if the user hasn't re-enabled in
                // the meantime and this was the current relay.
                if !self.state.isEnabled && relayURL == self.relayServerURL {
                    self.defaults.removeObject(forKey: Keys.unregisterPending)
                } else if self.state.isEnabled, relayURL == self.relayServerURL,
                          let current = self.state.deviceToken {
                    // Re-enabled while the unregister was in flight: make
                    // sure the row exists again.
                    self.clearRegistrationMarker()
                    self.register(token: current)
                }
            }
        }
    }

    /// A POST to `<relayURL>/<path>` carrying `body` plus the per-install
    /// secret for that relay. Nil if the URL is invalid or the Keychain is
    /// unavailable (e.g. before first unlock after reboot).
    private func request(relayURL: String, path: String, body: [String: String]) -> URLRequest? {
        var base = relayURL.trimmingCharacters(in: .whitespacesAndNewlines)
        while base.hasSuffix("/") { base.removeLast() }
        guard let url = URL(string: "\(base)/\(path)"), let host = url.host else { return nil }
        guard let secret = secret(host) else {
            print("Relay \(path) skipped: install secret unavailable")
            return nil
        }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.timeoutInterval = 15
        var payload = body
        payload["install_secret"] = secret
        request.httpBody = try? JSONSerialization.data(withJSONObject: payload)
        return request
    }

    /// Hash of token + relay, so UserDefaults never holds the raw token.
    static func fingerprint(token: String, relayURL: String) -> String {
        let digest = SHA256.hash(data: Data("\(token)|\(relayURL)".utf8))
        return digest.map { String(format: "%02x", $0) }.joined()
    }

    private func clearRegistrationMarker() {
        defaults.removeObject(forKey: Keys.registrationFingerprint)
        defaults.removeObject(forKey: Keys.registrationDate)
    }
}
