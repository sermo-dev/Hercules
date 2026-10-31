import XCTest

/// A relay that records requests and answers when the test says so.
final class FakeRelay: RelayTransport {
    struct Call {
        let path: String
        let body: [String: String]
        let completion: (Int?, Error?) -> Void
    }
    private(set) var calls: [Call] = []

    func post(_ request: URLRequest, completion: @escaping (Int?, Error?) -> Void) {
        let body = (try? JSONSerialization.jsonObject(with: request.httpBody ?? Data())) as? [String: String] ?? [:]
        calls.append(Call(path: request.url!.absoluteString, body: body, completion: completion))
    }

    var paths: [String] { calls.map(\.path) }
}

final class FakeRegistrar: PushRegistrar {
    var registers = 0
    var unregisters = 0
    func registerForRemoteNotifications() { registers += 1 }
    func unregisterForRemoteNotifications() { unregisters += 1 }
}

/// Ticket 054 section 5: the relay registration state machine.
final class RelayRegistrationTests: XCTestCase {
    private var suite: String!
    private var defaults: UserDefaults!
    private var relay: FakeRelay!
    private var registrar: FakeRegistrar!
    private var queue: DispatchQueue!
    private var clock = Date(timeIntervalSince1970: 1_800_000_000)

    override func setUp() {
        suite = "RelayRegistrationTests.\(UUID().uuidString)"
        defaults = UserDefaults(suiteName: suite)
        relay = FakeRelay()
        registrar = FakeRegistrar()
        queue = DispatchQueue(label: "relay-tests")
    }

    override func tearDown() {
        defaults.removePersistentDomain(forName: suite)
    }

    private func make() -> RelayRegistration {
        RelayRegistration(
            defaults: defaults, transport: relay, registrar: registrar,
            secret: { _ in "s3cret" }, defaultURL: "https://relay.example",
            reregisterInterval: 24 * 3600, now: { [unowned self] in self.clock }, queue: queue
        )
    }

    /// Answer call `i` and let the state machine handle it.
    private func answer(_ i: Int, _ status: Int?, error: Error? = nil) {
        relay.calls[i].completion(status, error)
        queue.sync {}
    }

    private var pending: Bool { defaults.bool(forKey: RelayRegistration.Keys.unregisterPending) }

    func testEnableRegistersOnceAndThrottles() {
        let r = make()
        r.enable()
        XCTAssertTrue(r.state.isEnabled)
        r.handleDeviceToken("tok")
        XCTAssertEqual(relay.paths, ["https://relay.example/register"])
        XCTAssertEqual(relay.calls[0].body["device_token"], "tok")
        XCTAssertEqual(relay.calls[0].body["install_secret"], "s3cret")
        answer(0, 200)
        // Same token, same relay, within a day: no second POST.
        r.handleDeviceToken("tok")
        XCTAssertEqual(relay.calls.count, 1)
        // A day later it re-registers (the relay's 30-day TTL).
        clock += 24 * 3600
        r.handleDeviceToken("tok")
        XCTAssertEqual(relay.calls.count, 2)
    }

    func testRateLimitedRegistrationIsRetriedNotRemembered() {
        let r = make()
        r.enable()
        r.handleDeviceToken("tok")
        answer(0, 429)
        r.handleDeviceToken("tok")
        XCTAssertEqual(relay.calls.count, 2, "a 429 doesn't count as registered")
        XCTAssertNil(r.state.registrationError)
    }

    func test403IsReported() {
        let r = make()
        r.enable()
        r.handleDeviceToken("tok")
        answer(0, 403)
        XCTAssertEqual(r.state.registrationError, "Relay rejected this install's registration")
    }

    func testDisableUnregistersFromRelayAndAPNs() {
        let r = make()
        r.enable()
        r.handleDeviceToken("tok")
        answer(0, 200)
        r.disable()
        XCTAssertFalse(r.state.isEnabled)
        XCTAssertNil(r.state.deviceToken)
        XCTAssertEqual(relay.paths.last, "https://relay.example/unregister")
        XCTAssertEqual(registrar.unregisters, 1, "ticket 054: unregister from APNs too")
        XCTAssertTrue(pending)
        answer(1, 200)
        XCTAssertFalse(pending)
    }

    func testFailedUnregisterStaysPendingAndAPushRetriesIt() {
        let r = make()
        r.enable()
        r.handleDeviceToken("tok")
        r.disable()
        answer(1, 503)
        XCTAssertTrue(pending, "a 5xx leaves the unregister pending")
        answer(0, 200) // the earlier register landing late changes nothing
        XCTAssertTrue(pending)

        // A fresh process: no token known; launch fetches one to retry.
        let next = make()
        XCTAssertFalse(next.state.isEnabled)
        next.refreshOnLaunch(authorized: true)
        XCTAssertEqual(registrar.registers, 1)
        // A push arriving meanwhile retries too (ticket 054).
        next.pushArrivedWhileDisabled()
        XCTAssertEqual(registrar.registers, 2)
        next.handleDeviceToken("tok")
        XCTAssertEqual(relay.paths.last, "https://relay.example/unregister")
        answer(relay.calls.count - 1, 200)
        XCTAssertFalse(pending)
    }

    func testOfflineUnregisterStaysPending() {
        let r = make()
        r.enable()
        r.handleDeviceToken("tok")
        r.disable()
        answer(1, nil, error: URLError(.notConnectedToInternet))
        XCTAssertTrue(pending)
    }

    func testReEnableDuringUnregisterRegistersAgain() {
        let r = make()
        r.enable()
        r.handleDeviceToken("tok")
        answer(0, 200)
        r.disable()
        r.enable()
        XCTAssertFalse(pending)
        r.handleDeviceToken("tok2")
        let before = relay.calls.count
        // The unregister (call 1) lands after the re-enable: the row is
        // gone, so the app registers again.
        answer(1, 200)
        XCTAssertEqual(relay.calls.count, before + 1)
        XCTAssertEqual(relay.paths.last, "https://relay.example/register")
        XCTAssertEqual(relay.calls.last?.body["device_token"], "tok2")
    }

    func testRelayURLChangeMovesTheRegistration() {
        let r = make()
        r.enable()
        r.handleDeviceToken("tok")
        answer(0, 200)
        r.updateRelayURL("  https://other.example/  ")
        XCTAssertEqual(r.relayServerURL, "https://other.example/")
        XCTAssertEqual(Array(relay.paths.suffix(2)), [
            "https://relay.example/unregister",
            "https://other.example/register",
        ])
        r.updateRelayURL("https://other.example/")
        XCTAssertEqual(relay.calls.count, 3, "an unchanged URL is a no-op")
    }

    func testPushWhileEnabledDoesNothing() {
        let r = make()
        r.enable()
        r.pushArrivedWhileDisabled()
        XCTAssertEqual(registrar.registers, 0)
        XCTAssertTrue(relay.calls.isEmpty)
    }

    /// Ticket 054 review: a push can launch the app before the first unlock,
    /// when the stored opt-in reads as off. That is "unknown", and `reload`
    /// picks up the real value once it can be read.
    func testOptInReadBeforeFirstUnlockIsUnknownAndReloaded() {
        XCTAssertNil(RelayRegistration.enabledSetting(stored: false, preferencesReadable: false))
        XCTAssertEqual(RelayRegistration.enabledSetting(stored: false, preferencesReadable: true), false)
        XCTAssertEqual(RelayRegistration.enabledSetting(stored: true, preferencesReadable: true), true)

        let r = make()
        XCTAssertFalse(r.state.isEnabled)
        var changes: [RelayRegistration.State] = []
        r.onChange = { changes.append($0) }
        defaults.set(true, forKey: RelayRegistration.Keys.enabled)
        r.reload()
        XCTAssertTrue(r.state.isEnabled)
        XCTAssertEqual(changes.count, 1)
        // A push in that process is no longer "while disabled".
        r.pushArrivedWhileDisabled()
        XCTAssertEqual(registrar.registers, 0)
    }
}
