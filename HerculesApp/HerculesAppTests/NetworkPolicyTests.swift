import Network
import XCTest

/// A path monitor the test drives by hand.
final class FakePathSource: NetworkPathSource {
    private var onUpdate: ((NetworkPolicy.PathState) -> Void)?
    private var queue: DispatchQueue?

    func start(queue: DispatchQueue, onUpdate: @escaping (NetworkPolicy.PathState) -> Void) {
        self.queue = queue
        self.onUpdate = onUpdate
    }

    func cancel() {}

    func deliver(_ status: NWPath.Status, expensive: Bool = false, constrained: Bool = false) {
        let update = onUpdate
        queue?.sync {
            update?(NetworkPolicy.PathState(status: status, isExpensive: expensive, isConstrained: constrained))
        }
    }
}

/// Ticket 054 section 5: `afterFirstPath` runs its body exactly once,
/// whether the first path or the timeout comes first.
final class NetworkPolicyTests: XCTestCase {
    private var suite: String!
    private var defaults: UserDefaults!

    override func setUp() {
        suite = "NetworkPolicyTests.\(UUID().uuidString)"
        defaults = UserDefaults(suiteName: suite)
    }

    override func tearDown() {
        defaults.removePersistentDomain(forName: suite)
    }

    func testBodyRunsOnceAfterTheTimeoutWhenNoPathArrives() {
        let policy = NetworkPolicy(source: FakePathSource(), defaults: defaults)
        var runs = 0
        let ran = expectation(description: "body")
        policy.afterFirstPath(timeout: 0.2) {
            runs += 1
            XCTAssertTrue(Thread.isMainThread)
            // No path yet: reads as offline.
            XCTAssertFalse(policy.shouldValidate)
            XCTAssertEqual(policy.indicator, .offline)
            ran.fulfill()
        }
        wait(for: [ran], timeout: 2)
        // Past any second firing.
        let settle = expectation(description: "settle")
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.3) { settle.fulfill() }
        wait(for: [settle], timeout: 2)
        XCTAssertEqual(runs, 1)
    }

    func testBodyRunsOnceWhenThePathArrivesFirst() {
        let source = FakePathSource()
        let policy = NetworkPolicy(source: source, defaults: defaults)
        var runs = 0
        let ran = expectation(description: "body")
        policy.afterFirstPath(timeout: 0.5) {
            runs += 1
            XCTAssertTrue(policy.shouldValidate)
            ran.fulfill()
        }
        source.deliver(.satisfied)
        wait(for: [ran], timeout: 0.4)
        // The timeout passing later doesn't run it again.
        let settle = expectation(description: "settle")
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.7) { settle.fulfill() }
        wait(for: [settle], timeout: 2)
        XCTAssertEqual(runs, 1)
    }

    func testWarmProcessRunsInline() {
        let source = FakePathSource()
        let policy = NetworkPolicy(source: source, defaults: defaults)
        source.deliver(.satisfied)
        var ran = false
        policy.afterFirstPath { ran = true }
        XCTAssertTrue(ran, "a known path on main runs the body inline")
        XCTAssertTrue(policy.waitForFirstPath(timeout: 0))
    }

    func testMeteredPathsNeedTheOptIn() {
        let source = FakePathSource()
        let policy = NetworkPolicy(source: source, defaults: defaults)
        source.deliver(.satisfied, expensive: true)
        XCTAssertFalse(policy.shouldValidate)
        XCTAssertEqual(policy.indicator, .meteredBlocked)
        source.deliver(.satisfied, constrained: true)
        XCTAssertEqual(policy.indicator, .meteredBlocked, "Low Data Mode is metered too")
        defaults.set(true, forKey: NetworkPolicy.useCellularDataKey)
        XCTAssertTrue(policy.shouldValidate)
        XCTAssertEqual(policy.indicator, .meteredAllowed)
        source.deliver(.unsatisfied)
        XCTAssertEqual(policy.indicator, .offline)
    }

    func testMeteredChangesAreReported() {
        let source = FakePathSource()
        let policy = NetworkPolicy(source: source, defaults: defaults)
        var reports: [Bool] = []
        policy.onMeteredChange = { reports.append($0) }
        source.deliver(.satisfied)
        source.deliver(.satisfied)
        source.deliver(.satisfied, expensive: true)
        source.deliver(.satisfied, expensive: true)
        source.deliver(.satisfied)
        XCTAssertEqual(reports, [false, true, false])
    }
}
