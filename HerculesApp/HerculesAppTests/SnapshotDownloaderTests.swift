import XCTest

/// Ticket 054 section 3: the download session follows the network policy,
/// and `didCompleteWithError` / `didFinishDownloading` decide correctly.
final class SnapshotDownloaderTests: XCTestCase {
    func testSessionFlagsFollowTheCellularOptIn() {
        let off = SnapshotDownloader.makeConfiguration(background: false, cellularAllowed: false)
        XCTAssertFalse(off.allowsCellularAccess)
        XCTAssertFalse(off.allowsExpensiveNetworkAccess, "a Personal Hotspot must pause the download")
        XCTAssertFalse(off.allowsConstrainedNetworkAccess, "so must Low Data Mode")

        let on = SnapshotDownloader.makeConfiguration(background: false, cellularAllowed: true)
        XCTAssertTrue(on.allowsCellularAccess)
        XCTAssertTrue(on.allowsExpensiveNetworkAccess)
        XCTAssertTrue(on.allowsConstrainedNetworkAccess)
    }

    func testHTTPStatuses() {
        XCTAssertTrue(SnapshotDownloader.acceptsHTTPStatus(200))
        XCTAssertTrue(SnapshotDownloader.acceptsHTTPStatus(206), "a resumed download")
        for code in [204, 301, 403, 404, 416, 500] {
            XCTAssertFalse(SnapshotDownloader.acceptsHTTPStatus(code), "\(code)")
        }
    }

    func testTheFileLivesOutsideCachesAndIsNotBackedUp() throws {
        let url = SnapshotDownloader.destinationURL()
        XCTAssertFalse(url.path.contains("/Library/Caches/"), url.path)
        XCTAssertTrue(url.path.contains("/Application Support/Snapshot/"), url.path)
        let dir = url.deletingLastPathComponent()
        let values = try dir.resourceValues(forKeys: [.isExcludedFromBackupKey])
        XCTAssertEqual(values.isExcludedFromBackup, true)
    }

    private func outcome(
        _ error: NSError, current: Bool = true, ours: Bool = false, active: Bool = true,
        noneActive: Bool = false, saved: Bool = false
    ) -> SnapshotDownloader.CompletionOutcome {
        SnapshotDownloader.completionOutcome(
            error: error, isCurrentURL: current, cancelledByUs: ours,
            isActive: active, noneActive: noneActive, hasSavedResumeData: saved
        )
    }

    private let cancelled = NSError(domain: NSURLErrorDomain, code: NSURLErrorCancelled)
    private let lost = NSError(domain: NSURLErrorDomain, code: NSURLErrorNetworkConnectionLost)
    private let bad = NSError(domain: NSURLErrorDomain, code: NSURLErrorCannotDecodeRawData)

    func testUserCancelAndPolicySwitchAreNotFailures() {
        let withData = NSError(
            domain: NSURLErrorDomain, code: NSURLErrorCancelled,
            userInfo: [NSURLSessionDownloadTaskResumeData: Data([1])]
        )
        XCTAssertEqual(outcome(cancelled, ours: true), .ignore)
        XCTAssertEqual(outcome(withData, ours: true), .ignore, "its resume data must not undo the wipe")
    }

    func testSystemCancelWithResumeDataSavesIt() {
        let systemCancel = NSError(
            domain: NSURLErrorDomain, code: NSURLErrorCancelled,
            userInfo: [NSURLSessionDownloadTaskResumeData: Data([1, 2, 3])]
        )
        guard case .failed(let message, .save) = outcome(systemCancel) else {
            return XCTFail("\(outcome(systemCancel))")
        }
        XCTAssertTrue(message.hasSuffix("retry will resume"), message)
    }

    func testTransientErrorKeepsTheOldBlob() {
        guard case .failed(let withBlob, .keep) = outcome(lost, saved: true) else {
            return XCTFail("\(outcome(lost, saved: true))")
        }
        XCTAssertTrue(withBlob.hasSuffix("retry will resume"))
        guard case .failed(let noBlob, .keep) = outcome(lost, saved: false) else {
            return XCTFail("\(outcome(lost))")
        }
        XCTAssertFalse(noBlob.contains("resume"))
    }

    func testOtherErrorsDeleteTheBlob() {
        XCTAssertEqual(
            outcome(bad, saved: true),
            .failed(message: "Download failed: \(bad.localizedDescription)", resume: .delete)
        )
    }

    func testStaleTasks() {
        // A newer download is running: the old task touches nothing.
        XCTAssertEqual(outcome(lost, active: false, noneActive: false), .ignore)
        // Nothing running (the previous process's task): resume data only.
        XCTAssertEqual(outcome(lost, active: false, noneActive: true), .stale(.keep))
        // Another URL (an older build's snapshot): never ours.
        XCTAssertEqual(outcome(lost, current: false), .ignore)
    }
}
