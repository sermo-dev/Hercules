import Combine
import Foundation

/// Downloads the AssumeUTXO snapshot from Cloudflare R2 in the background.
///
/// Uses `URLSessionConfiguration.background` so the OS continues the download
/// when the app is suspended and can resume after network interruption or app
/// relaunch. The compressed file (~8.8GB) lands in Application Support,
/// excluded from backup (ticket 054: not Caches, which iOS purges under the
/// very storage pressure this download and import create); the caller hands
/// the path to `HerculesNode.loadSnapshot` and deletes the file once the
/// import succeeds.
///
/// Singleton because background `URLSession` instances must be re-created with
/// the same identifier across app launches to receive completion delegate
/// callbacks for downloads started in a previous process.
class SnapshotDownloader: NSObject, ObservableObject {
    static let shared = SnapshotDownloader()

    // The R2 public URL. Must match `ASSUMEUTXO_HASH` baked into hercules-core,
    // which verifies the file before applying it to the database.
    static let downloadURL = URL(string:
        "https://pub-341db11a2808417d91d4fcabc62a2260.r2.dev/hercules-973303-utxo.hutx.gz"
    )!

    // Approximate compressed size (matches `SNAPSHOT_DOWNLOAD_SIZE` in assumeutxo.rs).
    // Used as a fallback for progress UI when the server hasn't returned
    // Content-Length yet.
    static let expectedBytes: Int64 = 8_720_212_870

    /// `SNAPSHOT_SESSION_ID` in Config/Shared.xcconfig.
    private static var backgroundSessionId: String { AppIdentifiers.snapshotSessionID }

    enum Status: Equatable {
        case idle
        case downloading
        case completed(URL)   // local file path of the .hutx.gz
        case failed(String)
    }

    @Published private(set) var status: Status = .idle
    @Published private(set) var bytesDownloaded: Int64 = 0
    @Published private(set) var bytesTotal: Int64 = SnapshotDownloader.expectedBytes
    @Published private(set) var progress: Double = 0

    /// Set by AppDelegate when iOS hands us the completion handler for a
    /// background session that finished while the app was suspended. We invoke
    /// it once `urlSessionDidFinishEvents(forBackgroundURLSession:)` fires.
    var backgroundCompletionHandler: (() -> Void)?

    // MARK: Session (ticket 054)

    /// The session's network flags, from `NetworkPolicy`. Expensive
    /// (cellular, Personal Hotspot) and constrained (Low Data Mode) paths
    /// are metered there, so all three follow the one "Use Cellular Data"
    /// opt-in; `allowsCellularAccess` alone let a hotspot through.
    static func makeConfiguration(background: Bool, cellularAllowed: Bool) -> URLSessionConfiguration {
        let config: URLSessionConfiguration
        if background {
            config = .background(withIdentifier: backgroundSessionId)
            config.isDiscretionary = false       // user-initiated, run promptly
            config.sessionSendsLaunchEvents = true
        } else {
            config = .default
        }
        config.allowsCellularAccess = cellularAllowed
        config.allowsExpensiveNetworkAccess = cellularAllowed
        config.allowsConstrainedNetworkAccess = cellularAllowed
        return config
    }

    // Background URLSessions are backed by `nsurlsessiond`, a system
    // daemon that does not exist in the iOS Simulator — attempting to
    // create a background download task there fails with an opaque
    // "unknown error" (NSCocoaErrorDomain 4097). Fall back to a default
    // session in simulator builds. Real devices keep the background
    // session so the download continues across app suspension.
    #if targetEnvironment(simulator)
    private static let usesBackgroundSession = false
    #else
    private static let usesBackgroundSession = true
    #endif

    /// The session, its policy, and a policy switch in progress. Under
    /// `taskLock`. A background configuration can't be changed once the
    /// session exists, so a policy change replaces the session: the task is
    /// cancelled with resume data, the session invalidated, and a new one
    /// (same identifier, new flags) resumes it (`didBecomeInvalidWithError`).
    private var _session: URLSession?
    private var sessionCellularAllowed = false
    private var switchingPolicy = false
    private var resumeAfterSwitch = false

    private var session: URLSession {
        taskLock.lock(); defer { taskLock.unlock() }
        if let s = _session { return s }
        let allowed = NetworkPolicy.shared.cellularAllowed
        let s = URLSession(
            configuration: Self.makeConfiguration(background: Self.usesBackgroundSession, cellularAllowed: allowed),
            delegate: self, delegateQueue: nil
        )
        _session = s
        sessionCellularAllowed = allowed
        return s
    }

    // `activeTask` is touched from the delegate operation queue, the main
    // queue, and `getAllTasks` completion handlers. Guard with a lock.
    private let taskLock = NSLock()
    private var _activeTask: URLSessionDownloadTask?
    private var activeTask: URLSessionDownloadTask? {
        get { taskLock.lock(); defer { taskLock.unlock() }; return _activeTask }
        set { taskLock.lock(); defer { taskLock.unlock() }; _activeTask = newValue }
    }
    /// Tasks `cancel()` cancelled, so their completion isn't taken for iOS
    /// cancelling the download or for a failure worth resuming (ticket
    /// 051), and tasks a policy switch cancelled (ticket 054). Under
    /// `taskLock`.
    private var userCancelledTaskIDs = Set<Int>()
    private var policySwitchTaskIDs = Set<Int>()
    private var defaultsObserver: NSObjectProtocol?

    private override init() {
        super.init()
        // Touch the session at init time so we re-attach to any download
        // that was running when the app was last terminated. The delegate
        // callbacks will fire as the OS catches us up.
        _ = session
        Self.deleteLegacyFiles()
        Self.moveOutOfCaches()
        rehydrateExistingTask()
        // "Use Cellular Data" is a UserDefaults toggle: follow it mid-download.
        defaultsObserver = NotificationCenter.default.addObserver(
            forName: UserDefaults.didChangeNotification, object: nil, queue: nil
        ) { [weak self] _ in
            self?.followPolicy()
        }
    }

    /// The opt-in changed since the session was made: move the download to
    /// a session whose flags match (ticket 054).
    private func followPolicy() {
        let allowed = NetworkPolicy.shared.cellularAllowed
        taskLock.lock()
        guard let current = _session, sessionCellularAllowed != allowed, !switchingPolicy else {
            taskLock.unlock()
            return
        }
        switchingPolicy = true
        let task = _activeTask
        if let task = task {
            policySwitchTaskIDs.insert(task.taskIdentifier)
            resumeAfterSwitch = true
            _activeTask = nil
        }
        taskLock.unlock()
        StoragePaths.log.notice("snapshot download: Use Cellular Data changed; moving to a new session")
        guard let running = task else {
            current.finishTasksAndInvalidate()
            return
        }
        running.cancel(byProducingResumeData: { data in
            if let data = data { Self.saveResumeData(data) }
            current.finishTasksAndInvalidate()
        })
    }

    // MARK: Files

    /// Where the download lives: Application Support/Snapshot, excluded
    /// from backup (ticket 054).
    private static var snapshotDir: URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        var dir = base.appendingPathComponent("Snapshot", isDirectory: true)
        if !FileManager.default.fileExists(atPath: dir.path) {
            try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        }
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try? dir.setResourceValues(values)
        return dir
    }

    private static var cachesDir: URL {
        FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask).first!
    }

    /// Object name of the current snapshot, e.g. `hercules-973303-utxo`.
    /// Local file names derive from it so a file, or resume data, from a
    /// different snapshot can never be mistaken for this one.
    private static var snapshotName: String {
        var name = downloadURL.lastPathComponent
        for ext in [".gz", ".hutx"] where name.hasSuffix(ext) {
            name = String(name.dropLast(ext.count))
        }
        return name
    }

    /// Delete download and resume files left by builds that used other
    /// snapshots (including the retracted 943,500 file, saved as
    /// `hercules-utxo.*`), so an anchor bump never strands gigabytes, in
    /// either the old Caches location or the current one.
    private static func deleteLegacyFiles() {
        let fm = FileManager.default
        for dir in [cachesDir, snapshotDir] {
            guard let names = try? fm.contentsOfDirectory(atPath: dir.path) else { continue }
            for name in names
            where name.hasPrefix("hercules-")
                && (name.hasSuffix(".hutx.gz") || name.hasSuffix(".resume"))
                && !name.hasPrefix(snapshotName + ".") {
                try? fm.removeItem(at: dir.appendingPathComponent(name))
            }
        }
    }

    /// A download (or its resume blob) that an older build left in Caches
    /// moves to the new location instead of being fetched again.
    private static func moveOutOfCaches() {
        let fm = FileManager.default
        for name in ["\(snapshotName).hutx.gz", "\(snapshotName).resume"] {
            let old = cachesDir.appendingPathComponent(name)
            let new = snapshotDir.appendingPathComponent(name)
            guard fm.fileExists(atPath: old.path) else { continue }
            if fm.fileExists(atPath: new.path) {
                try? fm.removeItem(at: old)
            } else {
                try? fm.moveItem(at: old, to: new)
            }
        }
    }

    /// Whether `task` is downloading the current snapshot URL. A background
    /// task started by an older build (for an older snapshot) can still be
    /// running in this session after an update.
    private static func isCurrent(_ task: URLSessionTask) -> Bool {
        let url = task.originalRequest?.url ?? task.currentRequest?.url
        return url == downloadURL
    }

    /// Cancel every task in the session that isn't for the current URL and
    /// return the first one that is.
    private static func currentTask(among tasks: [URLSessionTask]) -> URLSessionDownloadTask? {
        var current: URLSessionDownloadTask?
        for task in tasks {
            if let dl = task as? URLSessionDownloadTask, isCurrent(dl), current == nil {
                current = dl
            } else {
                task.cancel()
            }
        }
        return current
    }

    /// The completed download. Once the snapshot is imported into the UTXO
    /// database, the caller deletes this file.
    static func destinationURL() -> URL {
        return snapshotDir.appendingPathComponent("\(snapshotName).hutx.gz")
    }

    /// Path where we persist `URLSession`-provided resume data so a network
    /// failure or app force-quit doesn't lose hours of download progress.
    /// The blob is small (a few KB) and contains pointers into iOS's private
    /// partial-download cache plus HTTP Range bookkeeping.
    private static func resumeDataURL() -> URL {
        return snapshotDir.appendingPathComponent("\(snapshotName).resume")
    }

    /// The resume blob for the current snapshot. Its file name derives
    /// from the snapshot's object name (`resumeDataURL`), so a blob for an
    /// older snapshot is never picked up here.
    private static func loadResumeData() -> Data? {
        return try? Data(contentsOf: resumeDataURL())
    }

    private static func saveResumeData(_ data: Data) {
        try? data.write(to: resumeDataURL(), options: .atomic)
    }

    private static func deleteResumeData() {
        try? FileManager.default.removeItem(at: resumeDataURL())
    }

    /// Returns true if a fully-downloaded snapshot file exists on disk and
    /// exactly matches the expected size. We require strict equality so that
    /// a partial download from a previous attempt isn't mistaken for a
    /// completed file (which would lead to an infinite hash-mismatch retry
    /// loop in `loadSnapshot`). The hash check happens inside hercules-core
    /// during import; this is just a quick pre-flight gate.
    static func hasDownloadedFile() -> Bool {
        let url = destinationURL()
        guard FileManager.default.fileExists(atPath: url.path) else { return false }
        let attrs = try? FileManager.default.attributesOfItem(atPath: url.path)
        let size = (attrs?[.size] as? NSNumber)?.int64Value ?? 0
        return size == expectedBytes
    }

    /// Begin the download. Idempotent: if a task is already running or the
    /// file already exists, this is a no-op.
    ///
    /// Refuses to start when `NetworkPolicy.shouldValidate` is false — i.e.
    /// no network at all, or a metered connection without the user's
    /// explicit cellular opt-in. The status transitions to `.failed` with a
    /// human-readable reason so SettingsView's snapshot card can surface
    /// the block to the user instead of leaving them staring at a stalled
    /// progress bar.
    func start() {
        if Self.hasDownloadedFile() {
            DispatchQueue.main.async {
                self.progress = 1.0
                self.bytesDownloaded = Self.expectedBytes
                self.status = .completed(Self.destinationURL())
            }
            return
        }
        if activeTask != nil {
            return
        }
        let policy = NetworkPolicy.shared
        guard policy.shouldValidate else {
            let reason: String
            switch policy.indicator {
            case .offline:
                reason = "No network connection"
            case .meteredBlocked:
                reason = "On cellular or hotspot — enable Use Cellular Data in Settings to download over metered networks"
            case .meteredAllowed, .unmetered:
                reason = "Network unavailable"
            }
            DispatchQueue.main.async {
                self.status = .failed(reason)
            }
            return
        }
        DispatchQueue.main.async {
            // Reset stats so a retry after failure doesn't show stale progress.
            self.progress = 0
            self.bytesDownloaded = 0
            self.bytesTotal = Self.expectedBytes
            self.status = .downloading
        }

        let session = self.session
        session.getAllTasks { [weak self] tasks in
            guard let self = self else { return }
            // If iOS already has a task running for our session (e.g. survived
            // a relaunch), latch onto it instead of starting a new one —
            // unless it is for another URL (an older build's snapshot).
            if let existing = Self.currentTask(among: tasks) {
                self.activeTask = existing
                return
            }
            // Re-check under the lock to avoid spawning two tasks if start()
            // races with itself.
            self.taskLock.lock()
            if self._activeTask != nil || self.switchingPolicy {
                if self.switchingPolicy { self.resumeAfterSwitch = true }
                self.taskLock.unlock()
                return
            }
            // Resume from a previous interruption if we have resume data;
            // otherwise start fresh from byte 0. If the resume data is stale
            // (e.g., iOS purged its private partial-download cache), the OS
            // will report failure on the next didCompleteWithError, and the
            // user's retry falls back to a fresh download since we delete
            // resume data on every failure that doesn't yield a fresh blob.
            let task: URLSessionDownloadTask
            if let resumeData = Self.loadResumeData() {
                task = session.downloadTask(withResumeData: resumeData)
            } else {
                task = session.downloadTask(with: Self.downloadURL)
            }
            task.priority = URLSessionTask.highPriority
            self._activeTask = task
            self.taskLock.unlock()
            task.resume()
        }
    }

    /// Cancel the in-flight download (if any) and clear partial state. The
    /// status transitions to `.failed("Download cancelled")` so any waiter
    /// blocked in `awaitSnapshotDownload` is released with a clear error.
    ///
    /// User-initiated cancel discards resume data — the next attempt will
    /// start fresh from byte 0. This matches the user's mental model: tapping
    /// Cancel should mean "throw it all away", not "pause for later".
    func cancel() {
        taskLock.lock()
        let task = _activeTask
        _activeTask = nil
        resumeAfterSwitch = false
        if let task = task {
            userCancelledTaskIDs.insert(task.taskIdentifier)
        }
        taskLock.unlock()
        task?.cancel()
        Self.deleteResumeData()
        DispatchQueue.main.async {
            self.progress = 0
            self.bytesDownloaded = 0
            self.status = .failed("Download cancelled")
        }
    }

    /// Delete the downloaded snapshot file. Call after a successful import
    /// so we don't waste 8GB of storage indefinitely. Also clears any
    /// resume data — once we've consumed the file, there's nothing left to
    /// resume.
    static func deleteDownloadedFile() {
        try? FileManager.default.removeItem(at: destinationURL())
        deleteResumeData()
    }

    /// On startup, ask the session whether a task is already in flight from a
    /// previous app launch and re-attach to it. URLSession's delegate
    /// callbacks will then deliver progress to our @Published state.
    private func rehydrateExistingTask() {
        session.getAllTasks { [weak self] tasks in
            guard let self = self else { return }
            if let existing = Self.currentTask(among: tasks) {
                self.activeTask = existing
                DispatchQueue.main.async {
                    self.status = .downloading
                }
            }
        }
    }

    // MARK: Decisions (pure, unit-tested; ticket 054)

    /// An HTTP status a finished download may carry: R2 returns 200, or
    /// 206 when resumed from resume data; 403/404 when the object is
    /// missing.
    static func acceptsHTTPStatus(_ code: Int) -> Bool {
        code == 200 || code == 206
    }

    /// What to do with resume data when a task fails.
    enum ResumeAction: Equatable {
        /// Save the fresh blob the error carried.
        case save
        /// Keep the previous blob (a lost network or a system cancel).
        case keep
        /// Delete it (e.g. the blob itself was stale).
        case delete
    }

    enum CompletionOutcome: Equatable {
        /// Not ours to report: another URL's task, a cancel we made (the
        /// user's, or a policy switch), or a stale task while a newer one
        /// runs.
        case ignore
        /// A task from before the current one, with nothing else running
        /// (e.g. the previous process's, reporting after relaunch): its
        /// resume data is handled, no status change.
        case stale(ResumeAction)
        /// The active download failed.
        case failed(message: String, resume: ResumeAction)
    }

    /// `didCompleteWithError` for a task that ended with `error`.
    static func completionOutcome(
        error: NSError,
        isCurrentURL: Bool,
        cancelledByUs: Bool,
        isActive: Bool,
        noneActive: Bool,
        hasSavedResumeData: Bool
    ) -> CompletionOutcome {
        guard isCurrentURL, !cancelledByUs, isActive || noneActive else { return .ignore }
        let resume: ResumeAction
        let resumable: Bool
        if error.userInfo[NSURLSessionDownloadTaskResumeData] is Data {
            resume = .save
            resumable = true
        } else if isTransient(error) {
            resume = .keep
            resumable = hasSavedResumeData
        } else {
            resume = .delete
            resumable = false
        }
        guard isActive else { return .stale(resume) }
        let suffix = resumable ? " — retry will resume" : ""
        return .failed(message: "Download failed: \(error.localizedDescription)\(suffix)", resume: resume)
    }

    /// The network went away mid-download, or iOS cancelled the task, as
    /// opposed to the server or the resume data being bad.
    static func isTransient(_ error: NSError) -> Bool {
        guard error.domain == NSURLErrorDomain else { return false }
        switch error.code {
        case NSURLErrorNotConnectedToInternet,
             NSURLErrorNetworkConnectionLost,
             NSURLErrorTimedOut,
             NSURLErrorCannotConnectToHost,
             NSURLErrorCannotFindHost,
             NSURLErrorDNSLookupFailed,
             NSURLErrorInternationalRoamingOff,
             NSURLErrorDataNotAllowed,
             NSURLErrorCancelled:
            return true
        default:
            return false
        }
    }
}

// MARK: - URLSessionDownloadDelegate

extension SnapshotDownloader: URLSessionDownloadDelegate {

    func urlSession(
        _ session: URLSession,
        downloadTask: URLSessionDownloadTask,
        didWriteData bytesWritten: Int64,
        totalBytesWritten: Int64,
        totalBytesExpectedToWrite: Int64
    ) {
        guard Self.isCurrent(downloadTask) else { return }
        let total = totalBytesExpectedToWrite > 0
            ? totalBytesExpectedToWrite
            : Self.expectedBytes
        let pct = total > 0 ? Double(totalBytesWritten) / Double(total) : 0
        DispatchQueue.main.async {
            self.bytesDownloaded = totalBytesWritten
            self.bytesTotal = total
            self.progress = min(pct, 1.0)
        }
    }

    func urlSession(
        _ session: URLSession,
        downloadTask: URLSessionDownloadTask,
        didFinishDownloadingTo location: URL
    ) {
        // A task for another URL (cancelled by `currentTask`, but it may
        // finish first) must not land in our destination.
        guard Self.isCurrent(downloadTask) else { return }
        // `location` is a temporary file iOS will delete the moment this
        // callback returns. We must move it synchronously here.
        let dest = Self.destinationURL()
        let fm = FileManager.default
        do {
            if fm.fileExists(atPath: dest.path) {
                try fm.removeItem(at: dest)
            }
            try fm.moveItem(at: location, to: dest)
        } catch {
            DispatchQueue.main.async {
                self.status = .failed("Could not save snapshot: \(error.localizedDescription)")
                self.clearActiveTask(ifIs: downloadTask)
            }
            return
        }

        if let http = downloadTask.response as? HTTPURLResponse,
           !Self.acceptsHTTPStatus(http.statusCode) {
            try? fm.removeItem(at: dest)
            // Resuming would only replay the same error response forever.
            Self.deleteResumeData()
            DispatchQueue.main.async {
                self.status = .failed("Server returned HTTP \(http.statusCode)")
                self.clearActiveTask(ifIs: downloadTask)
            }
            return
        }

        // Successful download — drop any leftover resume data so the next
        // launch doesn't try to resume into a file that's already complete.
        Self.deleteResumeData()

        DispatchQueue.main.async {
            self.progress = 1.0
            self.status = .completed(dest)
            self.clearActiveTask(ifIs: downloadTask)
        }
    }

    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        didCompleteWithError error: Error?
    ) {
        guard let error = error else { return }   // success path handled above
        // A user cancel is already handled by `cancel()`, which also wipes
        // the resume data blob and reports the cancel; a policy switch
        // saved its blob and resumes on the new session. Nothing to do
        // here, whatever the error (it may end with a network error rather
        // than NSURLErrorCancelled; saving its resume data would undo the
        // wipe). Any other cancel is iOS's own (force-quit, Background App
        // Refresh turned off, low resources:
        // `NSURLErrorBackgroundTaskCancelledReasonKey`); it carries resume
        // data and is handled as a failure below, which also releases a
        // waiting `awaitSnapshotDownload` (ticket 051).
        let cancelledByUs = consumeOurCancel(of: task)

        // A task that is no longer ours (a new download has started since)
        // must not clear the new one or fail its waiter. Its resume data is
        // still kept if nothing else is running, e.g. a task from the
        // previous process reporting after relaunch.
        taskLock.lock()
        let isActive = _activeTask === task
        let noneActive = _activeTask == nil
        if isActive && !cancelledByUs {
            _activeTask = nil
        }
        taskLock.unlock()

        let nsErr = error as NSError
        let outcome = Self.completionOutcome(
            error: nsErr,
            isCurrentURL: Self.isCurrent(task),
            cancelledByUs: cancelledByUs,
            isActive: isActive,
            noneActive: noneActive,
            hasSavedResumeData: Self.loadResumeData() != nil
        )
        let resume: ResumeAction
        switch outcome {
        case .ignore:
            return
        case .stale(let r):
            resume = r
        case .failed(_, let r):
            resume = r
        }
        switch resume {
        case .save:
            if let data = nsErr.userInfo[NSURLSessionDownloadTaskResumeData] as? Data {
                Self.saveResumeData(data)
            }
        case .keep:
            break
        case .delete:
            Self.deleteResumeData()
        }
        if case .failed(let message, _) = outcome {
            DispatchQueue.main.async {
                self.status = .failed(message)
            }
        }
    }

    /// A policy switch invalidated the old session (ticket 054): make the
    /// next one with the current flags and resume the download on it.
    func urlSession(_ session: URLSession, didBecomeInvalidWithError error: Error?) {
        taskLock.lock()
        guard session === _session else {
            taskLock.unlock()
            return
        }
        _session = nil
        switchingPolicy = false
        let resume = resumeAfterSwitch
        resumeAfterSwitch = false
        taskLock.unlock()
        _ = self.session
        // The opt-in may have flipped again meanwhile.
        followPolicy()
        if resume {
            start()
        }
    }

    /// Clear `activeTask` if it is still `task`, under the lock: a task
    /// that finishes after a newer one started must not clear the newer
    /// one (ticket 051).
    private func clearActiveTask(ifIs task: URLSessionTask) {
        taskLock.lock(); defer { taskLock.unlock() }
        if _activeTask === task {
            _activeTask = nil
        }
    }

    /// True (once) if `cancel()` or a policy switch cancelled `task`.
    private func consumeOurCancel(of task: URLSessionTask) -> Bool {
        taskLock.lock(); defer { taskLock.unlock() }
        let user = userCancelledTaskIDs.remove(task.taskIdentifier) != nil
        let policy = policySwitchTaskIDs.remove(task.taskIdentifier) != nil
        return user || policy
    }

    /// Called when iOS finishes delivering background events to our session.
    /// We invoke the completion handler that AppDelegate stored for us so iOS
    /// knows it can re-suspend the app.
    func urlSessionDidFinishEvents(forBackgroundURLSession session: URLSession) {
        DispatchQueue.main.async {
            self.backgroundCompletionHandler?()
            self.backgroundCompletionHandler = nil
        }
    }
}
