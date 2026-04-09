import Combine
import Foundation

/// Downloads the AssumeUTXO snapshot from Cloudflare R2 in the background.
///
/// Uses `URLSessionConfiguration.background` so the OS continues the download
/// when the app is suspended and can resume after network interruption or app
/// relaunch. The compressed file (~8.2GB) lands in the Caches directory; the
/// caller is responsible for handing the path to `HerculesNode.loadSnapshot`
/// and deleting the file once import succeeds.
///
/// Singleton because background `URLSession` instances must be re-created with
/// the same identifier across app launches to receive completion delegate
/// callbacks for downloads started in a previous process.
class SnapshotDownloader: NSObject, ObservableObject {
    static let shared = SnapshotDownloader()

    // The R2 public URL. Must match `ASSUMEUTXO_HASH` baked into hercules-core,
    // which verifies the file before applying it to the database.
    static let downloadURL = URL(string:
        "https://pub-341db11a2808417d91d4fcabc62a2260.r2.dev/hercules-utxo.hutx.gz"
    )!

    // Approximate compressed size (matches `SNAPSHOT_DOWNLOAD_SIZE` in assumeutxo.rs).
    // Used as a fallback for progress UI when the server hasn't returned
    // Content-Length yet.
    static let expectedBytes: Int64 = 8_780_302_668

    private static let backgroundSessionId = "io.hercules.snapshot-download"

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

    private lazy var session: URLSession = {
        // Background URLSessions are backed by `nsurlsessiond`, a system
        // daemon that does not exist in the iOS Simulator — attempting to
        // create a background download task there fails with an opaque
        // "unknown error" (NSCocoaErrorDomain 4097). Fall back to a default
        // session in simulator builds. Real devices keep the background
        // session so the download continues across app suspension.
        //
        // `allowsCellularAccess` is read once at session-construction time
        // from `NetworkPolicy.shared.cellularAllowed`. URLSession does not
        // re-read this flag if the preference changes mid-session, so a
        // user toggling Settings → Use Cellular Data while a download is
        // in flight will see the new policy take effect on the *next* app
        // launch. The pre-flight gate in `start()` enforces the policy at
        // download-kick-off time, which is the case that matters: an 8 GB
        // download that's already running on Wi-Fi won't pivot to cellular
        // on its own.
        let allowCellular = NetworkPolicy.shared.cellularAllowed
        #if targetEnvironment(simulator)
        let config = URLSessionConfiguration.default
        config.allowsCellularAccess = allowCellular
        #else
        let config = URLSessionConfiguration.background(withIdentifier: Self.backgroundSessionId)
        config.isDiscretionary = false       // user-initiated, run promptly
        config.sessionSendsLaunchEvents = true
        config.allowsCellularAccess = allowCellular
        #endif
        return URLSession(configuration: config, delegate: self, delegateQueue: nil)
    }()

    // `activeTask` is touched from the delegate operation queue, the main
    // queue, and `getAllTasks` completion handlers. Guard with a lock.
    private let taskLock = NSLock()
    private var _activeTask: URLSessionDownloadTask?
    private var activeTask: URLSessionDownloadTask? {
        get { taskLock.lock(); defer { taskLock.unlock() }; return _activeTask }
        set { taskLock.lock(); defer { taskLock.unlock() }; _activeTask = newValue }
    }

    private override init() {
        super.init()
        // Touch the lazy session at init time so we re-attach to any download
        // that was running when the app was last terminated. The delegate
        // callbacks will fire as the OS catches us up.
        _ = session
        rehydrateExistingTask()
    }

    /// Caches directory destination — temporary storage that survives app
    /// relaunches but isn't backed up to iCloud. Once the snapshot is imported
    /// into SQLite, the caller deletes this file.
    static func destinationURL() -> URL {
        let caches = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask).first!
        return caches.appendingPathComponent("hercules-utxo.hutx.gz")
    }

    /// Path where we persist `URLSession`-provided resume data so a network
    /// failure or app force-quit doesn't lose hours of download progress.
    /// The blob is small (a few KB) and contains pointers into iOS's private
    /// partial-download cache plus HTTP Range bookkeeping. Lives next to the
    /// destination so if iOS purges Caches, both go together.
    private static func resumeDataURL() -> URL {
        let caches = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask).first!
        return caches.appendingPathComponent("hercules-utxo.resume")
    }

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

        session.getAllTasks { [weak self] tasks in
            guard let self = self else { return }
            // If iOS already has a task running for our session (e.g. survived
            // a relaunch), latch onto it instead of starting a new one.
            if let existing = tasks.first(where: { $0 is URLSessionDownloadTask }) as? URLSessionDownloadTask {
                self.activeTask = existing
                return
            }
            // Re-check under the lock to avoid spawning two tasks if start()
            // races with itself.
            self.taskLock.lock()
            if self._activeTask != nil {
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
                task = self.session.downloadTask(withResumeData: resumeData)
            } else {
                task = self.session.downloadTask(with: Self.downloadURL)
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
        activeTask?.cancel()
        activeTask = nil
        Self.deleteResumeData()
        DispatchQueue.main.async {
            self.progress = 0
            self.bytesDownloaded = 0
            self.status = .failed("Download cancelled")
        }
    }

    /// Delete the downloaded snapshot file from Caches. Call after a
    /// successful import so we don't waste 8GB of storage indefinitely.
    /// Also clears any resume data — once we've consumed the file, there's
    /// nothing left to resume.
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
            if let existing = tasks.first(where: { $0 is URLSessionDownloadTask }) as? URLSessionDownloadTask {
                self.activeTask = existing
                DispatchQueue.main.async {
                    self.status = .downloading
                }
            }
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
                self.activeTask = nil
            }
            return
        }

        // Validate HTTP status — R2 returns 200 on success, 403/404 on missing.
        if let http = downloadTask.response as? HTTPURLResponse, http.statusCode != 200 {
            try? fm.removeItem(at: dest)
            DispatchQueue.main.async {
                self.status = .failed("Server returned HTTP \(http.statusCode)")
                self.activeTask = nil
            }
            return
        }

        // Successful download — drop any leftover resume data so the next
        // launch doesn't try to resume into a file that's already complete.
        Self.deleteResumeData()

        DispatchQueue.main.async {
            self.progress = 1.0
            self.status = .completed(dest)
            self.activeTask = nil
        }
    }

    func urlSession(
        _ session: URLSession,
        task: URLSessionTask,
        didCompleteWithError error: Error?
    ) {
        guard let error = error else { return }   // success path handled above
        let nsErr = error as NSError
        // User-initiated cancel — already handled by `cancel()`, which also
        // wipes the resume data blob. Nothing to do here.
        if nsErr.domain == NSURLErrorDomain && nsErr.code == NSURLErrorCancelled {
            return
        }

        // Network/server failure or app force-quit. Capture the resume data
        // blob (if any) so the next start() picks up where we left off via
        // an HTTP Range request. If the OS didn't give us resume data (e.g.
        // the failure happened before any bytes landed), wipe any stale blob
        // so we don't try to resume into a now-broken state.
        let suffix: String
        if let resumeData = nsErr.userInfo[NSURLSessionDownloadTaskResumeData] as? Data {
            Self.saveResumeData(resumeData)
            suffix = " — retry will resume"
        } else {
            Self.deleteResumeData()
            suffix = ""
        }
        DispatchQueue.main.async {
            self.status = .failed("Download failed: \(error.localizedDescription)\(suffix)")
            self.activeTask = nil
        }
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
