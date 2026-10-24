import Darwin
import Foundation
import os

// MARK: - Storage layout (ticket 030)
//
//   Library/Application Support/Chain/    isExcludedFromBackup = true
//       hercules-headers.sqlite3(-wal,-shm), blocks.sqlite3(-wal,-shm),
//       peers.sqlite3(-wal,-shm), own_txs.sqlite3(-wal,-shm), utxo-lmdb/, utxo-lmdb.loading (transient),
//       tor/ (Arti state + cache), wallet_auth_token, .layout-v1 (marker)
//   Library/Application Support/Wallet/   backed up; empty until 036/039
//   Library/Caches/hercules-utxo.hutx.gz  snapshot download (SnapshotDownloader)
//   Documents/notification-history.json   small, user-facing, backed up
//
// Chain data is deliberately NOT in Caches (iOS purges Caches under storage
// pressure and the node would silently vanish) and NOT backed up (10-12 GB
// would blow the iCloud quota and fail the user's whole backup; a mid-write
// copy of a live LMDB/WAL database can restore inconsistent; App Review
// requires re-downloadable data to be excluded).
//
// File protection: everything under Chain/ (and Wallet/) is
// `completeUntilFirstUserAuthentication`, set explicitly. Push wakes and
// BGTasks run while the phone is locked, so `complete` would make every wake
// fail. The consequence is that after a reboot, *before the first unlock*,
// none of these files can be opened: wakes in that state are detected
// (`UIApplication.isProtectedDataAvailable` on the push path, an open(2)
// probe in `prepareForNodeOpen`) and skipped without touching the databases.

/// Errors surfaced by storage preparation and the disk-space guard.
enum StorageError: LocalizedError {
    /// The device has rebooted and has not been unlocked yet, so
    /// `completeUntilFirstUserAuthentication` files are unreadable.
    case protectedDataUnavailable
    /// Moving chain data out of Documents failed; nothing was deleted and the
    /// node will not open until a later launch completes the move.
    case migrationFailed(String)
    /// Not enough free space for the requested operation.
    case insufficientSpace(message: String)

    var errorDescription: String? {
        switch self {
        case .protectedDataUnavailable:
            return "iPhone locked since restart: unlock once to resume validation"
        case .migrationFailed(let detail):
            return "Could not move node data to its new location (\(detail)). Your data is intact; Hercules will retry on next launch."
        case .insufficientSpace(let message):
            return message
        }
    }
}

enum StoragePaths {
    static let log = Logger(subsystem: Bundle.main.bundleIdentifier ?? "Hercules", category: "storage")

    /// Protection class for chain data, Arti state and (later) wallet watch data.
    static let protectionClass = FileProtectionType.completeUntilFirstUserAuthentication

    static let headersFileName = "hercules-headers.sqlite3"
    static let torDirName = "tor"
    static let layoutMarkerName = ".layout-v1"
    static let conflictDirName = "migration-conflicts"

    /// Every name the Rust core (or an older build) ever wrote next to the
    /// headers DB in Documents. The headers/blocks/peers names come from
    /// `derive_sibling_path` in sync.rs; the `hercules-blocks` / `-peers` /
    /// `-utxo` names are orphans from builds before the LMDB switch and the
    /// sibling-path refactor. They're moved (not deleted) so they stop
    /// counting against the user's backup; `reset_database` cleans them up.
    static let legacyChainItems: [String] = {
        var names: [String] = []
        // `own_txs.sqlite3` (ticket 033) holds the user's own raw
        // transactions; it lives next to the headers DB, so it gets the same
        // move, protection class and backup exclusion.
        for db in [headersFileName, "blocks.sqlite3", "peers.sqlite3", "own_txs.sqlite3",
                   "hercules-blocks.sqlite3", "hercules-peers.sqlite3", "hercules-utxo.sqlite3"] {
            names += [db, db + "-wal", db + "-shm"]
        }
        // The `.loading` sentinel MUST travel with the env: without it an
        // interrupted snapshot import would be opened as a valid UTXO set.
        names += ["utxo-lmdb", "utxo-lmdb.loading", torDirName, "wallet_auth_token"]
        return names
    }()

    /// Directory roots. Injectable so the migration can be exercised
    /// against a scratch directory.
    struct Layout {
        let documents: URL
        let applicationSupport: URL

        var chainDir: URL { applicationSupport.appendingPathComponent("Chain", isDirectory: true) }
        var walletDir: URL { applicationSupport.appendingPathComponent("Wallet", isDirectory: true) }
        var markerURL: URL { chainDir.appendingPathComponent(StoragePaths.layoutMarkerName) }
        var conflictDir: URL { chainDir.appendingPathComponent(StoragePaths.conflictDirName, isDirectory: true) }

        static var system: Layout {
            let fm = FileManager.default
            return Layout(
                documents: fm.urls(for: .documentDirectory, in: .userDomainMask)[0],
                applicationSupport: fm.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            )
        }
    }

    static var chainDirectory: URL { Layout.system.chainDir }

    /// Path handed to `HerculesNode(dbPath:)`. The Rust core derives every
    /// other chain file (blocks, peers, utxo-lmdb, wallet token) as a sibling.
    static var headersDBPath: String { chainDirectory.appendingPathComponent(headersFileName).path }

    /// Arti state + cache directory handed to `HerculesNode(torDataDir:)`.
    static var torDataDir: String { chainDirectory.appendingPathComponent(torDirName).path }

    private static let lock = NSLock()
    private static var preparedThisProcess = false

    /// Must succeed before any `HerculesNode` is constructed (and before
    /// `resetDatabase`). Creates the directories, enforces backup exclusion
    /// and protection classes, and completes the one-time migration out of
    /// Documents.
    ///
    /// Runs at most once per process. Every node in the process is opened
    /// only after this returns, so the migration can never move a file out
    /// from under an open database. Serialised by a lock so a push wake and
    /// a foreground start racing at launch can't both migrate.
    ///
    /// Throws `protectedDataUnavailable` after a reboot before first unlock
    /// (callers skip the wake), or `migrationFailed` (node must not open; the
    /// next launch resumes).
    static func prepareForNodeOpen() throws {
        lock.lock()
        defer { lock.unlock() }
        if preparedThisProcess { return }
        try prepare(layout: .system)
        preparedThisProcess = true
    }

    /// Best-effort launch-time call (from `AppDelegate`), so backup exclusion
    /// is re-asserted and the migration happens even if the user never starts
    /// the node in this session. Runs off the main thread; failures are
    /// logged and retried by `prepareForNodeOpen`.
    static func prepareAtLaunch() {
        DispatchQueue.global(qos: .utility).async {
            do {
                try prepareForNodeOpen()
            } catch {
                log.notice("launch-time storage prepare deferred: \(error.localizedDescription, privacy: .public)")
            }
        }
    }

    static func prepare(layout: Layout) throws {
        // 0. Locked since reboot? Don't create, move, or touch anything.
        guard protectedDataReadable(layout) else {
            throw StorageError.protectedDataUnavailable
        }

        // 1. Directories, protection class, backup exclusion (re-asserted on
        //    every launch: cheap and idempotent, and a restore-from-backup or
        //    an OS update can't silently flip it back).
        do {
            try ensureDirectory(layout.chainDir)
            try excludeFromBackup(layout.chainDir)
            try ensureDirectory(layout.walletDir)
        } catch {
            throw StorageError.migrationFailed("create directories: \(error.localizedDescription)")
        }

        // 2. One-time migration out of Documents.
        try migrate(layout)

        // 3. Explicit protection class on everything already in Chain/
        //    (files the Rust core creates inherit the directory's class, but
        //    migrated files keep whatever they had in Documents).
        reassertProtection(under: layout.chainDir)
    }

    /// Move each legacy chain item from Documents into Chain/.
    ///
    /// Safety argument:
    /// - Each move is a single `rename(2)` (via `renamex_np(RENAME_EXCL)`):
    ///   atomic, same-volume (both live in the app container), never copies,
    ///   never overwrites, and nothing is ever deleted. After a crash every
    ///   item is in exactly one place; re-running just moves the rest.
    /// - A cross-volume layout (EXDEV) or any other failure throws, leaving
    ///   everything where it is. The node stays closed until a later attempt
    ///   succeeds rather than opening a half-moved database.
    /// - The `.layout-v1` marker is written only after every item has moved;
    ///   `prepareForNodeOpen` succeeding is what gates node open, so a
    ///   headers DB can't be opened without its `-wal` or the UTXO env
    ///   without its `.loading` sentinel.
    /// - If an item exists in BOTH places (only possible after a downgrade to
    ///   a pre-030 build recreated data in Documents), Chain/ wins and the
    ///   Documents copy is parked in `Chain/migration-conflicts/` (still out of
    ///   backup) instead of being deleted or merged.
    static func migrate(_ layout: Layout) throws {
        let fm = FileManager.default
        var moved: [String] = []
        var parked: [String] = []

        for name in legacyChainItems {
            let src = layout.documents.appendingPathComponent(name)
            // lstat-style existence (don't follow symlinks; a dangling one still moves).
            guard (try? fm.attributesOfItem(atPath: src.path)) != nil else { continue }

            var dst = layout.chainDir.appendingPathComponent(name)
            if (try? fm.attributesOfItem(atPath: dst.path)) != nil {
                do {
                    try ensureDirectory(layout.conflictDir)
                } catch {
                    throw StorageError.migrationFailed("create conflict dir: \(error.localizedDescription)")
                }
                let stamp = Int(Date().timeIntervalSince1970)
                dst = layout.conflictDir.appendingPathComponent("\(name).\(stamp)")
                parked.append(name)
            } else {
                moved.append(name)
            }

            if renamex_np(src.path, dst.path, UInt32(RENAME_EXCL)) != 0 {
                let err = String(cString: strerror(errno))
                log.error("migration: rename \(name, privacy: .public) failed: \(err, privacy: .public)")
                throw StorageError.migrationFailed("\(name): \(err)")
            }
        }

        if !moved.isEmpty || !parked.isEmpty {
            log.notice("migration: moved \(moved, privacy: .public); parked conflicts \(parked, privacy: .public)")
        }

        if (try? fm.attributesOfItem(atPath: layout.markerURL.path)) == nil {
            let body = "chain layout v1 (ticket 030); written after Documents migration\n"
            do {
                try Data(body.utf8).write(
                    to: layout.markerURL,
                    options: [.atomic, .completeFileProtectionUntilFirstUserAuthentication]
                )
            } catch {
                throw StorageError.migrationFailed("write marker: \(error.localizedDescription)")
            }
        }
    }

    /// Returns false when chain files exist but can't be opened, i.e. the
    /// device rebooted and hasn't been unlocked. Probes with open(2) because
    /// `UIApplication.isProtectedDataAvailable` is main-thread-only and this
    /// runs on background queues (BGTask handlers, node threads).
    static func protectedDataReadable(_ layout: Layout) -> Bool {
        let candidates = [
            layout.markerURL.path,
            layout.documents.appendingPathComponent(headersFileName).path,
        ]
        for path in candidates where FileManager.default.fileExists(atPath: path) {
            let fd = open(path, O_RDONLY)
            if fd < 0 {
                return !(errno == EPERM || errno == EACCES)
            }
            close(fd)
            return true
        }
        // Nothing written yet (fresh install): nothing to protect.
        return true
    }

    // MARK: Helpers

    private static func ensureDirectory(_ url: URL) throws {
        try FileManager.default.createDirectory(
            at: url,
            withIntermediateDirectories: true,
            attributes: [.protectionKey: protectionClass]
        )
        // createDirectory ignores attributes when the directory already exists.
        try FileManager.default.setAttributes([.protectionKey: protectionClass], ofItemAtPath: url.path)
    }

    private static func excludeFromBackup(_ url: URL) throws {
        var url = url
        var values = URLResourceValues()
        values.isExcludedFromBackup = true
        try url.setResourceValues(values)
    }

    /// Set the protection class on every item under `root` whose class
    /// differs. Runs before any node opens (see `prepareForNodeOpen`).
    private static func reassertProtection(under root: URL) {
        let fm = FileManager.default
        guard let walker = fm.enumerator(atPath: root.path) else { return }
        var changed = 0
        var failed = 0
        while let rel = walker.nextObject() as? String {
            let path = root.appendingPathComponent(rel).path
            let current = (try? fm.attributesOfItem(atPath: path))?[.protectionKey] as? FileProtectionType
            if current == protectionClass { continue }
            do {
                try fm.setAttributes([.protectionKey: protectionClass], ofItemAtPath: path)
                changed += 1
            } catch {
                failed += 1
            }
        }
        if changed > 0 || failed > 0 {
            log.notice("protection: set \(changed) items, \(failed) failures under \(root.lastPathComponent, privacy: .public)")
        }
    }

    /// Debug aid / verification hook: items under Chain/ whose protection
    /// class isn't the expected one. On the simulator the class is usually
    /// unreported, so this is only meaningful on device.
    static func protectionMismatches() -> [String] {
        let fm = FileManager.default
        let root = chainDirectory
        guard let walker = fm.enumerator(atPath: root.path) else { return [] }
        var bad: [String] = []
        while let rel = walker.nextObject() as? String {
            let cls = (try? fm.attributesOfItem(atPath: root.appendingPathComponent(rel).path))?[.protectionKey] as? FileProtectionType
            if cls != protectionClass { bad.append("\(rel)=\(cls?.rawValue ?? "nil")") }
        }
        return bad
    }
}

// MARK: - Disk space guard

enum StorageGuard {
    /// Free space required before starting the AssumeUTXO download:
    /// ~8.8 GB compressed snapshot + ~12 GB LMDB it unpacks into (both exist
    /// at once during import) + headroom for headers, blocks, and iOS.
    static let snapshotRequiredBytes: Int64 = 25 * 1_000_000_000

    /// Below this, block validation is paused so LMDB/SQLite never hit
    /// ENOSPC mid-transaction. Resumes above `resumeAboveBytes` (hysteresis
    /// so it doesn't flap around the threshold).
    static let pauseBelowBytes: Int64 = 2 * 1_000_000_000
    static let resumeAboveBytes: Int64 = 3 * 1_000_000_000

    /// Free space as iOS reports it for user-important writes (includes space
    /// iOS can reclaim by purging other apps' caches).
    static func availableBytes() -> Int64? {
        let url = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        let probe = FileManager.default.fileExists(atPath: url.path)
            ? url
            : FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        let values = try? probe.resourceValues(forKeys: [.volumeAvailableCapacityForImportantUsageKey])
        return values?.volumeAvailableCapacityForImportantUsage
    }

    static func format(_ bytes: Int64) -> String {
        ByteCountFormatter.string(fromByteCount: bytes, countStyle: .file)
    }

    /// Throws `insufficientSpace` with user-facing copy if there isn't room
    /// to download and import the snapshot. Bytes of a completed download
    /// already on disk are credited.
    static func snapshotPreflight(alreadyDownloaded: Int64 = 0) throws {
        guard let free = availableBytes() else { return } // unknown: don't block
        let needed = snapshotRequiredBytes - alreadyDownloaded
        if free < needed {
            throw StorageError.insufficientSpace(message:
                "Not enough storage to set up the node. The snapshot download and the UTXO database it unpacks into need about \(format(needed)) free; this iPhone has \(format(free)). Free up space in Settings > General > iPhone Storage, then tap Start again.")
        }
    }

    /// Banner copy shown while validation is paused for low storage.
    static func lowSpaceMessage(free: Int64) -> String {
        "Storage almost full: block validation is paused. Hercules needs at least \(format(pauseBelowBytes)) free to keep validating safely (\(format(free)) free now). It resumes automatically once you free up space."
    }

    /// Bytes used by chain data (allocated size on disk).
    static func chainDataBytes() -> Int64 {
        let root = StoragePaths.chainDirectory
        let keys: [URLResourceKey] = [.totalFileAllocatedSizeKey, .fileAllocatedSizeKey]
        guard let walker = FileManager.default.enumerator(at: root, includingPropertiesForKeys: keys) else { return 0 }
        var total: Int64 = 0
        for case let url as URL in walker {
            let v = try? url.resourceValues(forKeys: Set(keys))
            total += Int64(v?.totalFileAllocatedSize ?? v?.fileAllocatedSize ?? 0)
        }
        return total
    }
}
