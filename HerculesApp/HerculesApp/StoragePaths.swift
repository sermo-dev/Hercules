import Darwin
import Foundation
import os

// MARK: - Storage layout (ticket 030)
//
//   Library/Application Support/Chain/    isExcludedFromBackup = true
//       hercules-headers.sqlite3(-wal,-shm), blocks.sqlite3(-wal,-shm),
//       peers.sqlite3(-wal,-shm), own_txs.sqlite3(-wal,-shm), utxo-lmdb/, utxo-lmdb.loading (transient),
//       tor/ (Arti state + cache), wallet_auth_token, .layout-v1 (marker),
//       migration-conflicts/ (parked downgrade copies; deleted after 7 days
//       or on node reset)
//   Library/Application Support/Wallet/   backed up; empty until 036/039
//   Library/Caches/<snapshot>.hutx.gz      snapshot download (SnapshotDownloader)
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
// none of these files can be opened: wakes in that state are detected by
// an open(2) probe in `prepareForNodeOpen` and skipped without touching the
// databases. `UIApplication.isProtectedDataAvailable` is NOT used: it tracks
// the `complete` class, so it goes false ~10 s after every passcode lock,
// while our files stay readable until the next reboot.

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
    /// The UTXO LMDB map can't be made large enough for the AssumeUTXO set
    /// on this device (address-space limit). Detail from the Rust core.
    case cannotMapUtxoSet(String)

    var errorDescription: String? {
        switch self {
        case .protectedDataUnavailable:
            return "iPhone locked since restart: unlock once to resume validation"
        case .migrationFailed(let detail):
            return "Could not move node data to its new location (\(detail)). Your data is intact; Hercules will retry on next launch."
        case .insufficientSpace(let message):
            return message
        case .cannotMapUtxoSet(let detail):
            return "This iPhone can't reserve enough memory-mapped address space for the UTXO database, so the node can't be set up from a snapshot on this device. (\(detail))"
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
    ///
    /// Items are grouped: a primary plus companions that are only meaningful
    /// next to *that* primary (SQLite `-wal`/`-shm`, the LMDB `.loading`
    /// sentinel). A group moves or is parked as a unit, so a companion can
    /// never end up beside a different copy of its primary — a foreign `-wal`
    /// would be replayed onto the wrong database, and a stray `.loading`
    /// would make the next open wipe a valid UTXO set.
    struct ItemGroup {
        let primary: String
        let companions: [String]
    }

    static let legacyChainGroups: [ItemGroup] = {
        var groups: [ItemGroup] = []
        // `own_txs.sqlite3` (ticket 033) holds the user's own raw
        // transactions; it lives next to the headers DB, so it gets the same
        // move, protection class and backup exclusion.
        for db in [headersFileName, "blocks.sqlite3", "peers.sqlite3", "own_txs.sqlite3",
                   "hercules-blocks.sqlite3", "hercules-peers.sqlite3", "hercules-utxo.sqlite3"] {
            groups.append(ItemGroup(primary: db, companions: [db + "-wal", db + "-shm"]))
        }
        // The `.loading` sentinel MUST travel with the env: without it an
        // interrupted snapshot import would be opened as a valid UTXO set.
        groups.append(ItemGroup(primary: "utxo-lmdb", companions: ["utxo-lmdb.loading"]))
        groups.append(ItemGroup(primary: torDirName, companions: []))
        groups.append(ItemGroup(primary: "wallet_auth_token", companions: []))
        return groups
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

        // 2. One-time migration out of Documents, then drop conflict copies
        //    parked long enough ago that nobody is going to recover them.
        try migrate(layout)
        pruneParkedConflicts(layout)

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
    ///   backup) instead of being deleted or merged. Parked items are deleted
    ///   `parkedRetention` (7 days) later by `pruneParkedConflicts`, or by a
    ///   node reset.
    static func migrate(_ layout: Layout) throws {
        let fm = FileManager.default
        var moved: [String] = []
        var parked: [String] = []

        // lstat-style existence (don't follow symlinks; a dangling one still moves).
        func exists(_ url: URL) -> Bool { (try? fm.attributesOfItem(atPath: url.path)) != nil }
        func rename(_ name: String, _ src: URL, _ dst: URL) throws {
            if renamex_np(src.path, dst.path, UInt32(RENAME_EXCL)) != 0 {
                let err = String(cString: strerror(errno))
                log.error("migration: rename \(name, privacy: .public) failed: \(err, privacy: .public)")
                throw StorageError.migrationFailed("\(name): \(err)")
            }
        }

        for group in legacyChainGroups {
            let names = group.companions + [group.primary]
            let present = names.filter { exists(layout.documents.appendingPathComponent($0)) }
            if present.isEmpty { continue }

            if exists(layout.chainDir.appendingPathComponent(group.primary)) {
                // Conflict: Chain/ already has this primary (only possible
                // after a downgrade recreated data in Documents). Chain/ wins;
                // park the whole Documents group together so none of its
                // companions lands next to Chain/'s primary.
                do {
                    try ensureDirectory(layout.conflictDir)
                } catch {
                    throw StorageError.migrationFailed("create conflict dir: \(error.localizedDescription)")
                }
                let stamp = Int(Date().timeIntervalSince1970)
                for name in present {
                    try rename(name,
                               layout.documents.appendingPathComponent(name),
                               layout.conflictDir.appendingPathComponent("\(name).\(stamp)"))
                    parked.append(name)
                }
                continue
            }

            // Normal move. Companions go first, primary last: if we crash
            // part-way, the primary is still in Documents, so the next run
            // takes this branch again and finishes the group (companions
            // already in Chain/ are simply no longer present in Documents).
            for name in present {
                let dst = layout.chainDir.appendingPathComponent(name)
                if name != group.primary, exists(dst) {
                    // A companion already in Chain/ while its primary is
                    // still in Documents: a leftover from an interrupted
                    // migration, superseded because an older build reopened
                    // the Documents pair and wrote a new companion. The
                    // Documents pair is the live one; park the stale Chain/
                    // copy (never delete) and move the live one in.
                    do {
                        try ensureDirectory(layout.conflictDir)
                    } catch {
                        throw StorageError.migrationFailed("create conflict dir: \(error.localizedDescription)")
                    }
                    let stamp = Int(Date().timeIntervalSince1970)
                    try rename(name, dst, layout.conflictDir.appendingPathComponent("\(name).stale.\(stamp)"))
                    parked.append(name)
                }
                try rename(name, layout.documents.appendingPathComponent(name), dst)
                moved.append(name)
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

    /// How long a parked conflict copy is kept before it's deleted at launch.
    /// Long enough to recover from a bad migration by hand; parked chain
    /// data is otherwise multi-GB of dead weight.
    static let parkedRetention: TimeInterval = 7 * 24 * 3600

    /// Delete items in `Chain/migration-conflicts/` parked more than
    /// `parkedRetention` before `now`. Age comes from the Unix timestamp
    /// `migrate` appends to the name (`<name>.<ts>`, `<name>.stale.<ts>`),
    /// not the file dates, which a rename preserves from the original.
    /// Items without a parseable stamp are left alone. Best-effort: never
    /// blocks the node from opening. Returns the names removed.
    @discardableResult
    static func pruneParkedConflicts(_ layout: Layout, now: Date = Date()) -> [String] {
        let fm = FileManager.default
        guard let names = try? fm.contentsOfDirectory(atPath: layout.conflictDir.path) else { return [] }
        var removed: [String] = []
        for name in names {
            guard let stamp = parkedStamp(name),
                  now.timeIntervalSince1970 - TimeInterval(stamp) >= parkedRetention else { continue }
            do {
                try fm.removeItem(at: layout.conflictDir.appendingPathComponent(name))
                removed.append(name)
            } catch {
                log.error("prune parked \(name, privacy: .public) failed: \(error.localizedDescription, privacy: .public)")
            }
        }
        if !removed.isEmpty {
            log.notice("migration: deleted parked conflicts older than 7 days: \(removed, privacy: .public)")
        }
        return removed
    }

    /// Parking time encoded in a parked item's name, if any.
    static func parkedStamp(_ name: String) -> Int? {
        guard let dot = name.lastIndex(of: ".") else { return nil }
        return Int(name[name.index(after: dot)...])
    }

    /// Returns false when chain files exist but can't be opened, i.e. the
    /// device rebooted and hasn't been unlocked. Probes with open(2) on a
    /// file of our own class, so it fails only before first unlock (unlike
    /// `UIApplication.isProtectedDataAvailable`, which reflects `complete`
    /// and flips false on every lock). Plain syscalls, so safe on any thread
    /// (push handler's global queue, BGTask handlers, node threads).
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

    /// The imported UTXO LMDB's share of `snapshotRequiredBytes`.
    static let utxoEnvBytes: Int64 = 12 * 1_000_000_000

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
    ///
    /// `reusable` is the size of an existing UTXO LMDB file (left by an
    /// aborted import: LMDB never shrinks its file, and the next import
    /// reuses those pages), credited up to the LMDB's share.
    static func snapshotPreflight(alreadyDownloaded: Int64 = 0, reusable: Int64 = 0) throws {
        guard let free = availableBytes() else { return } // unknown: don't block
        let needed = snapshotRequiredBytes - alreadyDownloaded - min(reusable, utxoEnvBytes)
        if free < needed {
            throw StorageError.insufficientSpace(message:
                "Not enough storage to set up the node. The snapshot download and the UTXO database it unpacks into need about \(format(needed)) free; this iPhone has \(format(free)). Free up space in Settings > General > iPhone Storage, then tap Start again.")
        }
    }

    /// Banner copy when the snapshot import was stopped for low storage.
    static func snapshotImportLowSpaceMessage(free: Int64) -> String {
        "Storage almost full: the snapshot import was stopped (\(format(free)) free). The downloaded snapshot was kept. Free up space in Settings > General > iPhone Storage, then tap Start again."
    }

    /// Size of the UTXO LMDB data file, 0 if absent.
    static func utxoEnvFileBytes() -> Int64 {
        let url = StoragePaths.chainDirectory
            .appendingPathComponent("utxo-lmdb", isDirectory: true)
            .appendingPathComponent("data.mdb")
        let size = (try? FileManager.default.attributesOfItem(atPath: url.path))?[.size] as? NSNumber
        return size?.int64Value ?? 0
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
