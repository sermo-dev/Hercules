import Foundation
#if canImport(WidgetKit)
import WidgetKit
#endif

/// Snapshot of node state shared between the main Hercules app and the
/// `HerculesWidget` extension via an App Group container. The widget process
/// has no access to the main app's SQLite, the Tor data dir, or any in-memory
/// state; this struct + the JSON file at
/// `Application Group Container/Library/Caches/node_state.json` are the
/// entire surface area between them.
///
/// Writing rules (see `write(_:)`):
///
/// - The main app writes on every meaningful transition: a successful block
///   validation, a wake that was paused by the cellular gate, a network
///   path change, the snapshot becoming ready.
/// - Writes are atomic — we go through `Data.write(.atomic)` so a widget
///   reading concurrently never sees a half-written file.
/// - Each write nudges WidgetKit via `WidgetCenter.shared.reloadAllTimelines`
///   so a fresh render reflects the new state. WidgetKit budgets reloads to
///   roughly 40-70/day; per-block reloads (~144/day) will exceed that, so
///   the widget UI also leans on `Text(_:style:.relative)` for the
///   time-since-block field, which ticks forward without any reload.
struct SharedNodeState: Codable, Equatable {
    /// Block height that the node has fully validated and committed.
    let blockHeight: UInt32

    /// Hex-encoded block hash, big-endian (the form bitcoin block explorers
    /// display). May be empty if no block has been validated yet.
    let blockHash: String

    /// Wall-clock time at which the block at `blockHeight` was validated by
    /// this device. Used by the widget's `Text(_:style:.relative)` to render
    /// "4m ago", "2h ago", etc. without app code running.
    let lastBlockTime: Date

    /// Last-known peer count. May be stale by minutes — the main app process
    /// has been suspended since the last write, so the actual current count
    /// is unknowable from the widget. Render alongside `lastBlockTime` so
    /// the user reads them as a pair.
    let peerCount: UInt32

    /// True while a push wake is in flight. The widget can use this to show
    /// an "awake" dot vs. an "idle" dot. Cleared at wake end.
    let isAwake: Bool

    /// True when validation is currently being skipped due to the cellular
    /// gate (metered network without `useCellularData` opt-in). The widget
    /// surfaces this as the red "paused" indicator so the user understands
    /// why the height isn't moving.
    let isPaused: Bool

    /// Wall-clock time of *this* state write. Distinct from `lastBlockTime`:
    /// `updatedAt` advances even on writes that don't change the height
    /// (e.g. a wake-paused entry, a network change). The widget can use it
    /// to debug staleness.
    let updatedAt: Date

    static let empty = SharedNodeState(
        blockHeight: 0,
        blockHash: "",
        lastBlockTime: Date(timeIntervalSince1970: 0),
        peerCount: 0,
        isAwake: false,
        isPaused: false,
        updatedAt: Date(timeIntervalSince1970: 0)
    )
}

/// Backing-store helpers. Lives outside `SharedNodeState` so the main app
/// and the widget can both call `SharedNodeStore.load()` from their
/// respective processes without instance threading.
enum SharedNodeStore {
    /// App Group identifier — must match the entry in both targets'
    /// `*.entitlements` files. Hardcoded here as the single source of
    /// truth so a typo in one entitlements file fails loudly at runtime.
    static let appGroupIdentifier = "group.dev.sermo.hercules.shared"

    /// Filename inside the App Group container. We deliberately put this
    /// in the Caches subdirectory rather than the root: state can always
    /// be reconstructed from the SQLite headers DB, so iOS purging it
    /// under storage pressure is fine — the next wake re-publishes.
    private static let filename = "node_state.json"

    /// Resolves the JSON file URL inside the App Group's shared container.
    /// Returns nil if the entitlement is missing or the OS can't provide
    /// the container — both treated as fatal at first call by the main app
    /// (the widget will silently fall back to `SharedNodeState.empty`).
    static func fileURL() -> URL? {
        guard let container = FileManager.default.containerURL(
            forSecurityApplicationGroupIdentifier: appGroupIdentifier
        ) else {
            return nil
        }
        let caches = container.appendingPathComponent("Library/Caches", isDirectory: true)
        // Ensure the Caches subdir exists — App Group containers ship with
        // an empty Library/ but not the Caches/ subfolder.
        try? FileManager.default.createDirectory(at: caches, withIntermediateDirectories: true)
        return caches.appendingPathComponent(filename)
    }

    /// Read the most recent published state. Returns `.empty` if the file
    /// is missing, the entitlement is missing, or decoding fails — the
    /// widget shows a "no data yet" placeholder in those cases rather than
    /// crashing.
    static func load() -> SharedNodeState {
        guard let url = fileURL(),
              let data = try? Data(contentsOf: url),
              let decoded = try? JSONDecoder.shared.decode(SharedNodeState.self, from: data)
        else {
            return .empty
        }
        return decoded
    }

    /// Convenience writer for the "we just validated a fresh block" case.
    /// Replaces the entire stored state — height, hash, peer count, and
    /// `lastBlockTime` all advance together. Clears `isAwake` and
    /// `isPaused` so the widget reverts to its idle render.
    static func publishValidation(height: UInt32, blockHash: String, peerCount: UInt32) {
        write(SharedNodeState(
            blockHeight: height,
            blockHash: blockHash,
            lastBlockTime: Date(),
            peerCount: peerCount,
            isAwake: false,
            isPaused: false,
            updatedAt: Date()
        ))
    }

    /// Mark the node as paused by the cellular gate without losing the
    /// last-known block height. Does a load-modify-write so the widget
    /// keeps showing the most recent block we *have* validated, plus the
    /// red "paused" indicator on top.
    static func markPaused(_ paused: Bool) {
        var state = load()
        // Don't republish if nothing's actually changing — saves a
        // WidgetKit reload budget tick.
        if state.isPaused == paused { return }
        state = SharedNodeState(
            blockHeight: state.blockHeight,
            blockHash: state.blockHash,
            lastBlockTime: state.lastBlockTime,
            peerCount: state.peerCount,
            isAwake: state.isAwake,
            isPaused: paused,
            updatedAt: Date()
        )
        write(state)
    }

    /// Mark the node as awake (a wake is in flight) or idle. Used by the
    /// silent-push handler so the widget can render the awake dot during
    /// the brief window the node is actually doing work.
    static func markAwake(_ awake: Bool) {
        var state = load()
        if state.isAwake == awake { return }
        state = SharedNodeState(
            blockHeight: state.blockHeight,
            blockHash: state.blockHash,
            lastBlockTime: state.lastBlockTime,
            peerCount: state.peerCount,
            isAwake: awake,
            isPaused: state.isPaused,
            updatedAt: Date()
        )
        write(state)
    }

    /// Write a new state and (when WidgetKit is available — i.e. compiling
    /// the main app, not the simulator-bare unit-test bundle) reload the
    /// widget timeline so the home-screen render advances. The reload is
    /// best-effort; WidgetKit will simply ignore us once we've burned
    /// through the daily budget.
    static func write(_ state: SharedNodeState) {
        guard let url = fileURL() else {
            // Entitlement missing or container unavailable — silently no-op.
            // Logged once at app startup by the main app's diagnostic code.
            return
        }
        do {
            let data = try JSONEncoder.shared.encode(state)
            try data.write(to: url, options: .atomic)
        } catch {
            // Best-effort: a transient write failure doesn't break the app.
            // The next state transition will retry.
            return
        }

        #if canImport(WidgetKit)
        WidgetCenter.shared.reloadAllTimelines()
        #endif
    }
}

// MARK: - Encoder/Decoder singletons

private extension JSONEncoder {
    /// One encoder, ISO8601 dates, used by both the main app's writer and
    /// the widget's reader so date round-trips are stable.
    static let shared: JSONEncoder = {
        let e = JSONEncoder()
        e.dateEncodingStrategy = .iso8601
        return e
    }()
}

private extension JSONDecoder {
    static let shared: JSONDecoder = {
        let d = JSONDecoder()
        d.dateDecodingStrategy = .iso8601
        return d
    }()
}
