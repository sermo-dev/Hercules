import ActivityKit
import Foundation

/// Static attributes + dynamic content state for the per-wake Live
/// Activity. One of these is requested at the start of every silent-push
/// wake on iOS 16.1+ devices and ended at wake completion (or failure).
///
/// This file is a member of **both** the main `HerculesApp` target (which
/// requests/updates/ends the activity from `NotificationManager`) and the
/// `HerculesWidget` extension target (which renders it via the
/// `ActivityConfiguration` in the widget bundle). Both targets MUST agree
/// on the type, hence the shared file rather than duplicate definitions.
@available(iOS 16.2, *)
struct NodeActivityAttributes: ActivityAttributes {
    public typealias NodeActivityState = ContentState

    /// Mutating state pushed via `activity.update(...)` as the wake
    /// progresses. Encoded once per phase transition.
    public struct ContentState: Codable, Hashable {
        /// Current chain tip the wake is working on. Surfaced in the
        /// Dynamic Island compact trailing slot — 6-7 digits fits.
        var blockHeight: UInt32

        /// Where the wake is in its 25-second budget.
        var phase: WakePhase

        /// Live peer count from the active node, refreshed at each phase
        /// transition. Fine-grained accuracy isn't important here — the
        /// widget rounds it for display.
        var peerCount: UInt32

        /// Wall-clock start time of the wake. Used by the expanded view
        /// to render "elapsed: 4s" without needing to push that string
        /// from the main app.
        var startedAt: Date
    }

    /// Per-wake unique ID so multiple wakes don't accidentally clobber
    /// each other's activity if they overlap. APNs in theory shouldn't
    /// fire two wakes within 25 s, but defensive plumbing here is cheap.
    var wakeId: UUID
}

/// The five-stage phase progression of a single push wake. Order matters:
/// `WakePhase.allCases` (or `Self.allCases` in the widget) is treated as
/// a strictly monotonic progression for the visual progress bar.
///
/// `failed` is terminal but does not appear in the progress bar — when
/// the wake fails the bar is recolored red and we show the failed phase
/// icon instead of advancing through the bars.
///
/// Defined outside the `@available` block so the main app and the
/// widget extension can both `import` it without OS version gating on
/// the type itself; only the `Activity<...>` API surface that uses it
/// is iOS 16.2+.
public enum WakePhase: String, Codable, Hashable, CaseIterable {
    case connecting
    case headers
    case block
    case validating
    case done
    case failed
}
