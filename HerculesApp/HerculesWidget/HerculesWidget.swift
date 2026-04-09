import ActivityKit
import SwiftUI
import WidgetKit

// MARK: - Widget Bundle (entry point)

/// Single `@main` entry point that exposes both the home/lock screen widget
/// (`HerculesNodeWidget`) and the Live Activity / Dynamic Island
/// configuration (`HerculesNodeActivity`). The Live Activity is registered
/// here even though it's iOS 16.1+ only — the `@available` guard on
/// `HerculesNodeActivity` itself keeps the bundle compiling against the
/// iOS 17 deployment target.
@main
struct HerculesWidgetBundle: WidgetBundle {
    var body: some Widget {
        HerculesNodeWidget()
        if #available(iOS 16.2, *) {
            HerculesNodeActivity()
        }
    }
}

// MARK: - Home / Lock Screen Widget

/// The persistent glance surface. Renders the most recent block height,
/// time-since-last-block (auto-ticking via `Text(_:style:.relative)` so it
/// advances without app code running), peer count, and a status dot that
/// flips between idle / awake / paused.
///
/// All families share a single state source (`SharedNodeStore`) and a
/// single timeline provider — the differences are pure layout.
struct HerculesNodeWidget: Widget {
    let kind: String = "HerculesNodeWidget"

    var body: some WidgetConfiguration {
        StaticConfiguration(kind: kind, provider: NodeTimelineProvider()) { entry in
            HerculesNodeWidgetView(entry: entry)
                .containerBackground(.fill.tertiary, for: .widget)
        }
        .configurationDisplayName("Hercules Node")
        .description("Latest block your iPhone has validated, with live time-since-block.")
        .supportedFamilies([
            .systemSmall,
            .systemMedium,
            .accessoryCircular,
            .accessoryInline,
            .accessoryRectangular
        ])
    }
}

// MARK: - Timeline Provider

/// `TimelineEntry` carrying the JSON-published `SharedNodeState`. The widget
/// timeline only needs one entry at a time — the `Text(_:style:.relative)`
/// for time-since-block re-renders on its own without OS reloads — so we
/// emit a single entry per provider call and a long `.atEnd` policy so iOS
/// won't ask us again until something else (the main app's
/// `WidgetCenter.reloadAllTimelines()` call) wakes us.
struct NodeWidgetEntry: TimelineEntry {
    let date: Date
    let state: SharedNodeState
}

struct NodeTimelineProvider: TimelineProvider {
    /// Placeholder shown in the widget gallery and during the brief moment
    /// before any data has loaded. Pre-filled with believable values so
    /// the gallery doesn't show "0".
    func placeholder(in context: Context) -> NodeWidgetEntry {
        NodeWidgetEntry(
            date: Date(),
            state: SharedNodeState(
                blockHeight: 887_000,
                blockHash: "00000000000000000001abcdef...",
                lastBlockTime: Date().addingTimeInterval(-240),
                peerCount: 8,
                isAwake: false,
                isPaused: false,
                updatedAt: Date()
            )
        )
    }

    func getSnapshot(in context: Context, completion: @escaping (NodeWidgetEntry) -> Void) {
        completion(NodeWidgetEntry(date: Date(), state: SharedNodeStore.load()))
    }

    /// Single-entry timeline. iOS will not ask us again until the app
    /// nudges WidgetCenter — which happens at every block validation,
    /// network state change, or paused-by-policy transition. The relative
    /// time text inside the view ticks forward on its own.
    func getTimeline(in context: Context, completion: @escaping (Timeline<NodeWidgetEntry>) -> Void) {
        let entry = NodeWidgetEntry(date: Date(), state: SharedNodeStore.load())
        completion(Timeline(entries: [entry], policy: .atEnd))
    }
}

// MARK: - Widget Views

/// Family-dispatching root view. Each family gets its own layout because
/// the constraints are very different (Lock Screen accessory widgets are
/// monochrome and tiny; system widgets have full color and breathing room).
struct HerculesNodeWidgetView: View {
    let entry: NodeWidgetEntry
    @Environment(\.widgetFamily) var family

    var body: some View {
        switch family {
        case .systemSmall:        SystemSmallNodeView(state: entry.state)
        case .systemMedium:       SystemMediumNodeView(state: entry.state)
        case .accessoryCircular:  AccessoryCircularNodeView(state: entry.state)
        case .accessoryInline:    AccessoryInlineNodeView(state: entry.state)
        case .accessoryRectangular: AccessoryRectangularNodeView(state: entry.state)
        default:                  SystemSmallNodeView(state: entry.state)
        }
    }
}

/// Square home-screen widget. Block height takes the visual lead because
/// it's the one number a Bitcoin user actually wants to glance at. Time
/// since last block is the secondary signal: a healthy node has a number
/// here that's reliably in the single-digit minutes range.
struct SystemSmallNodeView: View {
    let state: SharedNodeState

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 6) {
                StatusDot(state: state)
                Text("Hercules")
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundStyle(.secondary)
                Spacer()
            }
            Spacer(minLength: 0)
            Text(formatHeight(state.blockHeight))
                .font(.system(size: 28, weight: .bold, design: .rounded))
                .monospacedDigit()
                .minimumScaleFactor(0.6)
                .lineLimit(1)
            relativeBlockTime(state: state)
                .font(.system(size: 11, weight: .medium))
                .foregroundStyle(.secondary)
            Spacer(minLength: 0)
            HStack(spacing: 4) {
                Image(systemName: "person.2.fill")
                    .font(.system(size: 9))
                Text("\(state.peerCount) peers")
                    .font(.system(size: 10, weight: .medium))
            }
            .foregroundStyle(.tertiary)
        }
    }
}

/// Wider rectangle for the medium home-screen size. Adds the truncated
/// block hash + cellular state so a user who taps to expand can verify the
/// node hasn't drifted from the network.
struct SystemMediumNodeView: View {
    let state: SharedNodeState

    var body: some View {
        HStack(alignment: .top, spacing: 16) {
            VStack(alignment: .leading, spacing: 6) {
                HStack(spacing: 6) {
                    StatusDot(state: state)
                    Text("Hercules Node")
                        .font(.system(size: 12, weight: .semibold))
                        .foregroundStyle(.secondary)
                }
                Text(formatHeight(state.blockHeight))
                    .font(.system(size: 32, weight: .bold, design: .rounded))
                    .monospacedDigit()
                    .lineLimit(1)
                    .minimumScaleFactor(0.6)
                relativeBlockTime(state: state)
                    .font(.system(size: 11, weight: .medium))
                    .foregroundStyle(.secondary)
            }
            Spacer()
            VStack(alignment: .trailing, spacing: 6) {
                HStack(spacing: 4) {
                    Text("\(state.peerCount)")
                        .font(.system(size: 14, weight: .semibold))
                        .monospacedDigit()
                    Image(systemName: "person.2.fill")
                        .font(.system(size: 10))
                }
                .foregroundStyle(.secondary)
                if !state.blockHash.isEmpty {
                    Text(truncatedHash(state.blockHash))
                        .font(.system(size: 9, design: .monospaced))
                        .foregroundStyle(.tertiary)
                        .lineLimit(1)
                }
                if state.isPaused {
                    Label("Paused", systemImage: "pause.circle.fill")
                        .font(.system(size: 10, weight: .semibold))
                        .foregroundStyle(.orange)
                } else if state.isAwake {
                    Label("Awake", systemImage: "bolt.fill")
                        .font(.system(size: 10, weight: .semibold))
                        .foregroundStyle(.green)
                }
            }
        }
    }
}

/// Lock Screen circular: just the awake/idle/paused dot in the center.
/// Black-and-white because Lock Screen accessory widgets are monochrome
/// (the OS recolors them based on Lock Screen wallpaper).
struct AccessoryCircularNodeView: View {
    let state: SharedNodeState

    var body: some View {
        ZStack {
            AccessoryWidgetBackground()
            VStack(spacing: 0) {
                Image(systemName: state.isPaused
                      ? "pause.circle.fill"
                      : (state.isAwake ? "bolt.fill" : "cube.fill"))
                    .font(.system(size: 14, weight: .semibold))
                Text(formatHeightShort(state.blockHeight))
                    .font(.system(size: 9, weight: .semibold, design: .rounded))
                    .monospacedDigit()
            }
        }
    }
}

/// Lock Screen inline: single line of text in the system font. Constrained
/// to ~30 characters max — keep it terse.
struct AccessoryInlineNodeView: View {
    let state: SharedNodeState

    var body: some View {
        Label {
            Text("\(state.blockHeight)")
                .monospacedDigit()
        } icon: {
            Image(systemName: state.isPaused ? "pause.circle.fill" : "cube.fill")
        }
    }
}

/// Lock Screen rectangular: room for height + relative time on two lines.
struct AccessoryRectangularNodeView: View {
    let state: SharedNodeState

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            HStack(spacing: 4) {
                Image(systemName: state.isPaused ? "pause.circle.fill" : "cube.fill")
                    .font(.system(size: 11, weight: .semibold))
                Text("Hercules")
                    .font(.system(size: 11, weight: .semibold))
            }
            Text(formatHeight(state.blockHeight))
                .font(.system(size: 18, weight: .bold, design: .rounded))
                .monospacedDigit()
                .lineLimit(1)
                .minimumScaleFactor(0.7)
            relativeBlockTime(state: state)
                .font(.system(size: 10))
        }
    }
}

// MARK: - Shared widget UI helpers

/// The colored dot that summarises node liveness for any of the system
/// widget families.
private struct StatusDot: View {
    let state: SharedNodeState

    var body: some View {
        Circle()
            .fill(color)
            .frame(width: 8, height: 8)
    }

    private var color: Color {
        if state.isPaused { return .red }
        if state.isAwake { return .green }
        return .gray
    }
}

/// Format a block height with thousands separators ("887,123").
private func formatHeight(_ h: UInt32) -> String {
    let f = NumberFormatter()
    f.numberStyle = .decimal
    return f.string(from: NSNumber(value: h)) ?? "\(h)"
}

/// Compact form for the tiny accessory widgets ("887k").
private func formatHeightShort(_ h: UInt32) -> String {
    if h >= 1_000_000 {
        return String(format: "%.1fM", Double(h) / 1_000_000)
    }
    if h >= 1_000 {
        return "\(h / 1000)k"
    }
    return "\(h)"
}

/// First 6 + "…" + last 4 chars of a hex hash.
private func truncatedHash(_ hash: String) -> String {
    guard hash.count > 16 else { return hash }
    return "\(hash.prefix(6))…\(hash.suffix(4))"
}

/// Renders the relative-time text. If we have no real `lastBlockTime`
/// yet (epoch zero placeholder), show a literal dash so the widget doesn't
/// claim "55 years ago".
@ViewBuilder
private func relativeBlockTime(state: SharedNodeState) -> some View {
    if state.lastBlockTime.timeIntervalSince1970 < 1 {
        Text("—")
    } else {
        Text(state.lastBlockTime, style: .relative) + Text(" ago")
    }
}

// MARK: - Live Activity

/// Live Activity / Dynamic Island configuration. Gated on iOS 16.2+ (when
/// `ActivityKit` reached its current API surface). On older OS versions
/// the widget bundle simply omits this — the home/lock-screen widget
/// remains available all the way back to the project's iOS 17 deployment
/// target.
@available(iOS 16.2, *)
struct HerculesNodeActivity: Widget {
    var body: some WidgetConfiguration {
        ActivityConfiguration(for: NodeActivityAttributes.self) { context in
            // Lock Screen / banner presentation (used on non-Pro iPhones
            // and on the Lock Screen of all devices).
            ActivityBannerView(context: context)
                .activityBackgroundTint(Color.black.opacity(0.5))
                .activitySystemActionForegroundColor(.white)
        } dynamicIsland: { context in
            DynamicIsland {
                // Expanded layout (long-press)
                DynamicIslandExpandedRegion(.leading) {
                    HStack(spacing: 6) {
                        Image(systemName: context.state.phase.icon)
                            .font(.system(size: 18, weight: .semibold))
                            .foregroundStyle(context.state.phase.tint)
                        VStack(alignment: .leading, spacing: 0) {
                            Text("Hercules")
                                .font(.system(size: 10, weight: .semibold))
                                .foregroundStyle(.secondary)
                            Text(context.state.phase.label)
                                .font(.system(size: 13, weight: .semibold))
                        }
                    }
                }
                DynamicIslandExpandedRegion(.trailing) {
                    VStack(alignment: .trailing, spacing: 0) {
                        Text("\(context.state.blockHeight)")
                            .font(.system(size: 22, weight: .bold, design: .rounded))
                            .monospacedDigit()
                        Text("\(context.state.peerCount) peers")
                            .font(.system(size: 10))
                            .foregroundStyle(.secondary)
                    }
                }
                DynamicIslandExpandedRegion(.bottom) {
                    PhaseProgressBar(phase: context.state.phase)
                        .padding(.horizontal, 4)
                        .padding(.top, 4)
                }
            } compactLeading: {
                Image(systemName: context.state.phase.icon)
                    .foregroundStyle(context.state.phase.tint)
            } compactTrailing: {
                Text("\(context.state.blockHeight)")
                    .monospacedDigit()
                    .font(.system(size: 13, weight: .semibold))
            } minimal: {
                Image(systemName: context.state.phase.icon)
                    .foregroundStyle(context.state.phase.tint)
            }
            .keylineTint(context.state.phase.tint)
        }
    }
}

/// Lock Screen banner / non-Pro iPhone presentation. Same data as the
/// Dynamic Island expanded view but with more vertical room.
@available(iOS 16.2, *)
struct ActivityBannerView: View {
    let context: ActivityViewContext<NodeActivityAttributes>

    var body: some View {
        HStack(spacing: 12) {
            Image(systemName: context.state.phase.icon)
                .font(.system(size: 28, weight: .semibold))
                .foregroundStyle(context.state.phase.tint)
                .frame(width: 36)
            VStack(alignment: .leading, spacing: 2) {
                Text(context.state.phase.label)
                    .font(.system(size: 14, weight: .semibold))
                    .foregroundStyle(.white)
                Text("Block \(context.state.blockHeight) · \(context.state.peerCount) peers")
                    .font(.system(size: 12))
                    .foregroundStyle(.white.opacity(0.7))
                PhaseProgressBar(phase: context.state.phase)
                    .padding(.top, 2)
            }
            Spacer()
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 12)
    }
}

/// 5-step phase indicator: ⚪️→⚪️→⚪️→⚪️→⚪️ with the current phase filled.
/// One row, no labels — the textual label sits above this in the parent
/// view, so this exists purely as a visual heartbeat showing forward
/// progress through the wake.
@available(iOS 16.2, *)
struct PhaseProgressBar: View {
    let phase: WakePhase

    private static let order: [WakePhase] = [.connecting, .headers, .block, .validating, .done]

    var body: some View {
        HStack(spacing: 4) {
            ForEach(Self.order, id: \.self) { p in
                Capsule()
                    .fill(phaseColor(for: p))
                    .frame(height: 4)
            }
        }
    }

    private func phaseColor(for p: WakePhase) -> Color {
        if phase == .failed { return .red.opacity(0.6) }
        let currentIndex = Self.order.firstIndex(of: phase) ?? 0
        let thisIndex = Self.order.firstIndex(of: p) ?? 0
        if thisIndex <= currentIndex {
            return phase.tint
        }
        return Color.white.opacity(0.2)
    }
}

@available(iOS 16.2, *)
extension WakePhase {
    var icon: String {
        switch self {
        case .connecting: return "network"
        case .headers:    return "arrow.down.doc"
        case .block:      return "cube"
        case .validating: return "checkmark.shield"
        case .done:       return "checkmark.circle.fill"
        case .failed:     return "xmark.octagon.fill"
        }
    }

    var tint: Color {
        switch self {
        case .connecting: return .blue
        case .headers:    return .blue
        case .block:      return .yellow
        case .validating: return .yellow
        case .done:       return .green
        case .failed:     return .red
        }
    }

    var label: String {
        switch self {
        case .connecting: return "Connecting to peers"
        case .headers:    return "Receiving headers"
        case .block:      return "Downloading block"
        case .validating: return "Validating block"
        case .done:       return "Block validated"
        case .failed:     return "Wake failed"
        }
    }
}
