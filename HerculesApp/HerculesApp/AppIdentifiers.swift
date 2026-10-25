import Foundation

/// Runtime identifiers, read from the running bundle's Info.plist.
///
/// The values are defined once in `Config/Shared.xcconfig` and injected into
/// each target's Info.plist as `HRC*` keys by `project.yml`, so renaming the
/// app is a one-file edit and Swift never hardcodes an identifier. Compiled
/// into both the app and the widget extension; the widget's Info.plist only
/// carries the keys it needs (`HRCAppGroupID`).
///
/// A missing key is a build-configuration bug, so it fails loudly on first
/// access rather than silently falling back to a stale literal.
enum AppIdentifiers {
    /// App Group shared by the app and the widget. Must match the
    /// `com.apple.security.application-groups` entitlement (both are
    /// generated from `APP_GROUP_ID`).
    static let appGroupID = value(for: "HRCAppGroupID")

    /// BGTaskScheduler identifier for accelerated catch-up. Must also appear
    /// in `BGTaskSchedulerPermittedIdentifiers` (generated from the same
    /// `BGTASK_CATCHUP_ID` setting). App target only.
    static var catchUpTaskID: String { value(for: "HRCCatchUpTaskID") }

    /// BGTaskScheduler identifier for the long, on-power catch-up
    /// (`BGProcessingTask`, ticket 051). Also in
    /// `BGTaskSchedulerPermittedIdentifiers` (from `BGTASK_PROCESSING_ID`).
    /// App target only.
    static var processingTaskID: String { value(for: "HRCProcessingTaskID") }

    /// Background URLSession identifier for the UTXO snapshot download.
    /// App target only.
    static var snapshotSessionID: String { value(for: "HRCSnapshotSessionID") }

    private static func value(for key: String) -> String {
        guard let value = Bundle.main.object(forInfoDictionaryKey: key) as? String,
              !value.isEmpty,
              !value.hasPrefix("$(") else {
            fatalError("Info.plist is missing \(key); check project.yml / Config/Shared.xcconfig")
        }
        return value
    }
}
