# Ticket 015: Offline Catch-Up After Long No-Network Period

## Summary

When Hercules is disconnected from the network for hours — no Wi-Fi with cellular policy disabled, airplane mode, dead zone, delayed APNs, anything — it accumulates a backlog of unvalidated blocks. When connectivity returns, the node needs to catch up multiple blocks without requiring the user to leave the app open. iOS background-execution constraints make this nontrivial: a single push wake (~25 s) is unlikely to validate dozens of blocks. This ticket designs the catch-up policy.

## Background

After ticket 013 lands, a user on cellular with "Use Cellular Data" off will have Hercules paused. When they reconnect to Wi-Fi later, the gap is typically:

- **1 hour offline** → ~6 missed blocks → ~12 MB to fetch + validate. Doable in one wake (~25 s budget).
- **6 hours offline** → ~36 missed blocks → ~72 MB. Way over a single wake budget.
- **Overnight (~10 hours)** → ~60 blocks. Definitively multi-wake territory.

Even without the cellular policy, this case happens whenever the user is in a cell-service dead zone, on a flight, or has APNs delivery delayed by Apple's infrastructure (which it routinely is, by minutes to hours).

## Current behavior

`NotificationManager.handleSilentPush` calls `validate_latest_block(timeout_secs: 25)`, which (per `sync.rs:1740-1862`):

1. Fetches headers from the best peer
2. If we're behind, walks forward up to some bound
3. Fetches the latest block body
4. Validates it
5. Returns

The path does *some* catch-up of intermediate headers, but it is not designed for the "50 blocks behind" case. With a 25 s budget it would either time out or only catch up the most recent block, leaving the rest stale and the chain tip dishonestly reported as fresh.

## Design

### Approach A: Multi-wake catch-up (v1, simple)

- Each push wake catches up at most **N blocks** (start with N=5, tune empirically)
- If still behind after the wake, schedule a follow-up via:
  - The next natural push wake from APNs (next mined block notification) — happens automatically
  - Optionally, a `BGAppRefreshTask` request submitted at the end of the wake, asking iOS to wake the app again soon
- Rust core gets a new entrypoint that supersedes `validate_latest_block`:

```
validate_blocks_until_caught_up_or_budget_exceeded(
    max_blocks: u32,
    budget_secs: u32,
) -> CatchUpStatus {
    caught_up: bool,
    blocks_validated: u32,
    current_height: u32,
    target_height: u32,
    error: Option<String>,
}
```

- Swift wake handler reads the status:
  - `caught_up == true`: normal completion, idle until next block
  - `caught_up == false && blocks_validated > 0`: progress, request another wake soon
  - `caught_up == false && blocks_validated == 0`: error or stuck — log, surface in UI

**Pros**: simple, no new background modes, works within existing push wake budget
**Cons**: catching up 50 blocks at N=5 takes 10 wakes. If wakes only happen on new blocks (~6/hour), that's ~100 minutes to fully catch up. Still better than nothing, and gets faster on better network conditions.

### Approach B: BGProcessingTask for batched catch-up (v2, better)

- Add the `processing` background mode to the app entitlements (`UIBackgroundModes`)
- When the network returns (NWPathMonitor flips from unsatisfied → satisfied + wifi), or when a wake notices a large backlog, submit a `BGProcessingTaskRequest`:
  - `requiresNetworkConnectivity = true`
  - `requiresExternalPower = true` (battery-friendly default; debatable)
  - `earliestBeginDate = .now`
- iOS runs the task when conditions are met (typically multiple minutes of budget, often run while charging overnight)
- During the task, Hercules can validate dozens of blocks in one go
- Task expiration handler ends gracefully: save state, optionally request another task if still behind

**Pros**: efficient, fewer wake-ups, less aggregate battery, ideal for the "catch up while charging overnight" case
**Cons**: no time guarantee from iOS — could be hours before the system schedules the task. Not the right fit for "catch up immediately when user comes home and rejoins Wi-Fi."

### Recommendation: ship A first, layer in B

**Phase 1** (immediately after ticket 013): Approach A

- Replace `validate_latest_block` with `validate_blocks_until_caught_up_or_budget_exceeded` in `sync.rs` and the UDL
- Update `NotificationManager.handleSilentPush` to honor the new return shape and decide whether to request a follow-up wake
- ~100 lines Rust + ~50 lines Swift

**Phase 2** (later): Approach B as augmentation

- `BGProcessingTaskRequest` submission in `HerculesApp.swift::scenePhase` and from the network-policy flip handler
- Task expiration handler delegating to the same Rust catch-up function with a larger budget
- `processing` background mode entitlement
- ~150 lines Swift, no Rust changes

The two approaches share the same Rust entrypoint, so the Phase 2 work is purely Swift plumbing.

### Catch-up UX

While catching up:

- Main app screen: "Catching up: 12 / 47 blocks" progress under the node status header
- Cellular icon (if applicable from ticket 013) shows green during the catch-up wake, returns to whatever state the policy dictates between wakes
- Live Activity (if Phase 3 of ticket 013 has shipped): the activity stays open across multiple wakes when actively catching up, ends when caught up or paused
- Widget (Phase 2 of ticket 013): shows the most-recent-validated height, not the target, so users see it advancing block by block. The "minutes since last block" timer resets on each newly-validated block, naturally communicating progress.

### Header-first vs full-block-first ordering

Two ordering strategies for catch-up:

- **Headers all the way to tip first, then block bodies backfill**: gives the user a fast "I now know about block N+47" feedback, but those blocks aren't fully validated yet
- **Headers + body for each block in order**: every reported height is fully validated; slower per-block

**Recommendation**: headers-to-tip first, then bodies in oldest-first order, with the UI distinguishing **tip known** from **tip validated**. This matches Bitcoin Core's IBD behavior. The header chain costs almost nothing (~80 bytes per header) so getting it to tip immediately is the right call.

## Verification

- Pause Hercules for 1 hour by turning off Wi-Fi with cellular policy off (ticket 013)
- Re-enable Wi-Fi, observe push wake fires, observe up to N blocks caught up per wake
- Wait for next block, observe further catch-up advance
- Eventually observe "fully caught up" + idle state, observe time-since-last-block timer matches reality
- Repeat with a 6-hour gap, observe multi-wake catch-up over time
- Verify catch-up budget is respected — wake never blocks the OS for more than the timeout
- (Phase 2) Plug in the device on Wi-Fi after a long gap, observe `BGProcessingTask` runs and catches up everything in a single batched operation
- Failure case: kill network mid-catch-up, observe partial progress is saved and the next wake resumes correctly

## Dependencies

- **Ticket 013** (cellular policy) — the most common cause of intentional offline gaps, and the gating logic this ticket builds on
- `sync.rs::validate_latest_block` and the UDL — needs to be extended/replaced with the budgeted catch-up entrypoint
- (Phase 2 only) iOS `processing` background mode entitlement — provisioning profile change

## Estimated effort

- **Phase 1**: ~100 lines Rust (refactor `validate_latest_block` into a budgeted loop with `CatchUpStatus`), ~50 lines Swift (handler logic + UI status field), small UDL change
- **Phase 2**: ~150 lines Swift (`BGProcessingTask` registration, submission, expiration), background mode entitlement

## Open questions

- **N (max blocks per wake)**: 5 is a starting guess. Each block validation is roughly 1–3 seconds (block fetch + sig verification + UTXO update). With 25 s wake budget minus ~5 s overhead, the practical ceiling is probably 5–7 blocks. **Measure on-device** before committing to a number.
- **`requiresExternalPower` for BGProcessingTask**: `true` is battery-friendly but delays catch-up until the user plugs in. `false` runs sooner but burns more battery on big catch-up bursts. Recommendation: `true` — the user can always foreground the app for instant catch-up if they need it now.
- **What if catch-up itself fails mid-wake** (timeout, peer error, malformed block)? Save partial progress, retry next wake. Already simple and resilient given the per-block commit pattern in LMDB.
- **Old blocks no longer in any peer's recent-block cache**: Bitcoin nodes serve blocks for the recent ~288 blocks via inv/getdata. A 50-block gap is comfortably within that. A 500-block gap (3+ days offline) might require fetching from peers that have those blocks, which is harder. For v1, document "catch-up beyond ~288 blocks may fail; user can foreground the app for IBD-style sync."
- **Header chain catch-up while bodies are still backfilling**: do we treat "headers known but not validated" as a special UI state? Yes — show two heights ("known: 887150 · validated: 887133") during catch-up, collapse to one when caught up.
- **Interaction with the cellular policy**: catch-up should respect the same gate as normal validation. If catch-up starts on Wi-Fi but the user walks out of range mid-catch-up, the next wake should land on cellular and either pause (if policy off) or continue (if policy on). The existing gate from ticket 013 handles this without extra logic.
