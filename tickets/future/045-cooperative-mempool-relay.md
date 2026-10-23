# Ticket 045: Cooperative Mempool Relay (v2)

## Summary

A pool of phones collectively provides continuous mempool relay, even though iOS won't let any single phone stay connected in the background. Each phone takes short scheduled **relay shifts**, woken by push. During a shift it connects, refreshes its view of the mempool, and relays transactions under the cooperative's shared **policy profile**, then hands off to the next phone. This is the novel research contribution described in README Phase 6. It is a **v2 nice-to-have**, likely the last ticket on the roadmap. It is drafted here so the earlier tickets (019, 028, 029, 041) don't make choices that block it.

## Background

- **Described, not built.** README "Cooperative Mempool Relay" (`README.md`, How It Works section, and Phase 6 at `README.md:279-298`) specifies policy profiles, deterministic slot scheduling `slot = hash(node_id + current_hour) mod slots_per_hour`, shift push wake-ups, warm-up optimisation, handoff, and a possible BIP.
- **Nothing exists in code.** No slot scheduling, profile distribution, cohort, or `node_id` concept in `hercules-core/src` or `server/`. ("Slot" in `peer_pool.rs` refers to peer connection slots.)
- **Today's relay pushes every block to every device.** `server/notify/index.js:49-68` scans the whole devices table and pushes each new block to every token. There's no targeting.
- **What a phone already does when awake:** plain node relay. `relay_policy.rs` filters, mempool acceptance, and Poisson-trickled `inv` relay with feefilter (`hercules-core/src/sync.rs`, `drain_relay_queue` at ~2060). A shift reuses all of this.
- **Apple limits background pushes.** Apple's guidance for background (`content-available`) notifications says the system treats them as low priority, may throttle or coalesce them, and advises not sending more than a few per hour per device (verify the current wording in Apple's "Pushing background updates to your App" doc). That already affects per-block wakes (~6/hour). Shift pushes would add to the same budget, which is a core feasibility question.

## Proposed design (draft)

### Goals

1. At any minute of the day, at least *k* phones in each policy cohort are connected and relaying.
2. Each phone's duty is small and predictable (battery and data budget).
3. The relay server learns as little as possible.

### Scheduling: two options

| | Server-side cohorts | Client-side deterministic (README design) |
|---|---|---|
| Identity needed | None beyond the APNs token already stored (019) | A stable `node_id` per device |
| How | Server hashes `(device_token, epoch_hour)` to assign shifts and sends a targeted "shift start" push | Each phone computes its own slot; the server still has to *push* at the right time, so it needs the same mapping anyway |
| Privacy | Server knows the token→profile mapping | Same, plus a new long-lived ID |
| Coordination | Central but simple | "No coordinator" is illusory while iOS needs a push to wake |

**Recommendation:** server-side cohorts keyed on the APNs token. Because iOS can only wake via push, the server is necessarily involved, so a client-computed schedule adds an identifier without removing the dependency. Never link this to contacts (043).

### What a shift does

1. Push arrives (`shift_start`, profile ID, shift length ≤ ~25 s, or longer if a `BGProcessingTask` window is available).
2. Connect to peers (clearnet by default per 029, for speed; warm reconnect via addrman).
3. Fetch the mempool view: `mempool` message / `inv` requests, honoring `feefilter`. Accept per the profile.
4. Relay: drain the relay queue, announce our onion/clearnet address if relevant.
5. Optional handoff: publish a small digest (tx count, feerate histogram) to the server so the next phone can skip already-relayed txs. This is a research item with privacy cost.

### Policy profiles

- Named profiles, e.g. **Core-like** and **Knots-like**, matching the relay-policy profiles from 041 and the 018 amendment.
- A device opts into one. The server must know it to group cohorts, which is a privacy cost to disclose in Settings.
- Profiles are versioned and shipped in the app, not fetched from the server, so the server can't change policy.

### Budget

- Target duty: ≤ 1-2 shifts per day per device at small scale, falling as the pool grows (README table).
- Data cap per shift; respect the cellular policy (`NetworkPolicy.shouldValidate`, ticket 013). Skip shifts on metered networks unless the user opts in.

### Measuring coverage

Server-side: count shift acks per cohort per minute (only an ack with a coarse timestamp and no peer data). Publish a public coverage dashboard. Client-side: diagnostics in the Node tab.

### Abuse and failure

- Fake registrations (019 hardening) inflate cohorts with dead tokens, so prune on APNs `Unregistered`/410.
- Devices that never ack get de-prioritised.
- A malicious relay server could stop scheduling shifts. That's a liveness failure, not a safety one: validation is unaffected.

## Files touched (indicative)

| File | Action |
|---|---|
| `server/schedule/index.js` | **New**: cohort assignment, shift pushes (EventBridge schedule) |
| `server/register/index.js` | Accept the profile ID |
| `server/template.yaml` | Scheduler Lambda, ack endpoint |
| `HerculesApp/.../NotificationManager.swift` | Handle `shift_start` push type |
| `hercules-core/src/sync.rs` / `lib.rs` | `run_relay_shift(budget)` entrypoint |
| `hercules-core/src/relay_policy.rs` | Named, versioned profiles |

## Dependencies

- **019** production relay. **028** wake budget and single node per process. **029** clearnet default (Tor warm-up would eat the shift). **041** relay-policy profiles. ❌ all.

## Estimated effort

Research and spec: 1-2 weeks. Implementation: 3-5 weeks. Field measurement: ongoing.

## Verification

- Simulated cohort of N test devices: coverage ≥ target over 24 h on the dashboard.
- Per-device battery and data per day stays within budget on real hardware.
- APNs throttling measured: delivered vs sent shift pushes over a week.

## Open research questions

- Does Apple's background-push throttling make sub-hourly shifts infeasible at all? This decides whether the idea is viable on iOS.
- Is relay from short-lived, intermittently connected peers actually useful to the network, given that peers deprioritise new connections?
- Can handoff digests improve anything without leaking which txs a user cares about?
- Is there a BIP-worthy protocol here, or is it an app-level scheduling scheme?

## Roadmap position

**v2, last.** Only after the v1 node + wallet + People app ships and wake reliability (028) is measured in the field.
