# Ticket 016: Header Tip Cross-Check and Peer Count Tuning

## Summary

Hercules's bursty wake model creates a unique eclipse-resistance gap that doesn't exist in continuously-running nodes like Bitcoin Core. Each push wake re-rolls the dice on which peers we sample, and we have **one shot** per wake to learn the true chain tip — if our chosen peer is malicious or just unlucky, we won't find out for ~10 minutes (the next wake), during which the widget and Live Activity will confidently show a stale or forked chain.

This ticket proposes two related improvements:

1. **Header tip cross-check**: parallel `getheaders` to 3 peers per wake, require tip agreement before reporting a new height. The cheap, high-value defense.
2. **Measurement-driven peer count tuning**: revisit `MAX_OUTBOUND = 8` (`peer_pool.rs:12`) once we have data on per-wake peer connection cost. Possibly bump to 12-16 if wake budget allows.

## Background

### How Core handles header sync (and why it's fine for Core)

Bitcoin Core picks a single "sync peer" — the one claiming the highest work — and downloads headers sequentially via `getheaders`/`headers` messages. **Not fan-out.** The reasoning:

- **Headers are self-verifying via PoW.** A malicious peer cannot make you accept invalid headers — they fail the difficulty check and the chain-of-work check unconditionally. The PoW *is* the verifier. Getting the same header bytes from multiple peers adds no verification value.
- **The real threat is eclipse, not bad headers.** A malicious peer can't lie *about* a header, but they can withhold the truth — show a stale chain or a low-work fork. The defense is **peer diversity**, not query redundancy. With 8 outbound peers from diverse IP/AS sources, even one honest peer means you'll learn the real tip.
- **`sendheaders` (BIP 130) provides implicit fan-out.** Once at the tip, peers proactively announce new headers. Receiving the same new tip from many peers in quick succession is itself a free consistency check.
- **Core swaps sync peers on stall.** If the chosen peer goes silent or sends garbage, Core picks a new one — "one peer at a time" but not "one peer forever."

This works for Core because Core is **always on**. If a malicious peer feeds you a stale tip at second 0, by second 60 you've heard from 7 other peers via `sendheaders` and noticed the disagreement.

### Why this doesn't work for Hercules

Hercules is not always on. It does a single-shot wake every ~10 minutes (or whenever a push arrives), validates one block, and goes back to sleep. Critical differences:

| Aspect | Bitcoin Core | Hercules wake |
|---|---|---|
| Time to learn truth from another peer | seconds to minutes (continuous gossip) | **next wake** (~10 min) |
| Implicit `sendheaders` fan-out | yes, free | **no** — gossip pipeline isn't running |
| Peer connections persist between samplings | yes (TCP sockets stay alive) | **no** (suspended → sockets torn down) |
| Sampling events per hour | thousands of messages | **~6 wakes** |

So during a Hercules wake, you have **one shot** at "is my view of the chain tip correct?" If the single peer you pick (`best_peer()` in `sync.rs:1740-1862`) is malicious or just unlucky, you don't find out for ~10 minutes. Meanwhile the widget says "tip = 887123" with full confidence, the Live Activity completes with a green checkmark, and the user trusts a value that may be wrong.

This is the case where **per-wake header tip cross-check** earns its keep.

## Design

### Part 1 — Header tip cross-check

#### What

For each wake, instead of asking one peer for headers and trusting the response, ask **3 peers in parallel** for the latest headers and require their reported tips to be **consistent**:

- All 3 agree on tip hash → high confidence, proceed with validation
- 2 agree, 1 disagrees by ≤1 block → likely natural propagation lag (the lagging peer just hasn't seen the latest block yet); proceed with the majority tip and demote the lagging peer's reputation slightly
- 2 agree, 1 disagrees by >1 block → either a real reorg in progress (rare but legitimate) or one peer is lying. Pick the higher-work tip per consensus rules. Log the disagreement for diagnostics.
- All 3 disagree → eclipse signal, abort the wake, log loudly, surface in UI, retry next wake from a different peer set

Header bytes are tiny (~80 bytes per header, plus protocol framing). Three parallel `getheaders` exchanges cost roughly the same as one — bandwidth-wise it's noise compared to the block body fetch (~1.5–2 MB).

#### Where

- New function in `sync.rs` (or a sibling): `fetch_tip_with_cross_check(pool: &PeerPool) -> Result<TipConsensus, EclipseSignal>`
- Returns either a `TipConsensus { hash, height, source_peers: Vec<PeerId> }` or an `EclipseSignal { observed_tips: Vec<(PeerId, Hash, u32)> }` with the disagreeing tips for diagnostics
- Called at the start of `validate_latest_block` (or its `validate_blocks_until_caught_up_or_budget_exceeded` successor from ticket 015) before any block-body fetch
- Block-body fetch continues to use a single peer — local re-validation already protects against bad block contents, so fan-out at the body layer is bandwidth waste with no safety gain

#### Distinguishing fan-out strategies

| Strategy | Useful for Hercules? | Why |
|---|---|---|
| **Header tip cross-check** (3 peers, tips must agree) | **Yes** | Cheap (~240 bytes), real eclipse defense for bursty wakes |
| **Header chain fan-out** (download full header chain from N peers) | No | PoW already verifies chain validity; tip cross-check captures the eclipse-defense value at a fraction of the cost |
| **Block body fan-out** (same block from N peers) | No | Local re-validation already protects against bad contents; redundant fetches waste bandwidth |
| **Block validation fan-out** (validate same block on N peers' state) | N/A | Doesn't make sense — we have one local UTXO set |

Only the first one is worth implementing.

#### UI signal

When a tip cross-check disagreement is detected:

- Wake completes but the icon (from ticket 013) reflects "verification incomplete" — proposal: a fourth state, **purple**, distinct from red (paused) and yellow (cellular)
- Tap reveals: "Couldn't reach consensus on chain tip. May be a real reorg or a network issue. Retrying next wake."
- The validation history entry records the disagreement and which peers reported what — useful for forensics if eclipse attacks become a real concern

### Part 2 — Peer count tuning

Current: `MAX_OUTBOUND = 8` in `peer_pool.rs:12`, matching Bitcoin Core's default.

This number comes from real research — Heilman et al. 2015's "Eclipse Attacks on Bitcoin's Peer-to-Peer Network" and the subsequent Core mitigations. 8 is grounded in eclipse-resistance math for a continuously-running node.

#### Forces pulling toward higher than 8

- Each Hercules wake re-rolls the dice on which peers we end up with. More peers per wake = better odds of sampling honest ones in any single wake.
- Eclipse attacks against bursty wake-based nodes are arguably *easier* than against continuous nodes — the attacker has fewer attempts to surveil but each attempt is a complete sampling event.
- Hercules pays no continuous bandwidth between wakes, so the marginal cost of "16 peers per wake" vs "8" is lower than for Core (which pays for keeping all 8 sockets alive 24/7).

#### Forces pulling toward 8 (or lower)

- Each peer connection eats wake budget. Tor circuit setup is roughly 3–8 seconds per connection. 16 parallel handshakes might consume the entire 25 s wake budget before validation even starts.
- Arti's circuit budget is finite. Many concurrent circuits per wake may run into Tor-side limits.
- Diminishing returns: 1→2 peers is huge, 2→4 is meaningful, 4→8 is real, 8→16 is small, 16→32 is tiny. The eclipse-resistance curve flattens.

#### Recommendation

**Don't change the constant blind.** Instead:

1. **Land Part 1 first** (header tip cross-check). This captures most of the eclipse-defense value of "more peers" without the wake-budget cost of more connections.
2. **Instrument the wake path** to record per-wake metrics: time from wake start to first peer ready, time to N peers ready (N=3, 5, 8), time to header tip, time to block body, time to validation done. Average + p95 across many wakes.
3. **Once data is in hand**, decide:
   - If wake budget regularly has 5+ seconds of headroom after validation completes → bump `MAX_OUTBOUND` to 12
   - If wake budget is tight (validation finishes within 2-3 s of timeout) → keep at 8
   - Either way, the cross-check makes the existing 8 meaningfully stronger

The instrumentation work itself is small (~50 lines in `sync.rs`) and useful regardless of the eventual peer count decision.

### Part 3 — Diversification beyond just count

A subtle but important point: **8 peers from one ASN is worse than 4 peers from 4 ASNs.** The existing AddrManager work (ticket 011) and ASN-tracking eclipse defense (ticket 001, completed) already address this for the Hercules pool — outbound peers are diversified across ASN buckets.

Worth verifying that the 3-peer cross-check sample also enforces diversity: the 3 chosen peers should come from 3 different ASN buckets. If they all happen to be in the same bucket, an attacker who controls that bucket trivially defeats the cross-check. ASN-diverse selection is the actual defense; the count is secondary.

This is a constraint to add to `fetch_tip_with_cross_check`'s peer selection, not a separate piece of work.

## Verification

- **Cross-check happy path**: 3 honest peers, all report the same tip → wake validates normally, log shows "tip cross-check: 3/3 agreement"
- **Cross-check propagation lag**: 2 peers report tip N, 1 reports tip N-1 → wake proceeds with tip N, log shows "tip cross-check: 2/3 + 1 lagging by 1 block, accepted"
- **Cross-check disagreement**: simulate by patching one peer to return a fake tip → wake aborts validation, icon turns purple, log shows "tip cross-check: disagreement, observed tips: [(peerA, hash1, h1), (peerB, hash2, h2), (peerC, hash3, h3)]"
- **ASN diversity**: confirm the 3 peers used for cross-check come from 3 different ASN buckets when available
- **Wake budget impact**: measure wake duration before/after cross-check on real hardware (iPhone over Tor). Acceptable ceiling: +2 seconds for the parallel header fetches.

## Dependencies

- Existing peer pool and AddrManager (`peer_pool.rs`)
- ASN bucketing from completed ticket 001
- Compatible with ticket 015's `validate_blocks_until_caught_up_or_budget_exceeded` (cross-check should be called once per wake, not per block during catch-up — the per-block cost would be prohibitive)

## Estimated effort

- **Part 1 (cross-check)**: ~150 lines Rust — parallel `getheaders` over the existing peer pool, consensus logic, error handling for disagreement cases
- **Part 1 UI**: ~50 lines Swift — fourth icon state and history entry plumbing
- **Part 2 (instrumentation)**: ~50 lines Rust to record per-wake timing metrics, exposed to the iOS UI for diagnostics
- **Part 2 (peer count change)**: trivial constant change pending data

## Open questions

- **Cross-check threshold**: 3 peers is the proposed minimum. Should it be configurable? Probably not — too many knobs. 3 is the smallest number that gives meaningful Byzantine fault tolerance (any 1 lying still leaves a 2-vs-1 outcome).
- **What counts as "lagging by ≤1 block"?** Strictly one block, or up to 2-3 to be more forgiving of real network propagation delays? Recommendation: strictly 1 — Bitcoin block propagation is sub-second over modern networks, so >1 block of lag is suspicious and worth flagging even if not definitively malicious.
- **Cross-check failure during catch-up**: if we're 50 blocks behind, do we cross-check at the start of every catch-up batch or only on the final wake when we're presumably at the tip? Recommendation: only at the tip — during catch-up, the headers we're fetching are by definition already-confirmed history, and cross-check adds no value mid-IBD.
- **Logging policy**: cross-check disagreements are rare and important. Worth a dedicated log channel or notification history entry, separate from regular validation events. Forensic value if eclipse attacks become real.
- **Should cross-check apply to inbound peers too?** Currently the proposal is "3 outbound peers." Inbound peers have different trust properties (they connected to us, not the reverse — easier for an attacker to set up). Recommendation: outbound only for the cross-check sample.
