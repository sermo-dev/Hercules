# Ticket 041: Fee Estimation That Works on a Phone

## Decisions (2026-10-23)

- **Decided:** relay policy does not change as part of this ticket. Accuracy comes from block-based estimation plus shadow-tracking the feerates of policy-filtered transactions; nothing extra is relayed or stored.
- The default relay profile (Knots-like vs Core-like) is decided separately (see 018 amendment / 045 policy profiles).

## Summary

Replace the current mempool-snapshot fee estimator with one that is (a) available immediately after every wake or launch, and (b) not biased low by our own relay-policy filtering. The primary signal becomes **recent validated blocks**. We see and fully validate every block, so we know what feerates actually got mined. The live mempool becomes a secondary signal when it's warm. This is a prerequisite for the send flow (020/037). Bad estimates mean either stuck transactions or overpaying, and both get blamed on the wallet.

## Background

### Why our mempool is "Knots-filtered"

Ticket 018 deliberately adopted **Bitcoin Knots-style relay policy**. `relay_policy.rs` rejects inscription envelopes, Runes, CAT-21, Stamps and `<data> OP_DROP` patterns. `mempool.rs` keeps an OP_RETURN size cap (`MAX_OP_RETURN_SIZE = 83`, `mempool.rs:44`, applied at `mempool.rs:291`). This is **policy only**. Consensus is unaffected: a block containing those transactions is still fully validated and accepted. We just don't keep or relay them.

That choice is fine for relay, but it quietly breaks fee estimation.

### The estimator today

`Mempool::estimate_fee_rates` (`mempool.rs:1214-1258`):
- Sorts our mempool by feerate and walks it until cumulative weight fills N × 4M weight units.
- **Filtered-mempool bias:** most hashrate mines inscription/Runes traffic, and it competes for the same block space. Our mempool doesn't contain it, so we see less demand than miners do and **underestimate fees**. That is exactly the failure mode that leaves a user's transaction stuck.
- **Cold-start:** if the mempool is empty it returns `1.0` sat/vB for every target (`mempool.rs:1215-1223`). On a phone the mempool is empty after *every* launch and every wake, because it lives in RAM (008 never added `mempool.dat` persistence; see 046). Right when a user opens the app to send, the estimator returns its worst answer.
- **Shallow mempool:** when our view is thin, the "mempool fits in fewer than target_blocks" fallback (`mempool.rs:1246-1247`) returns the lowest feerate we happen to hold. On a partially warm phone mempool that is near the floor.
- No tests (`mempool.rs` has 34 tests, none for `estimate_fee_rates`).

### Should we just stop filtering?

| | Keep Knots-style filtering | Revert to Core-like policy |
|---|---|---|
| Bandwidth / memory on phone | Lower: inscription traffic is large | Higher |
| Owner/user ideology | "Bitcoin is money" stance (018) | Neutral |
| Fee estimation from mempool | Biased low unless corrected | Accurate view of demand |
| Relays what miners will mine | No | Yes |

Note the current 83-byte OP_RETURN limit matches **neither** side any more. Knots defaults reject more. Bitcoin Core v30 (released 2025) raised its default OP_RETURN data allowance far above 83 bytes; verify the exact v30 default before quoting it in UI copy. Whatever we pick should be a deliberate, named profile (see the 018 amendment), not a leftover constant.

**Recommendation:** fee estimation must not depend on that choice. Fix the estimator (below), then offer relay policy as a user-visible profile. That is the same concept as the policy profiles in the cooperative relay (045).

## Proposed design

### 1. Primary: block-based estimator

During `apply_block` we already resolve every input's prevout, so per-transaction fee and vsize are computable at near-zero extra cost. For each validated block, record a compact summary:

```
BlockFeeSummary { height, total_vsize, p10, p25, p50, p75, p90, min_included_feerate }
```

Keep the last ~1008 blocks (~1 week, a few KB). Estimates for target N come from the distribution of recent blocks' lower percentiles, weighting recent blocks more heavily. This is a conservative block-percentile approach, not Core's full `estimatesmartfee` bucket tracker, and it's good enough for a phone. It's available the instant the app opens, because it's persisted.

After an AssumeUTXO bootstrap we have no history yet. In that case, fall back to the mempool estimator plus a hardcoded conservative floor until ~6 blocks have been validated.

### 2. Secondary: live mempool, corrected

When the mempool is warm (connected > ~2 minutes and > some tx count), blend in the current mempool estimate. To remove the filtering bias, keep a **shadow histogram** of transactions rejected *only* by relay policy, i.e. consensus- and script-valid and failing a Knots filter. Record `(feerate, vsize)` into feerate buckets with expiry, without storing the transaction, relaying it, or admitting it to the mempool. Include those buckets when computing "weight ahead of us". This costs almost nothing and makes the estimate policy-independent.

### 3. Output and safety rails

- Expose `estimate(target) -> { feerate, source: Blocks | Mempool | Blend | Floor, confidence }` so the UI can show "estimate based on recent blocks" honestly.
- Floor at the node's min relay feerate. Ceiling guard: warn if > 3× the recent-block p90.
- Staleness: if no block has been validated for > 2 hours, flag low confidence.

## Files touched

| File | Action |
|---|---|
| `hercules-core/src/fee_estimator.rs` | **New**: block summaries, blending, persistence |
| `hercules-core/src/block_validation.rs` / `utxo.rs` apply path | Emit per-tx fee/vsize while prevouts are resolved |
| `hercules-core/src/mempool.rs` | Shadow histogram for policy-rejected txs; retire or wrap `estimate_fee_rates` |
| `hercules-core/src/relay_policy.rs` | Hand rejected-but-valid tx stats to the shadow histogram |
| `hercules-core/src/wallet_rpc.rs` | `get_fee_estimates` uses the new estimator |
| `hercules.udl` | `FeeEstimate { feerate, source, confidence }` |

## Dependencies

- None blocking. Should land before the send flow in 037.
- Relay-policy profile decision: see the 018 amendment, and 045.

## Estimated effort

~4-5 days: block summaries plus persistence (1.5d), shadow histogram (1d), blending, floors and UDL (1d), tests (1-1.5d).

## Verification

- Unit: synthetic block sequences with known feerate distributions → expected estimates per target.
- Unit: empty mempool + persisted block history → block-based estimate, not 1 sat/vB.
- Unit: shadow histogram containing a large high-fee filtered backlog raises the mempool estimate.
- Replay (027 harness): feed ~200 real mainnet blocks and compare estimates against what mempool.space showed historically (manual spot-check).

## Open questions

- **Default relay profile.** Keep Knots-like as default (018's stance), or ship Core-like by default with Knots as an option? This is the owner's call. The estimator no longer depends on it.
- **Fee UI.** Three tiers (fast ~1 block, normal ~6, slow ~144) plus custom? Recommendation: yes. Show sats and fiat cost per tier.
- **Persist the mempool across launches (`mempool.dat`)?** It would help warm-start but costs disk and time. Probably unnecessary once block-based estimation exists.

## Roadmap position

Wallet foundations tier. Before the first send-capable wallet build.
