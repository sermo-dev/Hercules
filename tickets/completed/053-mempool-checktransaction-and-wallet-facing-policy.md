# Ticket 053: Mempool — Context-Free Transaction Checks and Wallet-Facing Policy

## Decisions (2026-10-30, owner)

- **Principle:** every policy change matches Bitcoin Core / Knots behavior (ticket 018); we don't invent policy.
- **Replacements that add a new unconfirmed input are rejected**, matching Knots (`replacement-adds-unconfirmed`). The existing test `rbf_allows_replacement_with_existing_mempool_parent` and the PR #29 divergence test are updated to match.
- **Minimum relay fee and incremental relay fee stay at 1 sat/vB.** No change. 041's estimator floors at 1 sat/vB.
- **Duplicate inputs / MoneyRange:** already shipped in PR #29.

## Summary

The mempool never runs Core's `CheckTransaction`, so it accepts and relays a transaction that spends the same coin twice. Core and Knots peers reject such a transaction as consensus-invalid and disconnect us, so an attacker holding one coin can keep knocking us off our peers for free. Under ticket 040 it would also show the user a fake, inflated "pending" payment.

Several smaller policy gaps would break the wallet's sends or make them look stuck:

- a flat 546-sat dust limit, where Core uses per-type limits;
- no warning when a send's fee is below what peers accept;
- an own transaction left "pending" for 14 days after its parent died;
- a capacity check that can return `Ok` for a transaction that was just evicted.

This ticket fixes the security hole now and the wallet-facing gaps before sending is built.

**Severity: High** for duplicate inputs, **Medium** for the wallet-facing items, **Low** for the rest. Found by the mempool reviewer (2026-10-28 team review of main @ 7732755). The duplicate-input gap was confirmed in code: `mempool.rs` has no duplicate-outpoint check.

## Background

Line numbers are at main 7732755.

### 1. No `CheckTransaction` in the mempool

- Phase 2 (`mempool.rs:461-518`) resolves each input independently, so an input listed twice resolves twice and `input_sum` counts it twice. Each copy carries a valid signature, and script checks run one input at a time.
- There are no per-output or total `MoneyRange` checks either (`mempool.rs:341-347`).
- Block validation already rejects duplicate inputs; the mempool doesn't share that code.

### 2. Dust limit

`mempool.rs:52-53, 378-388` uses a flat 546 sats. Core and Knots compute `GetDustThreshold` at a 3000 sat/kvB dust relay fee:

| Output type | Dust threshold (sats) |
|---|---|
| P2WPKH | 294 |
| P2TR | 330 |
| P2WSH | 330 |
| P2SH | 540 |
| P2PKH | 546 |

Effects:
- **Sends:** a 400-sat payment to a Taproot address, or 300–545 sats of change from the planned Core coin-selection port (034), fails with `NonStandard("peers will not relay it")`, which is false.
- **Relay:** we drop transactions with 330-sat Lightning anchor outputs, including incoming payments that carry one.

### 3. Sends below peers' fee floor vanish

After each launch our mempool starts nearly empty with no rolling minimum fee, so it accepts anything at ≥1 sat/vB. The fee estimator returns 1 sat/vB whenever the mempool is empty (`mempool.rs:1320-1329`).

During congestion, peers' `feefilter`s are higher:
- `drain_relay_queue` skips every peer (`sync.rs:4227-4230`), yet `submit_own_tx` still returns `Ok` and the tx stays "pending" until it expires.
- CPFP can't rescue it. A peer receiving the child asks us for the parent, and `handle_getdata` answers `notfound` (`sync.rs:4006-4009`) because that peer was never announced the parent.

### 4. Own transaction stuck when a parent that isn't ours dies

`own_tx_store.rs:770-832`, `sync.rs:1506-1513`, `mempool.rs:1036-1046`.

**Scenario:** the user's tx C spends an unconfirmed incoming tx P, which is then replaced or double-spent.
1. Our mempool evicts P and C without reporting it.
2. `on_block` only checks whether C's own inputs were spent. C's input is `P:n`, which the block never touches.
3. Re-adding C fails with `MissingInput`, and `readd_own_tx` swallows the error.

C stays active until its 14-day expiry and is never marked Conflicted. Confirmed coins C also spent look locked for those two weeks.

### 5. Capacity pre-check disagrees with eviction

`mempool.rs:857-891` (the simulation) vs `731-741`, `1257-1262` (the real loop):
- **Ties:** the simulation sorts stably with the new package last, but the real loop evicts the first root in HashMap order with a strict `<`. A new tx at exactly the minimum rate can be evicted right after insertion.
- **Double counting:** shared descendants of two roots are subtracted twice (line 891).
- **Result:** in release builds `accept_tx` returns `Ok(txid)` for a tx no longer in the pool; the `debug_assert` doesn't run.
- **Cost:** both paths scan O(N), plus a sort, under the mempool lock on every accept when full.

### 6. Smaller divergences

- **Relay policy false positives** (`relay_policy.rs:124-201`): the envelope and OP_DROP checks parse every witness element as script, including signatures and pubkeys. A compressed pubkey shaped `02 xx yy 00 63 …` is rejected as `InscriptionEnvelope`, roughly 1 in 10,000 P2WPKH inputs.
- **No `replacement-adds-unconfirmed` rule** (`mempool.rs:939-948`). Knots and Core ≤30 reject such replacements, so a fee bump that adds an unconfirmed input succeeds locally and dies on those peers. The comment's rationale is wrong.
- **Coinbase maturity one block stricter than Core** (`mempool.rs:506`; Core uses tip+1 as the spend height).
- **The 0.1 BTC absurd-fee cap applies to relayed transactions** (`mempool.rs:556`). It drops high-fee exchange batches and any payments to the user inside them; it should apply only to our own sends.
- **Missing standardness checks:** the standard sigops limit, push-only scriptSig and tx version.
- **`AlreadyKnown` mismatch:** the FFI returns `Err(AlreadyKnown)` where the RPC treats it as success.

## Proposed fix

### Now (security)

1. **Context-free checks before Phase 1**, sharing block validation's logic:
   - duplicate outpoints;
   - each output and the total in `MoneyRange`;
   - non-empty inputs and outputs;
   - size limits.
   Reject as consensus-invalid (peer misbehavior), as Core does.

### Before sending (wallet-facing)

2. **Dust:** port Core's `GetDustThreshold`, with the dust relay fee as a constant (3000 sat/kvB).
3. **Fee floor at submit:** compare the tx's package feerate with connected peers' feefilters. Return `FeeBelowNetworkMinimum` (or a warning flag) instead of silent success.
   - Record which peers fetched the tx with `getdata`, so the app can show "delivered".
   - Serve `getdata` for own unconfirmed ancestors to any peer that was sent an own descendant.
4. **Mempool event stream:** `remove_confirmed`, RBF replacement, expiry and capacity eviction return the removed txids with a reason (`Confirmed`, `ReplacedBy(txid)`, `Evicted`, `Expired`, `ConflictedByBlock`).
   - `own_tx_store` marks own txs among them Conflicted.
   - This is the same stream ticket 040 needs; design it as that API.
5. **Capacity:**
   - Require a new package's feerate to exceed the lowest surviving package plus the incremental relay fee (Core's rolling minimum).
   - Never evict the just-inserted package.
   - Turn the `debug_assert` into an error.
   - Track the minimum package with an ordered index, not a scan.

### With the above (smaller)

6. Parse only the tapscript leaf (control-block and annex aware) or the P2WSH witnessScript in the envelope and OP_DROP checks.
7. Add the `replacement-adds-unconfirmed` rule.
8. Fix coinbase maturity to tip+1.
9. Apply the absurd-fee cap to own transactions only.
10. Add the standard sigops, push-only scriptSig and version checks.
11. Treat `AlreadyKnown` as success on the Swift side.

### Owner decision

Decided: stay at 1 sat/vB (see Decisions).

## Files touched

| File | Action |
|---|---|
| `hercules-core/src/mempool.rs` | Context-free checks; dust; event stream; capacity rework; replacement rule; maturity; fee cap |
| `hercules-core/src/block_validation.rs` | Share the context-free transaction checks |
| `hercules-core/src/relay_policy.rs` | Witness parsing |
| `hercules-core/src/own_tx_store.rs` | Conflicted from evictions; delivery records |
| `hercules-core/src/sync.rs` | Feefilter check at submit; getdata for own ancestors; delivery tracking |
| `hercules-core/src/lib.rs`, `hercules.udl` | `FeeBelowNetworkMinimum`; delivery state in `OwnTxInfo` |

## Dependencies

- **033**: own-tx store.
- **Feeds** 040 (event stream) and 041 (fee floor).
- The `tests/data-path` PR from the 2026-10-28 test pass may already fix duplicate inputs (it was allowed to). It adds reproducer tests for the rest marked `#[ignore = "BUG: ..."]`; un-ignoring them is part of done.

## Estimated effort

3–4 days:
- context-free checks: 0.5 day (less if the test PR did it)
- dust and the smaller items: 1 day
- event stream and Conflicted: 1 day
- fee floor and delivery: 0.5 day
- capacity: 0.5–1 day

## Verification

- **Duplicate input:** rejected by both `accept_tx` and `accept_own_tx` with the consensus class; the relaying peer is penalized.
- **Dust:** boundaries per type (293/294 P2WPKH, 329/330 P2TR and P2WSH, 539/540 P2SH, 545/546 P2PKH).
- **Own child of a non-own parent:**
  - parent replaced through relay, then the replacement confirms;
  - a conflicting spend of the parent confirms.
  In both cases the own tx is Conflicted, not pending.
- **Full mempool:** tied minimum-rate packages, and a shared descendant of two roots. `Ok` implies `contains(txid)`, tested in release mode too.
- **Fee floor:** an own tx below every peer's feefilter is surfaced to the caller. `getdata` for an own parent from a peer that was sent its child is served.
- **Relay policy:** a P2WPKH witness with pubkey `02 xx yy 00 63…` passes.
- **Smaller rules:** a replacement adding an unconfirmed input is rejected; a coinbase spend at exactly 100 confirmations matches Core.

## Roadmap position

Third in the pre-wallet hardening block: **049 → 050 → 053 → 054 → 052 → 025**. The duplicate-input fix is small and can go first. The wallet-facing parts (items 2–5) must land before 040 and the send flow.

## Status (2026-10-31)

Part 1 merged in PR #31 (`661d64a`); part 2 in PR #36 (`4ebb3b4`). Part 2: Core's `STANDARD_SCRIPT_VERIFY_FLAGS` checked through `hercules_policy.cpp` in the patched v26 library (linked in every build; non-Apple kernel builds refused by `compile_error!`); input/witness standardness, tx-size-small, policy scripts last, fee floors and `FeeBelowNetworkMinimum`; the mempool removal stream wired through `settle_mempool_removals`; own-tx delivery records (`own_tx_delivered`, `own_txs.sqlite3` schema 2) and reconciliation from the chain (`resolve_missing_own_input`); a tracker failure never stops a block connect (`unsettled_blocks`, retried on the maintenance tick, status "transaction tracking is behind"). Owner decisions taken as recommended: `CheckTransaction` failures disconnect without scoring; a send below a stale fee floor is still refused; Core 30's 2,500 sigop limit (BIP 54); the ~1–2 MB larger app.

**At merge with 052:** the own-parent exception (serving a parent to a peer that knows an own descendant) sits on top of 052's rule that own txs only go to clean outbound peers.

**Follow-ups:** TRUC / v3 policy (057).
