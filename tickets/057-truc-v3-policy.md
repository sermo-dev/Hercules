# Ticket 057: TRUC (BIP 431, version 3) Transaction Policy

## Summary

The mempool refuses every version 3 transaction (`NonStandardVersion`, `mempool.rs` `TX_MAX_STANDARD_VERSION = 2`). Bitcoin Core 28+ and Knots accept them under the TRUC rules (BIP 431, "topologically restricted until confirmation"), and Lightning implementations are moving their commitment and anchor transactions to v3 so that a fee bump can't be pinned.

Refusing v3 is safe (we never relay what we can't police), but it has costs:

- **Relay:** we drop every TRUC transaction, so we relay less of what Core relays. Lightning force-closes and anchor spends are the main ones.
- **Wallet:** an incoming payment inside a v3 transaction is invisible until it confirms (ticket 040's unconfirmed view).
- **Own sends:** a user can't broadcast a v3 transaction they signed elsewhere (`SubmitError::NonStandard`), though our own wallet never builds one.

This ticket implements Core's TRUC policy, so v3 is accepted exactly where Core accepts it.

**Severity: Low.** Nothing breaks; we are just stricter than Core. Deferred from 053 part 2 (2026-10-31), which kept v3 refused.

## Background

Core's rules (`src/policy/truc_policy.{h,cpp}`, `SingleTRUCChecks` / `PackageTRUCChecks`, checked in `MemPoolAccept::PreChecks`):

| Constant | Value |
|---|---|
| `TRUC_VERSION` | 3 |
| `TRUC_ANCESTOR_LIMIT` (with itself) | 2 |
| `TRUC_DESCENDANT_LIMIT` (with itself) | 2 |
| `TRUC_MAX_VSIZE` | 10,000 vB (sigop-adjusted) |
| `TRUC_CHILD_MAX_VSIZE` | 1,000 vB (sigop-adjusted), when it has an unconfirmed parent |

1. A TRUC tx may only have TRUC unconfirmed ancestors, and a non-TRUC tx only non-TRUC ones.
2. At most one unconfirmed parent and one unconfirmed child (the limits above).
3. **Sibling eviction:** a second child of a TRUC parent may replace the existing child under the RBF fee rules, even though they don't conflict.
4. A TRUC tx is always replaceable (implicit signaling; we are full-RBF anyway).
5. Ephemeral dust (`PreCheckEphemeralTx` / `CheckEphemeralSpends`) is tied to it in practice: a zero-fee TRUC parent with one dust output that its child must spend. Today any dust output is a rejection here (053 part 1).

Core's `bypass_limits` (reorg re-adds) skips the TRUC checks; 053 part 2's `FeeFloor::Bypass` is where that goes.

What makes TRUC useful (a zero-fee parent paid for by its child) needs package relay: Core's 1p1c orphan resolution and `submitpackage`. Without it, a v3 parent below the minimum relay fee still can't get in, so the first version of this ticket is the single-transaction rules only.

## Proposed fix

1. Raise `TX_MAX_STANDARD_VERSION` to 3 (Core's `TX_MAX_STANDARD_VERSION`) only together with the checks below, in `accept_tx_with` after the ancestor closure (Phase 5), skipped under `FeeFloor::Bypass`:
   - version inheritance (rule 1) against in-mempool parents;
   - ancestor and descendant limits of 2;
   - `TRUC_MAX_VSIZE` and, with an unconfirmed parent, `TRUC_CHILD_MAX_VSIZE`, both sigop-adjusted (`GetVirtualTransactionSize` with sigop cost, which our vsize doesn't do yet).
2. Sibling eviction: treat the existing child as a conflict for `check_bip125` and `collect_eviction_set`, reporting it as `RemovalReason::ReplacedBy` so the event stream and the own-tx tracker see it.
3. Own transactions: same rules for `accept_own_tx`; map the new errors to `SubmitError::NonStandard` (or `Conflict` for a sibling that doesn't pay enough).
4. Later, with package relay (separate ticket): ephemeral dust and zero-fee TRUC parents.

## Files touched

| File | Action |
|---|---|
| `hercules-core/src/mempool.rs` | TRUC checks, sibling eviction, sigop-adjusted vsize |
| `hercules-core/src/own_tx_store.rs` | Error mapping |
| `hercules-core/src/relay_policy.rs` | Check the 018 filters don't misread Lightning v3 witnesses |

## Dependencies

- **053**: removal event stream, `FeeFloor`, capacity plan.
- **040**: shows incoming payments in v3 transactions once they're accepted.
- Package relay (not yet a ticket) for zero-fee TRUC parents and ephemeral dust.

## Estimated effort

1.5–2 days: the rules 0.5 day, sibling eviction 0.5 day, sigop-adjusted vsize and tests 0.5–1 day.

## Verification

- Port Core's `src/test/txvalidation_tests.cpp` TRUC cases and `test/functional/mempool_truc.py` scenarios as unit tests:
  - a v3 child of a v2 parent, and a v2 child of a v3 parent, are refused;
  - a second v3 child replaces the first only with a higher fee rate and absolute fee;
  - a v3 grandchild is refused;
  - a 10,001 vB v3 tx and a 1,001 vB v3 child are refused (boundaries at 10,000 and 1,000).
- A reorg re-add of a v3 tx skips the checks, as Core's `bypass_limits`.
- Relay of a real Lightning anchor-channel commitment pair (v3 parent, anchor-spending child) round-trips.

## Roadmap position

After the pre-wallet hardening block (049 → 050 → 053 → 054 → 052 → 025), and before anything that needs Lightning-style transactions to relay through us.
