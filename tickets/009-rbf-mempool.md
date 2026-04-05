# Ticket 009: Replace-By-Fee (BIP 125)

## Summary

Add BIP 125 Replace-By-Fee support to the mempool. Currently, if a transaction spends the same inputs as an existing mempool transaction, it's rejected with `ConflictsWith`. This causes our mempool to diverge from the network — when a user RBF-bumps a transaction, every other node replaces the old tx, but we keep the stale one until a block confirms the replacement.

## Background

BIP 125 defines opt-in RBF: a transaction signals replaceability by setting `nSequence < 0xfffffffe` on at least one input. When a conflicting transaction arrives that spends the same inputs, it can replace the original if it meets these rules:

1. The original signals replaceability (nSequence check)
2. The replacement pays a strictly higher fee rate
3. The replacement pays enough absolute fee to cover the relay cost of all evicted transactions (at minimum relay fee rate)
4. The replacement doesn't evict more than 100 transactions (ancestor/descendant chain limit)
5. The replacement doesn't introduce any new unconfirmed inputs that weren't in the original

Bitcoin Core v28+ enabled full RBF by default (`-mempoolfullrbf=1`), making the nSequence signal optional. Most of the network now accepts replacements regardless of signaling.

## Design

### Changes to `mempool.rs`

Modify `accept_tx()`:
- When `ConflictsWith` would fire, instead of rejecting, check if replacement is valid
- Calculate the fee delta: replacement fee must exceed original fee by at least the relay cost of evicted txs
- Walk the descendant graph of the original tx (requires the chain-spending feature from ticket 010 first, OR we can implement "direct conflicts only" RBF as a simpler first step — if the conflicting tx has no dependents in the mempool, replacement is straightforward)
- If replacement is valid, remove the original (and its descendants) and insert the replacement

### Phasing

**Phase A (simple, no deps):** Direct-conflict-only RBF. If the conflicting mempool tx has no children spending its outputs, allow replacement. This covers >95% of real-world RBF usage (fee bumps on single transactions).

**Phase B (requires ticket 010):** Full BIP 125 with descendant eviction. Requires ancestor/descendant tracking from CPFP work.

### Full RBF vs Opt-in

Follow Bitcoin Core v28+ and implement full RBF (no nSequence check). The network has converged on this.

## Testing

- Replace a single conflicting tx (higher fee rate)
- Reject replacement with lower fee rate
- Reject replacement that doesn't cover relay cost of evicted tx
- Replace with multiple conflicting inputs
- Reject replacement of tx that has descendants (Phase A)
- Full descendant eviction (Phase B)

## Dependencies

- Phase A: None (can be done now)
- Phase B: Ticket 010 (CPFP / ancestor tracking)
