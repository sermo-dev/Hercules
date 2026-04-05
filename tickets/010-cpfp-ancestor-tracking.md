# Ticket 010: CPFP and Ancestor/Descendant Tracking

## Summary

Add Child-Pays-For-Parent (CPFP) support and ancestor/descendant chain limits to the mempool. Currently the mempool only accepts transactions whose inputs exist in the confirmed UTXO set — it rejects any transaction spending an unconfirmed output. This prevents CPFP fee bumping and diverges from the network's mempool behavior.

## Background

### CPFP (Child Pays For Parent)

If a transaction is stuck with too low a fee, anyone who can spend one of its outputs can create a "child" transaction with a high fee. Miners evaluate the combined fee rate of parent + child (the "ancestor fee rate") and mine both together if it's profitable. This is critical for:

- Lightning Network: force-close transactions use pre-signed fees that may be stale. The other party bumps via CPFP on their output.
- Wallet fee bumping: when RBF isn't available (e.g., the tx didn't signal, or it's someone else's tx), CPFP is the only option.

### Ancestor/Descendant Tracking

For CPFP to work, the mempool must:
1. Allow transactions that spend unconfirmed outputs (mempool chain spending)
2. Track parent/child relationships as a directed graph
3. Compute "ancestor fee rate" = (sum of fees in ancestor chain) / (sum of sizes in ancestor chain)
4. Enforce limits to prevent DoS via deep chains

Bitcoin Core's limits: max 25 ancestors, max 25 descendants, max 101 kvB combined ancestor size.

## Design

### New data structures in `mempool.rs`

```
MempoolEntry (extend existing):
    + ancestors: HashSet<Txid>      // all unconfirmed ancestors
    + descendants: HashSet<Txid>    // direct + transitive children
    + ancestor_fee: u64             // sum of fees in ancestor chain
    + ancestor_size: usize          // sum of sizes in ancestor chain
    + ancestor_fee_rate: f64        // ancestor_fee / (ancestor_size / 4.0)
```

### Changes to `accept_tx()`

1. For each input, check UTXO set first (existing behavior)
2. If not in UTXO set, check if the input txid is in the mempool — if so, this is a child-pays-for-parent situation
3. For mempool-parent inputs: verify the specific output index exists and hasn't been spent by another mempool tx (double-spend check against the `spends` index)
4. Calculate ancestor set: union of all parents' ancestor sets + the parents themselves
5. Enforce ancestor limits:
   - `ancestors.len() + 1 <= 25` (including self)
   - `ancestor_size + self.size <= 101_000`
6. For each ancestor, update its descendant set to include the new tx

### Changes to `remove_confirmed()` and `remove_tx()`

When removing a tx, update all descendants' ancestor sets and recalculate ancestor fee rates. When removing a confirmed block, process in topological order (parents before children) to avoid stale references.

### Mining priority

Add `select_for_block(max_weight) -> Vec<Transaction>` that selects transactions by ancestor fee rate (highest first), removing selected txs' ancestors from the remaining pool. This isn't needed for relay but would be useful if we ever serve block templates.

## Complexity

This is the most complex mempool feature. Bitcoin Core's `CTxMemPool` ancestor tracking is ~1000 lines of carefully optimized code. Our implementation can be simpler since we're not building block templates, but the graph management is inherently complex.

Estimated: 300-500 lines of new code + significant refactoring of `accept_tx()`.

## Testing

- Accept a child spending an unconfirmed parent output
- Reject child if parent output doesn't exist (wrong vout)
- Reject child if parent output already spent by another mempool tx
- Enforce 25-ancestor limit
- Enforce 101 kvB ancestor size limit
- Ancestor fee rate calculation matches expected values
- Removing a confirmed parent correctly updates child's ancestors
- Removing a tx removes it from all descendants' ancestor sets
- Deep chain: A→B→C→D, remove B, verify C and D are also removed

## Dependencies

- None (extends existing mempool.rs)
- Ticket 009 Phase B depends on this
