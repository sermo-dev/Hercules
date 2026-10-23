# Ticket 022: Bind Every Fetched Block to Its Requested Header

## Summary

The push-wake validation path accepts whatever block a peer sends back, without checking that it is the block we asked for. A peer can answer with a fabricated block that has a valid-looking structure. Hercules then applies that block to the UTXO set and advances `validated_height`. The fix is small: check `block.block_hash() == requested` inside `Peer::get_block` itself, so every caller is protected. Unsolicited blocks get skipped instead of returned.

**Severity: Critical.** This can corrupt the UTXO set. Fake coins get added, the real block's spends are never applied, and every block validated afterwards builds on wrong state. This should ship as a standalone PR before anything else in the safety tier.

## Background

### The unchecked path

`HeaderSync::validate_latest_block` (`hercules-core/src/sync.rs:2278-2335`) runs on every silent-push wake:

```rust
let block_hash = new_header.block_hash();
...
match block_peer.get_block(block_hash) {
    Ok(block) => {
        // Structural validation
        if let Err(e) = validate_block(&block, new_tip) { ... }
        // Script validation
        if let Err(e) = validate_block_scripts(&block, new_tip, &self.utxo) { ... }
        // Apply to UTXO set
        if let Err(e) = self.utxo.apply_block(&block, new_tip) { ... }
        ...
        self.store.set_validated_height(new_tip)
```

Nothing in this sequence compares `block.block_hash()` to `block_hash`:

- `validate_block` (`block_validation.rs:62`) checks the merkle root against the block's **own** header (`block.check_merkle_root()`). It never checks the block against our stored header.
- No step re-checks proof-of-work on the received header.

So a peer that returns a coinbase-only block with a correct BIP34 height passes every check.

### `get_block` returns the first block it sees

`Peer::get_block` (`p2p.rs:532`) sends `getdata(WitnessBlock(hash))`, then calls `receive_block` (`p2p.rs:561`). `receive_block` reads up to 20 messages and returns the first `NetworkMessage::Block` it sees, whatever its hash.

That means an honest peer can trigger this bug too. A peer that has just learned about a new block may push it to us unsolicited (or in a race with our `getdata`), and that block would be mistaken for the one we requested. In the wake path that gets applied at the wrong height. Most often `validate_block` then rejects it on BIP34 height, but it is still the wrong mechanism to rely on.

### The other paths already check

- The main sync loop: `sync.rs:1073`, `if block.block_hash() != block_hash { return Err(...) }`
- `catch_up_blocks`: `sync.rs:2544`, same check.

The background push path is the only one missing the check. It is also the one that runs most often once the app is deployed.

### Why a hash comparison is enough

Once `block.block_hash() == requested`:

1. **The header is the one we stored.** The block hash is the hash of the header. Our stored header has already passed `validate_headers` (linkage, PoW, retarget, MTP, future-time), so proof-of-work is implicitly verified.
2. **The transactions are bound to that header.** `validate_block` checks:
   - the merkle root against the header,
   - the witness commitment (`check_witness_commitment`), which binds witness data,
   - duplicate txids (rule 7, `block_validation.rs:142`), which closes the CVE-2012-2459 merkle-duplication malleation.

Together these bind the full transaction set and witnesses to the header we validated.

## Proposed fix

1. **Make the check part of `get_block`'s contract** (`p2p.rs`):
   - `receive_block(expected: BlockHash)`. On `Block(b)` with `b.block_hash() != expected`, log at debug level and **keep reading**, because it may be an unsolicited announcement. This stays within the existing 20-message bound and the download timeout.
   - Add a `PeerError::BlockNotReceived { expected }` variant for "20 messages / timeout without the requested block". That way callers can tell "peer didn't deliver" apart from transport errors.
   - Keep the existing `NotFound` early return.
2. **Callers penalize and retry.** In `validate_latest_block`, a `BlockNotReceived` result calls `pool.misbehaving(addr, N)` and retries once with a different peer if the time budget allows. Otherwise it returns the header-only notification it already returns today. Ticket 024 generalizes this "penalize and retry" pattern.
3. **Keep the call-site checks** at `sync.rs:1073` and `sync.rs:2544` as defense in depth. Add the same explicit check in `validate_latest_block` right after `get_block`, so a future refactor of `p2p.rs` can't silently remove the protection.
4. **Fix the fallback.** If the wake path cannot get the right block, `validated_height` must not advance. It already doesn't advance in the `Err` arm; add a test that locks this in.

## Files touched

| File | Action |
|---|---|
| `hercules-core/src/p2p.rs` | `receive_block` takes `expected`, skips non-matching blocks; new `PeerError::BlockNotReceived` |
| `hercules-core/src/sync.rs` | `validate_latest_block`: explicit hash check, misbehavior penalty, one retry with another peer |
| `hercules-core/src/p2p.rs` (tests) | New loopback tests (below) |

## Dependencies

None. This can land immediately. Ticket 027 (integration harness) later adds an end-to-end test for the wake path.

## Estimated effort

About half a day, including tests.

## Verification

These unit tests use the existing `loopback_peer_pair()` helper (`p2p.rs:814`). The test drives the server side of a loopback TCP pair and writes raw P2P messages.

- **Wrong then right:** the server writes `block(B_other)` then `block(B_requested)`. `get_block(B_requested)` returns `B_requested`.
- **Only wrong:** the server writes `block(B_other)` and then nothing. `get_block` returns `BlockNotReceived` after the timeout or bound. It must **not** return `B_other`.
- **Not found:** the server writes `notfound`. Returns the existing not-found error.
- **Interleaved noise:** `ping`, `inv`, `block(B_other)`, `block(B_requested)`. Returns `B_requested` and the ping gets a pong.
- **Regression for the wake path:** an `apply_block` spy or UTXO-count assertion showing that `validated_height` is unchanged when the peer serves the wrong block. A unit-level version goes in now; the end-to-end version goes in 027.

## Open questions

- **Penalty size.** A peer that answers with the wrong block is either buggy or racing an announcement. Suggested: a small penalty (around 10) for `BlockNotReceived`, and the full ban weight only when a block whose hash *matches* fails consensus. Ticket 024 handles that case.
- **Should unsolicited blocks be cached?** When we skip a non-matching block, it may well be the next tip. Caching it, say one slot keyed by hash, would save a round trip on the next wake. Recommendation: no, not in this ticket. Keep the fix minimal.

## Roadmap position

First item in the safety tier: **022 → 023 → 024 → 027 → 025/026**. Ship it as its own small PR before any wallet work. A wallet that shows balances from a corruptible UTXO set is worse than having no wallet.
