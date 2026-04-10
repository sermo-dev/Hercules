# Ticket 003: Cooperative Historical Validation

## Summary

Extend the cooperative relay protocol (Phase 5) to include distributed historical block validation. Instead of each phone independently validating all 860K+ blocks from genesis, the cooperative divides the work so that the entire chain is verified collectively.

## Motivation

With AssumeUTXO, each phone trusts a hardcoded UTXO snapshot hash and validates only new blocks going forward. The historical chain behind the snapshot is assumed valid. Bitcoin Core verifies history in the background (taking hours on a desktop), but this is impractical on mobile due to iOS background execution limits.

By distributing historical validation across the cooperative, the full chain gets verified without any single phone bearing the full cost — achieving the same security guarantee as a desktop node running AssumeUTXO background validation.

## Design

### Phase 1: Structural Spot-Checking (no utreexo required)

Every phone already has all block headers from Phase 1. The cooperative can immediately do lightweight auditing:

1. Cooperative selects random block heights to audit
2. Assigned phone downloads the full block at that height
3. Verifies: merkle root matches header, coinbase reward is correct, transaction format is valid, witness commitments check out
4. Multiple phones independently verify the same block for redundancy
5. Results are compared — mismatches trigger re-validation by additional nodes

**What this catches:** Garbage blocks behind valid PoW headers, inflated coinbase rewards, malformed transactions, merkle root mismatches.

**What this does NOT catch:** Double-spends, fabricated inputs, invalid signatures, script violations. These require the UTXO set at that height to verify.

**Data cost per assignment:** ~1-2MB (one full block). Negligible.

### Phase 2: Full Cooperative Validation (requires utreexo)

With utreexo, each phone can validate a range of blocks without the full 8GB UTXO set:

1. Define ranges of one difficulty epoch (2,016 blocks)
2. Phone receives: the 1KB utreexo accumulator state at the range start + block data with proofs (~3-4GB per epoch)
3. Phone validates all blocks in the range (scripts, UTXO spends, rewards — everything)
4. Phone produces the accumulator hash at the end of the range
5. If the hash matches the known checkpoint (and agrees with independent validators), the range is verified

**What this catches:** Everything. Full consensus validation.

**Scaling:** ~430 epochs in Bitcoin's history. With 1,000 phones, each validates less than one epoch. The entire chain can be verified in a single round.

## Verification of Validators

UTXO/accumulator state at any height is deterministic. If two phones independently validate the same range starting from the same state and arrive at the same resulting hash, the validation is correct. This is a cryptographic proof of work — not PoW mining, but proof that correct validation was performed.

Mismatches between validators indicate either a bug or a malicious node, and trigger re-validation by additional phones.

## Security Comparison

| Approach | Catches | Misses | Practical risk of miss |
|---|---|---|---|
| No historical validation | — | Everything historical | Near-zero (blocks have years of PoW confirmations) |
| Structural spot-checking | Bad merkle roots, inflated rewards, malformed TX | Double-spends, bad signatures | Near-zero (attack requires mining + no other full node noticing) |
| Full cooperative validation | Everything | Nothing | Zero |

## Dependencies

- Phase 1 spot-checking: Only requires Phase 1 (header chain) + block download (Phase 2a)
- Phase 2 full validation: Requires utreexo (Ticket 002) + cooperative protocol (Phase 5)

## Implementation Order

1. Ship structural spot-checking as part of Phase 5 cooperative protocol
2. Add full cooperative validation when utreexo support is ready
