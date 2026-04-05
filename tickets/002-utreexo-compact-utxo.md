# Ticket 002: Utreexo Compact UTXO Accumulator

## Summary

Track utreexo as a potential alternative to the traditional UTXO database for Phase 2+. Utreexo replaces the ~8GB UTXO set with a ~1KB Merkle forest accumulator, eliminating the largest storage barrier for mobile nodes.

## Background

- **Paper:** "Utreexo: A dynamic hash-based accumulator optimized for the Bitcoin UTXO set" (Tadge Dryja, 2019)
- **Implementation:** Calvin Kim (MIT DCI / Chaincode Labs) — `utreexod` in Go
- **Status:** Working bridge nodes on mainnet, not merged into Bitcoin Core, no protocol-level changes required (bridge nodes serve proofs over existing P2P)

## How It Works

Instead of storing every UTXO (~100M entries, ~8GB), store only the roots of a Merkle forest (~1KB). When validating a transaction, the spending party provides a Merkle inclusion proof that the UTXO exists in the accumulator. The node verifies the proof and updates the roots.

## Tradeoffs vs Traditional UTXO Set

| Dimension | Traditional | Utreexo |
|---|---|---|
| Storage | ~8GB | ~1KB |
| Bandwidth/block | ~1-2MB | ~1.5-3MB (block + proofs) |
| CPU/block | DB reads/writes | Proof verification (hashing) |
| Peer dependency | Any Bitcoin peer | Needs utreexo bridge node |
| Maturity | Battle-tested (15 years) | Working but experimental |

## Why This Matters for Hercules

The #1 obstacle for a phone node is storage. Utreexo would reduce UTXO storage from 8GB to effectively zero, making the phone node footprint ~60MB (headers) + recent pruned blocks (~2GB) instead of ~10-12GB total.

## Action Items

- [ ] Monitor `utreexod` releases and stability (https://github.com/utreexo/utreexod)
- [ ] Evaluate whether utreexo bridge nodes are reliably available on mainnet
- [ ] Prototype: build a minimal utreexo verifier in Rust (proof verification is ~200 lines)
- [ ] Benchmark proof verification speed on iPhone (mostly SHA256 hashing)
- [ ] Design: could Hercules support both modes? Traditional UTXO for reliability, utreexo for storage-constrained devices?
- [ ] Track any Bitcoin Core PRs or BIPs related to utreexo proof serving

## Decision Point

Before starting Phase 2c (UTXO database), evaluate whether utreexo is stable enough to use as the primary mode. If not, build traditional UTXO first with utreexo as a future migration path.

## References

- Dryja, T. (2019). "Utreexo: A dynamic hash-based accumulator optimized for the Bitcoin UTXO set"
- https://github.com/utreexo/utreexod
- Calvin Kim's presentations at Bitcoin++ and Chaincode seminars
