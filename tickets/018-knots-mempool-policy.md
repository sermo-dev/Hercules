# Ticket 018: Align Mempool Relay Policy with Bitcoin Knots

## Summary

Tighten Hercules' mempool acceptance and relay policy to match **Bitcoin Knots**, not Bitcoin Core. The Hercules ethos is that **Bitcoin is money for transactional value transfer, not a general-purpose data storage layer**. Today our `mempool::accept_tx` mirrors Bitcoin Core's standardness rules circa v25, which means we currently relay Ordinals/inscriptions, BRC-20, Stamps, Atomicals, Runes, and other on-chain data-payload protocols. This ticket changes that.

The change is **policy-only**, not consensus. Filtered transactions remain valid Bitcoin transactions and will still confirm if a miner mines them — we simply refuse to *relay* them through our node, freeing our mempool slots for actual payments.

## Current state (2026-04-07)

`hercules-core/src/mempool.rs::accept_tx_internal` (lines 272–286) implements Core-style standardness:

```rust
let is_standard = spk.is_p2pkh()
    || spk.is_p2sh()
    || spk.is_witness_program()
    || spk.is_p2pk()
    || spk.is_multisig()                                          // ← Stamps vector
    || (spk.is_op_return() && spk.len() <= MAX_OP_RETURN_SIZE);  // ← Datacarrier
```

with `MAX_OP_RETURN_SIZE = 83` (Core's pre-v30 default).

What we currently accept and relay:
- **Ordinals / BRC-20 / inscriptions** — taproot witness envelope `OP_FALSE OP_IF "ord" ... OP_ENDIF` is invisible to script-class checks; the output looks like a normal P2TR send
- **Stamps** — bare-multisig outputs encoding image data in fake pubkey points; passes `is_multisig()`
- **OP_RETURN payloads ≤ 83 bytes** — Runes, Counterparty, Omni, etc.
- **Atomicals** — similar witness envelope pattern to Ordinals
- **Witness data blobs of arbitrary size** — no per-witness payload cap

## Background

### Why Knots' policy, specifically

[Bitcoin Knots](https://github.com/bitcoinknots/bitcoin) is Luke Dashjr's downstream Bitcoin Core fork, primarily distinguished by **stricter relay policy defaults** that filter out non-monetary transaction patterns. Knots takes the position that the mempool is a *public good* and that node operators are entitled to refuse to relay transactions that consume bandwidth and storage without serving Bitcoin's monetary function. Hercules shares this position and should default to it.

Concretely, Knots defaults that differ from Core:

- **`-datacarrier=0`** — refuses any tx with an OP_RETURN output for relay (Core defaults to enabled)
- **`-permitbaremultisig=0`** — bare multisig outputs are non-standard (Core: standard)
- **Inscription filtering** — Knots scans witness data for the Ordinal envelope pattern (`OP_FALSE OP_IF [tag] [body] OP_ENDIF`) and rejects matching transactions. Recent Knots releases extended this to other inscription protocol envelopes
- **`-mempoolfullrbf=0`** — opt-in RBF only (Core enabled full-RBF by default in v26)
- **Smaller default `-datacarriersize`** if datacarrier is left enabled
- **Witness datacarrier limits** — caps the size of pushdata segments in witness scripts that resemble payloads

### Why this matters for Hercules

1. **Mobile bandwidth is metered.** Every relayed inscription tx is iPhone cell data that didn't move money. A user paying for a 5 GB cell plan is subsidizing a JPEG.
2. **Mobile storage is small.** Every inscription block is disk space we can't reclaim. The 288-block serving window already costs ~500 MB.
3. **Mempool slots are scarce.** Our 150 MB mempool fills faster with junk and evicts real payments first when fee pressure rises.
4. **It is the correct ethical default for Hercules.** A node that opts out of being a data storage server is making an explicit statement of values, and we should make that statement loudly.

## Design

### Phase 1 — Drop datacarrier and bare multisig (small change)

Modify `accept_tx_internal` standardness check at `mempool.rs:272-286`:

```rust
let is_standard = spk.is_p2pkh()
    || spk.is_p2sh()
    || spk.is_witness_program()
    || spk.is_p2pk();
// Removed: is_multisig() — bare multisig is the Stamps vector
// Removed: is_op_return branch — no datacarrier outputs accepted
```

Delete the `MAX_OP_RETURN_SIZE` constant. Add an explanatory comment block at the top of the standardness check pointing to this ticket.

**Expected catch:** ~100% of OP_RETURN-based protocols (Runes, Counterparty, etc.) and ~100% of Stamps. Inscriptions/Ordinals will **still get through** because their payload is in the witness, not the script_pubkey.

### Phase 2 — Inscription envelope detection (the hard part)

The Ordinal envelope is hidden in input witness data, not output script pubkey. Detection requires walking each input's witness stack and looking for the `OP_FALSE OP_IF ... OP_ENDIF` sentinel pattern with a known protocol tag.

Concretely, an Ordinal inscription envelope in a P2TR script-path spend looks like:

```
<sig>
<inscription_script>:
    <pubkey> OP_CHECKSIG
    OP_FALSE
    OP_IF
        OP_PUSH "ord"
        OP_PUSH 1
        OP_PUSH "image/png"
        OP_PUSH 0
        OP_PUSH <bytes...>
        OP_PUSH <bytes...>
        ...
    OP_ENDIF
<control_block>
```

The detection algorithm:

1. For each input in the tx, examine its witness stack
2. The script-path spend script is the second-to-last element (last element is the control block)
3. Parse that script with `bitcoin::Script::instructions()` and walk opcodes
4. Look for the pattern: `OP_PUSHBYTES_0` (== `OP_FALSE`) immediately followed by `OP_IF`
5. After `OP_IF`, look for a push of one of the known protocol tags: `"ord"`, `"brc-20"`, `"sns"`, etc. (maintain a const list, easy to extend)
6. If matched, reject the entire transaction

A new module `hercules-core/src/relay_policy.rs` should host this detection so it can be unit-tested in isolation against fixture transactions.

### Phase 3 — Witness datacarrier size limit

Cap the total bytes of pushdata in any single witness element at a configurable limit (Knots uses 80 bytes). Transactions whose witness contains a push larger than this are rejected. This catches large inscription bodies *and* future inscription protocol variants we haven't seen yet, since they all rely on stuffing pushdata into witness elements.

Care needed here: legitimate large witness elements exist (e.g. multi-sig redeem scripts, complex MAST trees, future taproot script revelations). The limit should apply to **pushdata content within an OP_IF block following OP_FALSE**, not all witness pushes globally. This is the Knots compromise: you can have arbitrary script complexity, you just can't use the if-false-then-data trick to smuggle a JPEG.

### Phase 4 — Disable full-RBF by default (Knots `-mempoolfullrbf=0`)

`mempool.rs` currently accepts replacement based on BIP 125 rules without checking the explicit signaling bit. Change this so that a tx whose ancestors do not signal RBF (sequence number ≥ 0xFFFFFFFE on at least one input) is **not replaceable** in our mempool. This restores the Bitcoin Core pre-v26 behavior that Knots maintains.

### Phase 5 — Replacement-by-fee for opt-in only

Tighten BIP 125 rule enforcement so a replacement tx must:
- Pay an absolute fee at least `max_replaced_fee + min_relay_fee * replacement_size`
- Not introduce new unconfirmed inputs (Knots is stricter than Core here on RBF rule 2)

## Implementation Plan

| Phase | Files | Difficulty | Test fixtures needed |
|-------|-------|-----------|----------------------|
| 1 — Drop datacarrier + bare multisig | `mempool.rs` | Trivial | OP_RETURN tx → reject; bare 1-of-3 multisig → reject |
| 2 — Inscription envelope detection | New `relay_policy.rs` | Medium | Real Ordinal tx → reject; benign P2TR spend → accept; future-proof against new tag insertion |
| 3 — Witness datacarrier cap | `relay_policy.rs` | Medium | Large pushdata in OP_IF → reject; large pushdata outside OP_IF → accept |
| 4 — Disable full-RBF default | `mempool.rs` (BIP 125 path) | Small | Sequence-locked tx → not replaceable; opt-in RBF tx → still replaceable |
| 5 — Tighter RBF rules | `mempool.rs` | Small | Replacement adding new unconfirmed inputs → reject |

Phases 1, 4, 5 can ship immediately. Phase 2 needs research into the current Knots inscription detection code (`src/policy/policy.cpp`'s `IsWitnessStandard` and helpers in recent Knots tags) to make sure we're catching the same patterns. Phase 3 follows from Phase 2.

## Pre-implementation research

Before writing code, read the current Bitcoin Knots tip to confirm:

- Exactly which inscription protocols are detected (the list grows over time as new envelope formats emerge)
- The current `-datacarriersize` and `-datacarrier` defaults in the released config
- The full RBF policy state in the latest Knots release notes
- Whether Knots has added new policy categories we should mirror (e.g. spam-pattern detection for SRC-20, Atomicals, Runic-style transactions)

This research belongs in this ticket as a "Findings" section before code changes start. **Do not implement Phase 2/3 from training-data memory of inscription patterns** — the protocols mutate quickly and we'll miss live spam if we encode stale heuristics.

## Verification

- **Phase 1:** Hand-craft a tx with an OP_RETURN output > 0 bytes; assert `accept_tx` returns `NonStandardScript`. Same for bare multisig.
- **Phase 2:** Use a real recent Ordinal transaction (pull from mainnet by txid) as a test fixture in `tests/inscription_fixtures/`. Assert `accept_tx` rejects it. Use a real legitimate P2TR transfer as a negative fixture; assert it accepts.
- **Phase 3:** Construct a witness with `OP_FALSE OP_IF <80-byte push> OP_ENDIF` → accept. With `OP_FALSE OP_IF <81-byte push> OP_ENDIF` → reject. With `<81-byte push>` outside any OP_IF → accept.
- **Phase 4:** Tx with all sequences = 0xFFFFFFFF in mempool. Submit higher-fee replacement → reject (would have been accepted before this change). Tx with one sequence < 0xFFFFFFFE → replaceable.
- **End-to-end:** Run a Hercules node connected to a Bitcoin Core node mirroring mainnet for an hour. Inspect `get_mempool_status()`: count of accepted txs should be roughly the share of mainnet traffic that is *not* inscriptions/data-carrier (varies by network conditions, but Q4 2025 / Q1 2026 was running ~30-50% inscription traffic — we expect mempool growth to be roughly half what an unfiltered Core node would see).

## Out of scope

- **Consensus changes.** This ticket is policy-only. We do not soft-fork inscriptions out of validity.
- **UI for policy toggles.** First version is a hard-coded Knots-equivalent default. A future ticket can expose toggles in Settings if users ask for finer-grained control.
- **Block validation policy changes.** When validating blocks during sync, we accept whatever miners include — we never reject blocks for containing inscriptions. Filtering is purely for our mempool acceptance and relay path.
- **Wallet-side filtering.** If the user's own wallet creates an inscription send (which Hercules' wallet won't, but a paired hardware wallet could), we still accept it for our own broadcast — outbound from the user is treated as authoritative.

## Dependencies

None. Self-contained policy change inside `mempool.rs` + a new `relay_policy.rs` module.

## Estimated effort

- Phase 1: ~20 lines of code changes + 4 unit tests. Half a day.
- Phase 2: ~150 lines for the envelope parser + ~5 fixture transactions + research time on current Knots. Two to three days including research.
- Phase 3: ~50 lines layered on top of Phase 2's parser. One day.
- Phase 4: ~30 lines of BIP 125 path tightening + 2 tests. Half a day.
- Phase 5: ~40 lines + 3 tests. Half a day.

Phase 1 + 4 + 5 (the trivial wins, no research dependency) can land in a single small PR. Phase 2 + 3 should be a separate PR after the research is documented in this ticket.
